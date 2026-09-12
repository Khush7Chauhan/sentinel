import ast
from pathlib import Path
from src.models import PackageRecord, Finding, Severity

DANGEROUS_IMPORTS = {"os", "subprocess", "socket", "urllib", "requests", "base64", "pty"}
DANGEROUS_CALLS = {"eval", "exec", "__import__", "system", "popen", "run", "call"}

class SentinelASTVisitor(ast.NodeVisitor):
    def __init__(self, package_name: str, file_path: str):
        self.package_name = package_name
        self.file_path = file_path
        self.findings = []
        self._imported_modules = set()

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            if alias.name in DANGEROUS_IMPORTS:
                self._imported_modules.add(alias.name)
                self._add_finding(
                    type="DANGEROUS_IMPORT",
                    severity=Severity.MEDIUM,
                    evidence={"module": alias.name, "line": node.lineno},
                    explanation=f"Imports potentially dangerous module: '{alias.name}'."
                )
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module in DANGEROUS_IMPORTS:
            self._imported_modules.add(node.module)
            self._add_finding(
                type="DANGEROUS_IMPORT",
                severity=Severity.MEDIUM,
                evidence={"module": node.module, "line": node.lineno},
                explanation=f"Imports from potentially dangerous module: '{node.module}'."
            )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        # Check direct function calls like eval(), exec(), or getattr()
        if isinstance(node.func, ast.Name):
            if node.func.id in DANGEROUS_CALLS:
                self._add_finding(
                    type="DANGEROUS_EXECUTION_CALL",
                    severity=Severity.CRITICAL,
                    evidence={"call": node.func.id, "line": node.lineno},
                    explanation=f"Direct execution of untrusted payload via '{node.func.id}'."
                )
            elif node.func.id == "getattr":
                self._add_finding(
                    type="OBFUSCATION_GETATTR",
                    severity=Severity.HIGH,
                    evidence={"line": node.lineno},
                    explanation="Potential obfuscation using 'getattr' to hide malicious system calls."
                )
        
        # Check attribute calls like os.system() or subprocess.run()
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in DANGEROUS_CALLS:
                if isinstance(node.func.value, ast.Name) and node.func.value.id in DANGEROUS_IMPORTS:
                    self._add_finding(
                        type="SYSTEM_COMMAND_EXECUTION",
                        severity=Severity.HIGH,
                        evidence={"module": node.func.value.id, "call": node.func.attr, "line": node.lineno},
                        explanation=f"System command execution detected: '{node.func.value.id}.{node.func.attr}'."
                    )
                
        self.generic_visit(node)

    def _add_finding(self, type: str, severity: Severity, evidence: dict, explanation: str):
        self.findings.append(Finding(
            id=f"AST-{type}-{evidence.get('line', 0)}",
            layer="L2",
            package=self.package_name,
            type=type,
            severity=severity,
            confidence=0.9,
            evidence={"file": self.file_path, **evidence},
            human_explanation=explanation,
            mitigation="Inspect this file manually. If this package shouldn't require system access or dynamic execution, do not install it.",
            points=20.0 if severity == Severity.CRITICAL else (15.0 if severity == Severity.HIGH else 5.0)
        ))

def scan_file_ast(package: PackageRecord, file_path: Path) -> list[Finding]:
    """Parses a Python file into an AST and scans it for malicious patterns."""
    if not file_path.exists():
        return []
        
    try:
        source_code = file_path.read_text(encoding="utf-8")
        tree = ast.parse(source_code, filename=str(file_path))
    except (SyntaxError, UnicodeDecodeError):
        return [Finding(
            id="AST-PARSE-ERROR",
            layer="L2",
            package=package.name,
            type="OBFUSCATION_SYNTAX_ERROR",
            severity=Severity.HIGH,
            confidence=0.7,
            evidence={"file": str(file_path)},
            human_explanation="Could not parse Python file. It may be heavily obfuscated or corrupted.",
            mitigation="Check if the source code contains disguised binary payloads.",
            points=15.0
        )]

    visitor = SentinelASTVisitor(package.name, str(file_path))
    visitor.visit(tree)
    return visitor.findings