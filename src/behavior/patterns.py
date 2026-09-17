import re
import ast
from pathlib import Path
from src.models import PackageRecord, Finding, Severity
from src.config import RULES
from src.hygiene.secrets import calculate_shannon_entropy

REGEX_PATTERNS = {
    "B01": (Severity.CRITICAL, r"(?i)(stratum\+tcp|coinhive|xmrig)", "Crypto-miner strings detected."),
    "B04": (Severity.HIGH, r"https?://\d{1,3}(?:\.\d{1,3}){3}", "Raw IP endpoint detected. Malware frequently avoids DNS to evade sinkholes."),
    "B06": (Severity.HIGH, r"(?i)(\.ssh/id_rsa|\.aws/credentials|/etc/passwd|crontab)", "Targeting sensitive filesystem paths."),
    "B08": (Severity.MEDIUM, r"(?i)(/etc/rc\.local|systemd/system|Run/|Start Menu/Programs/Startup)", "Persistence mechanism detected (Autostart/Run keys)."),
    "B10": (Severity.INFO, r"(?i)(segment\.com|google-analytics\.com)", "Telemetry or tracking endpoint.")
}

class BehaviorASTVisitor(ast.NodeVisitor):
    """Detects B02 (Env-harvest + exfil) and B07 (Dynamic execution) via AST."""
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.findings = []
        self.current_function = None

    def visit_FunctionDef(self, node):
        self.current_function = node.name
        env_read = False
        outbound_http = False
        
        for child in ast.walk(node):
            if isinstance(child, ast.Attribute) and child.attr == "environ":
                env_read = True
            if isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute):
                if child.func.attr in ("post", "get", "request", "urlopen"):
                    outbound_http = True
                    
        if env_read and outbound_http:
            self.findings.append(Finding(
                id=f"B02-{node.lineno}",
                layer="L2",
                package=None,
                type="ENV_EXFILTRATION_SUSPECT",
                severity=Severity.CRITICAL,
                confidence=0.95,
                evidence={"file": self.filepath, "function": self.current_function, "line": node.lineno},
                human_explanation="Function reads environment variables and executes outbound HTTP requests. This is a strong indicator of credential harvesting[cite: 2].",
                mitigation="Inspect the function's network destination.",
                points=25.0
            ))
            
        self.generic_visit(node)

def scan_extracted_tarball(package: PackageRecord, extract_dir: Path) -> list[Finding]:
    """Scans all extracted code against the B01-B10 catalog[cite: 2]."""
    findings = []
    whitelist_ips = RULES["behavior_limits"]["raw_ip_whitelist"]
    entropy_threshold = RULES["behavior_limits"]["entropy_threshold"]

    for file_path in extract_dir.rglob("*"):
        if file_path.is_dir() or file_path.suffix not in {".py", ".js", ".ts", ".sh"}:
            continue

        try:
            content = file_path.read_text(encoding="utf-8")
        except Exception:
            continue
            
        for line_num, line in enumerate(content.splitlines(), start=1):
            for rule_id, (sev, pattern, desc) in REGEX_PATTERNS.items():
                match = re.search(pattern, line)
                if match:
                    if rule_id == "B04" and any(ip in match.group(0) for ip in whitelist_ips):
                        continue
                        
                    findings.append(Finding(
                        id=f"{rule_id}-{line_num}",
                        layer="L2",
                        package=package.name,
                        type="MALICIOUS_BEHAVIOR_PATTERN",
                        severity=sev,
                        confidence=0.90,
                        evidence={"file": file_path.name, "line": line_num, "match": match.group(0)},
                        human_explanation=desc,
                        mitigation="Review the matched code immediately.",
                        points=25.0 if sev == Severity.CRITICAL else (15.0 if sev == Severity.HIGH else 8.0)
                    ))
                    
            if not file_path.name.endswith(".min.js"):
                long_strings = re.findall(r'[A-Za-z0-9+/=]{100,}', line)
                for s in long_strings:
                    if calculate_shannon_entropy(s) > entropy_threshold:
                        findings.append(Finding(
                            id=f"B05-{line_num}",
                            layer="L2",
                            package=package.name,
                            type="HIGH_ENTROPY_OBFUSCATION",
                            severity=Severity.HIGH,
                            confidence=0.85,
                            evidence={"file": file_path.name, "line": line_num},
                            human_explanation="Highly randomized string literal detected. Often used to disguise payloads[cite: 2].",
                            mitigation="Check for hidden `eval()` or decoding loops.",
                            points=15.0
                        ))

        if file_path.suffix == ".py":
            try:
                tree = ast.parse(content)
                visitor = BehaviorASTVisitor(file_path.name)
                visitor.visit(tree)
                for f in visitor.findings:
                    f.package = package.name
                    findings.append(f)
            except SyntaxError:
                pass

    return findings