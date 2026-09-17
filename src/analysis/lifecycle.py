import ast
from pathlib import Path
from src.models import PackageRecord, Finding, Severity

def inspect_setup_py(package: PackageRecord, file_path: Path) -> list[Finding]:
    if not file_path.exists():
        return []

    findings = []
    try:
        source_code = file_path.read_text(encoding="utf-8")
        tree = ast.parse(source_code, filename=str(file_path))
    except Exception:
        return findings

    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "setup":
            for keyword in node.keywords:
                if keyword.arg == "cmdclass":
                    findings.append(Finding(
                        id="L3-CMDCLASS-HOOK",
                        layer="L3",
                        package=package.name,
                        type="INSTALL_HOOK_OVERRIDE",
                        severity=Severity.HIGH,
                        confidence=0.85,
                        evidence={"line": node.lineno},
                        human_explanation="Package overrides installation hooks via 'cmdclass', which can execute arbitrary code during installation.",
                        mitigation="Verify if the custom install hook is legitimate.",
                        points=15.0
                    ))
    return findings