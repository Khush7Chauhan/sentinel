import sys
import json
import argparse
from pathlib import Path
from src.models import PackageRecord, Severity
from src.intel.typosquat import check_typosquat
from src.intel.osv import check_osv_vulnerabilities
from src.analysis.ast_scanner import scan_file_ast
from src.analysis.lifecycle import inspect_setup_py
from src.analysis.secrets import scan_file_secrets
from src.parsers.requirements import parse_requirements

RISK_FAILURE_THRESHOLD = 40.0

def print_terminal_report(scanned_target: str, findings: list, packages_count: int):
    print(f"\n[SENTINEL AUDIT REPORT] Target: {scanned_target}")
    print(f"Dependencies Evaluated: {packages_count}")
    print("=" * 65)

    if not findings:
        print("\033[92m✅ No critical threats detected. Build passed.\033[0m")
        return

    total_score = sum(f.points for f in findings)
    print(f"⚠️ TOTAL RISK SCORE: {total_score} (Fail Threshold: {RISK_FAILURE_THRESHOLD})\n")

    for f in findings:
        color = "\033[91m" if f.severity in (Severity.CRITICAL, Severity.HIGH) else "\033[93m"
        reset = "\033[0m"
        print(f"{color}[{f.layer}] {f.severity.value} - {f.type} ({f.package}){reset}")
        print(f"   Reason: {f.human_explanation}")
        if "line" in f.evidence:
            print(f"   Location: Line {f.evidence['line']}")
        if "entropy" in f.evidence:
            print(f"   Entropy Score: {f.evidence['entropy']}")
        print("-" * 65)

def export_json_report(scanned_target: str, findings: list, output_file: str = "sentinel_report.json"):
    report = {
        "target": scanned_target,
        "total_risk_score": sum(f.points for f in findings),
        "total_findings": len(findings),
        "build_status": "FAILED" if sum(f.points for f in findings) >= RISK_FAILURE_THRESHOLD else "PASSED",
        "findings": [f.to_dict() for f in findings]
    }
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4)
    print(f"✅ Machine-readable report exported to {output_file}")

def main():
    parser = argparse.ArgumentParser(description="Sentinel: End-to-End Dependency & Codebase Vulnerability Scanner")
    parser.add_argument("target_dir", help="Project directory to scan")
    parser.add_argument("--json", action="store_true", help="Export findings to sentinel_report.json")
    parser.add_argument("--threshold", type=float, default=RISK_FAILURE_THRESHOLD, help="Risk score threshold to fail CI")

    args = parser.parse_args()
    target_path = Path(args.target_dir)

    if not target_path.exists() or not target_path.is_dir():
        print(f"Error: Directory '{args.target_dir}' does not exist.")
        sys.exit(2)

    findings = []
    packages = []

    req_file = target_path / "requirements.txt"
    if req_file.exists():
        packages = parse_requirements(req_file)
    else:
        packages = [PackageRecord(name=target_path.name)]

    for pkg in packages:
        typo_finding = check_typosquat(pkg)
        if typo_finding:
            findings.append(typo_finding)
        if pkg.version:
            findings.extend(check_osv_vulnerabilities(pkg))
    for file_path in target_path.rglob("*.py"):
        pkg_ref = packages[0] if packages else PackageRecord(name="local-code")
        findings.extend(scan_file_ast(pkg_ref, file_path))
        findings.extend(scan_file_secrets(pkg_ref, file_path))
        if file_path.name == "setup.py":
            findings.extend(inspect_setup_py(pkg_ref, file_path))

    if args.json:
        export_json_report(str(target_path), findings)
    else:
        print_terminal_report(str(target_path), findings, len(packages))
    total_score = sum(f.points for f in findings)
    has_critical = any(f.severity == Severity.CRITICAL for f in findings)

    if total_score >= args.threshold or has_critical:
        sys.exit(1)

    sys.exit(0)

if __name__ == "__main__":
    main()