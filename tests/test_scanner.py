import pytest
from pathlib import Path
from src.models import PackageRecord, Severity
from src.intel.typosquat import check_typosquat
from src.analysis.ast_scanner import scan_file_ast

def test_l1_typosquat_detection():
    # Simulate a parsed requirements.txt entry
    pkg = PackageRecord(name="reqeusts", version="2.31.0")
    finding = check_typosquat(pkg)
    
    assert finding is not None
    assert finding.layer == "L1"
    assert finding.type == "TYPOSQUAT_DISTANCE"
    assert finding.severity == Severity.HIGH
    assert finding.evidence["target_package"] == "requests"

def test_l2_ast_malicious_payload():
    pkg = PackageRecord(name="demo-app-auth", version="1.0")
    target_file = Path("demo-app/malicious_auth.py")
    
    findings = scan_file_ast(pkg, target_file)
    
    # We expect multiple findings: dangerous imports and eval/system calls
    finding_types = [f.type for f in findings]
    
    assert len(findings) >= 3
    assert "DANGEROUS_IMPORT" in finding_types
    assert "DANGEROUS_EXECUTION_CALL" in finding_types
    assert "SYSTEM_COMMAND_EXECUTION" in finding_types

    critical_finding = next(f for f in findings if f.severity == Severity.CRITICAL)
    assert critical_finding.evidence["call"] == "eval"