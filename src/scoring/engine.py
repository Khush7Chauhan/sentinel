from datetime import datetime
from src.models import Finding, PackageVerdict, PackageRecord, ScanReport
from src.config import RULES

def calculate_package_score(record: PackageRecord, findings: list[Finding]) -> PackageVerdict:
    caps = RULES.get("category_caps", {})
    
    cat_totals = {"typosquat": 0.0, "behavior": 0.0, "cve": 0.0, "maintainer": 0.0, "other": 0.0}
    
    for f in findings:
        effective_points = f.points * f.confidence
        
        if f.layer == "L1" and "TYPOSQUAT" in f.type:
            cat_totals["typosquat"] += effective_points
        elif f.layer == "L1" and "CVE" in f.type:
            cat_totals["cve"] += effective_points
        elif f.layer == "L1" and ("MAINTAINER" in f.type or "ANOMALY" in f.type):
            cat_totals["maintainer"] += effective_points
        elif f.layer == "L2":
            cat_totals["behavior"] += effective_points
        else:
            cat_totals["other"] += effective_points

    total_deduction = 0.0
    for cat, points in cat_totals.items():
        if cat in caps:
            total_deduction += min(points, caps[cat])
        else:
            total_deduction += points

    score = max(0.0, 100.0 - total_deduction)
    return PackageVerdict(record=record, score=round(score, 2), findings=findings)

def generate_report(target: str, verdicts: list[PackageVerdict], repo_findings: list[Finding]) -> ScanReport:
    total_deduction = 0.0
    for v in verdicts:
        depth_weight = 1.0 if v.record.direct else (1.0 / max(1, v.record.depth))
        total_deduction += depth_weight * (100.0 - v.score)
        
    for f in repo_findings:
        total_deduction += (f.points * f.confidence)

    project_score = max(0.0, 100.0 - total_deduction)
    
    return ScanReport(
        target=target,
        started_at=datetime.utcnow(),
        finished_at=datetime.utcnow(),
        project_score=round(project_score, 2),
        packages=verdicts,
        repo_findings=repo_findings,
        tool_version="1.0",
        config_hash="static-hash"
    )