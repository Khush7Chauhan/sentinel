import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pathlib import Path
from src.models import PackageRecord
from src.intel.typosquat import check_typosquat
from src.hygiene.secrets import scan_repo_secrets
from src.scoring.engine import calculate_package_score

app = FastAPI(title="Supply Chain Sentinel API")

app.add_middleware(
    CORSMiddleware, 
    allow_origins=["*"], 
    allow_methods=["*"]
)

@app.post("/api/scan")
def trigger_scan(target_dir:str):
    target_path = Path(target_path)
    if not target_path.exist():
        raise HTTPException(status_code=404, detail="Target directory not found")

    pkg = PackageRecord(
        name="reqeusts", 
        version="2.31.0", 
        ecosystem="pypi", 
        direct=True, 
        depth=0, 
        source_file="requirements.txt"
    )

    findings = []
    if tf := check_typosquat(pkg):
        findings.append(tf)
        
    repo_findings = scan_repo_secrets(target_path)
    verdict = calculate_package_score(pkg, findings)

    return {
        "key": "live-scan",
        "label": str(target_path.name),
        "graph": {
            "nodes": [
                {"id": "root", "label": target_path.name, "x": 300, "y": 150, "kind": "root"},
                {"id": pkg.name, "label": pkg.name, "x": 140, "y": 240, "kind": "pkg"}
            ],
            "edges": [["root", pkg.name]]
        },
        "packages": [{
            "id": verdict.record.name,
            "name": verdict.record.name,
            "version": verdict.record.version,
            "ecosystem": verdict.record.ecosystem,
            "direct": verdict.record.direct,
            "depth": verdict.record.depth,
            "l1": 100 - verdict.score, #
            "l2": 10,
            "findings": [
                {
                    "severity": f.severity.value.lower(), 
                    "title": f.type, 
                    "detail": f.human_explanation, 
                    "fix": f.mitigation
                } for f in verdict.findings
            ]
        }],
        "projectFindings": [
            {
                "severity": f.severity.value.lower(), 
                "title": f.type, 
                "file": f.evidence.get("file", "repo"), 
                "fix": f.mitigation
            } for f in repo_findings
        ]
    }