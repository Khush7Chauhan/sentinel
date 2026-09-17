import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pathlib import Path
from src.parsers.manifest import parse_target_directory
from src.intel.typosquat import check_typosquat
from src.hygiene.secrets import scan_repo_secrets
from src.scoring.engine import calculate_package_score

app = FastAPI(title="Supply Chain Sentinel API")

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"])

@app.post("/api/scan")
def trigger_scan(target_dir: str):
    target_path = Path(target_dir)
    if not target_path.exists():
        raise HTTPException(status_code=404, detail="Target directory not found")
        
    parsed_packages = parse_target_directory(target_path)
    repo_findings = scan_repo_secrets(target_path)
    processed_packages = []
    graph_nodes = [{"id": "root", "label": target_path.name, "x": 300, "y": 150, "kind": "root"}]
    graph_edges = []
    x_offset = 100
    y_offset = 70
    
    for pkg in parsed_packages:
        findings = []
    
        if tf := check_typosquat(pkg):
            findings.append(tf)
            
        verdict = calculate_package_score(pkg, findings)
        graph_nodes.append({"id": pkg.name, "label": pkg.name, "x": x_offset, "y": y_offset, "kind": "pkg"})
        graph_edges.append(["root", pkg.name])

        x_offset += 120
        if x_offset > 500:
            x_offset = 100
            y_offset += 100
            
        processed_packages.append({
            "id": verdict.record.name,
            "name": verdict.record.name,
            "version": verdict.record.version,
            "ecosystem": verdict.record.ecosystem,
            "direct": verdict.record.direct,
            "depth": verdict.record.depth,
            "l1": 100 - verdict.score, 
            "l2": 0, 
            "findings": [
                {
                    "severity": f.severity.value.lower(), 
                    "title": f.type, 
                    "detail": f.human_explanation, 
                    "fix": f.mitigation
                } for f in verdict.findings
            ]
        })
    return {
        "key": "live-scan",
        "label": str(target_path.name),
        "graph": {
            "nodes": graph_nodes,
            "edges": graph_edges
        },
        "packages": processed_packages,
        "projectFindings": [
            {
                "severity": f.severity.value.lower(), 
                "title": f.type, 
                "file": f.evidence.get("file", "repo"), 
                "fix": f.mitigation
            } for f in repo_findings
        ]
    }