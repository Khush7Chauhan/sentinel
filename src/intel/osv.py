import httpx
from src.models import PackageRecord, Finding, Severity

def check_osv_vulnerabilities(package: PackageRecord) -> list[Finding]:
    """Queries the OSV.dev API for known CVEs affecting this package version."""
    if not package.version:
        return []

    url = "https://api.osv.dev/v1/query"
    # OSV expects ecosystem names like "PyPI" or "npm"
    ecosystem_format = "PyPI" if package.ecosystem == "pypi" else package.ecosystem.capitalize()
    
    payload = {
        "version": package.version,
        "package": {
            "name": package.name,
            "ecosystem": ecosystem_format
        }
    }
    
    findings = []
    try:
        response = httpx.post(url, json=payload, timeout=5.0)
        if response.status_code != 200:
            return []
            
        data = response.json()
        
        for vuln in data.get("vulns", []):
            vuln_id = vuln.get("id", "UNKNOWN-VULN")
            summary = vuln.get("summary", "Security vulnerability detected.")
            
            findings.append(Finding(
                id=f"L1-OSV-{vuln_id}",
                layer="L1",
                package=package.name,
                type="KNOWN_CVE",
                severity=Severity.CRITICAL,
                confidence=1.0,
                evidence={"osv_id": vuln_id},
                human_explanation=f"Public vulnerability {vuln_id}: {summary}",
                mitigation=f"Upgrade {package.name} to a patched version immediately.",
                points=25.0
            ))
    except Exception:
        # Fails silently to prevent crash during offline demo execution
        pass 

    return findings