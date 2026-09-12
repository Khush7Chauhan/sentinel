import httpx
from datetime import datetime
from src.models import PackageRecord, Finding, Severity

def check_registry_anomalies(package: PackageRecord) -> list[Finding]:
    """Analyzes registry metadata for sleeper releases and maintainer trust scores[cite: 2]."""
    if package.ecosystem != "pypi":
        return []
        
    url = f"https://pypi.org/pypi/{package.name}/json"
    findings = []
    
    try:
        response = httpx.get(url, timeout=5.0)
        if response.status_code != 200:
            return findings
            
        data = response.json()
        releases = data.get("releases", {})
        
        # Extract and sort valid release dates
        release_dates = []
        for ver, files in releases.items():
            if files:
                upload_time_str = files[0].get("upload_time")
                if upload_time_str:
                    try:
                        dt = datetime.strptime(upload_time_str, "%Y-%m-%dT%H:%M:%S")
                        release_dates.append((dt, ver))
                    except ValueError:
                        continue
                    
        release_dates.sort(key=lambda x: x[0])
        
        # Version Anomaly: Sleeper Package (Gap > 365 days)[cite: 2]
        if len(release_dates) >= 2:
            latest_dt, latest_ver = release_dates[-1]
            prev_dt, prev_ver = release_dates[-2]
            
            gap_days = (latest_dt - prev_dt).days
            if gap_days > 365:
                findings.append(Finding(
                    id="L1-SLEEPER-RELEASE",
                    layer="L1",
                    package=package.name,
                    type="VERSION_ANOMALY_SLEEPER",
                    severity=Severity.HIGH,
                    confidence=0.85,
                    evidence={"gap_days": gap_days, "previous_version": prev_ver, "latest_version": latest_ver},
                    human_explanation=f"Package was dormant for {gap_days} days before the sudden release of v{latest_ver}. This is a strong indicator of a hijacked or sold package[cite: 2].",
                    mitigation="Audit the codebase heavily before upgrading to this version.",
                    points=15.0
                ))
                
        # Maintainer Trust Approximation[cite: 2]
        info = data.get("info", {})
        author_email = info.get("author_email", "")
        
        if author_email:
            is_freemail = any(domain in author_email.lower() for domain in ["gmail.com", "yahoo.com", "hotmail.com"])
            if is_freemail and len(release_dates) < 3:
                findings.append(Finding(
                    id="L1-UNTRUSTED-MAINTAINER",
                    layer="L1",
                    package=package.name,
                    type="UNTRUSTED_MAINTAINER",
                    severity=Severity.MEDIUM,
                    confidence=0.70,
                    evidence={"email": author_email, "releases": len(release_dates)},
                    human_explanation="Maintainer uses a free email provider and has very few historical releases, resulting in a low trust score[cite: 2].",
                    mitigation="Verify package provenance and author identity.",
                    points=8.0
                ))
                
    except Exception:
        pass

    return findings