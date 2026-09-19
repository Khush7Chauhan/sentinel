import httpx
from src.models import PackageRecord, Finding, Severity

def check_dependency_confusion(package: PackageRecord, is_internal_candidate: bool = False) -> list[Finding]:
    if not is_internal_candidate:
        return []

    findings = []
    if package.ecosystem == "pypi":
        url = f"https://pypi.org/pypi/{package.name}/json"
    elif package.ecosystem == "npm":
        url = f"https://registry.npmjs.org/{package.name}"
    else:
        return []

    try:
        response = httpx.get(url, timeout=4.0)
        if response.status_code == 404:
            findings.append(Finding(
                id=f"L3-DEP-CONFUSION-{package.name}",
                layer="L3",
                package=package.name,
                type="DEPENDENCY_CONFUSION_RISK",
                severity=Severity.HIGH,
                confidence=0.85,
                evidence={"ecosystem": package.ecosystem, "target": package.name},
                human_explanation=f"Package '{package.name}' is referenced locally but does not exist on the public {package.ecosystem} registry. An attacker can register it publicly to poison builds.",
                mitigation=f"Claim '{package.name}' on {package.ecosystem} or configure an explicit internal registry scope.",
                points=15.0
            ))
    except Exception:
        pass

    return findings