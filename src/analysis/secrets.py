import math
import re
from pathlib import Path
from src.models import PackageRecord, Finding, Severity

SECRET_PATTERNS = {
    "AWS_ACCESS_KEY": r"(?i)AKIA[0-9A-Z]{16}",
    "GENERIC_API_KEY": r"(?i)(?:api_key|token|secret)[ \t]*=[ \t]*['\"][a-zA-Z0-9_\-]{20,}['\"]",
    "PRIVATE_KEY": r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"
}

def calculate_shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    occurrences = {char: data.count(char) for char in set(data)}
    
    for count in occurrences.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
        
    return entropy

def scan_file_secrets(package: PackageRecord, file_path: Path) -> list[Finding]:
    if not file_path.exists():
        return []

    findings = []
    try:
        lines = file_path.read_text(encoding="utf-8").splitlines()
    except UnicodeDecodeError:
        return findings

    for line_num, line in enumerate(lines, start=1):
        for secret_type, pattern in SECRET_PATTERNS.items():
            if re.search(pattern, line):
                findings.append(Finding(
                    id=f"L2-SECRET-{secret_type}",
                    layer="L2",
                    package=package.name,
                    type="HARDCODED_SECRET",
                    severity=Severity.CRITICAL,
                    confidence=0.95,
                    evidence={"type": secret_type, "line": line_num},
                    human_explanation=f"Hardcoded {secret_type} detected. This is a severe security risk.",
                    mitigation="Remove the secret from source code and use environment variables.",
                    points=25.0
                ))


        words = re.findall(r'[a-zA-Z0-9+/=]{40,}', line)
        for word in words:
            entropy = calculate_shannon_entropy(word)
            if entropy > 5.5:  
                findings.append(Finding(
                    id="L2-HIGH-ENTROPY",
                    layer="L2",
                    package=package.name,
                    type="OBFUSCATED_PAYLOAD",
                    severity=Severity.HIGH,
                    confidence=0.80,
                    evidence={"entropy": round(entropy, 2), "line": line_num},
                    human_explanation=f"High entropy string ({round(entropy, 2)}) detected. Likely an obfuscated or base64-encoded payload.",
                    mitigation="Inspect this string. Malware often hides malicious commands in base64 variables.",
                    points=15.0
                ))

    return findings