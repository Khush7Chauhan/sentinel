import math
import re
from pathlib import Path
from src.models import Finding, Severity

SECRET_PATTERNS = {
    "AWS_ACCESS_KEY": r"AKIA[0-9A-Z]{16}",
    "GITHUB_TOKEN": r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}",
    "SLACK_TOKEN": r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*",
    "STRIPE_KEY": r"sk_live_[0-9a-zA-Z]{24}",
    "PRIVATE_KEY": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
}

def mask_secret(secret_str: str) -> str:
    
    trimmed = secret_str.strip()
    if len(trimmed) <= 4:
        return "****"
    return f"{trimmed[:4]}****"

def calculate_shannon_entropy(data: str) -> float:
    
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    occurrences = {char: data.count(char) for char in set(data)}
    for count in occurrences.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy

def scan_repo_secrets(repo_path: Path) -> list[Finding]:
    
    findings = []
    ignored_dirs = {".git", ".pytest_cache", "node_modules", "venv", "__pycache__"}
    extensions = {".py", ".js", ".ts", ".env", ".json", ".yaml", ".yml", ".txt", ".conf"}

    for file_path in repo_path.rglob("*"):
        if file_path.is_dir() or any(part in ignored_dirs for part in file_path.parts):
            continue
        if file_path.suffix not in extensions and not file_path.name.startswith(".env"):
            continue

        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        for line_num, line in enumerate(content.splitlines(), start=1):
            for secret_type, regex in SECRET_PATTERNS.items():
                match = re.search(regex, line)
                if match:
                    raw_val = match.group(0)
                    findings.append(Finding(
                        id=f"L3-SECRET-{secret_type}",
                        layer="L3",
                        package=None,
                        type="HARDCODED_SECRET",
                        severity=Severity.CRITICAL,
                        confidence=0.95,
                        evidence={
                            "file": str(file_path.relative_to(repo_path)),
                            "line": line_num,
                            "type": secret_type,
                            "masked_value": mask_secret(raw_val)
                        },
                        human_explanation=f"Hardcoded {secret_type} exposed at line {line_num}. Secrets in repositories can be harvested by automated scrapers.",
                        mitigation="Rotate this credential immediately and migrate storage to environment variables or secret managers.",
                        points=25.0
                    ))

            words = re.findall(r'[A-Za-z0-9_\-\.\+/=]{20,}', line)
            for word in words:
                entropy = calculate_shannon_entropy(word)
                if entropy > 4.5 and not any(re.search(pat, word) for pat in SECRET_PATTERNS.values()):
                    findings.append(Finding(
                        id="L3-SECRET-ENTROPY",
                        layer="L3",
                        package=None,
                        type="HIGH_ENTROPY_TOKEN",
                        severity=Severity.HIGH,
                        confidence=0.80,
                        evidence={
                            "file": str(file_path.relative_to(repo_path)),
                            "line": line_num,
                            "entropy": round(entropy, 2),
                            "masked_value": mask_secret(word)
                        },
                        human_explanation=f"High-entropy token detected ({round(entropy, 2)} bits/char). Likely an unclassified API secret or key.",
                        mitigation="Verify if this token is sensitive and remove it from committed tracking.",
                        points=15.0
                    ))

    return findings