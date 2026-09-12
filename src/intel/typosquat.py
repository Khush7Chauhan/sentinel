import unicodedata
from typing import Optional
from src.models import PackageRecord, Finding, Severity

# Top PyPI targets frequently spoofed by attackers
TOP_PACKAGES = [
    "requests", "urllib3", "setuptools", "boto3", "botocore", "certifi",
    "idna", "charset-normalizer", "pip", "typing-extensions", "wheel",
    "python-dateutil", "s3transfer", "packaging", "six", "numpy", "cryptography",
    "pydantic", "pyyaml", "click", "jinja2", "markupsafe", "attrs", "pillow",
    "pandas", "scipy", "pytest", "colorama", "virtualenv", "rsa", "protobuf",
    "google-api-python-client", "flit-core", "cffi", "pycparser", "greenlet",
    "sqlalchemy", "black", "isort", "mypy", "pluggy", "filelock", "rich",
    "httpx", "aiohttp", "fastapi", "uvicorn", "starlette", "tqdm", "scikit-learn",
    "torch", "torchvision", "openai", "transformers", "flask", "django", "toml",
    "tomli", "importlib-metadata", "zipp", "distro", "pyasn1", "asn1crypto",
    "oauthlib", "pyjwt", "werkzeug", "itsdangerous", "cachetools", "sniffio",
    "anyio", "h11", "httpcore", "psutil", "docker", "redis", "celery", "pika",
    "beautifulsoup4", "lxml", "pytz", "simplejson", "websockets", "paramiko",
    "async-timeout", "watchdog", "pathlib2", "mock", "more-itertools", "joblib"
]

HOMOGLYPH_MAP = {
    'а': 'a', 'с': 'c', 'е': 'e', 'о': 'o', 'р': 'p', 'х': 'x', 'у': 'y',
    'і': 'i', 'ј': 'j', 'ѕ': 's', 'ԁ': 'd', 'ԛ': 'q', 'ԝ': 'w',
    'α': 'a', 'ο': 'o', 'ρ': 'p', 'ν': 'v', '0': 'o', '1': 'l'
}

def normalize_homoglyphs(text: str) -> tuple[str, bool]:
    """Replaces confusable homoglyphs with standard ASCII chars."""
    normalized_chars = []
    changed = False

    decomposed = unicodedata.normalize("NFKD", text)
    
    for char in decomposed:
        lower_char = char.lower()
        if lower_char in HOMOGLYPH_MAP:
            normalized_chars.append(HOMOGLYPH_MAP[lower_char])
            changed = True
        else:
            normalized_chars.append(lower_char)
            
    return "".join(normalized_chars), changed

def levenshtein_distance(s1: str, s2: str) -> int:
    """Computes Damerau-Levenshtein distance, supporting insertions, deletions, substitutions, and transpositions."""
    d = {}
    len1, len2 = len(s1), len(s2)
    for i in range(-1, len1 + 1):
        d[(i, -1)] = i + 1
    for j in range(-1, len2 + 1):
        d[(-1, j)] = j + 1

    for i in range(len1):
        for j in range(len2):
            cost = 0 if s1[i] == s2[j] else 1
            d[(i, j)] = min(
                d[(i - 1, j)] + 1,       # deletion
                d[(i, j - 1)] + 1,       # insertion
                d[(i - 1, j - 1)] + cost # substitution
            )
            # Transposition check
            if i > 0 and j > 0 and s1[i] == s2[j - 1] and s1[i - 1] == s2[j]:
                d[(i, j)] = min(d[(i, j)], d[(i - 2, j - 2)] + 1)

    return d[(len1 - 1, len2 - 1)]

def check_typosquat(package: PackageRecord) -> Optional[Finding]:
    """Inspects package name for homoglyph attacks and typosquat distance."""
    raw_name = package.name.lower().strip()
    norm_name, homoglyph_detected = normalize_homoglyphs(raw_name)

    # 1. Homoglyph Substitution Detection
    if homoglyph_detected and norm_name in TOP_PACKAGES:
        return Finding(
            id="TYPO-HOMOGLYPH",
            layer="L1",
            package=package.name,
            type="HOMOGLYPH_ATTACK",
            severity=Severity.CRITICAL,
            confidence=0.98,
            evidence={
                "original": package.name,
                "normalized": norm_name,
                "target_package": norm_name
            },
            human_explanation=f"Package '{package.name}' uses visual homoglyphs spoofing official package '{norm_name}'.",
            mitigation=f"Remove '{package.name}' immediately and replace with '{norm_name}'.",
            points=25.0
        )

    # 2. Levenshtein Distance Matching (Typosquatting)
    for target in TOP_PACKAGES:
        if raw_name == target:
            continue

        distance = levenshtein_distance(raw_name, target)
        
        # Distance 1: High probability typosquat (e.g., reqeusts vs requests)
        if distance == 1:
            return Finding(
                id="TYPO-DISTANCE-1",
                layer="L1",
                package=package.name,
                type="TYPOSQUAT_DISTANCE",
                severity=Severity.HIGH,
                confidence=0.85,
                evidence={"distance": distance, "target_package": target},
                human_explanation=f"Package '{package.name}' is an edit distance of 1 away from popular package '{target}'.",
                mitigation=f"Verify if you intended to install '{target}' instead of '{package.name}'.",
                points=18.0
            )
        # Distance 2: Suspicious similarity on longer names (len >= 7)
        elif distance == 2 and len(target) >= 7:
            return Finding(
                id="TYPO-DISTANCE-2",
                layer="L1",
                package=package.name,
                type="TYPOSQUAT_DISTANCE",
                severity=Severity.MEDIUM,
                confidence=0.60,
                evidence={"distance": distance, "target_package": target},
                human_explanation=f"Package '{package.name}' is very similar to widely used package '{target}'.",
                mitigation=f"Check package author and verify if '{target}' was intended.",
                points=8.0
            )

    return None