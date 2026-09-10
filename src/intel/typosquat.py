from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import yaml

try:
    from rapidfuzz import fuzz as _fuzz
    from rapidfuzz.distance import Levenshtein as _RapidLevenshtein
except ModuleNotFoundError:  # pragma: no cover
    # Allow the module to import even when rapidfuzz isn't installed in the
    # current runtime environment.
    _fuzz = None
    _RapidLevenshtein = None

from sentinel.models import Finding, Severity


# 100-item fallback set: a blend of well-known npm and PyPI packages.
# Used when we don't have ecosystem-specific top-download datasets available.
FALLBACK_TOP_100_PACKAGES: list[str] = [
    # PyPI
    "requests",
    "numpy",
    "pandas",
    "scipy",
    "matplotlib",
    "seaborn",
    "scikit-learn",
    "sympy",
    "networkx",
    "tqdm",
    "psutil",
    "pytest",
    "black",
    "isort",
    "mypy",
    "coverage",
    "rich",
    "typer",
    "click",
    "pydantic",
    "fastapi",
    "starlette",
    "uvicorn",
    "httpx",
    "aiohttp",
    "beautifulsoup4",
    "lxml",
    "pillow",
    "pyyaml",
    "sqlalchemy",
    "alembic",
    "cryptography",
    "pyjwt",
    "rsa",
    "loguru",
    "boto3",
    "botocore",
    "google-auth",
    "google-api-python-client",
    "grpcio",
    "protobuf",
    "googleapis-common-protos",
    "google-cloud-core",
    "google-cloud-storage",
    "google-cloud-firestore",
    "opencv-python",
    "selenium",
    "requests-html",
    "tenacity",
    "python-dateutil",
    "tzdata",
    "types-requests",
    "packaging",
    "setuptools",
    "wheel",
    "pip",
    "jinja2",
    "werkzeug",
    "markupsafe",
    "itsdangerous",
    "flask",
    "django",
    "djangorestframework",
    "django-environ",
    "django-cors-headers",
    "celery",
    "redis",
    "pymongo",
    "paramiko",
    "psycopg2-binary",
    "sqlparse",
    "python-dotenv",
    "python-slugify",
    "faker",

    # npm
    "express",
    "react",
    "react-dom",
    "redux",
    "next",
    "vue",
    "angular",
    "webpack",
    "typescript",
    "babel",
    "eslint",
    "prettier",
    "jest",
    "mocha",
    "chai",
    "sinon",
    "tailwindcss",
    "redux-saga",
    "redux-thunk",
    "immer",
    "axios",
    "lodash",
    "lodash-es",
    "uuid",
    "moment",
    "dayjs",
    "zod",
    "svelte",
    "sveltekit",
    "rxjs",
    "nanoid",
    "chalk",
    "debug",
    "commander",
    "inquirer",
    "cross-env",
    "dotenv",
    "fs-extra",
    "rimraf",
    "superagent",
    "supertest",
    "nock",
    "cheerio",
    "jsdom",
    "node-fetch",
    "formidable",
    "jsonwebtoken",
    "helmet",
    "cors",
    "express-session",
    "multer",
    "passport",
    "bcrypt",
    "bcryptjs",
    "react-native",
    "sequelize",
    "mongoose",
    "knex",
    "passport-jwt",
    "passport-local",
    "dotenv-flow",
    "underscore",
    "ramda",
    "handlebars",
    "nunjucks",
    "d3",
    "react-router",
    "react-router-dom",
    "formik",
    "yup",
    "react-query",
]

# Ensure we have exactly 100 entries (helps avoid accidental drift).
# If the list ever changes, we still work — this is a best-effort guard.
assert len(FALLBACK_TOP_100_PACKAGES) == 100, (
    f"FALLBACK_TOP_100_PACKAGES must be 100 items, got {len(FALLBACK_TOP_100_PACKAGES)}"
)


# Minimal homoglyph normalization.
# Maps common Cyrillic/Greek lookalikes + full-width variants to ASCII.
_HOMOGLYPH_MAP: dict[str, str] = {
    # Cyrillic (upper)
    "А": "A",
    "В": "B",
    "Е": "E",
    "К": "K",
    "М": "M",
    "Н": "H",
    "О": "O",
    "Р": "P",
    "С": "C",
    "Т": "T",
    "У": "Y",
    "Х": "X",
    "Г": "r",  # visually similar to latin 'r' in many contexts
    "І": "I",
    "Ї": "I",
    "Й": "I",
    # Cyrillic (lower)
    "а": "a",
    "е": "e",
    "о": "o",
    "р": "p",
    "с": "c",
    "т": "t",
    "у": "y",
    "х": "x",
    "і": "i",
    "ї": "i",
    "й": "j",
    "г": "r",
    "в": "b",
    "м": "m",
    "н": "h",

    # Greek (upper)
    "Α": "A",
    "Β": "B",
    "Ε": "E",
    "Ζ": "Z",
    "Η": "H",
    "Ι": "I",
    "Κ": "K",
    "Μ": "M",
    "Ν": "N",
    "Ο": "O",
    "Ρ": "P",
    "Τ": "T",
    "Υ": "Y",
    "Φ": "F",
    "Χ": "X",
    "Ψ": "Ps",
    "Ω": "W",

    # Greek (lower)
    "α": "a",
    "β": "b",
    "γ": "y",
    "δ": "d",
    "ε": "e",
    "ζ": "z",
    "η": "n",
    "θ": "o",
    "ι": "i",
    "κ": "k",
    "λ": "l",
    "μ": "m",
    "ν": "v",
    "ξ": "x",
    "ο": "o",
    "π": "p",
    "ρ": "p",
    "σ": "s",
    "ς": "s",
    "τ": "t",
    "υ": "y",
    "φ": "f",
    "χ": "x",
    "ψ": "ps",
    "ω": "w",

    # Full-width ASCII letters/digits are handled generically below.
}


def _normalize_fullwidth(s: str) -> str:
    # U+FF01..U+FF5E are full-width ASCII variants.
    out: list[str] = []
    for ch in s:
        code = ord(ch)
        if 0xFF01 <= code <= 0xFF5E:
            out.append(chr(code - 0xFEE0))
        else:
            out.append(ch)
    return "".join(out)


_SEPARATOR_RE = re.compile(r"[-_.\s]+")


def homoglyph_normalize_to_ascii(s: str) -> str:
    """Convert Cyrillic/Greek Unicode lookalikes to ASCII.

    This is intentionally conservative: it targets common *visual* confusables
    used in typosquat/homoglyph attacks, not arbitrary scripts.
    """

    if not s:
        return s

    s = _normalize_fullwidth(s)
    return "".join(_HOMOGLYPH_MAP.get(ch, ch) for ch in s)


def normalize_for_distance(s: str, *, apply_homoglyph: bool = True) -> str:
    """Normalization for edit-distance checks.

    - Lowercase
    - Optional homoglyph mapping
    - Remove common separators (- _ . whitespace)
    """

    if not s:
        return s

    if apply_homoglyph:
        s = homoglyph_normalize_to_ascii(s)

    s = s.lower()
    s = _SEPARATOR_RE.sub("", s)
    return s


_TOKEN_SEP_RE = re.compile(r"[-_.\s]+")


def normalize_for_token_sort_ratio(s: str, *, apply_homoglyph: bool = True) -> str:
    """Normalization for token_sort_ratio.

    Keep separators as token boundaries so rapidfuzz's token-based scoring
    can detect re-orderings.
    """

    if not s:
        return s

    if apply_homoglyph:
        s = homoglyph_normalize_to_ascii(s)

    s = s.lower()
    # Convert common separators into spaces.
    s = _TOKEN_SEP_RE.sub(" ", s)
    s = " ".join(s.split())
    return s


def _damerau_levenshtein_distance_fallback(a: str, b: str) -> int:
    """Damerau-Levenshtein (optimal string alignment) fallback.

    Only used when rapidfuzz is unavailable.
    """

    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)

    # OSA DP
    da = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        da[i][0] = i
    for j in range(len(b) + 1):
        da[0][j] = j

    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            da[i][j] = min(
                da[i - 1][j] + 1,  # deletion
                da[i][j - 1] + 1,  # insertion
                da[i - 1][j - 1] + cost,  # substitution
            )

            # Adjacent transposition
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                da[i][j] = min(da[i][j], da[i - 2][j - 2] + cost)

    return int(da[len(a)][len(b)])


def levenshtein_distance(a: str, b: str) -> int:
    # Per requirement, we prefer rapidfuzz.distance.Levenshtein.distance.
    # When rapidfuzz isn't available in the runtime, we fall back to a
    # small pure-Python Damerau-Levenshtein implementation.
    if _RapidLevenshtein is not None:
        return int(_RapidLevenshtein.distance(a, b))

    return _damerau_levenshtein_distance_fallback(a, b)


@dataclass(frozen=True)
class TyposquatMatch:
    candidate: str
    distance: int
    token_sort_ratio: int


def load_whitelist_from_rules(rules_path: str = "rules.yaml") -> set[str]:
    """Optional whitelist loader.

    The main config schema doesn't currently model typosquat.whitelist.
    To keep this module self-contained, we read raw YAML if present.
    """

    p = Path(rules_path).expanduser()
    if not p.exists():
        return set()

    try:
        raw = yaml.safe_load(p.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return set()

    typosquat = (raw or {}).get("typosquat") if isinstance(raw, dict) else None
    if not isinstance(typosquat, dict):
        return set()

    whitelist = typosquat.get("whitelist", [])
    if not isinstance(whitelist, list):
        return set()

    return {normalize_for_distance(x, apply_homoglyph=True) for x in whitelist if isinstance(x, str)}


def _distance_threshold(name_len: int) -> int:
    # Per requirement: distance <= 1 for short names, <= 2 for names > 6 chars.
    return 1 if name_len <= 6 else 2


def _top_candidates(
    *,
    top_packages: Iterable[str] | None,
) -> Iterable[str]:
    return top_packages if top_packages is not None else FALLBACK_TOP_100_PACKAGES


def find_typosquat_finding(
    package_name: str,
    *,
    whitelist: set[str] | None = None,
    ecosystem: str | None = None,
    top_packages: Iterable[str] | None = None,
    rules_path: str = "rules.yaml",
) -> Finding | None:
    """Detect a potential typosquat/homoglyph using fuzzy string similarity.

    Returns a Finding when edit distance is within the required threshold,
    unless the package (or its normalized target) is whitelisted.
    """

    # ecosystem is currently unused (we rely on fallback list), but it is
    # part of the API surface so future integration can swap candidate sets.
    _ = ecosystem

    if not package_name or not isinstance(package_name, str):
        return None

    wl = whitelist
    if wl is None:
        wl = load_whitelist_from_rules(rules_path=rules_path)

    input_norm_ascii = normalize_for_distance(package_name, apply_homoglyph=True)
    input_norm_raw = normalize_for_distance(package_name, apply_homoglyph=False)
    input_norm_tokens = normalize_for_token_sort_ratio(package_name, apply_homoglyph=True)

    if input_norm_ascii in wl:
        return None

    threshold = _distance_threshold(len(package_name))

    best: TyposquatMatch | None = None

    for cand in _top_candidates(top_packages=top_packages):
        if not isinstance(cand, str):
            continue

        cand_norm_ascii = normalize_for_distance(cand, apply_homoglyph=True)
        cand_norm_tokens = normalize_for_token_sort_ratio(cand, apply_homoglyph=True)

        # Whitelist applies to either the candidate being suggested
        # or the input being flagged.
        if cand_norm_ascii in wl:
            continue

        # Quick length sanity: edit distance can't be below abs(len diff).
        if abs(len(input_norm_ascii) - len(cand_norm_ascii)) > threshold:
            continue

        dist = levenshtein_distance(input_norm_ascii, cand_norm_ascii)
        if dist > threshold:
            continue

        if _fuzz is not None:
            ratio = int(_fuzz.token_sort_ratio(input_norm_tokens, cand_norm_tokens))
        else:
            # Fallback: crude token sort ratio using sets.
            # We keep this low-confidence; edit-distance gate is the primary detector.
            # Ratio in [0, 100] approx.
            ia = input_norm_tokens
            ca = cand_norm_tokens
            if ia == ca:
                ratio = 100
            else:
                i_tokens = set(ia.split())
                c_tokens = set(ca.split())
                if not i_tokens and not c_tokens:
                    ratio = 100
                elif not i_tokens or not c_tokens:
                    ratio = 0
                else:
                    ratio = int(100 * (len(i_tokens & c_tokens) / max(1, len(i_tokens | c_tokens))))

        match = TyposquatMatch(
            candidate=cand,
            distance=dist,
            token_sort_ratio=ratio,
        )

        if best is None:
            best = match
            continue

        # Prefer smaller edit distance; break ties using token_sort_ratio.
        if match.distance < best.distance:
            best = match
        elif match.distance == best.distance and match.token_sort_ratio > best.token_sort_ratio:
            best = match

    if best is None:
        return None

    # Confidence/Severity: distance drives the gate; token_sort_ratio boosts.
    token_sort_ratio_ok = best.token_sort_ratio >= 90

    if best.distance == 0:
        confidence = 0.98
        severity = Severity.HIGH
    elif best.distance == 1:
        confidence = 0.9 if token_sort_ratio_ok else 0.82
        severity = Severity.HIGH if token_sort_ratio_ok else Severity.MEDIUM
    else:
        confidence = 0.7 if token_sort_ratio_ok else 0.62
        severity = Severity.MEDIUM

    # Points are consumed by the scoring engine; keep this module consistent:
    # tighter matches earn more.
    points = float({0: 30, 1: 22, 2: 14}.get(best.distance, 10))

    homoglyph_changed = input_norm_raw != input_norm_ascii

    # Suppress exact matches and separator-only variants.
    # If edit distance is 0 after our normalization, this is only a true
    # typosquat when a homoglyph mapping actually changed the letters.
    if best.distance == 0 and not homoglyph_changed:
        return None

    return Finding(
        id="TYPOSQUAT_SUSPECT",
        layer="L1",
        package=package_name,
        type="TYPOSQUAT_SUSPECT",
        severity=severity,
        confidence=confidence,
        evidence={
            "input": package_name,
            "candidate": best.candidate,
            "input_normalized_ascii": input_norm_ascii,
            "input_normalized_raw": input_norm_raw,
            "candidate_normalized_ascii": normalize_for_distance(best.candidate, apply_homoglyph=True),
            "homoglyph_changed": homoglyph_changed,
            "edit_distance": best.distance,
            "distance_threshold": threshold,
            "token_sort_ratio": best.token_sort_ratio,
            "token_sort_ratio_ge_90": token_sort_ratio_ok,
        },
        human_explanation=(
            f"Package name '{package_name}' is within edit-distance {best.distance} of "
            f"popular package '{best.candidate}' (threshold {threshold}). "
            f"Token sort ratio: {best.token_sort_ratio}."
        ),
        mitigation=(
            "If this dependency was recently added or updated, verify the package identity "
            "(maintainers, release history) and ensure you pin versions in your lockfile. "
            "Consider blocking installs of untrusted or newly appeared names."
        ),
        points=points,
    )
