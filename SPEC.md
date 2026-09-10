# SUPPLY CHAIN SENTINEL — Complete Technical Specification
**Version:** 1.0 · **Project:** TNL Hackathon submission · **Status:** Ready for implementation
**Document purpose:** After reading this document, an engineer (or AI assistant) should be able to implement the system end-to-end without further clarification. Where choices remain, the tie-breakers in §0 take precedence.

---

## 0. Ground Rules & Hard Constraints (non-negotiable)

1. **Defensive tool only.** SCS never creates, executes, or distributes real malware. The demo's "malicious" packages simulate *patterns only* — base64 blobs decode to benign strings, network calls target `127.0.0.1`, nothing harmful executes.
2. **AI usage must be disclosed.** If an LLM is used to polish natural-language explanations, this is stated in the README and final slide. The scoring engine is deterministic code the team can explain line by line.
3. **Only public data + open-source libraries.** All data sources are free, keyless public APIs.
4. **Original work.** Heuristics, scoring engine, and integration are written by the team; all third-party libraries are listed with licenses in the README.
5. **Tie-breakers:** when implementation choices conflict, preserve in this order: (a) determinism of scores, (b) explainability of every deduction, (c) strict harmlessness of all demo artifacts.

---

## 1. Problem Statement

Modern applications are assembled, not written: a typical Node.js or Python project imports hundreds of transitive open-source packages. Attackers have shifted from attacking the target's own code to attacking its **supply chain**: publishing typosquatted packages, buying or hijacking maintainer accounts, injecting malicious install hooks, compromising CI pipelines, or exploiting dependency confusion. Reference incidents: SolarWinds (build system), xz-utils backdoor (2024, maintainer-persona grooming), event-stream npm backdoor, Snowflake customer breaches via third parties, US Treasury breach via a vendor.

**SCS answers one question:** *"If I run `npm install` / `pip install` on this project tomorrow, what could go wrong — and why?"*

### One-line pitch
> *"SolarWinds, xz-utils, Snowflake — modern breaches don't attack your code, they attack your dependencies. Supply Chain Sentinel scans your project's dependencies, CI/CD pipelines, and secrets to detect compromise **before** it reaches production — and explains every flag in plain language."*

---

## 2. Threat Model

SCS defends against these adversary capabilities, each mapped to a detection layer:

| # | Adversary capability | Example real incident | Layer |
|---|---|---|---|
| T1 | Publish a look-alike package name (typosquat / homoglyph) | `reqeusts`, fake `python-dateutil` | L1 |
| T2 | Inject malicious code into install hooks or runtime | event-stream backdoor, malicious `postinstall` | L2 |
| T3 | Hijack / buy a maintainer account, push a poisoned update | xz-utils (Jia Tan), ua-parser-js hijack | L1 |
| T4 | Ship a known-vulnerable version | Log4Shell-class CVEs | L1 |
| T5 | Exfiltrate secrets from repo or CI logs | Hardcoded AWS keys in commits | L3 |
| T6 | Steal CI credentials via workflow misconfiguration | `pull_request_target` attacks, script injection | L3 |
| T7 | Dependency confusion: claim a private package name on the public registry | Alex Birsan (2021) research | L3 |
| T8 | Obfuscate intent (encoding, dynamic eval) to evade naive scanners | base64/eval blobs in npm malware | L2 |

**Out of scope (state explicitly if judges ask):** runtime behavioral sandboxing (dynamic analysis), license compliance, full binary/reversing analysis, container image scanning (stretch only).

---

## 3. System Overview

**Product form factor:** Python CLI (`sentinel`) + local FastAPI server + React dashboard. One command scans a project directory and produces (a) a terminal report, (b) JSON/SARIF export, (c) an interactive dashboard.

### High-level data flow

```
project_dir/
   │
   ├─[Parsers]──► DependencyGraph (nodes: name, version, ecosystem, source, depth)
   │
   ├─[L1 DependencyIntel]──► per-package: CVEs (OSV), registry metadata,
   │      maintainer profile, version history, typosquat verdict, provenance
   ├─[L2 BehaviorStatic]──► per-package: tarball download → static pattern scan
   ├─[L3 RepoHygiene]─────► repo-wide: secrets, workflow misconfigs, dep-confusion
   │
   ├─[ScoringEngine]──► deterministic weights → RiskScore per package + project,
   │      each with structured explanation records (machine- and human-readable)
   │
   └─[Outputs]──► CLI report (rich) │ JSON/SARIF │ React dashboard (D3 graph)
```

---

## 4. Tech Stack

- **Language:** Python 3.11+
- **CLI:** Typer + Rich (formatted output, live progress)
- **API server:** FastAPI + Uvicorn (serves scan results to the dashboard)
- **Frontend:** React 18 + Vite + TailwindCSS + D3.js (or ECharts) for the dependency graph
- **Key libraries:** `httpx` (async API calls), `rapidfuzz` (fuzzy matching), `regex` (pattern catalog), `pydantic` (data models), `pyyaml` (config), `gitleaks` **or** `trufflehog` (secret scanning, open source; a self-written scanner earns more implementation credit)
- **Data sources (all free, no API key):**
  - OSV.dev: `POST https://api.osv.dev/v1/query`, body `{"package": {"name": ..., "ecosystem": ...}, "version": ...}` → vulnerabilities
  - deps.dev (Google Open Source Insights): `GET https://api.deps.dev/v3/systems/{npm|pypi|go|cargo}/packages/{name}` → advisories, scorecard
  - npm Registry: `GET https://registry.npmjs.org/{name}` → maintainers, versions, publish times, tarball URLs
  - PyPI JSON API: `GET https://pypi.org/pypi/{name}/json` → releases, maintainers, artifact URLs
  - GitHub REST API: workflow file contents (respect rate limits; cache aggressively)

---

## 5. Repository Structure

```
sentinel/
├── pyproject.toml
├── README.md                  # AI-usage disclosure + rules-compliance note
├── rules.yaml                 # tunable scoring weights & thresholds
├── sentinel/
│   ├── cli.py                 # Typer entry: `sentinel scan|report|serve`
│   ├── config.py
│   ├── models.py              # pydantic schemas (§8)
│   ├── parsers/
│   │   ├── npm.py             # package.json + package-lock.json
│   │   ├── pypi.py            # requirements.txt + Pipfile.lock
│   │   ├── gomod.py           # go.mod (stretch)
│   │   └── cargo.py           # Cargo.lock (stretch)
│   ├── intel/
│   │   ├── osv.py             # OSV client
│   │   ├── registry.py        # npm / PyPI metadata clients
│   │   ├── typosquat.py       # fuzzy-match + homoglyph engine
│   │   ├── maintainer.py      # trust scoring + takeover detection
│   │   └── provenance.py      # Sigstore / SLSA presence checks
│   ├── behavior/
│   │   ├── fetcher.py         # tarball download + cache (~/.sentinel/cache)
│   │   ├── js_scan.py         # JS/TS pattern + AST-lite checks
│   │   ├── py_scan.py         # Python pattern + ast-module checks
│   │   └── patterns.py        # the pattern catalog (§6.3)
│   ├── hygiene/
│   │   ├── secrets.py
│   │   ├── workflows.py       # GitHub Actions static rules
│   │   └── dep_confusion.py
│   ├── scoring/
│   │   └── engine.py          # deterministic scoring (§7)
│   ├── report/
│   │   ├── terminal.py        # rich-rendered CLI report
│   │   ├── export.py          # JSON + SARIF
│   │   └── server.py          # FastAPI app
│   └── dashboard/             # React app (separate npm project)
├── demo-app/                  # planted-threat project for the live demo (§10)
└── tests/
    ├── fixtures/              # sample package tarballs (benign + simulated-malicious)
    └── golden/                # expected scan outputs for regression
```

---

## 6. Module Specifications

### 6.1 Parsers → DependencyGraph

- **npm** (`package-lock.json` v3 preferred; fall back to `package.json`): extract `name`, `version`, `resolved` URL, `integrity` hash, `dev` flag. Recursively walk `dependencies`. Mark direct vs transitive via `depth`.
- **PyPI** (`requirements.txt` and/or `Pipfile.lock`): parse pinned (`==`) and ranged specs; resolve ranged specs to a concrete version via the PyPI JSON API. Record `extras`.
- **Output:** `DependencyGraph { nodes: PackageRecord[], edges: (parent→child)[] }`,
  `PackageRecord = { name, version, ecosystem ∈ {npm,pypi,go,cargo}, direct, depth, source_file, resolved_url? }`.
- **Edge cases:** malformed lockfiles (log warning, continue); git-URL deps (`non_registry: true` → skip registry intel, still scan local source); workspace/monorepo globs.

### 6.2 L1 — Dependency Intelligence

#### 6.2.1 OSV / CVE matching
Per `PackageRecord`: POST to OSV; map response to `{cve, id (GHSA/OSV), summary, severity, fixed_version}`. Deduplicate by OSV ID. Concurrency ≤8 via `httpx` + semaphore; exponential backoff; disk cache keyed `(ecosystem, name, version)`, TTL 24h.

#### 6.2.2 Typosquat Engine (`typosquat.py`)
**Inputs:** package name; per-ecosystem top-package lists (pre-downloaded top ~10k by downloads — npm download-count API; PyPI via the public top-pypi-packages dataset).

**Checks:**
1. **Edit distance:** normalized Levenshtein / Damerau-Levenshtein to each top-package name. Flag if `distance ≤ threshold`, threshold scaling with length: `1 if len≤6 else 2 if len≤12 else 3`. Use `rapidfuzz.distance` with early-abandon.
2. **Fuzzy ratio:** `rapidfuzz.fuzz.token_sort_ratio ≥ 90` as a secondary signal (catches reordering: `python-dateutil` ↔ `dateutil-python`).
3. **Homoglyph normalization:** map visually identical Unicode (Cyrillic а/е/о/р, Greek, full-width forms) to ASCII *before* distance computation; flag when the normalized form collides with a top package while raw forms differ.
4. **Separator confusion:** ignore `-`/`_`/`.` variants (`lodash-es` vs `lodash_es`); flag near-collisions after normalization.
5. **Suppression list:** `rules.yaml → typosquat.whitelist` (legit forks/variants).

**Output:** `{type: TYPOSQUAT_SUSPECT, target, distance, confidence, evidence}`.

#### 6.2.3 Maintainer Trust Scoring (`maintainer.py`)
Registry metadata per maintainer:
- `account_age_days` (npm: first publish / profile; PyPI: earliest release as approximation)
- `email_domain_type` ∈ {custom corporate, free-mail (riskier), masked/none (riskiest)}
- `packages_maintained_count`
- `verified` status where exposed

**Trust score (0–100):** `0.4·min(age/1825,1)·100 + 0.3·(custom email)·100 + 0.2·min(packages/50,1)·100 + 0.1·verified·100`. Flag `< 30` → `UNTRUSTED_MAINTAINER`.

#### 6.2.4 Takeover Detection
Diff the maintainer set of the **installed version** vs the **latest version** (npm `maintainers` field; PyPI release-uploaders). If maintainers were removed/replaced — especially original owners gone + new young accounts (correlate with 6.2.3) → `MAINTAINER_TURNOVER`, high severity. This is the xz-utils signal. Also flag: single new account added + new release within days.

#### 6.2.5 Version Anomaly Detection
From the version→publish-time map:
- `CADENCE_SPIKE`: publish frequency of last 3 versions > 3× the historical median
- `MAJOR_JUMP`: ≥2 major-version jumps with tiny code delta (tarball-size delta as proxy)
- `SLEEPER`: dormant > 1 year, then a sudden release (hijack signal)

#### 6.2.6 Provenance
Check for npm Sigstore attestations in registry metadata; SLSA provenance files; reproducible-build notes. Absence → mild `NO_PROVENANCE` (low weight — absence is common, avoid noise).

### 6.3 L2 — Static Behavior Analysis (the differentiator)

**Fetcher:** resolve tarball URL from lockfile `resolved` / registry; download to `~/.sentinel/cache/{ecosystem}/{name}@{version}.tgz`; extract to temp dir; cap 50 MB / file count; skip binaries except hashing.

**Scan targets:** all `.js/.ts/.mjs/.cjs/.py/.sh` files, `package.json` scripts, `setup.py`, `*.cfg|toml` exec fields.

**Pattern catalog (`patterns.py`)** — each pattern = `{id, severity, regex(es) or AST check, description, mitigation}`:

| ID | Severity | Detection |
|---|---|---|
| B01 | CRITICAL | Crypto-miner: stratum-protocol strings, known pool domains, `coinhive`, xmrig config |
| B02 | CRITICAL | Env-harvest + exfil correlation: same file reads `process.env`/`os.environ` **and** performs outbound HTTP (`http.request`, `fetch(`, `urllib`, `requests.post`) — high confidence; env-read alone is INFO |
| B03 | HIGH | Install-hook execution: npm `preinstall/install/postinstall` containing network/fs side effects; `setup.py` with `subprocess`/network at module top level |
| B04 | HIGH | Raw-IP endpoints: `https?://\d{1,3}(\.\d{1,3}){3}` (whitelist localhost via rules.yaml) |
| B05 | HIGH | Obfuscation: base64 blob > 200 chars, hex runs > 100 chars, `eval(`/`Function(`/`atob(`/`fromCharCode` chains, `__proto__`/`constructor` tricks |
| B06 | HIGH | Filesystem targeting of sensitive paths: `~/.ssh`, `id_rsa`, `.aws/credentials`, `crontab`, `/etc/passwd`, browser cookie stores, wallet dirs |
| B07 | MEDIUM | Dynamic execution: `child_process.exec/spawn` with variable (non-literal) args; Python `exec/eval/compile/__import__` on non-literal input |
| B08 | MEDIUM | Persistence: autostart dirs, `rc.local`, systemd units, Windows run keys |
| B09 | MEDIUM | Bundled hidden deps: package ships its own copy of a network library inside the tarball (invisible to the lockfile) |
| B10 | INFO | Telemetry/tracking endpoints (segment, analytics) — informational only |

**Entropy check (B05 support):** Shannon entropy > 4.5 bits/char on string literals > 100 chars → obfuscation suspect.
**AST-lite (Python):** stdlib `ast` — detect `os.environ[...]` reads in the same function scope as `urllib.request.urlopen` (precise B02). For JS, a lightweight brace/paren matcher suffices at hackathon scope (full parser = stretch).

**Anti-noise rules:** skip B05 length checks on minified files (`*.min.js`); skip test fixtures; every CRITICAL/HIGH requires ≥1 corroborating signal or an exact regex (e.g., stratum) to fire — reduces false positives (judge Q&A prep).

### 6.4 L3 — Repository & CI/CD Hygiene

**Secrets (`secrets.py`):** run `gitleaks detect` (open source) or self-written scanner: regex set (AWS `AKIA[0-9A-Z]{16}`, GitHub `ghp_/gho_`, Slack `xox[baprs]-`, Stripe `sk_`, `-----BEGIN … PRIVATE KEY-----`) + Shannon entropy > 4.5 + candidate length > 20. **Never print the full secret** — print type, file, line, first 4 chars + `***` (responsible handling judges notice).

**Workflows (`workflows.py`)** — static rules over `.github/workflows/*.yml`:
- **W1 CRITICAL:** `pull_request_target` event **and** `actions/checkout` with `ref: ${{ github.event.pull_request.head.* }}` (credential-theft pattern)
- **W2 HIGH:** `run:` lines containing `${{ github.event.*.title/body/branch }}` or issue fields (script injection)
- **W3 MEDIUM:** action refs not SHA-pinned (`@main|v1|v2` instead of `@<40-hex>`)
- **W4 MEDIUM:** `self-hosted` runner on a workflow reachable from forks
- **W5 INFO:** `permissions: write-all` or overly broad `GITHUB_TOKEN` scope

**Dependency confusion (`dep_confusion.py`):** for package names that (a) are absent from the public registry but (b) appear in the lockfile (presumed internal): if the name is **claimable** (available for registration) on npm/PyPI → `DEP_CONFUSION_RISK` (an attacker could register it and poison builds on machines without the internal registry configured). Read-only checks only — never register anything.

### 6.5 Outputs

**Terminal (`rich`):** progress spinner during scan; summary box (project score, counts by severity); table of top-10 riskiest packages; expandable per-package flag trees; colored severity glyphs. CLI: `sentinel scan ./target --format table|json|sarif`.

**JSON export:** full `ScanReport` (§8). **SARIF export** for GitHub code-scanning uploads.

**Server:** `sentinel serve` → FastAPI on `localhost:8000`:
- `POST /scan` `{path}` → starts scan, returns `job_id`
- `GET /scan/{job_id}` → status / result
- `GET /report/{job_id}` → full JSON
- `WS /scan/{job_id}/progress` → live progress for the dashboard

**Dashboard (React):**
- **Overview:** project-score gauge, severity donut, top-finding cards
- **Dependency Graph:** D3 force-directed tree; node color by score (green ≥ 80, amber 50–79, red < 50); node size ∝ reach/downloads; click node → side panel with full explanation records; edges show direct/transitive
- **Findings table:** filter/sort by layer, severity, package; export buttons (JSON/SARIF)
- **Remediation:** deduplicated fix checklist ("Pin action X to SHA", "Replace `reqeusts` with `requests`")

---

## 7. Scoring Engine (`scoring/engine.py`) — deterministic, explainable

Each finding carries a base weight by severity: `CRITICAL 25 · HIGH 15 · MEDIUM 8 · LOW 3 · INFO 0` (tunable in `rules.yaml`). Confidence `c ∈ [0,1]` scales it: `points = base_weight × c`.

- **Package score:** `max(0, 100 − Σ points)`, with per-category caps (e.g., typosquat contributes max 30) so one noisy category cannot zero a package.
- **Project score:** direct deps weighted 1.0, transitive `1/depth`; repo-level findings applied once: `max(0, 100 − Σ_pkg(wᵢ·(100−score_pkgᵢ)) − Σ_repo(base×c))`.
- **Determinism:** same input → same score. No randomness. An LLM (if used) only rewrites `human_explanation` text post-hoc; it can never alter scores. Disclose this in the README.

**Explanation record (the key feature)** — every deduction produces:

```json
{
  "finding_id": "B02",
  "package": "left-pad-utils",
  "severity": "CRITICAL",
  "confidence": 0.92,
  "points_deducted": 23.0,
  "evidence": {"file": "index.js", "line": 14, "snippet_hash": "a9f3...", "signals": ["env-read", "outbound-http"]},
  "human_explanation": "This package reads environment variables and sends them to an external server in the same function — the signature of a credential stealer.",
  "mitigation": "Remove the package; rotate any credentials present in your environment; audit install logs."
}
```

---

## 8. Data Models (pydantic)

```python
class PackageRecord(BaseModel):
    name: str
    version: str
    ecosystem: Literal["npm", "pypi", "go", "cargo"]
    direct: bool
    depth: int
    source_file: str
    resolved_url: str | None

class Finding(BaseModel):
    id: str
    layer: Literal["L1", "L2", "L3"]
    package: str | None          # None for repo-level findings
    type: str                    # TYPOSQUAT_SUSPECT, B02, W1, SECRET, ...
    severity: Severity           # CRITICAL|HIGH|MEDIUM|LOW|INFO
    confidence: float
    evidence: dict
    human_explanation: str
    mitigation: str
    points: float

class PackageVerdict(BaseModel):
    record: PackageRecord
    score: float
    findings: list[Finding]

class ScanReport(BaseModel):
    target: str
    started_at: datetime
    finished_at: datetime
    project_score: float
    packages: list[PackageVerdict]
    repo_findings: list[Finding]
    tool_version: str
    config_hash: str
```

---

## 9. Configuration (`rules.yaml`)

```yaml
scoring:
  weights: {CRITICAL: 25, HIGH: 15, MEDIUM: 8, LOW: 3, INFO: 0}
  category_caps: {typosquat: 30, behavior: 60, cve: 25, maintainer: 20}
typosquat:
  top_packages_file: data/top-pypi.json
  distance_threshold: {short: 1, medium: 2, long: 3}
  ratio_threshold: 90
  whitelist: ["django-rest-framework"]
behavior:
  max_tarball_mb: 50
  entropy_threshold: 4.5
  raw_ip_whitelist: ["127.0.0.1", "localhost"]
```

---

## 10. Demo Application (`demo-app/`) — the live-demo payload

A fake e-commerce project ("shopcart") containing exactly 4 planted threats, one per layer. **All simulated — nothing executes maliciously:**

1. **T1 / L1 typosquat:** `requirements.txt` contains `reqeusts==2.31.0` (1-char edit from `requests`).
2. **T2 / L2 behavior:** local file-dependency package `utils-paygate/` whose `setup.py` install subclass contains a base64 blob (decodes to the literal string `"SIMULATED_EXFIL_MARKER_NOT_HARMFUL"`) and an HTTP call to `http://127.0.0.1:9/collect`. Plus a nested copy of `node-fetch` hidden inside the tarball (B09).
3. **T5 / L3 secret:** `config/prod.env` contains `AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE` (AWS's documented example key — safe and well-known) plus a high-entropy fake token.
4. **T6 / L3 workflow:** `.github/workflows/ci.yml` with `pull_request_target` + checkout of the PR head SHA, `uses: actions/checkout@main`, and `run: echo "${{ github.event.pull_request.title }}"`.

Also include ~15 clean popular dependencies so the graph is mostly green with red islands — demonstrating low false-positive noise.

### Live demo script (5–7 min)

| T+ | Action | Screen shows |
|---|---|---|
| 0:00 | Hook: SolarWinds / xz story (30 s) | Slide |
| 0:30 | `sentinel scan ./demo-app` | Terminal: progress lines streaming |
| 1:30 | Flags stream in live | Terminal: CRITICAL / HIGH findings |
| 2:30 | `sentinel serve` → open dashboard | Gauge: **38**, mostly-green graph, red nodes |
| 3:00 | Click `reqeusts` node | "1 edit-distance from `requests`, ~30M downloads/month — the #1 supply-chain trick" |
| 3:45 | Click `left-pad-utils` node | env-harvest + raw-IP explanation |
| 4:15 | Remediation tab | Ordered fix checklist |
| 4:45 | Scan a real, clean open-source repo live | Green 95+ — proves low false positives |
| 5:15 | Close: "Free, open-source early warning for the #1 attack vector of 2025" | Slide with repo QR code |

**Backup:** pre-recorded 2-min video + offline cached scan results (Wi-Fi-proof). Secondary backup: single-file mock dashboard (`supply-chain-sentinel-dashboard.html`).

---

## 11. End-to-End Runtime Workflow

```
sentinel scan ./project
  → Parsers build DependencyGraph
  → L1 (parallel, async, cached): OSV CVEs · registry metadata · typosquat · maintainer/trust · takeover · version anomaly · provenance
  → L2: tarball fetch → extract → pattern catalog B01–B10 (regex + Python AST) → anti-noise filters
  → L3: secrets scan (masked output) · workflow rules W1–W5 · dependency-confusion check
  → Scoring engine: severity × confidence, category caps → package scores → project score + explanation records
  → Outputs: rich CLI report · JSON/SARIF export · FastAPI → React dashboard
```

---

## 12. Implementation Plan (team of 4, ~36 h; scale proportionally)

| Hours | Workstream | Owner(s) | Exit criterion |
|---|---|---|---|
| 0–3 | Repo setup, `models.py`, `rules.yaml`, roles locked | All | `sentinel --help` runs |
| 3–10 | Parsers (npm + pip) + OSV client + cache layer | A | Scan a real `package.json` → CVE list |
| 6–14 | Typosquat engine + top-package lists | A | Catches `reqeusts` vs `requests`; ignores whitelist |
| 10–18 | Tarball fetcher + pattern catalog B01–B10 + Python AST check | B | Flags fixture tarball with B02/B04/B05 |
| 14–20 | Maintainer trust + takeover + version anomaly | A | Flags planted maintainer-swap fixture |
| 18–26 | Scoring engine + explanation records + terminal report | B | Deterministic score; rich report renders |
| 20–28 | FastAPI server + React dashboard (graph + panels) | C | Live progress + clickable graph |
| 26–31 | demo-app planting, workflow rules, secrets scan | D | All 4 demo threats fire |
| 31–36 | End-to-end rehearsal ×5, deck, README (AI disclosure + rules note), video backup | All | Demo passes twice back-to-back |

**Roles:** A = dependency intel / APIs · B = static behavior scanner + scoring · C = dashboard / CLI UX · D = demo-app + repo hygiene + pitch deck + README.

**Solo fallback:** npm+pip parsers, OSV, typosquat, 3 behavior patterns (B02/B04/B05), scoring, CLI + single-page dashboard, demo-app. Cut go/cargo, provenance, dep-confusion, SARIF. Depth beats breadth.

**Rule of the room:** anything that breaks the demo-app scan (to green-or-correctly-red) is P0; everything else waits until after the first full rehearsal.

---

## 13. Testing Strategy

- **Unit:** parser fixtures (including malformed lockfiles); rapidfuzz threshold table (name pairs → expected verdict); scoring golden tests (fixed findings → exact score).
- **Integration:** `tests/fixtures/` holds 3 tarballs — clean; simulated-malicious (all B-patterns, harmless payloads); minified-legit (must NOT flag B05) — regression against false positives.
- **Golden scans:** expected `demo-app/` report committed; CI fails on drift.
- **Judge-proofing dry run:** scan 3 real popular repos; record score + flag count to answer "false-positive rate?" credibly.

---

## 14. Anticipated Judge Q&A (prepared answers)

- **"How is this different from Dependabot/Snyk?"** → They match known CVEs (T4). SCS detects *intent and behavior*: typosquats (T1), malicious install hooks (T2), maintainer takeovers (T3), CI credential theft (T6), dependency confusion (T7) — with explainable scoring on top.
- **"False positives?"** → Anti-noise rules (§6.3), confidence scaling, category caps; measured on real repos (bring numbers).
- **"Scale?"** → Async API calls with caching and bounded concurrency; static scans are regex/AST over small tarballs; per-package parallelism.
- **"Ethics / rules?"** → Read-only against public registries; simulated malware patterns only; secrets never printed in full; fully defensive (rules 3–4).
- **"AI usage?"** → Disclosed per rule 5; the LLM optionally polishes explanation text only — scoring is deterministic code we can walk through line by line.

---

## 15. Risks & Mitigations

| Risk | Mitigation |
|---|---|
| Registry rate limits during demo | Aggressive disk cache; pre-warm cache before presenting |
| No Wi-Fi | Cached scan results + recorded video fallback + offline mock dashboard |
| React graph over-ambitious | Fallback: ECharts treemap, or server-rendered static D3 SVG |
| False-positive embarrassment in live scan | Only scan `demo-app/` + one pre-vetted clean repo live |
| Time overrun | Priority: parsers → OSV → typosquat → 3 behavior patterns → scoring → CLI → dashboard → everything else |

---

## 16. Pitch Deck Outline (6 slides)

1. **Hook:** SolarWinds → xz-utils → Snowflake. "They didn't hack the code. They hacked the supply chain."
2. **Scale:** 45% of orgs hit by 2025 (Gartner); third-party breaches = primary 2025 vector (Fortinet). Most teams have zero visibility.
3. **Demo:** the live scan (QR code + "watch").
4. **How it works:** 4-layer diagram; explainable risk scores.
5. **Impact:** any dev team; free/open-source; CI-integrable. vs. commercial tools costing $$$ — detection + explanation in one pass.
6. **Future:** GitHub Action, VS Code extension, watch mode + AI-disclosure note.

---

## 17. Rules-Compliance Checklist

| Rule | How SCS complies |
|---|---|
| Original work | All heuristics/scoring/integration written by the team; third-party libs listed with licenses |
| Cybersecurity relevance | Directly addresses the #1 named 2025 attack vector (supply-chain compromise) |
| Responsible security research | Read-only public-registry queries; detection only; no unauthorized access |
| No malicious software | Demo "malware" simulates patterns with benign payloads + localhost targets |
| AI usage disclosure | LLM (if any) rewrites explanation text only; disclosed in README + final slide |
| Intellectual property | Free public APIs/datasets; licenses noted |
| Respect / CoC | Professional presentation, inclusive framing |

---

## 18. Glossary

**SBOM** software bill of materials · **OSV** Open Source Vulnerabilities database · **Typosquat** deceptive package name mimicking a popular one · **Homoglyph** visually identical Unicode character substitution · **Install hook** script executed at package-install time (npm `postinstall`, pip `setup.py`) · **Maintainer takeover** account hijack or sale resulting in poisoned releases · **Dependency confusion** public-registry claim of an internal package name · **SARIF** static-analysis results interchange format · **Provenance (Sigstore/SLSA)** cryptographic attestation of build origin · **Entropy** information-density measure used to detect encoded/obfuscated strings · **Dwell time** attacker persistence duration in a system (context stat, not a feature).

---

*End of specification. Implementers: begin from §5 (repo structure), §6 (module specs), §10 (demo-app); wire outputs per §6.5. Preserve, in order: determinism, explainability, harmlessness.*