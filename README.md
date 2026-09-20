# 🛡️ Supply Chain Sentinel

## The Problem
Modern software development is built on blind trust. Every time a developer types `npm install` or `pip install`, they unknowingly pull in thousands of lines of code written by strangers. Attackers are poisoning the open-source well with typosquats, malicious install hooks, and hijacked maintainer accounts. 

## Our Solution
**Supply Chain Sentinel** is a real-time, full-stack security platform that makes dependency risk completely visible. Instead of relying on static databases, our engine performs live, ephemeral analysis on any repository using a deterministic mathematical risk scoring model.

### 🔍 Core Detection Tiers:
* **L1 (Dependency Intelligence):** Scans for typosquatting (Levenshtein distance) and unverified maintainers.
* **L2 (Behavioral Scanning):** Parses the AST and install hooks to catch malicious post-install scripts.
* **L3 (Repository Hygiene):** Runs entropy-based secret scanning for leaked API keys and audits GitHub Actions `.yml` files for CI/CD misconfigurations.

---

## 🛠️ How to Run the Project Locally

This project requires **two terminal windows** running simultaneously: one for the Python FastAPI backend, and one for the React/Vite frontend.

### Prerequisites
* Python 3.8+
* Node.js 18+

### Terminal 1: Start the Backend (FastAPI)
The backend engine handles the live `git clone` operations, manifest parsing, and OSV database queries.

```bash
# 1. Install Python dependencies
pip install -r requirements.txt

# 2. Start the FastAPI server (Runs on port 8000)
python -m uvicorn src.report.server:app --reload --port 8000
```

###Terminal 2: Start the Frontend (React + Vite)
The frontend calculates the dynamic radial graph UI using our custom trigonometric layout engine.
```Bash
# 1. Install Node modules
npm install

# 2. Start the Vite development server (Runs on port 5173)
npm run dev
```
#Features & Usage
Live Scanning: Enter a GitHub repository URL or local directory path into the landing page search bar.

Interactive Topology: Explore the threat landscape using the dynamic dependency graph. Clicking on any critical (red) node will reveal engine notes and AI context.

Remediation: Click the Remediation → button to view an actionable checklist to secure the repository.

CI/CD Integration: Click Export JSON or Export SARIF to download the analysis for standard pipeline integration.
