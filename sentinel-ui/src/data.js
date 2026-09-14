export const TIMELINE = [
  { year: "2018", title: "event-stream", copy: "A popular npm package changed hands, and malicious code shipped to millions of installs before anyone noticed." },
  { year: "2020", title: "SolarWinds", copy: "Attackers compromised a build pipeline directly. The backdoor rode out through a routine, trusted update." },
  { year: "2024", title: "xz-utils", copy: "A patient maintainer takeover, two years in the making, nearly reached every major Linux distribution." },
];

export const DEMO_DATA = {
  key: "demo",
  label: "acme/shopcart (demo-app)",
  graph: {
    nodes: [
      { id: "root", label: "shopcart", x: 300, y: 165, kind: "root" },
      { id: "lodahs", label: "lodahs", x: 115, y: 55, kind: "pkg" },
      { id: "left-pad-fork", label: "left-pad-fork", x: 475, y: 45, kind: "pkg" },
      { id: "colorz-utils", label: "colorz-utils", x: 505, y: 215, kind: "pkg" },
      { id: "requests", label: "requests", x: 85, y: 255, kind: "pkg" },
      { id: "axios", label: "axios", x: 300, y: 295, kind: "pkg" },
    ],
    edges: [
      ["root", "lodahs"], ["root", "left-pad-fork"], ["root", "axios"],
      ["root", "requests"], ["left-pad-fork", "colorz-utils"],
    ],
  },
  packages: [
    {
      id: "lodahs", name: "lodahs", version: "4.17.21", ecosystem: "npm",
      direct: true, depth: 0, l1: 88, l2: 95,
      findings: [
        { severity: "critical", title: 'Typosquat of "lodash"',
          detail: "Levenshtein distance 1 from lodash (~14M weekly downloads). This package was first published 6 days ago.",
          fix: "Remove immediately: npm uninstall lodahs && npm install lodash. Audit install logs for anything it already sent." },
        { severity: "critical", title: "Install script contacts an external host",
          detail: "postinstall script issues a request on package install (demo target: 127.0.0.1 — simulated only, nothing executes).",
          fix: "Remove the package; rotate any CI/npm tokens present on the machine that installed it." },
        { severity: "high", title: "New, unverified maintainer",
          detail: "Publishing account created 9 days ago with no prior published packages.",
          fix: "Hold the version; verify the maintainer's identity out-of-band before upgrading." },
      ],
    },
    {
      id: "left-pad-fork", name: "left-pad-fork", version: "1.3.0", ecosystem: "npm",
      direct: true, depth: 0, l1: 62, l2: 70,
      findings: [
        { severity: "high", title: "Hardcoded secret pattern detected", detail: "String matching an AWS access-key format found in lib/index.js.", fix: "Rotate the key in IAM; purge git history (BFG); add gitleaks to pre-commit." },
        { severity: "medium", title: "Sudden version spike", detail: "6 versions published in the last 48 hours — unusual against this package's release history.", fix: "Pin to the last known-good version and review the diffs before upgrading." },
      ],
    },
    {
      id: "colorz-utils", name: "colorz-utils", version: "0.9.4", ecosystem: "npm",
      direct: false, depth: 1, l1: 52, l2: 30,
      findings: [
        { severity: "medium", title: "Provenance unverifiable", detail: "No Sigstore or SLSA attestation found for this release.", fix: "Prefer attested alternatives where available; otherwise pin and review." },
        { severity: "low", title: "Maintainer email domain recently registered", detail: "Contact domain on the publishing account was registered 3 weeks ago.", fix: "Monitor; treat future updates from this maintainer with suspicion." },
      ],
    },
    {
      id: "requests", name: "requests", version: "2.31.0", ecosystem: "pypi", direct: true, depth: 0, l1: 14, l2: 10, findings: [{ severity: "low", title: "Outdated transitive dependency", detail: "urllib3 is pinned below its latest patch release.", fix: "Run pip install -U urllib3." }]
    },
    {
      id: "axios", name: "axios", version: "1.6.2", ecosystem: "npm", direct: true, depth: 0, l1: 5, l2: 8, findings: [{ severity: "low", title: "Known CVE — already patched", detail: "CVE-2023-45857 affects versions below 1.6.0; the installed version is unaffected.", fix: "None needed — informational only." }]
    },
  ],
  projectFindings: [
    { severity: "critical", title: "Plaintext API key committed to workflow file", file: ".github/workflows/deploy.yml", fix: "Rotate the key now; move it to GitHub Secrets; purge git history." },
    { severity: "medium", title: "pull_request_target used with write-level permissions", file: ".github/workflows/test.yml", fix: "Split trusted/untrusted work into two jobs; never checkout PR code with a write token." },
    { severity: "low", title: "No required reviews on the main branch", file: "repository settings", fix: "Enable branch protection requiring at least one review." },
  ],
};

export const CLEAN_DATA = {
  key: "clean",
  label: "vercel/next.js (clean repo)",
  graph: {
    nodes: [
      { id: "root", label: "next.js", x: 300, y: 150, kind: "root" },
      { id: "react", label: "react", x: 140, y: 70, kind: "pkg" },
      { id: "lodash", label: "lodash", x: 460, y: 70, kind: "pkg" },
      { id: "requests", label: "requests", x: 140, y: 240, kind: "pkg" },
      { id: "flask", label: "flask", x: 460, y: 240, kind: "pkg" },
    ],
    edges: [["root", "react"], ["root", "lodash"], ["root", "requests"], ["root", "flask"]],
  },
  packages: [
    { id: "react", name: "react", version: "18.3.1", ecosystem: "npm", direct: true, depth: 0, l1: 8, l2: 6, findings: [{ severity: "low", title: "Action not SHA-pinned in upstream CI", detail: "A workflow in the upstream repo uses @main refs.", fix: "None needed — informational." }] },
    { id: "lodash", name: "lodash", version: "4.17.21", ecosystem: "npm", direct: true, depth: 0, l1: 6, l2: 4, findings: [{ severity: "low", title: "No Sigstore attestation", detail: "No provenance attestation found.", fix: "None needed — informational." }] },
    { id: "requests", name: "requests", version: "2.32.3", ecosystem: "pypi", direct: true, depth: 0, l1: 10, l2: 8, findings: [{ severity: "low", title: "urllib3 one patch behind", detail: "A newer patch release exists.", fix: "pip install -U urllib3 when convenient." }] },
    { id: "flask", name: "flask", version: "3.0.3", ecosystem: "pypi", direct: true, depth: 0, l1: 12, l2: 9, findings: [{ severity: "low", title: "Maintenance: minor version available", detail: "A newer minor release is available.", fix: "Upgrade during your next maintenance window." }] },
  ],
  projectFindings: [{ severity: "low", title: "No branch-protection issues found", file: "repository settings", fix: "Nothing to do." }],
};