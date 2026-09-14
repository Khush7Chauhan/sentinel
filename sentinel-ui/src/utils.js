export const SEVERITY_COLOR = { critical: "var(--critical)", high: "var(--high)", medium: "var(--medium)", low: "var(--low)", clean: "var(--clean)" };
export const SEVERITY_LABEL = { critical: "Critical", high: "High", medium: "Medium", low: "Low", clean: "Clean" };
export const FINDING_DEDUCTION = { critical: 25, high: 15, medium: 8, low: 3, clean: 0 };
export const GH_URL_RE = /^(https?:\/\/)?(www\.)?github\.com\/[\w.-]+\/[\w.-]+\/?$/i;

export function severityFromRisk(r) {
  if (r >= 75) return "critical";
  if (r >= 55) return "high";
  if (r >= 25) return "medium";
  if (r >= 1) return "low";
  return "clean";
}

export function packageRisk(p) { return Math.max(p.l1 || 0, p.l2 || 0); }
export function packageSeverity(p) { return severityFromRisk(packageRisk(p)); }

export function projectRisk(packages, projectFindings) {
  let wSum = 0, rSum = 0;
  for (const p of packages) {
    const w = p.direct ? 1 : 1 / (p.depth + 1);
    wSum += w;
    rSum += w * packageRisk(p);
  }
  const base = wSum ? rSum / wSum : 0;
  const ded = projectFindings.reduce((a, f) => a + (FINDING_DEDUCTION[f.severity] || 0), 0);
  return Math.min(100, Math.round(base + ded));
}

export function download(filename, text) {
  const blob = new Blob([text], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
}

export function buildReport(target, dataset) {
  return {
    tool: "supply-chain-sentinel", tool_version: "0.1.0-demo", mock_data: true,
    target, scanned_at: new Date().toISOString(), convention: "risk_score_0_100_higher_is_worse",
    project_risk: projectRisk(dataset.packages, dataset.projectFindings),
    packages: dataset.packages.map((p) => ({
      name: p.name, version: p.version, ecosystem: p.ecosystem,
      direct: p.direct, depth: p.depth, l1_dependency_intel: p.l1, l2_behavior_scan: p.l2,
      risk: packageRisk(p), severity: packageSeverity(p), findings: p.findings,
    })),
    repo_findings: dataset.projectFindings,
  };
}

export function buildSarif(target, dataset) {
  const results = [];
  for (const p of dataset.packages) {
    for (const f of p.findings) {
      results.push({ ruleId: f.title, level: f.severity === "critical" ? "error" : "warning", message: { text: `${p.name}@${p.version}: ${f.detail}` } });
    }
  }
  for (const f of dataset.projectFindings) {
    results.push({ ruleId: f.title, level: "warning", message: { text: `${f.file}: ${f.title}` } });
  }
  return { $schema: "https://json.schemastore.org/sarif-2.1.0.json", version: "2.1.0", runs: [{ tool: { driver: { name: "SupplyChainSentinel", version: "0.1.0-demo" } }, results }] };
}