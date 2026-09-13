import { projectRisk, packageRisk, packageSeverity } from "./scoring";

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
    tool: "supply-chain-sentinel",
    tool_version: "1.0.0",
    target,
    scanned_at: new Date().toISOString(),
    project_risk: projectRisk(dataset.packages, dataset.projectFindings),
    packages: dataset.packages.map((p) => ({
      name: p.name,
      version: p.version,
      ecosystem: p.ecosystem,
      direct: p.direct,
      depth: p.depth,
      l1_dependency_intel: p.l1,
      l2_behavior_scan: p.l2,
      risk: packageRisk(p),
      severity: packageSeverity(p),
      findings: p.findings,
    })),
    repo_findings: dataset.projectFindings,
  };
}

export function buildSarif(target, dataset) {
  const results = [];
  for (const p of dataset.packages) {
    for (const f of p.findings) {
      results.push({
        ruleId: f.title,
        level: f.severity === "critical" ? "error" : "warning",
        message: { text: `${p.name}@${p.version}: ${f.detail}` },
      });
    }
  }
  for (const f of dataset.projectFindings) {
    results.push({
      ruleId: f.title,
      level: "warning",
      message: { text: `${f.file}: ${f.title}` },
    });
  }
  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [{ tool: { driver: { name: "SupplyChainSentinel", version: "1.0.0" } }, results }],
  };
}