export const SEVERITY_COLOR = {
  critical: "var(--critical)",
  high: "var(--high)",
  medium: "var(--medium)",
  low: "var(--low)",
  clean: "var(--clean)",
};

export const SEVERITY_LABEL = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  clean: "Clean",
};

export const FINDING_DEDUCTION = { critical: 25, high: 15, medium: 8, low: 3, clean: 0 };

export function severityFromRisk(riskScore) {
  if (riskScore >= 75) return "critical";
  if (riskScore >= 55) return "high";
  if (riskScore >= 25) return "medium";
  if (riskScore >= 1) return "low";
  return "clean";
}

export function packageRisk(pkg) {
  return Math.max(pkg.l1 ?? 0, pkg.l2 ?? 0);
}

export function packageSeverity(pkg) {
  return severityFromRisk(packageRisk(pkg));
}

export function projectRisk(packages = [], projectFindings = []) {
  let wSum = 0;
  let rSum = 0;
  for (const p of packages) {
    const w = p.direct ? 1 : 1 / ((p.depth ?? 0) + 1);
    wSum += w;
    rSum += w * packageRisk(p);
  }
  const base = wSum ? rSum / wSum : 0;
  const deductions = projectFindings.reduce(
    (acc, f) => acc + (FINDING_DEDUCTION[f.severity] || 0),
    0
  );
  return Math.min(100, Math.round(base + deductions));
}