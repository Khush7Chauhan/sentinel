import React, { useState } from "react";
import { projectRisk, severityFromRisk, SEVERITY_COLOR, SEVERITY_LABEL, FINDING_DEDUCTION } from "../../utils/scoring";
import { download, buildReport, buildSarif } from "../../utils/export";

export default function Remediation({ target, dataset, onBack }) {
  const items = [
    ...(dataset.packages || []).flatMap((p) =>
      (p.findings || [])
        .filter((f) => f.severity !== "low" || f.fix.startsWith("Rotate"))
        .map((f) => ({ severity: f.severity, title: `${p.name}: ${f.title}`, fix: f.fix }))
    ),
    ...(dataset.projectFindings || []).map((f) => ({ severity: f.severity, title: f.title, fix: f.fix })),
  ].sort((a, b) => (FINDING_DEDUCTION[b.severity] || 0) - (FINDING_DEDUCTION[a.severity] || 0));

  const risk = projectRisk(dataset.packages, dataset.projectFindings);
  const [done, setDone] = useState({});

  const toggle = (i) => setDone((d) => ({ ...d, [i]: !d[i] }));
  const doneCount = Object.values(done).filter(Boolean).length;
  const pct = items.length ? Math.round((doneCount / items.length) * 100) : 0;

  return (
    <div className="panel remediation">
      <div className="detail-head">
        <div>
          <h2>Remediation checklist</h2>
          <div className="meta">{target} · project risk <b style={{ color: SEVERITY_COLOR[severityFromRisk(risk)] }}>{risk}/100</b></div>
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          <button className="rescan" onClick={() => download("scan-report.json", JSON.stringify(buildReport(target, dataset), null, 2))}>Export JSON</button>
          <button className="rescan" onClick={() => download("scan-report.sarif", JSON.stringify(buildSarif(target, dataset), null, 2))}>Export SARIF</button>
          <button className="rescan" onClick={onBack}>← Back</button>
        </div>
      </div>
      
      {items.length > 0 && (
        <div className="rem-progress-row">
          <div className="rem-progress-track">
            <div className="rem-progress-fill" style={{ width: `${pct}%` }} />
          </div>
          <span className="rem-progress-label">{doneCount} / {items.length} fixed</span>
        </div>
      )}

      <div className="detail-body">
        {items.length === 0 && <p style={{ color: "var(--clean)" }}>✓ Nothing to fix. This project looks clean.</p>}
        {items.map((it, i) => (
          <div className={`rem-item ${done[i] ? "checked" : ""}`} key={i} onClick={() => toggle(i)}>
            <div className="rem-check">
              {done[i] && (
                <svg viewBox="0 0 24 24" width="11" height="11" fill="none" stroke="#fff" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round">
                  <polyline points="4 12.5 9.5 18 20 6" />
                </svg>
              )}
            </div>
            <div>
              <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                <span className="sev-tag" style={{ color: SEVERITY_COLOR[it.severity] }}>{SEVERITY_LABEL[it.severity]}</span>
                <span style={{ fontWeight: 600 }}>{it.title}</span>
              </div>
              <div className="finding-detail" style={{ marginTop: 3 }}>→ {it.fix}</div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}