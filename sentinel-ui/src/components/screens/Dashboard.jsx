import React, { useState, useMemo } from "react";
import DependencyGraph from "../graph/DependencyGraph";
import ScoreBar from "../common/ScoreBar";
import FindingRow from "../common/FindingRow";
import { packageRisk, packageSeverity, projectRisk, severityFromRisk, SEVERITY_COLOR, SEVERITY_LABEL } from "../../utils/scoring";

export default function Dashboard({ target, dataset, onRescan }) {
  const sortedPackages = useMemo(() => {
    return [...(dataset?.packages || [])].sort((a, b) => packageRisk(b) - packageRisk(a));
  }, [dataset]);

  const [selectedId, setSelectedId] = useState(sortedPackages[0]?.id || null);
  const [query, setQuery] = useState("");

  const risk = projectRisk(dataset.packages, dataset.projectFindings);
  const riskSev = severityFromRisk(risk);
  const selectedPkg = sortedPackages.find((p) => p.id === selectedId) || sortedPackages[0];

  const filteredPkgs = sortedPackages.filter((p) =>
    (p.name + p.ecosystem).toLowerCase().includes(query.toLowerCase())
  );

  if (!dataset || !selectedPkg) return null;

  return (
    <div className="scs">
      <div className="scs-header">
        <div className="scs-title">
          <h1>Supply Chain Sentinel</h1>
          <span className="sub">{target} · scanned just now</span>
        </div>
        <div className="header-right">
          <div className="overall-badge" title="Weighted package rollup + repo findings">
            <span className="n" style={{ color: SEVERITY_COLOR[riskSev] }}>{risk}</span>
            <span className="l">/100 risk</span>
          </div>
          <button className="rescan btn-primary" onClick={onRescan}>New scan</button>
        </div>
      </div>

      <div className="scs-body">
        <div className="panel">
          <div className="panel-head">
            Packages
            <input className="pkg-search" type="text" placeholder="filter..." value={query} onChange={(e) => setQuery(e.target.value)} />
          </div>
          <div>
            {filteredPkgs.map((p) => {
              const sev = packageSeverity(p);
              return (
                <div key={p.id} className={`pkg-row ${p.id === selectedId ? "active" : ""}`} onClick={() => setSelectedId(p.id)}>
                  <div>
                    <span className="sev-dot" style={{ background: SEVERITY_COLOR[sev] }} />
                    <span className="pkg-name">{p.name}</span>
                    <span className="pkg-eco">{p.ecosystem} {p.direct ? "" : "· trans"}</span>
                  </div>
                  <span className="pkg-score" style={{ color: SEVERITY_COLOR[sev] }}>{packageRisk(p)}</span>
                </div>
              );
            })}
          </div>
        </div>

        <div className="panel">
          <div className="detail-head">
            <div>
              <h2>{selectedPkg.name}<span style={{ color: "var(--muted)", fontWeight: 400 }}>@{selectedPkg.version}</span></h2>
              <div className="meta">{selectedPkg.ecosystem} · risk {packageRisk(selectedPkg)}/100</div>
            </div>
            <span className="sev-tag" style={{ color: SEVERITY_COLOR[packageSeverity(selectedPkg)] }}>
              {SEVERITY_LABEL[packageSeverity(selectedPkg)]}
            </span>
          </div>
          <div className="detail-body">
            <div className="score-bars">
              <ScoreBar label="L1 · Dependency intel" value={selectedPkg.l1 || 0} />
              <ScoreBar label="L2 · Behavior scan" value={selectedPkg.l2 || 0} />
            </div>
            <div className="section-label">Findings for this package</div>
            {selectedPkg.findings?.map((f, i) => <FindingRow f={f} key={i} />)}
            
            <div className="section-label">Project-wide · L3 repo hygiene</div>
            {dataset.projectFindings?.map((f, i) => <FindingRow f={f} key={i} />)}
          </div>
        </div>

        <DependencyGraph dataset={dataset} selectedId={selectedId} onSelect={setSelectedId} />
      </div>
    </div>
  );
}