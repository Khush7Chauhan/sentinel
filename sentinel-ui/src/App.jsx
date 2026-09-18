import React, { useState, useEffect, useMemo, useRef, useCallback } from "react";
import './index.css';
import { DEMO_DATA, CLEAN_DATA, TIMELINE } from './data';
import { 
  SEVERITY_COLOR, SEVERITY_LABEL, FINDING_DEDUCTION, GH_URL_RE,
  severityFromRisk, packageRisk, packageSeverity, projectRisk, download, buildReport, buildSarif 
} from './utils';

const iconProps = { viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: "1.6", strokeLinecap: "round", strokeLinejoin: "round" };
function IconSearch(p) { return <svg {...iconProps} {...p}><circle cx="11" cy="11" r="7" /><line x1="21" y1="21" x2="16.5" y2="16.5" /></svg>; }
function IconLock(p) { return <svg {...iconProps} {...p}><rect x="4.5" y="10.5" width="15" height="9.5" rx="2.5" /><path d="M7.5 10.5V7a4.5 4.5 0 0 1 9 0v3.5" /></svg>; }
function IconArrow(p) { return <svg {...iconProps} {...p} strokeWidth="1.8"><line x1="4" y1="12" x2="19" y2="12" /><polyline points="13 6 19 12 13 18" /></svg>; }

function ScoreBar({ label, value }) {
  const color = value >= 75 ? "var(--critical)" : value >= 55 ? "var(--high)" : value >= 25 ? "var(--medium)" : "var(--clean)";
  return (
    <div className="score-bar">
      <div className="score-bar-head"><span>{label}</span><span className="score-bar-value">{value}</span></div>
      <div className="score-bar-track"><div className="score-bar-fill" style={{ width: `${value}%`, background: color }} /></div>
    </div>
  );
}

function FindingRow({ f }) {
  return (
    <div className="finding-row">
      <span className="finding-dot" style={{ background: SEVERITY_COLOR[f.severity] }} />
      <div>
        <div className="finding-title">{f.title}</div>
        <div className="finding-detail">{f.detail}</div>
        {f.file && <div className="finding-file">{f.file}</div>}
      </div>
    </div>
  );
}

function Graph({ dataset, selectedId, onSelect }) {
  const riskOf = (id) => {
    const p = dataset.packages.find((p) => p.id === id);
    return p ? packageRisk(p) : 0;
  };
  const nodeSev = (n) => severityFromRisk(n.kind === "root" ? projectRisk(dataset.packages, dataset.projectFindings) : riskOf(n.id));

  // DYNAMIC RADIAL LAYOUT ENGINE
  const { nodes, edges } = useMemo(() => {
    if (!dataset || !dataset.graph) return { nodes: [], edges: [] };
    
    const rootNode = dataset.graph.nodes.find(n => n.kind === "root") || { id: "root", x: 300, y: 160, kind: "root", label: "target" };
    const pkgNodes = dataset.graph.nodes.filter(n => n.kind !== "root");
    
    const cx = 300, cy = 160, radius = 115;
    const positionedNodes = [ { ...rootNode, x: cx, y: cy } ];
    
    // Auto-distribute package nodes in a perfect circle
    pkgNodes.forEach((node, i) => {
      const angle = (i / pkgNodes.length) * 2 * Math.PI - (Math.PI / 2);
      positionedNodes.push({
        ...node,
        x: cx + radius * Math.cos(angle),
        y: cy + radius * Math.sin(angle)
      });
    });
    
    return { nodes: positionedNodes, edges: dataset.graph.edges || [] };
  }, [dataset]);

  return (
    <div className="panel graph-panel">
      <div className="panel-head">
        Dependency graph
        <span className="live-tag"><span className="live-dot" />live</span>
      </div>
      <svg viewBox="0 0 600 340" style={{ width: "100%", height: "260px" }} preserveAspectRatio="xMidYMid meet">
        <defs>
          <filter id="graph-blur"><feGaussianBlur stdDeviation="22" /></filter>
          <filter id="node-blur"><feGaussianBlur stdDeviation="5" /></filter>
          <filter id="particle-blur"><feGaussianBlur stdDeviation="2.2" /></filter>
        </defs>

        <circle className="graph-drift graph-drift-a" cx="150" cy="90" r="110" fill="rgba(76,140,255,.22)" filter="url(#graph-blur)" />
        <circle className="graph-drift graph-drift-b" cx="470" cy="250" r="100" fill="rgba(229,72,77,.14)" filter="url(#graph-blur)" />
        <circle className="graph-drift graph-drift-c" cx="380" cy="70" r="80" fill="rgba(76,140,255,.12)" filter="url(#graph-blur)" />

        {edges.map(([a, b], i) => {
          const na = nodes.find((n) => n.id === a);
          const nb = nodes.find((n) => n.id === b);
          if(!na || !nb) return null;
          
          const mx = (na.x + nb.x) / 2, my = (na.y + nb.y) / 2 - 14;
          const targetSev = nodeSev(nb);
          const hot = targetSev === "critical" || targetSev === "high";
          const d = `M ${na.x} ${na.y} Q ${mx} ${my} ${nb.x} ${nb.y}`;
          const particleColor = hot ? SEVERITY_COLOR[targetSev] : "#6FA0FF";
          const dur = (hot ? 1.8 : 2.6) + (i % 3) * 0.4;
          const begin = (i * 0.5).toFixed(2);
          
          return (
            <React.Fragment key={i}>
              <path d={d} fill="none" stroke={hot ? SEVERITY_COLOR[targetSev] : "var(--border)"} strokeOpacity={hot ? 0.55 : 1} strokeWidth="1.5" strokeDasharray="5 5" className="graph-edge" style={{ animationDelay: `${i * -0.3}s` }} />
              <circle r="5" fill={particleColor} opacity="0.35" filter="url(#particle-blur)"><animateMotion dur={`${dur}s`} begin={`${begin}s`} repeatCount="indefinite" path={d} /></circle>
              <circle r="2.1" fill={particleColor}><animateMotion dur={`${dur}s`} begin={`${begin}s`} repeatCount="indefinite" path={d} /><animate attributeName="opacity" values="0;1;1;0" keyTimes="0;0.08;0.92;1" dur={`${dur}s`} begin={`${begin}s`} repeatCount="indefinite" /></circle>
            </React.Fragment>
          );
        })}

        {nodes.map((n, i) => {
          const sev = nodeSev(n);
          const fill = n.kind === "root" ? "var(--ink)" : SEVERITY_COLOR[sev];
          const r = n.kind === "root" ? 8 : n.id === selectedId ? 9 : 6;
          const risky = n.kind !== "root" && (sev === "critical" || sev === "high");
          
          return (
            <g key={n.id} className="graph-node-group" style={{ animationDelay: `${i * 0.07}s, ${0.4 + i * 0.45}s`, animationDuration: `.5s, ${3.4 + (i % 3) * 0.6}s` }} onClick={() => n.kind !== "root" && onSelect(n.id)} cursor={n.kind === "root" ? "default" : "pointer"}>
              <circle cx={n.x} cy={n.y} r={r + 10} fill={fill} opacity={risky || n.kind === "root" ? 0.28 : 0.14} filter="url(#node-blur)" />
              {risky && <circle cx={n.x} cy={n.y} r={r} fill="none" stroke={SEVERITY_COLOR[sev]} strokeWidth="2" className="graph-ping" style={{ animationDelay: `${i * 0.6}s` }} />}
              {n.kind === "root" && <circle cx={n.x} cy={n.y} r={r + 6} fill="none" stroke="var(--low)" strokeWidth="1.5" className="graph-ping" style={{ animationDuration: "3s" }} />}
              {n.id === selectedId && <circle cx={n.x} cy={n.y} r={r + 6} fill="none" stroke="var(--ink)" strokeWidth="1" strokeDasharray="3 4" className="graph-orbit" />}
              <circle cx={n.x} cy={n.y} r={r} fill={fill} className="graph-node" stroke={n.id === selectedId ? "var(--ink)" : "none"} strokeWidth="2" />
              <text x={n.x} y={n.y - 14} textAnchor="middle" fontSize="11" fontFamily="IBM Plex Mono, monospace" fill="var(--muted)">{n.label}</text>
            </g>
          );
        })}
      </svg>
      <div className="graph-legend">{Object.entries(SEVERITY_LABEL).map(([k, v]) => <div className="legend-item" key={k}><span className="sev-dot" style={{ background: SEVERITY_COLOR[k] }} />{v}</div>)}</div>
    </div>
  );
}

function Landing({ onScan, apiError }) {
  const [url, setUrl] = useState("");
  const [localError, setLocalError] = useState("");
  const [revealed, setRevealed] = useState(false);
  const inputRef = useRef(null);

  const reveal = () => { setRevealed(true); setTimeout(() => inputRef.current && inputRef.current.focus(), 200); };
  const scrollToTry = () => { reveal(); document.getElementById("try")?.scrollIntoView({ behavior: "smooth", block: "center" }); };
  
  const submit = () => {
    if (url.trim().length < 2) { setLocalError("Enter a valid target directory or GitHub URL"); return; }
    setLocalError("");
    onScan(url.trim().replace(/^https?:\/\//, "").replace(/^www\./, ""));
  };

  const displayError = localError || apiError;

  return (
    <div className="future-page">
      <div className="future-nav">
        <div className="future-brand"><span className="future-brand-mark">🛡</span>Supply Chain Sentinel</div>
        <button className="future-nav-cta" onClick={scrollToTry}>Try now</button>
      </div>

      <div className="future-hero">
        <div className="future-glow" />
        <div className="future-badge"><span className="dot" /> Built for the TNL Hackathon</div>
        <div className="future-orb"><IconLock width="30" height="30" /></div>
        <h1>The trust you place in one package is the trust you place in all of them.</h1>
        <p className="sub">Every install pulls in code you didn't write, from people you've never met. Sentinel makes that trust visible — before it costs you.</p>
        <button className="cta-reveal-btn" onClick={scrollToTry}>Try now <IconArrow width="15" height="15" /></button>
      </div>

      <div className="future-section">
        <div className="future-eyebrow">It's already happened, more than once</div>
        <h2>The supply chain has been the target for years</h2>
        <div className="future-timeline">
          {TIMELINE.map((t) => (
            <div className="ft-item" key={t.year}>
              <div className="ft-dot">{t.year}</div>
              <div className="ft-body"><b>{t.title}</b><span>{t.copy}</span></div>
            </div>
          ))}
        </div>
      </div>

      <div className="future-section" style={{ paddingTop: 0 }}>
        <p className="future-tension">You shouldn't have to choose between <em>shipping fast</em> and <em>knowing what you shipped</em>.</p>
      </div>

      <div className="future-cta-section" id="try">
        <div className="future-eyebrow">See it on your own code</div>
        <h2 style={{ marginBottom: 26 }}>Scan a repo in seconds</h2>
        <div className="future-cta-glass">
          {!revealed && <button className="cta-reveal-btn" onClick={reveal}>Try now <IconArrow width="15" height="15" /></button>}
          <div className={`cta-input-wrap ${revealed ? "open" : ""}`}>
            <div className="cta-glass-pill">
              <IconSearch width="17" height="17" />
              <input ref={inputRef} placeholder="github.com/owner/repo or C:/local/path" value={url} onChange={(e) => { setUrl(e.target.value); setLocalError(""); }} onKeyDown={(e) => e.key === "Enter" && submit()} />
              <button onClick={submit}>Scan Live</button>
            </div>
            {displayError && <div className="cta-error">{displayError}</div>}
          </div>
        </div>
      </div>
      <div className="future-foot">Defensive analysis only — no exploits, no payloads.</div>
    </div>
  );
}

const SCAN_STEPS = ["Parsers", "L1 · Dependency intel", "L2 · Behavior scan", "L3 · Repo hygiene", "Scoring engine"];

function Scanning({ target, onCancel, scanPromise, onScanComplete }) {
  const [step, setStep] = useState(0);
  const [logs, setLogs] = useState([`Initializing connection to scanning engine...`]);
  
  useEffect(() => {
    let currentStep = 0;
    const stepLogs = [
      [`Cloning ${target} (shallow, read-only)`, "Extracting manifests..."],
      ["Querying OSV vulnerability database…", "Fetching registry metadata…"],
      ["Downloading tarballs (cached)…", `Scanning install hooks & AST...`],
      ["Scanning .github/workflows/*.yml…", "Entropy-based secret scan…"],
      ["Applying severity weights…", "Finalizing report…"],
    ];

    const iv = setInterval(() => {
      if (currentStep < SCAN_STEPS.length - 1) {
        setLogs((L) => [...L, ...(stepLogs[currentStep] || [])]);
        setStep(currentStep + 1);
        currentStep++;
      }
    }, 800);

    scanPromise.then(data => {
      clearInterval(iv);
      setStep(SCAN_STEPS.length);
      setLogs((L) => [...L, "Done."]);
      setTimeout(() => onScanComplete(data), 600);
    }).catch(err => {
      clearInterval(iv);
      onCancel(err.message); 
    });

    return () => clearInterval(iv);
  }, [target, scanPromise, onCancel, onScanComplete]);

  const progress = Math.min(100, Math.round((step / SCAN_STEPS.length) * 100));

  return (
    <div className="landing">
      <div className="panel scanning-card">
        <div className="scanning-head"><div className="spin" /><div><div className="mono" style={{ fontWeight: 600 }}>sentinel scan {target}</div><div style={{ color: "var(--muted)", fontSize: 12 }}>read-only · temp clone deleted after scan</div></div></div>
        <div className="scan-progress"><div className="scan-progress-fill" style={{ width: `${progress}%` }} /></div>
        <div className="pipeline" style={{ marginBottom: 12 }}>{SCAN_STEPS.map((st, i) => <React.Fragment key={st}><span className={`pipe-step ${i < step ? "done" : i === step ? "active" : ""}`}>{i < step ? "✓ " : ""}{st}</span>{i < SCAN_STEPS.length - 1 && <span className="pipe-arrow">→</span>}</React.Fragment>)}</div>
        <div className="scan-logs mono">{logs.map((l, i) => <div key={i}>{l}</div>)}</div>
        <button className="rescan" onClick={() => onCancel("Scan cancelled by user")}>Cancel</button>
      </div>
    </div>
  );
}

function Remediation({ target, dataset, onBack }) {
  const items = [
    ...dataset.packages.flatMap((p) => p.findings.filter((f) => f.severity !== "low" || f.fix.startsWith("Rotate")).map((f) => ({ severity: f.severity, title: `${p.name}: ${f.title}`, fix: f.fix }))),
    ...dataset.projectFindings.map((f) => ({ severity: f.severity, title: f.title, fix: f.fix })),
  ].sort((a, b) => (FINDING_DEDUCTION[b.severity] || 0) - (FINDING_DEDUCTION[a.severity] || 0));
  const risk = projectRisk(dataset.packages, dataset.projectFindings);
  const [done, setDone] = useState({});
  const toggle = (i) => setDone((d) => ({ ...d, [i]: !d[i] }));
  const doneCount = Object.values(done).filter(Boolean).length;
  const pct = items.length ? Math.round((doneCount / items.length) * 100) : 0;

  return (
    <div className="panel remediation">
      <div className="detail-head">
        <div><h2>Remediation checklist</h2><div className="meta">{target} · project risk <b style={{ color: SEVERITY_COLOR[severityFromRisk(risk)] }}>{risk}/100</b></div></div>
        <div style={{ display: "flex", gap: 8 }}><button className="rescan" onClick={() => download("scan-report.json", JSON.stringify(buildReport(target, dataset), null, 2))}>Export JSON</button><button className="rescan" onClick={() => download("scan-report.sarif", JSON.stringify(buildSarif(target, dataset), null, 2))}>Export SARIF</button><button className="rescan" onClick={onBack}>← Back</button></div>
      </div>
      {items.length > 0 && <div className="rem-progress-row"><div className="rem-progress-track"><div className="rem-progress-fill" style={{ width: `${pct}%` }} /></div><span className="rem-progress-label">{doneCount} / {items.length} fixed</span></div>}
      <div className="detail-body">
        {items.length === 0 && <p style={{ color: "var(--clean)" }}>✓ Nothing to fix. This project looks clean.</p>}
        {items.map((it, i) => (
          <div className={`rem-item ${done[i] ? "checked" : ""}`} key={i} onClick={() => toggle(i)}>
            <div className="rem-check">{done[i] && <svg viewBox="0 0 24 24" width="11" height="11" fill="none" stroke="#fff" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round"><polyline points="4 12.5 9.5 18 20 6" /></svg>}</div>
            <div><div style={{ display: "flex", gap: 8, alignItems: "center" }}><span className="sev-tag" style={{ color: SEVERITY_COLOR[it.severity] }}>{SEVERITY_LABEL[it.severity]}</span><span style={{ fontWeight: 600 }}>{it.title}</span></div><div className="finding-detail" style={{ marginTop: 3 }}>→ {it.fix}</div></div>
          </div>
        ))}
      </div>
    </div>
  );
}

function Dashboard({ target, dataset, onRescan }) {
  const sorted = useMemo(() => [...dataset.packages].sort((a, b) => packageRisk(b) - packageRisk(a)), [dataset]);
  const [selectedId, setSelectedId] = useState(sorted[0]?.id || "");
  const [showExplain, setShowExplain] = useState(false);
  const [view, setView] = useState("findings"); 
  const [sevFilter, setSevFilter] = useState("all");
  const [query, setQuery] = useState("");

  const selected = sorted.find((p) => p.id === selectedId) || sorted[0];
  const risk = projectRisk(dataset.packages, dataset.projectFindings);
  const riskSev = severityFromRisk(risk);
  const critCount = dataset.packages.filter((p) => packageSeverity(p) === "critical").length;
  const highCount = dataset.packages.filter((p) => packageSeverity(p) === "high").length;
  const filteredPkgs = sorted.filter((p) => (p.name + p.ecosystem).toLowerCase().includes(query.toLowerCase()));
  
  if (!selected) return null; 
  
  const shownFindings = selected.findings.filter((f) => sevFilter === "all" || f.severity === sevFilter);
  const explainText = packageSeverity(selected) === "critical" || packageSeverity(selected) === "high"
      ? `This package requires immediate review based on strict deterministic rules. Please verify the findings below.`
      : `No critical indicators found. Findings are standard maintenance items.`;

  if (view === "remediation") return <div className="scs"><Remediation target={target} dataset={dataset} onBack={() => setView("findings")} /></div>;

  return (
    <div className="scs">
      <div className="scs-header">
        <div className="scs-title"><h1>Supply Chain Sentinel</h1><span className="sub">{target} · scanned live via FastAPI</span></div>
        <div className="header-right"><span className="sub" style={{ color: "var(--muted)", fontSize: 12.5 }}>{dataset.packages.length} packages · {critCount} critical · {highCount} high</span><div className="overall-badge" title="Weighted package rollup + repo findings"><span className="n" style={{ color: SEVERITY_COLOR[riskSev] }}>{risk}</span><span className="l">/100 risk</span></div><button className="rescan" onClick={() => download("scan-report.json", JSON.stringify(buildReport(target, dataset), null, 2))}>Export</button><button className="rescan" onClick={() => setView("remediation")}>Remediation →</button><button className="rescan btn-primary" onClick={onRescan}>New scan</button></div>
      </div>
      <div className="pipeline">{SCAN_STEPS.map((step, i) => <React.Fragment key={step}><span className="pipe-step done">✓ {step}</span>{i < SCAN_STEPS.length - 1 && <span className="pipe-arrow">→</span>}</React.Fragment>)}</div>
      <div className="scs-body">
        <div className="panel">
          <div className="panel-head">Packages<input className="pkg-search" type="text" placeholder="filter…" value={query} onChange={(e) => setQuery(e.target.value)} /></div>
          <div>
            {filteredPkgs.map((p) => {
              const sev = packageSeverity(p);
              return (
                <div key={p.id} className={`pkg-row ${p.id === selectedId ? "active" : ""}`} onClick={() => { setSelectedId(p.id); setShowExplain(false); }}>
                  <div><span className="sev-dot" style={{ background: SEVERITY_COLOR[sev] }} /><span className="pkg-name">{p.name}</span><span className="pkg-eco">{p.ecosystem}{p.direct ? "" : " · transitive"}</span></div><span className="pkg-score" style={{ color: SEVERITY_COLOR[sev] }}>{packageRisk(p)}</span>
                </div>
              );
            })}
            {filteredPkgs.length === 0 && <div className="pkg-empty">No packages match "{query}"</div>}
          </div>
        </div>
        <div className="panel">
          <div className="detail-head"><div><h2>{selected.name}<span style={{ color: "var(--muted)", fontWeight: 400 }}>@{selected.version}</span></h2><div className="meta">{selected.ecosystem} package · risk {packageRisk(selected)}/100</div></div><span className="sev-tag" style={{ color: SEVERITY_COLOR[packageSeverity(selected)] }}>{SEVERITY_LABEL[packageSeverity(selected)]}</span></div>
          <div className="detail-body">
            <div className="score-bars"><ScoreBar label="L1 · Dependency intel" value={selected.l1} /><ScoreBar label="L2 · Behavior scan" value={selected.l2} /></div>
            <div className="section-label">Findings for this package<span className="filter-chips">{["all", "critical", "high", "medium", "low"].map((s) => <button key={s} className={`fchip ${sevFilter === s ? "on" : ""}`} onClick={() => setSevFilter(s)}>{s}</button>)}</span></div>
            {shownFindings.length === 0 && <p className="finding-detail">No {sevFilter} findings for this package.</p>}
            {shownFindings.map((f, i) => <FindingRow f={f} key={i} />)}
            <button className="explain-toggle" onClick={() => setShowExplain((v) => !v)}>{showExplain ? "Hide" : "Explain"} AI Context</button>
            {showExplain && <div className="explain-box"><span className="explain-label">Engine notes</span>{explainText}</div>}
            <div className="section-label">Project-wide · L3 repo hygiene</div>
            {dataset.projectFindings.map((f, i) => <FindingRow f={f} key={i} />)}
          </div>
        </div>
        <Graph dataset={dataset} selectedId={selectedId} onSelect={(id) => { setSelectedId(id); setShowExplain(false); }} />
      </div>
      <div className="scs-foot">Live analysis from Python Backend. Scores are mathematically deterministic based on engine weights.</div>
    </div>
  );
}

export default function App() {
  const [screen, setScreen] = useState("landing"); 
  const [target, setTarget] = useState("");
  const [dataset, setDataset] = useState(null);
  
  // This correctly initializes the states required by the updated Scanning component
  const [apiError, setApiError] = useState(""); 
  const [scanPromise, setScanPromise] = useState(null);

  const startScan = (t) => { 
    setTarget(t); 
    setApiError("");
    
    const fetchPromise = fetch(`http://127.0.0.1:8000/api/scan?target_dir=${encodeURIComponent(t)}`, { method: 'POST' })
      .then(async res => {
        if (!res.ok) {
          const errText = await res.text();
          throw new Error(`Backend Error: ${res.status}. ${errText || 'Make sure FastAPI is running.'}`);
        }
        return res.json();
      });

    setScanPromise(fetchPromise);
    setScreen("scanning"); 
  };

  const handleScanCancel = useCallback((errorMessage) => {
    setApiError(errorMessage || "Scan aborted.");
    setScreen("landing");
  }, []);

  const handleScanComplete = useCallback((liveData) => {
    setDataset(liveData);
    setScreen("dashboard");
  }, []);

  return (
    <div className="scs-root">
      {screen === "landing" && <Landing onScan={startScan} apiError={apiError} />}
      {screen === "scanning" && (
        <Scanning 
          target={target} 
          scanPromise={scanPromise} 
          onScanComplete={handleScanComplete} 
          onCancel={handleScanCancel} 
        />
      )}
      {screen === "dashboard" && <Dashboard target={target} dataset={dataset} onRescan={() => setScreen("landing")} />}
    </div>
  );
}