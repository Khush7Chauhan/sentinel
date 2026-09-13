import React, { useState, useEffect } from "react";

const SCAN_STEPS = ["Parsers", "L1 · Dependency intel", "L2 · Behavior scan", "L3 · Repo hygiene", "Scoring engine"];

export default function Scanning({ target, dataset, onDone, onCancel }) {
  const [step, setStep] = useState(0);
  const [logs, setLogs] = useState([]);

  useEffect(() => {
    const pkgs = dataset?.packages?.map((p) => p.name) || [];
    const stepLogs = [
      [`Cloning ${target} (shallow, read-only)`, "Found package-lock.json · requirements.txt", `Parsed ${pkgs.length} packages`],
      ["Querying OSV vulnerability database...", "Fetching registry metadata...", "Profiling maintainer history..."],
      ["Downloading tarballs (cached)...", "Scanning install hooks & AST...", "Applying Shannon entropy checks..."],
      ["Scanning .github/workflows/*.yml...", "Executing regex pattern matching..."],
      ["Applying severity weights...", "Composing deterministic explanation records...", "Done."],
    ];

    let currentStep = 0;
    const interval = setInterval(() => {
      setLogs((prev) => [...prev, ...(stepLogs[currentStep] || [])]);
      setStep(currentStep + 1);
      currentStep += 1;
      
      if (currentStep >= SCAN_STEPS.length) {
        clearInterval(interval);
        setTimeout(onDone, 600);
      }
    }, 800);

    return () => clearInterval(interval);
  }, [target, dataset, onDone]);

  const progress = Math.min(100, Math.round((step / SCAN_STEPS.length) * 100));

  return (
    <div className="landing">
      <div className="panel scanning-card">
        <div className="scanning-head">
          <div className="spin" />
          <div>
            <div className="mono" style={{ fontWeight: 600 }}>sentinel scan {target}</div>
            <div style={{ color: "var(--muted)", fontSize: 12 }}>read-only · temp clone deleted after scan</div>
          </div>
        </div>
        <div className="scan-progress">
          <div className="scan-progress-fill" style={{ width: `${progress}%` }} />
        </div>
        <div className="pipeline" style={{ marginBottom: 12 }}>
          {SCAN_STEPS.map((st, i) => (
            <React.Fragment key={st}>
              <span className={`pipe-step ${i < step ? "done" : i === step ? "active" : ""}`}>
                {i < step ? "✓ " : ""}{st}
              </span>
              {i < SCAN_STEPS.length - 1 && <span className="pipe-arrow">→</span>}
            </React.Fragment>
          ))}
        </div>
        <div className="scan-logs mono">
          {logs.map((log, i) => <div key={i}>{log}</div>)}
        </div>
        <button className="rescan" onClick={onCancel}>Cancel</button>
      </div>
    </div>
  );
}