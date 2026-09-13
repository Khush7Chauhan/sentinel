import React from "react";

export default function ScoreBar({ label, value }) {
  const color = value >= 75 ? "var(--critical)" : value >= 55 ? "var(--high)" : value >= 25 ? "var(--medium)" : "var(--clean)";
  
  return (
    <div className="score-bar">
      <div className="score-bar-head">
        <span>{label}</span>
        <span className="score-bar-value">{value}</span>
      </div>
      <div className="score-bar-track">
        <div className="score-bar-fill" style={{ width: `${value}%`, background: color }} />
      </div>
    </div>
  );
}