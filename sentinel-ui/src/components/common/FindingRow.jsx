import React from "react";
import { SEVERITY_COLOR } from "../../utils/scoring";

export default function FindingRow({ f }) {
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