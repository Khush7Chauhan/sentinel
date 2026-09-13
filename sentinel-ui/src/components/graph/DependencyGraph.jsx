import React from "react";
import { packageRisk, severityFromRisk, projectRisk, SEVERITY_COLOR, SEVERITY_LABEL } from "../../utils/scoring";

export default function DependencyGraph({ dataset, selectedId, onSelect }) {
  const getRisk = (id) => {
    const pkg = dataset.packages.find((p) => p.id === id);
    return pkg ? packageRisk(pkg) : 0;
  };

  const getNodeSeverity = (node) =>
    severityFromRisk(
      node.kind === "root"
        ? projectRisk(dataset.packages, dataset.projectFindings)
        : getRisk(node.id)
    );

  return (
    <div className="panel graph-panel">
      <div className="panel-head">
        <span>Dependency Graph</span>
        <span className="live-tag">
          <span className="live-dot" /> LIVE
        </span>
      </div>

      <svg viewBox="0 0 600 340" style={{ width: "100%", height: "260px" }} preserveAspectRatio="xMidYMid meet">
        <defs>
          <filter id="graph-blur"><feGaussianBlur stdDeviation="22" /></filter>
          <filter id="node-blur"><feGaussianBlur stdDeviation="5" /></filter>
          <filter id="particle-blur"><feGaussianBlur stdDeviation="2.2" /></filter>
        </defs>

        {dataset.graph.edges.map(([fromId, toId], idx) => {
          const fromNode = dataset.graph.nodes.find((n) => n.id === fromId);
          const toNode = dataset.graph.nodes.find((n) => n.id === toId);
          if (!fromNode || !toNode) return null;

          const midX = (fromNode.x + toNode.x) / 2;
          const midY = (fromNode.y + toNode.y) / 2 - 14;
          const targetSev = getNodeSeverity(toNode);
          const isHighRisk = targetSev === "critical" || targetSev === "high";
          const pathD = `M ${fromNode.x} ${fromNode.y} Q ${midX} ${midY} ${toNode.x} ${toNode.y}`;
          const particleColor = isHighRisk ? SEVERITY_COLOR[targetSev] : "#6FA0FF";

          return (
            <React.Fragment key={idx}>
              <path
                d={pathD}
                fill="none"
                stroke={isHighRisk ? SEVERITY_COLOR[targetSev] : "var(--border)"}
                strokeOpacity={isHighRisk ? 0.6 : 1}
                strokeWidth="1.5"
                strokeDasharray="5 5"
                className="graph-edge"
              />
              <circle r="2.2" fill={particleColor}>
                <animateMotion dur="2.4s" repeatCount="indefinite" path={pathD} />
              </circle>
            </React.Fragment>
          );
        })}

        {dataset.graph.nodes.map((node) => {
          const sev = getNodeSeverity(node);
          const isRoot = node.kind === "root";
          const isSelected = node.id === selectedId;
          const fill = isRoot ? "var(--ink)" : SEVERITY_COLOR[sev];
          const radius = isRoot ? 8 : isSelected ? 9 : 6;

          return (
            <g
              key={node.id}
              className="graph-node-group"
              onClick={() => !isRoot && onSelect(node.id)}
              style={{ cursor: isRoot ? "default" : "pointer" }}
            >
              <circle cx={node.x} cy={node.y} r={radius + 8} fill={fill} opacity="0.2" filter="url(#node-blur)" />
              {isSelected && (
                <circle cx={node.x} cy={node.y} r={radius + 5} fill="none" stroke="var(--ink)" strokeWidth="1" strokeDasharray="3 3" />
              )}
              <circle cx={node.x} cy={node.y} r={radius} fill={fill} stroke={isSelected ? "var(--ink)" : "none"} strokeWidth="2" />
              <text x={node.x} y={node.y - 12} textAnchor="middle" fontSize="11" fill="var(--muted)" fontFamily="IBM Plex Mono, monospace">
                {node.label}
              </text>
            </g>
          );
        })}
      </svg>

      <div className="graph-legend">
        {Object.entries(SEVERITY_LABEL).map(([key, label]) => (
          <div className="legend-item" key={key}>
            <span className="sev-dot" style={{ background: SEVERITY_COLOR[key] }} />
            {label}
          </div>
        ))}
      </div>
    </div>
  );
}