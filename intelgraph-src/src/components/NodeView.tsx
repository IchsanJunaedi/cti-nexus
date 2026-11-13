import { memo } from "react";
import type { DiagramNode } from "../types";
import { DISPOSITION_MAP, NODE_TYPE_MAP, STATUS_MAP } from "../constants/nodeTypes";
import { NodeIconGlyph } from "./NodeIcon";
import { StatusIconGlyph } from "./StatusIcon";

interface Props {
  node: DiagramNode;
  selected: boolean;
  showPorts: boolean;
  editing: boolean;
  editValue: string;
  onEditValueChange: (v: string) => void;
  onEditCommit: () => void;
  onEditCancel: () => void;
  dim?: boolean;
  highlight?: boolean;
}

const PORT_SIDES = ["n", "e", "s", "w"] as const;

function portPos(n: DiagramNode, side: (typeof PORT_SIDES)[number]) {
  switch (side) {
    case "n":
      return { x: n.x + n.w / 2, y: n.y };
    case "s":
      return { x: n.x + n.w / 2, y: n.y + n.h };
    case "e":
      return { x: n.x + n.w, y: n.y + n.h / 2 };
    case "w":
      return { x: n.x, y: n.y + n.h / 2 };
  }
}

export const NodeView = memo(function NodeView({
  node,
  selected,
  showPorts,
  editing,
  editValue,
  onEditValueChange,
  onEditCommit,
  onEditCancel,
  dim,
  highlight,
}: Props) {
  const t = NODE_TYPE_MAP[node.type];
  const disposition = node.disposition ? DISPOSITION_MAP[node.disposition] : null;
  const statusIds = Array.isArray(node.status) ? node.status : node.status ? [node.status] : [];
  const statuses = statusIds.map((id) => STATUS_MAP[id]).filter(Boolean);
  const worstStatus = statuses[statuses.length - 1] ?? null;
  const dispW = disposition ? Math.max(46, disposition.label.length * 6.4 + 14) : 0;
  const borderColor = highlight ? "var(--accent)" : selected ? t.accent : disposition ? disposition.color : "var(--border2)";
  const metaLines = [node.meta?.owner, node.meta?.hostname, node.meta?.ip, node.meta?.address, node.meta?.coords].filter(
    (v): v is string => !!v
  );
  const iconY = metaLines.length === 0 ? node.y + node.h / 2 - 12 : node.y + 12;
  const labelY = metaLines.length === 0 ? node.y + node.h / 2 + 4 : node.y + 29;

  return (
    <g className="nodeg" data-id={node.id} data-kind="node" opacity={dim ? 0.22 : 1}>
      {highlight && (
        <rect
          x={node.x - 5}
          y={node.y - 5}
          width={node.w + 10}
          height={node.h + 10}
          rx={16}
          fill="none"
          stroke="var(--accent)"
          strokeWidth={2}
          style={{ filter: "drop-shadow(0 0 5px var(--accent))" }}
          pointerEvents="none"
        />
      )}
      {worstStatus && (
        <rect
          className="status-ring"
          x={node.x - 5}
          y={node.y - 5}
          width={node.w + 10}
          height={node.h + 10}
          rx={16}
          fill="none"
          stroke={worstStatus.color}
          strokeWidth={2}
          style={{ color: worstStatus.color }}
          pointerEvents="none"
        />
      )}
      <rect
        x={node.x}
        y={node.y}
        width={node.w}
        height={node.h}
        rx={12}
        fill="url(#nodeCardGrad)"
        stroke={borderColor}
        strokeWidth={highlight || selected ? 2.5 : 1.5}
        data-id={node.id}
        data-kind="node"
      />
      {disposition && (
        <g pointerEvents="none">
          <rect x={node.x - 4} y={node.y - 9} width={dispW} height={17} rx={8.5} fill="var(--bg)" stroke={disposition.color} strokeWidth={1.3} />
          <text x={node.x - 4 + dispW / 2} y={node.y + 3.5} textAnchor="middle" fill={disposition.color} fontSize={9.5} fontWeight={700}>
            {disposition.label}
          </text>
        </g>
      )}
      {statuses.map((s, i) => {
        const cx = node.x + node.w - 8 - i * 17;
        const cy = node.y;
        return (
          <g key={s.id} pointerEvents="none">
            <circle cx={cx} cy={cy} r={8.5} fill="var(--bg)" stroke={s.color} strokeWidth={1.5} />
            <svg
              x={cx - 5.5}
              y={cy - 5.5}
              width={11}
              height={11}
              viewBox="0 0 24 24"
              fill="none"
              stroke={s.color}
              strokeWidth={2.6}
              strokeLinecap="round"
              strokeLinejoin="round"
              style={{ color: s.color }}
            >
              <title>{s.label}</title>
              <StatusIconGlyph status={s.id} />
            </svg>
          </g>
        );
      })}
      <svg
        x={node.x + 10}
        y={iconY}
        width={24}
        height={24}
        viewBox="0 0 24 24"
        fill="none"
        stroke={t.accent}
        strokeWidth={1.6}
        strokeLinecap="round"
        strokeLinejoin="round"
        pointerEvents="none"
      >
        <NodeIconGlyph type={node.type} />
      </svg>
      {editing ? (
        <foreignObject x={node.x + 40} y={labelY - 16} width={node.w - 50} height={24}>
          <input
            autoFocus
            value={editValue}
            onChange={(e) => onEditValueChange(e.target.value)}
            onBlur={onEditCommit}
            onKeyDown={(e) => {
              e.stopPropagation();
              if (e.key === "Enter") onEditCommit();
              if (e.key === "Escape") onEditCancel();
            }}
            style={{
              width: "100%",
              height: "100%",
              background: "var(--panel)",
              border: "1px solid var(--accent)",
              borderRadius: 6,
              color: "var(--text)",
              font: "600 12px ui-sans-serif, system-ui, sans-serif",
              padding: "0 6px",
            }}
          />
        </foreignObject>
      ) : (
        <>
          <text
            x={node.x + 40}
            y={labelY}
            fill="var(--text)"
            fontSize={12.5}
            fontWeight={600}
            data-id={node.id}
            data-kind="node"
          >
            {node.label}
          </text>
          {metaLines.map((line, i) => (
            <text
              key={i}
              x={node.x + 40}
              y={labelY + 16 + i * 14}
              fill="var(--faint)"
              fontSize={10.5}
              data-id={node.id}
              data-kind="node"
            >
              {line}
            </text>
          ))}
        </>
      )}
      {selected &&
        !editing &&
        (["nw", "ne", "sw", "se"] as const).map((corner) => {
          const hx = corner.includes("e") ? node.x + node.w : node.x;
          const hy = corner.includes("s") ? node.y + node.h : node.y;
          return (
            <rect
              key={corner}
              className="node-handle"
              data-id={node.id}
              data-kind="node-handle"
              data-corner={corner}
              x={hx - 4}
              y={hy - 4}
              width={8}
              height={8}
              rx={2}
              fill="var(--panel)"
              stroke="var(--accent)"
              strokeWidth={1.5}
              style={{ cursor: corner === "nw" || corner === "se" ? "nwse-resize" : "nesw-resize" }}
            />
          );
        })}
      {showPorts &&
        PORT_SIDES.map((side) => {
          const p = portPos(node, side);
          return (
            <circle
              key={side}
              className="port"
              data-id={node.id}
              data-kind="port"
              data-side={side}
              cx={p.x}
              cy={p.y}
              r={5}
              fill="var(--panel)"
              stroke="var(--accent)"
              strokeWidth={2}
            />
          );
        })}
    </g>
  );
});
