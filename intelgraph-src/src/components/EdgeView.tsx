import { memo } from "react";
import type { DiagramEdge, DiagramNode, FlowDirection, LineStyle } from "../types";
import { curvedEdge } from "../lib/geometry";

const LINE_DASH: Record<LineStyle, string | undefined> = {
  solid: undefined,
  dashed: "9 6",
  dotted: "1.5 5",
  sneakernet: "1.5 5 14 5",
};

/**
 * Drawn pointing along +x (the direction offset-rotate:auto aligns with travel), shifted off
 * the line. For the reverse stream, offset-rotate's extra 180deg also flips this perpendicular
 * offset, so the same fixed shift naturally lands the two streams on opposite sides.
 */
function FootGlyph({ color }: { color: string }) {
  return (
    <g transform="translate(0,-5)" pointerEvents="none">
      <ellipse cx={-1.6} cy={0} rx={2.9} ry={2} fill={color} opacity={0.85} />
      <circle cx={2.6} cy={-1.3} r={0.9} fill={color} opacity={0.85} />
      <circle cx={3.3} cy={0} r={1} fill={color} opacity={0.85} />
      <circle cx={2.6} cy={1.3} r={0.9} fill={color} opacity={0.85} />
    </g>
  );
}

const FLOW_DURATION = 3.2;
const STEP_COUNT = 8;

/** Marching-ants: a steady stream of footstep marks looping along the path, evenly spaced. */
function FeetTrail({ d, selected, direction }: { d: string; selected: boolean; direction: FlowDirection }) {
  const color = selected ? "var(--accent)" : "var(--flow-color)";
  const forward = Array.from({ length: STEP_COUNT }, (_, i) => (
    <g
      key={`f${i}`}
      className="edge-foot"
      style={{
        offsetPath: `path('${d}')`,
        offsetRotate: "auto",
        animationDelay: `${-(i / STEP_COUNT) * FLOW_DURATION}s`,
      }}
    >
      <FootGlyph color={color} />
    </g>
  ));
  if (direction !== "both") return <>{forward}</>;
  const backward = Array.from({ length: STEP_COUNT }, (_, i) => (
    <g
      key={`b${i}`}
      className="edge-foot edge-foot-reverse"
      style={{
        offsetPath: `path('${d}')`,
        offsetRotate: "auto 180deg",
        animationDelay: `${-(i / STEP_COUNT) * FLOW_DURATION}s`,
      }}
    >
      <FootGlyph color={color} />
    </g>
  ));
  return (
    <>
      {forward}
      {backward}
    </>
  );
}

interface Props {
  edge: DiagramEdge;
  from: DiagramNode;
  to: DiagramNode;
  selected: boolean;
  editing: boolean;
  editValue: string;
  onEditValueChange: (v: string) => void;
  onEditCommit: () => void;
  onEditCancel: () => void;
  dim?: boolean;
  highlight?: boolean;
}

export const EdgeView = memo(function EdgeView({
  edge,
  from,
  to,
  selected,
  editing,
  editValue,
  onEditValueChange,
  onEditCommit,
  onEditCancel,
  dim,
  highlight,
}: Props) {
  const geom = curvedEdge(from, to, edge.curve);
  const d = geom.path;
  // Nudge the label off the handle dot (both sit at the curve's midpoint) when selected.
  const midX = geom.mid.x;
  const midY = selected && !editing ? geom.mid.y - 16 : geom.mid.y;
  const chipW = Math.max(28, (edge.label?.length ?? 0) * 6.5 + 14);
  const arrow = edge.arrow ?? "end";
  const lineStyle = edge.lineStyle ?? "solid";

  return (
    <g className="edgeg" data-id={edge.id} data-kind="edge" opacity={dim ? 0.22 : 1}>
      <path d={d} fill="none" stroke="transparent" strokeWidth={14} data-id={edge.id} data-kind="edge" />
      <path
        d={d}
        fill="none"
        stroke={highlight ? "var(--accent)" : selected ? "var(--accent)" : "var(--edge-dim)"}
        strokeWidth={highlight || selected ? 2.5 : 1.8}
        style={highlight ? { filter: "drop-shadow(0 0 4px var(--accent))" } : undefined}
        strokeDasharray={LINE_DASH[lineStyle]}
        strokeLinecap={lineStyle === "dotted" ? "round" : undefined}
        markerStart={arrow === "both" ? "url(#arrow)" : undefined}
        markerEnd={arrow === "end" || arrow === "both" ? "url(#arrow)" : undefined}
        data-id={edge.id}
        data-kind="edge"
      />
      {edge.animated && <FeetTrail d={d} selected={selected} direction={edge.flowDirection ?? "one"} />}
      {selected && !editing && (
        <circle
          className="edge-curve-handle"
          data-id={edge.id}
          data-kind="edge-curve"
          cx={geom.mid.x}
          cy={geom.mid.y}
          r={5}
          fill="var(--accent)"
          stroke="var(--panel)"
          strokeWidth={1.5}
          style={{ cursor: "move" }}
        />
      )}
      {editing ? (
        <foreignObject x={midX - chipW / 2} y={midY - 11} width={chipW} height={22}>
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
              borderRadius: 5,
              color: "var(--text)",
              font: "600 10.5px ui-sans-serif, system-ui, sans-serif",
              padding: "0 5px",
              textAlign: "center",
            }}
          />
        </foreignObject>
      ) : (
        edge.label && (
          <g data-id={edge.id} data-kind="edge" pointerEvents="none">
            <rect x={midX - chipW / 2} y={midY - 10} width={chipW} height={20} rx={5} fill="var(--panel)" stroke="var(--border2)" strokeWidth={1} />
            <text x={midX} y={midY + 4} textAnchor="middle" fill="var(--muted)" fontSize={10.5} fontWeight={600}>
              {edge.label}
            </text>
          </g>
        )
      )}
    </g>
  );
});
