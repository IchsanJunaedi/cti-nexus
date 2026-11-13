import { memo } from "react";
import type { Zone } from "../types";

interface Props {
  zone: Zone;
  selected: boolean;
  editing: boolean;
  editValue: string;
  onEditValueChange: (v: string) => void;
  onEditCommit: () => void;
  onEditCancel: () => void;
}

const HANDLE_SIZE = 8;
const ZONE_CORNERS = ["nw", "ne", "sw", "se"] as const;

function handlePos(z: Zone, corner: (typeof ZONE_CORNERS)[number]) {
  switch (corner) {
    case "nw":
      return { x: z.x, y: z.y };
    case "ne":
      return { x: z.x + z.w, y: z.y };
    case "sw":
      return { x: z.x, y: z.y + z.h };
    case "se":
      return { x: z.x + z.w, y: z.y + z.h };
  }
}

export const ZoneView = memo(function ZoneView({
  zone,
  selected,
  editing,
  editValue,
  onEditValueChange,
  onEditCommit,
  onEditCancel,
}: Props) {
  const midX = zone.x + zone.w / 2;
  const chipW = Math.max(50, zone.label.length * 7 + 20);

  return (
    <g className="zoneg" data-id={zone.id} data-kind="zone">
      <rect
        x={zone.x}
        y={zone.y}
        width={zone.w}
        height={zone.h}
        rx={10}
        fill={zone.color + "14"}
        stroke={zone.color}
        strokeWidth={selected ? 2.5 : 1.5}
        strokeDasharray="6 4"
        data-id={zone.id}
        data-kind="zone"
      />
      {editing ? (
        <foreignObject x={midX - Math.max(60, zone.w - 20) / 2} y={zone.y - 12} width={Math.max(60, zone.w - 20)} height={24}>
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
              background: "var(--bg)",
              border: `1px solid ${zone.color}`,
              borderRadius: 6,
              color: "var(--text)",
              font: "700 12px ui-sans-serif, system-ui, sans-serif",
              padding: "0 6px",
              textAlign: "center",
            }}
          />
        </foreignObject>
      ) : (
        <g data-id={zone.id} data-kind="zone-label">
          <rect
            x={midX - chipW / 2}
            y={zone.y - 9}
            width={chipW}
            height={18}
            rx={9}
            fill="var(--bg)"
            stroke={zone.color}
            strokeWidth={1.3}
            data-id={zone.id}
            data-kind="zone-label"
          />
          <text
            x={midX}
            y={zone.y + 4}
            textAnchor="middle"
            fill={zone.color}
            fontSize={12}
            fontWeight={700}
            data-id={zone.id}
            data-kind="zone-label"
          >
            {zone.label}
          </text>
        </g>
      )}
      {selected &&
        ZONE_CORNERS.map((corner) => {
          const p = handlePos(zone, corner);
          const cursor = corner === "nw" || corner === "se" ? "nwse-resize" : "nesw-resize";
          return (
            <rect
              key={corner}
              className="zone-handle"
              data-id={zone.id}
              data-kind="zone-handle"
              data-corner={corner}
              x={p.x - HANDLE_SIZE / 2}
              y={p.y - HANDLE_SIZE / 2}
              width={HANDLE_SIZE}
              height={HANDLE_SIZE}
              rx={2}
              fill="var(--panel)"
              stroke={zone.color}
              strokeWidth={2}
              style={{ cursor }}
            />
          );
        })}
    </g>
  );
});
