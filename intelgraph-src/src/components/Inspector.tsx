import { useEffect, useState } from "react";
import { useStore } from "../state/store";
import { DISPOSITIONS, isOwnableType, isPlaceType, isTechnicalType, NODE_TYPE_MAP, STATUSES, ZONE_COLORS } from "../constants/nodeTypes";
import type { DiagramEdge, DiagramNode, Zone } from "../types";

function OrderControls({ onReorder }: { onReorder: (to: "front" | "back" | "forward" | "backward") => void }) {
  return (
    <label className="ifield">
      <span>Order</span>
      <div className="order-controls">
        <button type="button" title="Bring to Front" onClick={() => onReorder("front")}>
          To Front
        </button>
        <button type="button" title="Bring Forward" onClick={() => onReorder("forward")}>
          Forward
        </button>
        <button type="button" title="Send Backward" onClick={() => onReorder("backward")}>
          Backward
        </button>
        <button type="button" title="Send to Back" onClick={() => onReorder("back")}>
          To Back
        </button>
      </div>
    </label>
  );
}

export function Inspector() {
  const nodes = useStore((s) => s.nodes);
  const edges = useStore((s) => s.edges);
  const zones = useStore((s) => s.zones);
  const selectedNodeIds = useStore((s) => s.selectedNodeIds);
  const selectedEdgeIds = useStore((s) => s.selectedEdgeIds);
  const selectedZoneIds = useStore((s) => s.selectedZoneIds);
  const updateNode = useStore((s) => s.updateNode);
  const updateEdge = useStore((s) => s.updateEdge);
  const updateZone = useStore((s) => s.updateZone);
  const reorderNode = useStore((s) => s.reorderNode);
  const reorderEdge = useStore((s) => s.reorderEdge);

  const node =
    selectedNodeIds.length === 1 && selectedEdgeIds.length === 0 && selectedZoneIds.length === 0
      ? nodes.find((n) => n.id === selectedNodeIds[0])
      : null;
  const edge =
    selectedEdgeIds.length === 1 && selectedNodeIds.length === 0 && selectedZoneIds.length === 0
      ? edges.find((e) => e.id === selectedEdgeIds[0])
      : null;
  const zone =
    selectedZoneIds.length === 1 && selectedNodeIds.length === 0 && selectedEdgeIds.length === 0
      ? zones.find((z) => z.id === selectedZoneIds[0])
      : null;

  return (
    <div id="inspector">
      {node ? (
        <NodeFields key={node.id} node={node} updateNode={updateNode} onReorder={(to) => reorderNode(node.id, to)} />
      ) : edge ? (
        <EdgeFields key={edge.id} edge={edge} updateEdge={updateEdge} onReorder={(to) => reorderEdge(edge.id, to)} />
      ) : zone ? (
        <ZoneFields key={zone.id} zone={zone} updateZone={updateZone} />
      ) : (
        <div className="inspector-empty">Select an item</div>
      )}
    </div>
  );
}

function NodeFields({
  node,
  updateNode,
  onReorder,
}: {
  node: DiagramNode;
  updateNode: (id: string, patch: Partial<DiagramNode>) => void;
  onReorder: (to: "front" | "back" | "forward" | "backward") => void;
}) {
  const [label, setLabel] = useState(node.label);
  const [ip, setIp] = useState(node.meta?.ip ?? "");
  const [hostname, setHostname] = useState(node.meta?.hostname ?? "");
  const [owner, setOwner] = useState(node.meta?.owner ?? "");
  const [address, setAddress] = useState(node.meta?.address ?? "");
  const [coords, setCoords] = useState(node.meta?.coords ?? "");
  const [notes, setNotes] = useState(node.meta?.notes ?? "");
  const ownable = isOwnableType(node.type);
  const technical = isTechnicalType(node.type);
  const place = isPlaceType(node.type);

  useEffect(() => {
    setLabel(node.label);
    setIp(node.meta?.ip ?? "");
    setHostname(node.meta?.hostname ?? "");
    setOwner(node.meta?.owner ?? "");
    setAddress(node.meta?.address ?? "");
    setCoords(node.meta?.coords ?? "");
    setNotes(node.meta?.notes ?? "");
  }, [node.id, node.label, node.meta?.ip, node.meta?.hostname, node.meta?.owner, node.meta?.address, node.meta?.coords, node.meta?.notes]);

  function commitLabel() {
    if (label !== node.label) updateNode(node.id, { label: label.trim() || "Untitled" });
  }
  function commitMeta() {
    updateNode(node.id, {
      meta: {
        ip: technical ? ip : undefined,
        hostname: technical ? hostname : undefined,
        owner: ownable ? owner : undefined,
        address: place ? address : undefined,
        coords: place ? coords : undefined,
        notes,
      },
    });
  }

  return (
    <div className="inspector-body">
      <h3>Node</h3>
      <label className="ifield">
        <span>Type</span>
        <input value={NODE_TYPE_MAP[node.type]?.label ?? node.type} disabled />
      </label>
      <label className="ifield">
        <span>Label</span>
        <input
          value={label}
          onChange={(e) => setLabel(e.target.value)}
          onBlur={commitLabel}
          onKeyDown={(e) => {
            if (e.key === "Enter") (e.target as HTMLInputElement).blur();
          }}
        />
      </label>
      <label className="ifield">
        <span>Disposition</span>
        <div className="pill-select">
          {DISPOSITIONS.map((d) => {
            const active = node.disposition === d.id;
            return (
              <button
                key={d.id}
                type="button"
                className={"pill" + (active ? " active" : "")}
                style={{ ["--pill-color" as string]: d.color }}
                onClick={() => updateNode(node.id, { disposition: active ? undefined : d.id })}
              >
                {d.label}
              </button>
            );
          })}
        </div>
      </label>
      <label className="ifield">
        <span>Status (multi-select)</span>
        <div className="pill-select">
          {STATUSES.map((s) => {
            const current = node.status ?? [];
            const active = current.includes(s.id);
            return (
              <button
                key={s.id}
                type="button"
                className={"pill" + (active ? " active" : "")}
                style={{ ["--pill-color" as string]: s.color }}
                onClick={() =>
                  updateNode(node.id, {
                    status: active ? current.filter((id) => id !== s.id) : [...current, s.id],
                  })
                }
              >
                {s.label}
              </button>
            );
          })}
        </div>
      </label>
      {technical && (
        <>
          <label className="ifield">
            <span>IP address</span>
            <input value={ip} onChange={(e) => setIp(e.target.value)} onBlur={commitMeta} onKeyDown={(e) => e.key === "Enter" && (e.target as HTMLInputElement).blur()} />
          </label>
          <label className="ifield">
            <span>Hostname</span>
            <input value={hostname} onChange={(e) => setHostname(e.target.value)} onBlur={commitMeta} onKeyDown={(e) => e.key === "Enter" && (e.target as HTMLInputElement).blur()} />
          </label>
        </>
      )}
      {place && (
        <>
          <label className="ifield">
            <span>Address</span>
            <input
              value={address}
              placeholder="Address"
              onChange={(e) => setAddress(e.target.value)}
              onBlur={commitMeta}
              onKeyDown={(e) => e.key === "Enter" && (e.target as HTMLInputElement).blur()}
            />
          </label>
          <label className="ifield">
            <span>Coordinates</span>
            <input
              value={coords}
              placeholder="Coordinate"
              onChange={(e) => setCoords(e.target.value)}
              onBlur={commitMeta}
              onKeyDown={(e) => e.key === "Enter" && (e.target as HTMLInputElement).blur()}
            />
          </label>
        </>
      )}
      {ownable && (
        <label className="ifield">
          <span>Owner / User</span>
          <input value={owner} onChange={(e) => setOwner(e.target.value)} onBlur={commitMeta} onKeyDown={(e) => e.key === "Enter" && (e.target as HTMLInputElement).blur()} />
        </label>
      )}
      <label className="ifield">
        <span>Notes</span>
        <textarea value={notes} onChange={(e) => setNotes(e.target.value)} onBlur={commitMeta} rows={5} />
      </label>
      <OrderControls onReorder={onReorder} />
    </div>
  );
}

function EdgeFields({
  edge,
  updateEdge,
  onReorder,
}: {
  edge: DiagramEdge;
  updateEdge: (id: string, patch: Partial<DiagramEdge>) => void;
  onReorder: (to: "front" | "back" | "forward" | "backward") => void;
}) {
  const [label, setLabel] = useState(edge.label ?? "");

  useEffect(() => {
    setLabel(edge.label ?? "");
  }, [edge.id, edge.label]);

  function commit() {
    if (label !== (edge.label ?? "")) updateEdge(edge.id, { label });
  }

  return (
    <div className="inspector-body">
      <h3>Edge</h3>
      <label className="ifield">
        <span>Label</span>
        <input
          value={label}
          onChange={(e) => setLabel(e.target.value)}
          onBlur={commit}
          onKeyDown={(e) => {
            if (e.key === "Enter") (e.target as HTMLInputElement).blur();
          }}
        />
      </label>
      <label className="ifield">
        <span>Line style</span>
        <select
          value={edge.lineStyle ?? "solid"}
          onChange={(e) => updateEdge(edge.id, { lineStyle: e.target.value as DiagramEdge["lineStyle"] })}
        >
          <option value="solid">Solid</option>
          <option value="dashed">Dashed</option>
          <option value="dotted">Dotted</option>
          <option value="sneakernet">Sneakernet</option>
        </select>
      </label>
      <label className="ifield">
        <span>Arrow</span>
        <select
          value={edge.arrow ?? "end"}
          onChange={(e) => updateEdge(edge.id, { arrow: e.target.value as DiagramEdge["arrow"] })}
        >
          <option value="none">None</option>
          <option value="end">One-way (→)</option>
          <option value="both">Two-way (↔)</option>
        </select>
      </label>
      <label className="ifield">
        <span>Animate flow</span>
        <select
          value={edge.animated ? (edge.flowDirection ?? "one") : "off"}
          onChange={(e) => {
            const v = e.target.value;
            if (v === "off") updateEdge(edge.id, { animated: false });
            else updateEdge(edge.id, { animated: true, flowDirection: v as DiagramEdge["flowDirection"] });
          }}
        >
          <option value="off">Off</option>
          <option value="one">One-way flow</option>
          <option value="both">Both-way flow</option>
        </select>
      </label>
      <OrderControls onReorder={onReorder} />
    </div>
  );
}

function ZoneFields({
  zone,
  updateZone,
}: {
  zone: Zone;
  updateZone: (id: string, patch: Partial<Zone>) => void;
}) {
  const [label, setLabel] = useState(zone.label);

  useEffect(() => {
    setLabel(zone.label);
  }, [zone.id, zone.label]);

  function commit() {
    if (label !== zone.label) updateZone(zone.id, { label: label.trim() || "Zone" });
  }

  return (
    <div className="inspector-body">
      <h3>Zone</h3>
      <label className="ifield">
        <span>Label</span>
        <input
          value={label}
          onChange={(e) => setLabel(e.target.value)}
          onBlur={commit}
          onKeyDown={(e) => {
            if (e.key === "Enter") (e.target as HTMLInputElement).blur();
          }}
        />
      </label>
      <label className="ifield">
        <span>Color</span>
        <div className="swatches">
          {ZONE_COLORS.map((c) => (
            <button
              key={c}
              className={"swatch" + (zone.color === c ? " active" : "")}
              style={{ background: c }}
              title={c}
              onClick={() => updateZone(zone.id, { color: c })}
            />
          ))}
          <input
            type="color"
            className="swatch-custom"
            value={zone.color}
            onChange={(e) => updateZone(zone.id, { color: e.target.value })}
            title="Custom color"
          />
        </div>
      </label>
    </div>
  );
}
