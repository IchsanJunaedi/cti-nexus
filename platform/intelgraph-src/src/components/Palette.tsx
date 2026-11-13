import { PALETTE_GROUPS, NODE_TYPE_MAP } from "../constants/nodeTypes";
import { NodeIconGlyph } from "./NodeIcon";
import { useStore } from "../state/store";

export function Palette() {
  const addNode = useStore((s) => s.addNode);

  function handleAdd(type: (typeof PALETTE_GROUPS)[number]["items"][number]) {
    const svg = document.getElementById("canvas") as SVGSVGElement | null;
    const w = svg?.clientWidth ?? 800;
    const h = svg?.clientHeight ?? 600;
    const view = useStore.getState().view;
    const cx = (w / 2 - view.x) / view.k;
    const cy = (h / 2 - view.y) / view.k;
    addNode(type, cx, cy);
  }

  return (
    <div id="palette">
      {PALETTE_GROUPS.map((group) => (
        <div key={group.title}>
          <h3>{group.title}</h3>
          <div className="pitems">
            {group.items.map((id) => {
              const t = NODE_TYPE_MAP[id];
              return (
                <div
                  key={id}
                  className="pitem"
                  draggable
                  onDragStart={(e) => {
                    e.dataTransfer.setData("application/x-netdraw-type", t.id);
                    e.dataTransfer.effectAllowed = "copy";
                  }}
                  onClick={() => handleAdd(id)}
                  title={t.label}
                >
                  <div className="pic" style={{ background: t.accent + "1a" }}>
                    <svg
                      width={22}
                      height={22}
                      viewBox="0 0 24 24"
                      fill="none"
                      stroke={t.accent}
                      strokeWidth={1.6}
                      strokeLinecap="round"
                      strokeLinejoin="round"
                    >
                      <NodeIconGlyph type={t.id} />
                    </svg>
                  </div>
                  <span className="pname">{t.label}</span>
                </div>
              );
            })}
          </div>
        </div>
      ))}
      <div className="hint">Drag onto canvas, or click to drop at center.</div>
    </div>
  );
}
