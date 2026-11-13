import { useEffect, useRef, useState } from "react";
import { useStore } from "../state/store";
import { useScenarioStore } from "../state/scenarioStore";
import { exportPngFile, exportSvgFile } from "../lib/exportSvg";
import { downloadJSON, importJSONFile } from "../lib/persist";
import { encodeDoc } from "../lib/share";
import { getUserInfo } from "../lib/authToken";
import { useConfirm } from "./ConfirmDialog";
import { MIN_K, MAX_K, computeFitView } from "../lib/viewport";

const me = getUserInfo();
const privileged = me?.role === "admin" || me?.role === "superadmin";

function canDelete(owner: string | undefined): boolean {
  if (privileged) return true;
  if (!owner) return true; // not synced yet / ownership unknown — local record, safe to allow
  return !me || owner === me.username;
}

const SHARE_URL_WARN_LEN = 30000;

export function TopBar() {
  const tool = useStore((s) => s.tool);
  const setTool = useStore((s) => s.setTool);
  const view = useStore((s) => s.view);
  const setView = useStore((s) => s.setView);
  const undo = useStore((s) => s.undo);
  const redo = useStore((s) => s.redo);
  const past = useStore((s) => s.past);
  const future = useStore((s) => s.future);
  const nodes = useStore((s) => s.nodes);
  const edges = useStore((s) => s.edges);
  const zones = useStore((s) => s.zones);
  const loadDoc = useStore((s) => s.loadDoc);
  const snap = useStore((s) => s.snap);
  const setSnap = useStore((s) => s.setSnap);
  const duplicateSelection = useStore((s) => s.duplicateSelection);
  const selectedNodeIds = useStore((s) => s.selectedNodeIds);
  const theme = useStore((s) => s.theme);
  const setTheme = useStore((s) => s.setTheme);

  const diagramName = useStore((s) => s.diagramName);
  const renameDiagram = useStore((s) => s.renameDiagram);
  const currentId = useStore((s) => s.currentId);
  const diagrams = useStore((s) => s.diagrams);
  const newDiagram = useStore((s) => s.newDiagram);
  const openDiagram = useStore((s) => s.openDiagram);
  const removeDiagram = useStore((s) => s.removeDiagram);
  const persistError = useStore((s) => s.persistError);
  const clearPersistError = useStore((s) => s.clearPersistError);

  const scenarioMode = useScenarioStore((s) => s.mode);
  const setScenarioMode = useScenarioStore((s) => s.setMode);

  const fileInputRef = useRef<HTMLInputElement>(null);
  const [nameDraft, setNameDraft] = useState(diagramName);
  const [diagramsOpen, setDiagramsOpen] = useState(false);
  const [toast, setToast] = useState<string | null>(null);
  const { confirm, confirmDialog } = useConfirm();

  useEffect(() => {
    setNameDraft(diagramName);
  }, [currentId, diagramName]);

  function showToast(msg: string) {
    setToast(msg);
    setTimeout(() => setToast(null), 3500);
  }

  function getSvg(): SVGSVGElement | null {
    return document.getElementById("canvas") as SVGSVGElement | null;
  }

  function zoomBy(factor: number) {
    const newK = Math.min(MAX_K, Math.max(MIN_K, view.k * factor));
    setView({ ...view, k: newK });
  }

  function zoomFit() {
    const svg = getSvg();
    const w = svg?.clientWidth ?? 800;
    const h = svg?.clientHeight ?? 600;
    setView(computeFitView(nodes, zones, w, h));
  }

  function handleSave() {
    downloadJSON({ state: { nodes, edges, zones }, view }, `${diagramName || "diagram"}.json`);
  }

  async function handleOpenFile(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    e.target.value = "";
    if (!file) return;
    try {
      const doc = await importJSONFile(file);
      loadDoc(doc.state, doc.view);
    } catch {
      alert("Could not read that file — not a valid IntelGraph JSON export.");
    }
  }

  async function handleShare() {
    const encoded = await encodeDoc({ nodes, edges, zones }, view);
    const url = `${location.origin}${location.pathname}#d=${encoded}`;
    if (url.length > SHARE_URL_WARN_LEN) {
      showToast("Diagram too large for a share link — use Save JSON instead.");
      return;
    }
    try {
      await navigator.clipboard.writeText(url);
      showToast("Link copied. Anyone with it can see this diagram's data in plaintext.");
    } catch {
      showToast("Could not copy link to clipboard.");
    }
  }

  function commitName() {
    const v = nameDraft.trim() || "Untitled";
    setNameDraft(v);
    if (v !== diagramName) renameDiagram(v);
  }

  return (
    <div id="topbar">
      <a id="backLink" href="/newsroom" title="Back to CTI Nexus">
        ← CTI Nexus
      </a>
      <div className="sep" />
      <div id="logo">IntelGraph</div>
      <input
        id="diagramNameInput"
        className="diagramName"
        value={nameDraft}
        onChange={(e) => setNameDraft(e.target.value)}
        onBlur={commitName}
        onKeyDown={(e) => {
          if (e.key === "Enter") (e.target as HTMLInputElement).blur();
        }}
        title="Diagram name"
      />
      <div className="tgroup" style={{ position: "relative" }}>
        <button onClick={() => setDiagramsOpen((v) => !v)} title="Diagrams">
          Diagrams
        </button>
        {diagramsOpen && (
          <div className="diagrams-panel">
            <button
              className="diagrams-new"
              onClick={() => {
                void newDiagram();
                setDiagramsOpen(false);
              }}
            >
              + New
            </button>
            <div className="diagrams-list">
              {diagrams.length === 0 && <div className="diagrams-empty">No diagrams yet</div>}
              {[...diagrams]
                .sort((a, b) => b.updatedAt - a.updatedAt)
                .map((d) => (
                  <div key={d.id} className={"diagrams-item" + (d.id === currentId ? " active" : "")}>
                    <button
                      className="diagrams-open"
                      onClick={() => {
                        void openDiagram(d.id);
                        setDiagramsOpen(false);
                      }}
                    >
                      <span className="dname">{d.name}</span>
                      <span className="dtime">{new Date(d.updatedAt).toLocaleString()}</span>
                    </button>
                    <button
                      className="diagrams-del"
                      disabled={!canDelete(d.owner)}
                      title={canDelete(d.owner) ? "Delete diagram" : "Only the owner or an admin can delete this diagram"}
                      onClick={() => {
                        void confirm(`Permanently delete diagram "${d.name}"? This cannot be undone.`).then((ok) => {
                          if (ok) void removeDiagram(d.id);
                        });
                      }}
                    >
                      ✕
                    </button>
                  </div>
                ))}
            </div>
          </div>
        )}
      </div>
      <div className="sep" />
      <div className="tgroup">
        <button className={scenarioMode === "diagram" ? "active" : ""} onClick={() => setScenarioMode("diagram")} title="Edit the diagram">
          Diagram
        </button>
        <button className={scenarioMode === "scenario" ? "active" : ""} onClick={() => setScenarioMode("scenario")} title="Build/play a scenario">
          Scenario
        </button>
      </div>
      <div className="sep" />
      <div className="tgroup">
        <button className={tool === "select" ? "active" : ""} onClick={() => setTool("select")} title="Select (V)">
          Select
        </button>
        <button className={tool === "connect" ? "active" : ""} onClick={() => setTool("connect")} title="Connect (C)">
          Connect
        </button>
        <button className={tool === "pan" ? "active" : ""} onClick={() => setTool("pan")} title="Pan">
          Pan
        </button>
        <button className={tool === "zone" ? "active" : ""} onClick={() => setTool("zone")} title="Draw zone (Z)">
          Zone
        </button>
      </div>
      <div className="sep" />
      <div className="tgroup">
        <button onClick={undo} disabled={past.length === 0} title="Undo">
          Undo
        </button>
        <button onClick={redo} disabled={future.length === 0} title="Redo">
          Redo
        </button>
      </div>
      <div className="sep" />
      <div className="tgroup">
        <button onClick={() => zoomBy(1 / 1.2)} title="Zoom out">
          −
        </button>
        <span id="zoomPct">{Math.round(view.k * 100)}%</span>
        <button onClick={() => zoomBy(1.2)} title="Zoom in">
          +
        </button>
        <button onClick={zoomFit} title="Fit to content">
          Fit
        </button>
      </div>
      <div className="sep" />
      <div className="tgroup">
        <button className={snap ? "active" : ""} onClick={() => setSnap(!snap)} title="On: snap to 20px grid. Off: magnetic snap to other nodes/zones (hold Alt while dragging to bypass).">
          Snap
        </button>
        <button onClick={() => duplicateSelection()} disabled={selectedNodeIds.length === 0} title="Duplicate selection (Ctrl/Cmd+D)">
          Duplicate
        </button>
        <button onClick={() => setTheme(theme === "dark" ? "light" : "dark")} title="Toggle light / dark theme">
          {theme === "dark" ? "Light" : "Dark"}
        </button>
      </div>
      <div className="spacer" />
      {toast && <div className="toast">{toast}</div>}
      {persistError && (
        <div className="toast" onClick={clearPersistError} title="Dismiss">
          {persistError}
        </div>
      )}
      <div className="tgroup">
        <button onClick={() => void handleShare()} title="Copy shareable link">
          Share
        </button>
        <button onClick={() => getSvg() && exportPngFile(getSvg()!)} title="Export PNG">
          PNG
        </button>
        <button onClick={() => getSvg() && exportSvgFile(getSvg()!)} title="Export SVG">
          SVG
        </button>
      </div>
      <div className="sep" />
      <div className="tgroup">
        <button onClick={handleSave} title="Save diagram as JSON">
          Save
        </button>
        <button onClick={() => fileInputRef.current?.click()} title="Open diagram JSON">
          Open
        </button>
        <input ref={fileInputRef} type="file" accept="application/json" hidden onChange={handleOpenFile} />
      </div>
      {confirmDialog}
    </div>
  );
}
