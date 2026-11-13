import { useState } from "react";
import { useScenarioStore } from "../state/scenarioStore";
import { useConfirm } from "./ConfirmDialog";

export function ScenarioBar() {
  const scenarios = useScenarioStore((s) => s.scenarios);
  const current = useScenarioStore((s) => s.current);
  const subMode = useScenarioStore((s) => s.subMode);
  const setSubMode = useScenarioStore((s) => s.setSubMode);
  const newScenario = useScenarioStore((s) => s.newScenario);
  const selectScenario = useScenarioStore((s) => s.selectScenario);
  const deleteCurrentScenario = useScenarioStore((s) => s.deleteCurrentScenario);
  const error = useScenarioStore((s) => s.error);
  const clearError = useScenarioStore((s) => s.clearError);

  const [pickerOpen, setPickerOpen] = useState(false);
  const [nameDraft, setNameDraft] = useState("");
  const { confirm, confirmDialog } = useConfirm();

  function handleNew() {
    const name = nameDraft.trim() || "Untitled scenario";
    setNameDraft("");
    void newScenario(name);
    setPickerOpen(false);
  }

  return (
    <div id="scenariobar">
      <div className="tgroup" style={{ position: "relative" }}>
        <button onClick={() => setPickerOpen((v) => !v)} title="Scenarios">
          {current ? current.name : "Select scenario"}
        </button>
        {pickerOpen && (
          <div className="diagrams-panel">
            <div style={{ display: "flex", gap: 6, marginBottom: 6 }}>
              <input
                className="ifield-inline-input"
                placeholder="New scenario name"
                value={nameDraft}
                onChange={(e) => setNameDraft(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") handleNew();
                }}
                style={{
                  flex: 1,
                  font: "inherit",
                  fontSize: 12,
                  color: "var(--text)",
                  background: "var(--panel)",
                  border: "1px solid var(--border)",
                  borderRadius: 7,
                  padding: "6px 8px",
                }}
              />
              <button className="diagrams-new" style={{ margin: 0 }} onClick={handleNew}>
                + New
              </button>
            </div>
            <div className="diagrams-list">
              {scenarios.length === 0 && <div className="diagrams-empty">No scenarios for this diagram yet</div>}
              {scenarios.map((s) => (
                <div key={s.id} className={"diagrams-item" + (s.id === current?.id ? " active" : "")}>
                  <button
                    className="diagrams-open"
                    onClick={() => {
                      void selectScenario(s.id);
                      setPickerOpen(false);
                    }}
                  >
                    <span className="dname">{s.name}</span>
                    <span className="dtime">
                      {s.stepCount} step{s.stepCount === 1 ? "" : "s"}
                    </span>
                  </button>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
      {current && (
        <>
          <div className="tgroup">
            <button className={subMode === "builder" ? "active" : ""} onClick={() => setSubMode("builder")}>
              Builder
            </button>
            <button className={subMode === "player" ? "active" : ""} onClick={() => setSubMode("player")}>
              Player
            </button>
          </div>
          <div className="sep" />
          <div className="tgroup">
            <button
              onClick={() => {
                void confirm(`Delete scenario "${current.name}"? This cannot be undone.`).then((ok) => {
                  if (ok) void deleteCurrentScenario();
                });
              }}
              title="Delete scenario"
            >
              Delete
            </button>
          </div>
        </>
      )}
      <div className="spacer" />
      {error && (
        <div className="toast" style={{ position: "static" }} onClick={clearError}>
          {error}
        </div>
      )}
      {confirmDialog}
    </div>
  );
}
