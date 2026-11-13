import { useState } from "react";
import { useScenarioStore } from "../state/scenarioStore";
import { useStore } from "../state/store";

/** Local-state note editor. Keyed by step id so it reseeds only when the step changes,
 * never when the store round-trips a save — that async replace used to eat in-flight keystrokes. */
function StepNote({ initial, onChange }: { initial: string; onChange: (v: string) => void }) {
  const [value, setValue] = useState(initial);
  return (
    <textarea
      rows={2}
      value={value}
      onClick={(e) => e.stopPropagation()}
      onChange={(e) => {
        setValue(e.target.value);
        onChange(e.target.value);
      }}
      placeholder="What happens in this step…"
    />
  );
}

export function ScenarioBuilder() {
  const current = useScenarioStore((s) => s.current);
  const activeStepIndex = useScenarioStore((s) => s.activeStepIndex);
  const setActiveStepIndex = useScenarioStore((s) => s.setActiveStepIndex);
  const addStep = useScenarioStore((s) => s.addStep);
  const removeStep = useScenarioStore((s) => s.removeStep);
  const moveStep = useScenarioStore((s) => s.moveStep);
  const updateStepNote = useScenarioStore((s) => s.updateStepNote);
  const captureSelectionIntoStep = useScenarioStore((s) => s.captureSelectionIntoStep);
  const setSelection = useStore((s) => s.setSelection);

  if (!current) {
    return (
      <div id="inspector">
        <div className="inspector-empty">Create or select a scenario to start building steps.</div>
      </div>
    );
  }

  return (
    <div id="inspector">
      <div className="inspector-body">
        <h3>Scenario Steps</h3>
        {current.steps.length === 0 && <div className="inspector-empty">No steps yet.</div>}
        {current.steps.map((step, i) => (
          <div
            key={step.id}
            className="step-card"
            style={{
              border: "1px solid " + (activeStepIndex === i ? "var(--accent)" : "var(--border)"),
              borderRadius: 8,
              padding: 10,
              marginBottom: 10,
              background: "var(--panel2)",
              cursor: "pointer",
            }}
            onClick={() => {
              setActiveStepIndex(i);
              setSelection(step.nodeIds, step.edgeIds);
            }}
          >
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
              <span style={{ fontSize: 11, fontWeight: 700, color: "var(--accent)" }}>STEP {i + 1}</span>
              <div style={{ display: "flex", gap: 2 }}>
                <button
                  disabled={i === 0}
                  onClick={(e) => {
                    e.stopPropagation();
                    moveStep(i, -1);
                  }}
                  title="Move up"
                >
                  ↑
                </button>
                <button
                  disabled={i === current.steps.length - 1}
                  onClick={(e) => {
                    e.stopPropagation();
                    moveStep(i, 1);
                  }}
                  title="Move down"
                >
                  ↓
                </button>
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    removeStep(i);
                  }}
                  title="Delete step"
                >
                  ✕
                </button>
              </div>
            </div>
            <div className="ifield">
              <span>Note</span>
              <StepNote key={step.id} initial={step.note} onChange={(v) => updateStepNote(i, v)} />
            </div>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <span style={{ fontSize: 11, color: "var(--muted)" }}>
                {step.nodeIds.length} node{step.nodeIds.length === 1 ? "" : "s"}, {step.edgeIds.length} edge
                {step.edgeIds.length === 1 ? "" : "s"}
              </span>
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  captureSelectionIntoStep(i);
                }}
                title="Use the canvas' current selection for this step"
              >
                Capture selection
              </button>
            </div>
          </div>
        ))}
        <button onClick={addStep} style={{ width: "100%", justifyContent: "center", background: "#1d3a5c", color: "var(--accent)" }}>
          + Add Step
        </button>
      </div>
    </div>
  );
}
