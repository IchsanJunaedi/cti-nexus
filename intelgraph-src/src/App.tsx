import { useEffect } from "react";
import { TopBar } from "./components/TopBar";
import { ScenarioBar } from "./components/ScenarioBar";
import { Palette } from "./components/Palette";
import { Canvas } from "./components/Canvas";
import { Inspector } from "./components/Inspector";
import { ScenarioBuilder } from "./components/ScenarioBuilder";
import { ScenarioPlayerControls } from "./components/ScenarioPlayerControls";
import { useStore } from "./state/store";
import { useScenarioStore } from "./state/scenarioStore";
import { computeFitView, isContentVisible } from "./lib/viewport";

function App() {
  const booted = useStore((s) => s.booted);
  const boot = useStore((s) => s.boot);
  const currentId = useStore((s) => s.currentId);
  const scenarioMode = useScenarioStore((s) => s.mode);
  const subMode = useScenarioStore((s) => s.subMode);

  useEffect(() => {
    void boot();
  }, [boot]);

  // Saved pan/zoom can land outside the current window (resized/rotated/different
  // screen since last save). If the diagram would open with nothing on screen,
  // silently re-fit instead of leaving the user staring at an empty canvas.
  useEffect(() => {
    if (!booted) return;
    const reconcile = () => {
      const svg = document.getElementById("canvas") as SVGSVGElement | null;
      if (!svg) return;
      const w = svg.clientWidth;
      const h = svg.clientHeight;
      if (w === 0 || h === 0) return;
      const { nodes, zones, view, setView } = useStore.getState();
      if (!isContentVisible(nodes, zones, view, w, h)) {
        setView(computeFitView(nodes, zones, w, h));
      }
    };
    reconcile();
    window.addEventListener("resize", reconcile);
    return () => window.removeEventListener("resize", reconcile);
  }, [booted, currentId]);

  if (!booted) {
    return <div id="app" />;
  }

  const inScenario = scenarioMode === "scenario";

  return (
    <div id="app">
      <TopBar />
      {inScenario && <ScenarioBar />}
      <div id="main">
        <Palette />
        <div id="canvasWrap" style={{ display: "flex", flexDirection: "column" }}>
          <div style={{ flex: 1, minHeight: 0, position: "relative" }}>
            <Canvas />
          </div>
          {inScenario && subMode === "player" && <ScenarioPlayerControls />}
        </div>
        {inScenario && subMode === "builder" ? <ScenarioBuilder /> : <Inspector />}
      </div>
    </div>
  );
}

export default App;
