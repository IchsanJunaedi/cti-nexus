import { useScenarioStore } from "../state/scenarioStore";

export function ScenarioPlayerControls() {
  const current = useScenarioStore((s) => s.current);
  const playIndex = useScenarioStore((s) => s.playIndex);
  const playing = useScenarioStore((s) => s.playing);
  const cumulative = useScenarioStore((s) => s.cumulative);
  const playIntervalMs = useScenarioStore((s) => s.playIntervalMs);
  const play = useScenarioStore((s) => s.play);
  const pause = useScenarioStore((s) => s.pause);
  const next = useScenarioStore((s) => s.next);
  const prev = useScenarioStore((s) => s.prev);
  const setCumulative = useScenarioStore((s) => s.setCumulative);
  const setPlayIntervalMs = useScenarioStore((s) => s.setPlayIntervalMs);

  if (!current) return null;

  const total = current.steps.length;

  return (
    <div id="playerbar">
      <button onClick={prev} disabled={total === 0 || playIndex === 0} title="Previous step">
        ◀ Prev
      </button>
      <button className={playing ? "active" : ""} onClick={() => (playing ? pause() : play())} disabled={total === 0}>
        {playing ? "⏸ Pause" : "▶ Play"}
      </button>
      <button onClick={next} disabled={total === 0 || playIndex >= total - 1} title="Next step">
        Next ▶
      </button>
      <span className="player-progress">
        Step {total === 0 ? 0 : playIndex + 1}/{total}
      </span>
      <select value={playIntervalMs} onChange={(e) => setPlayIntervalMs(Number(e.target.value))}>
        <option value={1000}>1s</option>
        <option value={2000}>2s</option>
        <option value={3000}>3s</option>
      </select>
      <label style={{ display: "flex", alignItems: "center", gap: 5, fontSize: 11, color: "var(--muted)" }}>
        <input type="checkbox" checked={cumulative} onChange={(e) => setCumulative(e.target.checked)} />
        Cumulative
      </label>
    </div>
  );
}
