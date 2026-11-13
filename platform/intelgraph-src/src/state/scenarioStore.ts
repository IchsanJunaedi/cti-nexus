import { create } from "zustand";
import type { Scenario, ScenarioStep, ScenarioSummary } from "../types";
import { uid } from "../lib/id";
import { useStore } from "./store";
import { deleteCachedScenario, getCachedScenario, putCachedScenario } from "../lib/db";
import {
  createScenario as apiCreateScenario,
  deleteScenario as apiDeleteScenario,
  getScenario as apiGetScenario,
  listScenarios as apiListScenarios,
  replaceSteps as apiReplaceSteps,
  ScenarioAuthError,
} from "../lib/scenarioApi";

const STEP_SAVE_DEBOUNCE_MS = 300;
const DEFAULT_PLAY_INTERVAL_MS = 2000;

export type ScenarioMode = "diagram" | "scenario";
export type ScenarioSubMode = "builder" | "player";

interface ScenarioStore {
  mode: ScenarioMode;
  subMode: ScenarioSubMode;
  scenarios: ScenarioSummary[];
  current: Scenario | null;
  activeStepIndex: number;
  playIndex: number;
  playing: boolean;
  cumulative: boolean;
  playIntervalMs: number;
  error: string | null;

  setMode: (m: ScenarioMode) => void;
  setSubMode: (m: ScenarioSubMode) => void;
  clearError: () => void;

  refreshScenarios: () => Promise<void>;
  newScenario: (name: string) => Promise<void>;
  selectScenario: (id: string) => Promise<void>;
  deleteCurrentScenario: () => Promise<void>;

  setActiveStepIndex: (i: number) => void;
  addStep: () => void;
  removeStep: (i: number) => void;
  moveStep: (i: number, dir: 1 | -1) => void;
  updateStepNote: (i: number, note: string) => void;
  captureSelectionIntoStep: (i: number) => void;

  play: () => void;
  pause: () => void;
  next: () => void;
  prev: () => void;
  setPlayIndex: (i: number) => void;
  setCumulative: (v: boolean) => void;
  setPlayIntervalMs: (ms: number) => void;
}

function diagramId(): string {
  return useStore.getState().currentId ?? "";
}

/** Locally-created scenarios get a "s_"-prefixed id before they've synced to the backend;
 * Mongo-assigned ids never look like that. */
function isRemoteScenarioId(id: string): boolean {
  return !id.startsWith("s_");
}

const OFFLINE_MSG = "Backend unreachable — scenario saved locally, will sync when it's back.";

function reportError(e: unknown, fallback = "Scenario request failed. Try again.") {
  if (e instanceof ScenarioAuthError) {
    useScenarioStore.setState({ error: e.message });
  } else {
    useScenarioStore.setState({ error: fallback });
  }
}

let stepSaveTimer: ReturnType<typeof setTimeout> | null = null;

function scheduleStepSave() {
  if (stepSaveTimer) clearTimeout(stepSaveTimer);
  stepSaveTimer = setTimeout(() => {
    stepSaveTimer = null;
    const { current } = useScenarioStore.getState();
    if (!current) return;

    if (!isRemoteScenarioId(current.id)) {
      // never synced yet — retry create (with the current steps) to get a real id
      const oldId = current.id;
      void apiCreateScenario(current.name, current.diagramId, current.description, current.steps)
        .then((created) => {
          // Keep whatever the user has typed since this save started; only adopt the
          // server-assigned id/metadata. Overwriting steps here would clobber in-flight edits.
          const latest = useScenarioStore.getState().current;
          const merged = latest && latest.id === oldId ? { ...created, steps: latest.steps } : created;
          useScenarioStore.setState({ current: merged, error: null });
          void putCachedScenario({ id: merged.id, scenario: merged, updatedAt: Date.now(), syncPending: false });
          void deleteCachedScenario(oldId);
          void useScenarioStore.getState().refreshScenarios();
        })
        .catch((e) => {
          void putCachedScenario({ id: oldId, scenario: current, updatedAt: Date.now(), syncPending: true });
          reportError(e, OFFLINE_MSG);
        });
      return;
    }

    void apiReplaceSteps(current.id, current.steps)
      .then((updated) => {
        // Preserve the freshest local steps — the user may have typed more characters while
        // this request was in flight. Adopt only the server's version/metadata, not its step echo.
        const latest = useScenarioStore.getState().current;
        const merged = latest && latest.id === updated.id ? { ...updated, steps: latest.steps } : updated;
        useScenarioStore.setState({ current: merged, error: null });
        void putCachedScenario({ id: merged.id, scenario: merged, updatedAt: Date.now(), syncPending: false });
      })
      .catch((e) => {
        void putCachedScenario({ id: current.id, scenario: current, updatedAt: Date.now(), syncPending: true });
        reportError(e, "Backend unreachable — steps saved locally, will sync when it's back.");
      });
  }, STEP_SAVE_DEBOUNCE_MS);
}

let playTimer: ReturnType<typeof setInterval> | null = null;

function stopPlayTimer() {
  if (playTimer) {
    clearInterval(playTimer);
    playTimer = null;
  }
}

export const useScenarioStore = create<ScenarioStore>((set, get) => ({
  mode: "diagram",
  subMode: "builder",
  scenarios: [],
  current: null,
  activeStepIndex: -1,
  playIndex: 0,
  playing: false,
  cumulative: true,
  playIntervalMs: DEFAULT_PLAY_INTERVAL_MS,
  error: null,

  setMode: (m) => {
    set({ mode: m });
    if (m === "scenario") void get().refreshScenarios();
    else {
      stopPlayTimer();
      set({ playing: false });
    }
  },

  setSubMode: (m) => {
    stopPlayTimer();
    set({ subMode: m, playing: false, playIndex: 0 });
  },

  clearError: () => set({ error: null }),

  refreshScenarios: async () => {
    const did = diagramId();
    if (!did) return;
    try {
      const scenarios = await apiListScenarios(did);
      set({ scenarios });
    } catch (e) {
      reportError(e);
    }
  },

  newScenario: async (name) => {
    const did = diagramId();
    if (!did) return;
    try {
      const scenario = await apiCreateScenario(name, did);
      await get().refreshScenarios();
      set({ current: scenario, activeStepIndex: -1, playIndex: 0, subMode: "builder", error: null });
      void putCachedScenario({ id: scenario.id, scenario, updatedAt: Date.now(), syncPending: false });
    } catch (e) {
      if (e instanceof ScenarioAuthError) {
        reportError(e);
        return;
      }
      // offline / backend down — local-only placeholder, synced on next step edit
      const now = new Date().toISOString();
      const scenario: Scenario = {
        id: uid("s_"),
        name,
        description: "",
        diagramId: did,
        steps: [],
        version: 1,
        createdAt: now,
        updatedAt: now,
      };
      await putCachedScenario({ id: scenario.id, scenario, updatedAt: Date.now(), syncPending: true });
      set({ current: scenario, activeStepIndex: -1, playIndex: 0, subMode: "builder", error: OFFLINE_MSG });
    }
  },

  selectScenario: async (id) => {
    try {
      const scenario = await apiGetScenario(id);
      set({ current: scenario, activeStepIndex: -1, playIndex: 0, subMode: "builder", error: null });
      void putCachedScenario({ id: scenario.id, scenario, updatedAt: Date.now(), syncPending: false });
    } catch (e) {
      const cached = await getCachedScenario(id);
      if (cached) {
        set({ current: cached.scenario, activeStepIndex: -1, playIndex: 0, subMode: "builder" });
        set({ error: "Showing a locally cached copy — backend unreachable, edits will sync once it's back." });
      } else {
        reportError(e);
      }
    }
  },

  deleteCurrentScenario: async () => {
    const { current } = get();
    if (!current) return;
    if (!isRemoteScenarioId(current.id)) {
      // never synced — safe to drop purely locally, backend has never heard of it
      void deleteCachedScenario(current.id);
      set({ current: null, activeStepIndex: -1, playIndex: 0, error: null });
      return;
    }
    try {
      await apiDeleteScenario(current.id);
      void deleteCachedScenario(current.id);
      set({ current: null, activeStepIndex: -1, playIndex: 0, error: null });
      await get().refreshScenarios();
    } catch (e) {
      reportError(e);
    }
  },

  setActiveStepIndex: (i) => set({ activeStepIndex: i }),

  addStep: () => {
    const { current } = get();
    if (!current) return;
    const step: ScenarioStep = {
      id: uid("st_"),
      order: current.steps.length,
      note: "",
      nodeIds: [],
      edgeIds: [],
      createdAt: new Date().toISOString(),
    };
    const steps = [...current.steps, step];
    set({ current: { ...current, steps }, activeStepIndex: steps.length - 1 });
    scheduleStepSave();
  },

  removeStep: (i) => {
    const { current } = get();
    if (!current) return;
    const steps = current.steps.filter((_, idx) => idx !== i).map((s, idx) => ({ ...s, order: idx }));
    set({ current: { ...current, steps }, activeStepIndex: -1 });
    scheduleStepSave();
  },

  moveStep: (i, dir) => {
    const { current } = get();
    if (!current) return;
    const j = i + dir;
    if (j < 0 || j >= current.steps.length) return;
    const steps = [...current.steps];
    [steps[i], steps[j]] = [steps[j], steps[i]];
    steps.forEach((s, idx) => (s.order = idx));
    set({ current: { ...current, steps }, activeStepIndex: j });
    scheduleStepSave();
  },

  updateStepNote: (i, note) => {
    const { current } = get();
    if (!current) return;
    const steps = current.steps.map((s, idx) => (idx === i ? { ...s, note } : s));
    set({ current: { ...current, steps } });
    scheduleStepSave();
  },

  captureSelectionIntoStep: (i) => {
    const { current } = get();
    if (!current) return;
    const { selectedNodeIds, selectedEdgeIds } = useStore.getState();
    const steps = current.steps.map((s, idx) =>
      idx === i ? { ...s, nodeIds: [...selectedNodeIds], edgeIds: [...selectedEdgeIds] } : s
    );
    set({ current: { ...current, steps } });
    scheduleStepSave();
  },

  play: () => {
    const { current, cumulative, playIntervalMs } = get();
    if (!current || current.steps.length === 0) return;
    if (get().playIndex >= current.steps.length - 1) set({ playIndex: 0 });
    set({ playing: true });
    stopPlayTimer();
    playTimer = setInterval(() => {
      const s = get();
      const total = s.current?.steps.length ?? 0;
      if (s.playIndex >= total - 1) {
        stopPlayTimer();
        set({ playing: false });
        return;
      }
      set({ playIndex: s.playIndex + 1 });
    }, playIntervalMs);
    void cumulative;
  },

  pause: () => {
    stopPlayTimer();
    set({ playing: false });
  },

  next: () => {
    stopPlayTimer();
    const { current, playIndex } = get();
    const total = current?.steps.length ?? 0;
    set({ playing: false, playIndex: Math.min(playIndex + 1, Math.max(0, total - 1)) });
  },

  prev: () => {
    stopPlayTimer();
    const { playIndex } = get();
    set({ playing: false, playIndex: Math.max(playIndex - 1, 0) });
  },

  setPlayIndex: (i) => set({ playIndex: i }),
  setCumulative: (v) => set({ cumulative: v }),
  setPlayIntervalMs: (ms) => {
    set({ playIntervalMs: ms });
    if (get().playing) {
      get().play();
    }
  },
}));
