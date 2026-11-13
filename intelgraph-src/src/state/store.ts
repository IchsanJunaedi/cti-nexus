import { create } from "zustand";
import type { DiagramEdge, DiagramNode, DiagramState, NodeTypeId, Tool, ViewState, Zone } from "../types";
import { uid } from "../lib/id";
import { computeNodeHeight, DEFAULT_NODE_H, DEFAULT_NODE_W, ZONE_COLORS } from "../constants/nodeTypes";
import { loadFromLocalStorage } from "../lib/persist";
import { deleteDiagram as dbDeleteDiagram, getDiagram as dbGetDiagram, listDiagrams as dbListDiagrams, putDiagram, type DiagramRecord } from "../lib/db";
import { decodeDoc, clearShareHash } from "../lib/share";
import * as diagramApi from "../lib/diagramApi";
import { DiagramForbiddenError } from "../lib/diagramApi";

const HISTORY_LIMIT = 100;
const MIN_ZONE_SIZE = 60;
const SAVE_DEBOUNCE_MS = 300;
const SNAP_LS_KEY = "netdraw:snap";

/** Move item `id` within `list` for z-order: array index = paint order, later = on top. */
function reorder<T extends { id: string }>(list: T[], id: string, to: "front" | "back" | "forward" | "backward"): T[] {
  const i = list.findIndex((item) => item.id === id);
  if (i === -1) return list;
  const next = [...list];
  const [item] = next.splice(i, 1);
  if (to === "front") next.push(item);
  else if (to === "back") next.unshift(item);
  else if (to === "forward") next.splice(Math.min(i + 1, next.length), 0, item);
  else next.splice(Math.max(i - 1, 0), 0, item);
  return next;
}

/** Locally-created diagrams get a "d_"-prefixed id before they've synced to the backend;
 * Mongo-assigned ids never look like that. Used to know whether a save should PUT (update)
 * an existing remote doc or still needs to POST (create) one for the first time. */
function isRemoteId(id: string): boolean {
  return !id.startsWith("d_");
}

interface Clipboard {
  nodes: DiagramNode[];
  edges: DiagramEdge[];
}

interface DiagramListItem {
  id: string;
  name: string;
  updatedAt: number;
  owner?: string;
}

interface Store {
  nodes: DiagramNode[];
  edges: DiagramEdge[];
  zones: Zone[];
  view: ViewState;
  tool: Tool;
  selectedNodeIds: string[];
  selectedEdgeIds: string[];
  selectedZoneIds: string[];

  past: DiagramState[];
  future: DiagramState[];

  booted: boolean;
  currentId: string | null;
  diagramName: string;
  currentCreatedAt: number;
  currentOwner: string | null;
  diagrams: DiagramListItem[];
  persistError: string | null;

  snap: boolean;
  clipboard: Clipboard | null;
  theme: Theme;
  setTheme: (t: Theme) => void;

  setTool: (t: Tool) => void;
  setView: (v: ViewState) => void;
  setSelection: (nodeIds: string[], edgeIds?: string[], zoneIds?: string[]) => void;
  clearSelection: () => void;
  selectAll: () => void;

  addNode: (type: NodeTypeId, x: number, y: number, label?: string) => string;
  addEdge: (from: string, to: string) => void;
  addZone: (x: number, y: number, w: number, h: number) => string;
  beginChange: () => void;
  moveNodesLive: (deltas: Record<string, { x: number; y: number }>) => void;
  moveZonesLive: (deltas: Record<string, { x: number; y: number }>) => void;
  resizeZoneLive: (id: string, rect: { x: number; y: number; w: number; h: number }) => void;
  resizeNodeLive: (id: string, rect: { x: number; y: number; w: number; h: number }) => void;
  renameNode: (id: string, label: string) => void;
  renameZone: (id: string, label: string) => void;
  updateNode: (id: string, patch: Partial<DiagramNode>) => void;
  updateEdge: (id: string, patch: Partial<DiagramEdge>) => void;
  moveEdgeCurveLive: (id: string, curve: number) => void;
  updateZone: (id: string, patch: Partial<Zone>) => void;
  deleteSelection: () => void;
  reorderNode: (id: string, to: "front" | "back" | "forward" | "backward") => void;
  reorderEdge: (id: string, to: "front" | "back" | "forward" | "backward") => void;

  copySelection: () => void;
  pasteClipboard: () => void;
  duplicateSelection: () => void;

  setSnap: (v: boolean) => void;

  undo: () => void;
  redo: () => void;
  persistNow: () => void;
  scheduleSave: () => void;
  clearPersistError: () => void;

  loadDoc: (doc: DiagramState, view?: ViewState) => void;

  boot: () => Promise<void>;
  refreshDiagramList: () => Promise<void>;
  newDiagram: () => Promise<void>;
  openDiagram: (id: string) => Promise<void>;
  renameDiagram: (name: string) => void;
  removeDiagram: (id: string) => Promise<void>;
}

function snapshot(s: Store): DiagramState {
  return {
    nodes: s.nodes.map((n) => ({ ...n })),
    edges: s.edges.map((e) => ({ ...e })),
    zones: s.zones.map((z) => ({ ...z })),
  };
}

function readSnapPref(): boolean {
  try {
    return localStorage.getItem(SNAP_LS_KEY) === "1";
  } catch {
    return false;
  }
}

function writeSnapPref(v: boolean) {
  try {
    localStorage.setItem(SNAP_LS_KEY, v ? "1" : "0");
  } catch {
    /* ignore */
  }
}

type Theme = "dark" | "light";
const THEME_LS_KEY = "netdraw:theme";

function readThemePref(): Theme | null {
  try {
    const v = localStorage.getItem(THEME_LS_KEY);
    return v === "dark" || v === "light" ? v : null;
  } catch {
    return null;
  }
}

function applyTheme(theme: Theme | null) {
  if (typeof document === "undefined") return;
  if (theme) document.documentElement.dataset.theme = theme;
  else delete document.documentElement.dataset.theme;
}

function writeThemePref(theme: Theme) {
  try {
    localStorage.setItem(THEME_LS_KEY, theme);
  } catch {
    /* ignore */
  }
  applyTheme(theme);
}

const initialTheme: Theme =
  readThemePref() ?? (typeof matchMedia !== "undefined" && matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark");
applyTheme(initialTheme);

let saveTimer: ReturnType<typeof setTimeout> | null = null;

/** Create a diagram, remote-first (Mongo is the source of truth); falls back to an
 * IndexedDB-only local record (flagged syncPending) if the backend isn't reachable. */
async function createDiagramRecord(name: string, doc: DiagramState, view: ViewState): Promise<DiagramRecord> {
  try {
    const remote = await diagramApi.createDiagram(name, doc, view);
    const rec: DiagramRecord = {
      id: remote.id,
      name: remote.name,
      doc: remote.doc,
      view: remote.view,
      createdAt: Date.parse(remote.createdAt) || Date.now(),
      updatedAt: Date.parse(remote.updatedAt) || Date.now(),
      owner: remote.owner,
      syncPending: false,
    };
    await putDiagram(rec);
    return rec;
  } catch {
    const now = Date.now();
    const rec: DiagramRecord = {
      id: `d_${now.toString(36)}_${Math.random().toString(36).slice(2, 8)}`,
      name,
      doc,
      view,
      createdAt: now,
      updatedAt: now,
      syncPending: true,
    };
    await putDiagram(rec);
    return rec;
  }
}

async function doSave(s: Store) {
  const doc: DiagramState = { nodes: s.nodes, edges: s.edges, zones: s.zones };
  const name = s.diagramName || "Untitled";

  if (!s.currentId) {
    const rec = await createDiagramRecord(name, doc, s.view);
    useStore.setState({
      currentId: rec.id,
      currentCreatedAt: rec.createdAt,
      currentOwner: rec.owner ?? null,
      persistError: rec.syncPending ? "Backend unreachable — saved locally, will sync when it's back." : null,
    });
    await useStore.getState().refreshDiagramList();
    return;
  }

  let owner = s.currentOwner;
  let syncPending = false;

  if (isRemoteId(s.currentId)) {
    try {
      const remote = await diagramApi.saveDiagram(s.currentId, { name, doc, view: s.view });
      owner = remote.owner;
    } catch {
      syncPending = true;
    }
  } else {
    // still a locally-created id from an earlier offline save — retry create to get a real one
    try {
      const remote = await diagramApi.createDiagram(name, doc, s.view);
      const oldId = s.currentId;
      owner = remote.owner;
      await putDiagram({
        id: remote.id,
        name: remote.name,
        doc: remote.doc,
        view: remote.view,
        createdAt: Date.parse(remote.createdAt) || Date.now(),
        updatedAt: Date.parse(remote.updatedAt) || Date.now(),
        owner: remote.owner,
        syncPending: false,
      });
      await dbDeleteDiagram(oldId);
      useStore.setState({ currentId: remote.id, currentOwner: owner, persistError: null });
      await useStore.getState().refreshDiagramList();
      return;
    } catch {
      syncPending = true;
    }
  }

  const record: DiagramRecord = {
    id: s.currentId,
    name,
    doc,
    view: s.view,
    createdAt: s.currentCreatedAt,
    updatedAt: Date.now(),
    owner: owner ?? undefined,
    syncPending,
  };
  await putDiagram(record);
  useStore.setState({
    currentOwner: owner,
    persistError: syncPending ? "Backend unreachable — saved locally, will sync when it's back." : null,
  });
  await useStore.getState().refreshDiagramList();
}

function persist(s: Store) {
  void doSave(s);
}

export const useStore = create<Store>((set, get) => ({
  nodes: [],
  edges: [],
  zones: [],
  view: { x: 0, y: 0, k: 1 },
  tool: "select",
  selectedNodeIds: [],
  selectedEdgeIds: [],
  selectedZoneIds: [],
  past: [],
  future: [],

  booted: false,
  currentId: null,
  diagramName: "Untitled",
  currentCreatedAt: Date.now(),
  currentOwner: null,
  diagrams: [],
  persistError: null,

  snap: readSnapPref(),
  clipboard: null,
  theme: initialTheme,
  setTheme: (t) => {
    writeThemePref(t);
    set({ theme: t });
  },

  setTool: (t) => set({ tool: t }),
  setView: (v) => set({ view: v }),
  setSelection: (nodeIds, edgeIds = [], zoneIds = []) =>
    set({ selectedNodeIds: nodeIds, selectedEdgeIds: edgeIds, selectedZoneIds: zoneIds }),
  clearSelection: () => set({ selectedNodeIds: [], selectedEdgeIds: [], selectedZoneIds: [] }),
  selectAll: () =>
    set((s) => ({
      selectedNodeIds: s.nodes.map((n) => n.id),
      selectedEdgeIds: s.edges.map((e) => e.id),
      selectedZoneIds: s.zones.map((z) => z.id),
    })),

  addNode: (type, x, y, label) => {
    get().beginChange();
    const id = uid("n_");
    const snap = get().snap;
    const px = snap ? Math.round((x - DEFAULT_NODE_W / 2) / 20) * 20 : x - DEFAULT_NODE_W / 2;
    const py = snap ? Math.round((y - DEFAULT_NODE_H / 2) / 20) * 20 : y - DEFAULT_NODE_H / 2;
    const node: DiagramNode = {
      id,
      type,
      x: px,
      y: py,
      w: DEFAULT_NODE_W,
      h: DEFAULT_NODE_H,
      label: label ?? type[0].toUpperCase() + type.slice(1),
    };
    set((s) => ({ nodes: [...s.nodes, node] }));
    get().scheduleSave();
    return id;
  },

  addEdge: (from, to) => {
    if (from === to) return;
    const exists = get().edges.some(
      (e) => (e.from === from && e.to === to) || (e.from === to && e.to === from)
    );
    if (exists) return;
    get().beginChange();
    const edge: DiagramEdge = { id: uid("e_"), from, to };
    set((s) => ({ edges: [...s.edges, edge] }));
    get().scheduleSave();
  },

  addZone: (x, y, w, h) => {
    get().beginChange();
    const id = uid("z_");
    const color = ZONE_COLORS[get().zones.length % ZONE_COLORS.length];
    const zone: Zone = {
      id,
      x: Math.min(x, x + w),
      y: Math.min(y, y + h),
      w: Math.max(MIN_ZONE_SIZE, Math.abs(w)),
      h: Math.max(MIN_ZONE_SIZE, Math.abs(h)),
      label: "Zone",
      color,
    };
    set((s) => ({ zones: [...s.zones, zone] }));
    get().scheduleSave();
    return id;
  },

  beginChange: () => {
    set((s) => ({
      past: [...s.past, snapshot(s)].slice(-HISTORY_LIMIT),
      future: [],
    }));
  },

  moveNodesLive: (deltas) => {
    set((s) => ({
      nodes: s.nodes.map((n) =>
        deltas[n.id] ? { ...n, x: n.x + deltas[n.id].x, y: n.y + deltas[n.id].y } : n
      ),
    }));
  },

  moveZonesLive: (deltas) => {
    set((s) => ({
      zones: s.zones.map((z) =>
        deltas[z.id] ? { ...z, x: z.x + deltas[z.id].x, y: z.y + deltas[z.id].y } : z
      ),
    }));
  },

  resizeZoneLive: (id, rect) => {
    set((s) => ({
      zones: s.zones.map((z) => (z.id === id ? { ...z, ...rect } : z)),
    }));
  },

  resizeNodeLive: (id, rect) => {
    set((s) => ({
      nodes: s.nodes.map((n) => (n.id === id ? { ...n, ...rect, manualSize: true } : n)),
    }));
  },

  renameNode: (id, label) => {
    get().beginChange();
    set((s) => ({ nodes: s.nodes.map((n) => (n.id === id ? { ...n, label } : n)) }));
    get().scheduleSave();
  },

  renameZone: (id, label) => {
    get().beginChange();
    set((s) => ({ zones: s.zones.map((z) => (z.id === id ? { ...z, label } : z)) }));
    get().scheduleSave();
  },

  updateNode: (id, patch) => {
    get().beginChange();
    set((s) => ({
      nodes: s.nodes.map((n) => {
        if (n.id !== id) return n;
        const meta = { ...n.meta, ...patch.meta };
        const merged = { ...n, ...patch, meta };
        // Manually-resized nodes keep their height; otherwise auto-fit to meta line count.
        if (merged.manualSize) return merged;
        const lineCount = [meta.owner, meta.hostname, meta.ip, meta.address, meta.coords].filter(Boolean).length;
        return { ...merged, h: computeNodeHeight(lineCount) };
      }),
    }));
    get().scheduleSave();
  },

  updateEdge: (id, patch) => {
    get().beginChange();
    set((s) => ({ edges: s.edges.map((e) => (e.id === id ? { ...e, ...patch } : e)) }));
    get().scheduleSave();
  },

  moveEdgeCurveLive: (id, curve) => {
    set((s) => ({ edges: s.edges.map((e) => (e.id === id ? { ...e, curve } : e)) }));
  },

  reorderNode: (id, to) => {
    get().beginChange();
    set((s) => ({ nodes: reorder(s.nodes, id, to) }));
    get().scheduleSave();
  },

  reorderEdge: (id, to) => {
    get().beginChange();
    set((s) => ({ edges: reorder(s.edges, id, to) }));
    get().scheduleSave();
  },


  updateZone: (id, patch) => {
    get().beginChange();
    set((s) => ({ zones: s.zones.map((z) => (z.id === id ? { ...z, ...patch } : z)) }));
    get().scheduleSave();
  },

  deleteSelection: () => {
    const { selectedNodeIds, selectedEdgeIds, selectedZoneIds } = get();
    if (selectedNodeIds.length === 0 && selectedEdgeIds.length === 0 && selectedZoneIds.length === 0) return;
    get().beginChange();
    set((s) => ({
      nodes: s.nodes.filter((n) => !selectedNodeIds.includes(n.id)),
      edges: s.edges.filter(
        (e) =>
          !selectedEdgeIds.includes(e.id) &&
          !selectedNodeIds.includes(e.from) &&
          !selectedNodeIds.includes(e.to)
      ),
      zones: s.zones.filter((z) => !selectedZoneIds.includes(z.id)),
      selectedNodeIds: [],
      selectedEdgeIds: [],
      selectedZoneIds: [],
    }));
    get().scheduleSave();
  },

  copySelection: () => {
    const s = get();
    const nodeIds = new Set(s.selectedNodeIds);
    if (nodeIds.size === 0) return;
    const nodes = s.nodes.filter((n) => nodeIds.has(n.id));
    const edges = s.edges.filter((e) => nodeIds.has(e.from) && nodeIds.has(e.to));
    set({ clipboard: { nodes, edges } });
  },

  pasteClipboard: () => {
    const s = get();
    const cb = s.clipboard;
    if (!cb || cb.nodes.length === 0) return;
    s.beginChange();
    const idMap = new Map<string, string>();
    const newNodes = cb.nodes.map((n) => {
      const id = uid("n_");
      idMap.set(n.id, id);
      return { ...n, id, x: n.x + 20, y: n.y + 20 };
    });
    const newEdges = cb.edges.map((e) => ({
      ...e,
      id: uid("e_"),
      from: idMap.get(e.from)!,
      to: idMap.get(e.to)!,
    }));
    set((st) => ({
      nodes: [...st.nodes, ...newNodes],
      edges: [...st.edges, ...newEdges],
      selectedNodeIds: newNodes.map((n) => n.id),
      selectedEdgeIds: [],
      selectedZoneIds: [],
    }));
    get().scheduleSave();
  },

  duplicateSelection: () => {
    const s = get();
    const nodeIds = new Set(s.selectedNodeIds);
    if (nodeIds.size === 0) return;
    const nodes = s.nodes.filter((n) => nodeIds.has(n.id));
    const edges = s.edges.filter((e) => nodeIds.has(e.from) && nodeIds.has(e.to));
    s.beginChange();
    const idMap = new Map<string, string>();
    const newNodes = nodes.map((n) => {
      const id = uid("n_");
      idMap.set(n.id, id);
      return { ...n, id, x: n.x + 20, y: n.y + 20 };
    });
    const newEdges = edges.map((e) => ({
      ...e,
      id: uid("e_"),
      from: idMap.get(e.from)!,
      to: idMap.get(e.to)!,
    }));
    set((st) => ({
      nodes: [...st.nodes, ...newNodes],
      edges: [...st.edges, ...newEdges],
      selectedNodeIds: newNodes.map((n) => n.id),
      selectedEdgeIds: [],
      selectedZoneIds: [],
    }));
    get().scheduleSave();
  },

  setSnap: (v) => {
    writeSnapPref(v);
    set({ snap: v });
  },

  undo: () => {
    const s = get();
    if (s.past.length === 0) return;
    const prev = s.past[s.past.length - 1];
    const cur = snapshot(s);
    set({
      nodes: prev.nodes,
      edges: prev.edges,
      zones: prev.zones,
      past: s.past.slice(0, -1),
      future: [cur, ...s.future],
      selectedNodeIds: [],
      selectedEdgeIds: [],
      selectedZoneIds: [],
    });
    get().scheduleSave();
  },

  redo: () => {
    const s = get();
    if (s.future.length === 0) return;
    const next = s.future[0];
    const cur = snapshot(s);
    set({
      nodes: next.nodes,
      edges: next.edges,
      zones: next.zones,
      past: [...s.past, cur],
      future: s.future.slice(1),
      selectedNodeIds: [],
      selectedEdgeIds: [],
      selectedZoneIds: [],
    });
    get().scheduleSave();
  },

  persistNow: () => persist(get()),

  scheduleSave: () => {
    if (saveTimer) clearTimeout(saveTimer);
    saveTimer = setTimeout(() => {
      saveTimer = null;
      void doSave(useStore.getState());
    }, SAVE_DEBOUNCE_MS);
  },

  clearPersistError: () => set({ persistError: null }),

  loadDoc: (doc, view) => {
    set({
      nodes: doc.nodes,
      edges: doc.edges,
      zones: doc.zones ?? [],
      view: view ?? get().view,
      past: [],
      future: [],
      selectedNodeIds: [],
      selectedEdgeIds: [],
      selectedZoneIds: [],
    });
    get().scheduleSave();
  },

  boot: async () => {
    if (get().booted) return;

    if (location.hash.startsWith("#d=")) {
      const shared = await decodeDoc(location.hash.slice(3));
      clearShareHash();
      if (shared) {
        set({
          nodes: shared.doc.nodes,
          edges: shared.doc.edges,
          zones: shared.doc.zones ?? [],
          view: shared.view,
          currentId: null,
          diagramName: "Shared",
          currentCreatedAt: Date.now(),
          currentOwner: null,
          past: [],
          future: [],
          booted: true,
        });
        await get().refreshDiagramList();
        return;
      }
    }

    await get().refreshDiagramList();
    let diagrams = get().diagrams;

    if (diagrams.length === 0) {
      const legacy = loadFromLocalStorage();
      const rec = await createDiagramRecord(
        "Imported",
        legacy?.state ?? { nodes: [], edges: [], zones: [] },
        legacy?.view ?? { x: 0, y: 0, k: 1 }
      );
      await get().refreshDiagramList();
      diagrams = get().diagrams;
      set({
        nodes: rec.doc.nodes,
        edges: rec.doc.edges,
        zones: rec.doc.zones ?? [],
        view: rec.view,
        currentId: rec.id,
        diagramName: rec.name,
        currentCreatedAt: rec.createdAt,
        currentOwner: rec.owner ?? null,
        diagrams,
        past: [],
        future: [],
        booted: true,
      });
      return;
    }

    const latest = [...diagrams].sort((a, b) => b.updatedAt - a.updatedAt)[0];
    await get().openDiagram(latest.id);
    set({ booted: true });
  },

  refreshDiagramList: async () => {
    try {
      const remote = await diagramApi.listDiagrams();
      set({
        diagrams: remote.map((d) => ({ id: d.id, name: d.name, updatedAt: Date.parse(d.updatedAt) || 0, owner: d.owner })),
      });
    } catch {
      const local = await dbListDiagrams();
      set({
        diagrams: local
          .sort((a, b) => b.updatedAt - a.updatedAt)
          .map((d) => ({ id: d.id, name: d.name, updatedAt: d.updatedAt, owner: d.owner })),
      });
    }
  },

  newDiagram: async () => {
    const rec = await createDiagramRecord("Untitled", { nodes: [], edges: [], zones: [] }, { x: 0, y: 0, k: 1 });
    await get().refreshDiagramList();
    set({
      nodes: [],
      edges: [],
      zones: [],
      view: { x: 0, y: 0, k: 1 },
      currentId: rec.id,
      diagramName: rec.name,
      currentCreatedAt: rec.createdAt,
      currentOwner: rec.owner ?? null,
      past: [],
      future: [],
      selectedNodeIds: [],
      selectedEdgeIds: [],
      selectedZoneIds: [],
    });
  },

  openDiagram: async (id) => {
    try {
      const remote = await diagramApi.getDiagram(id);
      await putDiagram({
        id: remote.id,
        name: remote.name,
        doc: remote.doc,
        view: remote.view,
        createdAt: Date.parse(remote.createdAt) || Date.now(),
        updatedAt: Date.parse(remote.updatedAt) || Date.now(),
        owner: remote.owner,
        syncPending: false,
      });
      set({
        nodes: remote.doc.nodes,
        edges: remote.doc.edges,
        zones: remote.doc.zones ?? [],
        view: remote.view,
        currentId: remote.id,
        diagramName: remote.name,
        currentCreatedAt: Date.parse(remote.createdAt) || Date.now(),
        currentOwner: remote.owner,
        past: [],
        future: [],
        selectedNodeIds: [],
        selectedEdgeIds: [],
        selectedZoneIds: [],
      });
      return;
    } catch {
      /* offline / unreachable — fall back to local cache below */
    }
    const rec = await dbGetDiagram(id);
    if (!rec) return;
    set({
      nodes: rec.doc.nodes,
      edges: rec.doc.edges,
      zones: rec.doc.zones ?? [],
      view: rec.view,
      currentId: rec.id,
      diagramName: rec.name,
      currentCreatedAt: rec.createdAt,
      currentOwner: rec.owner ?? null,
      past: [],
      future: [],
      selectedNodeIds: [],
      selectedEdgeIds: [],
      selectedZoneIds: [],
    });
  },

  renameDiagram: (name) => {
    set({ diagramName: name });
    get().scheduleSave();
  },

  removeDiagram: async (id) => {
    if (!isRemoteId(id)) {
      // never synced — safe to drop purely locally, nobody else can see it
      await dbDeleteDiagram(id);
    } else {
      try {
        await diagramApi.deleteDiagram(id);
        await dbDeleteDiagram(id);
      } catch (e) {
        set({
          persistError:
            e instanceof DiagramForbiddenError ? e.message : "Couldn't delete diagram — backend unreachable. Try again.",
        });
        return;
      }
    }
    await get().refreshDiagramList();
    const diagrams = get().diagrams;
    if (get().currentId === id) {
      if (diagrams.length > 0) {
        const rec = [...diagrams].sort((a, b) => b.updatedAt - a.updatedAt)[0];
        await get().openDiagram(rec.id);
      } else {
        await get().newDiagram();
      }
    }
  },
}));
