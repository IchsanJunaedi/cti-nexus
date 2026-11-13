import { openDB, type IDBPDatabase } from "idb";
import type { DiagramState, Scenario, ViewState } from "../types";

export interface DiagramRecord {
  id: string;
  name: string;
  doc: DiagramState;
  view: ViewState;
  createdAt: number;
  updatedAt: number;
  /** Mongo owner username, once known — undefined for diagrams that haven't synced yet. */
  owner?: string;
  /** True when this record has local edits not yet pushed to the backend. */
  syncPending?: boolean;
}

export interface CachedScenario {
  id: string;
  scenario: Scenario;
  updatedAt: number;
  /** True when this cached copy has step edits not yet pushed to the backend. */
  syncPending?: boolean;
}

const DB_NAME = "netdraw";
const STORE_NAME = "diagrams";
const SCENARIO_STORE_NAME = "scenarios";
const DB_VERSION = 2;

let dbPromise: Promise<IDBPDatabase> | null = null;

function getDb() {
  if (!dbPromise) {
    dbPromise = openDB(DB_NAME, DB_VERSION, {
      upgrade(db) {
        if (!db.objectStoreNames.contains(STORE_NAME)) {
          db.createObjectStore(STORE_NAME, { keyPath: "id" });
        }
        if (!db.objectStoreNames.contains(SCENARIO_STORE_NAME)) {
          db.createObjectStore(SCENARIO_STORE_NAME, { keyPath: "id" });
        }
      },
    });
  }
  return dbPromise;
}

export async function listDiagrams(): Promise<DiagramRecord[]> {
  try {
    const db = await getDb();
    return await db.getAll(STORE_NAME);
  } catch {
    return [];
  }
}

export async function getDiagram(id: string): Promise<DiagramRecord | undefined> {
  try {
    const db = await getDb();
    return await db.get(STORE_NAME, id);
  } catch {
    return undefined;
  }
}

export async function putDiagram(record: DiagramRecord): Promise<void> {
  try {
    const db = await getDb();
    await db.put(STORE_NAME, record);
  } catch {
    /* storage unavailable — ignore */
  }
}

export async function deleteDiagram(id: string): Promise<void> {
  try {
    const db = await getDb();
    await db.delete(STORE_NAME, id);
  } catch {
    /* ignore */
  }
}

export async function createDiagram(name: string): Promise<DiagramRecord> {
  const now = Date.now();
  const record: DiagramRecord = {
    id: `d_${now.toString(36)}_${Math.random().toString(36).slice(2, 8)}`,
    name,
    doc: { nodes: [], edges: [], zones: [] },
    view: { x: 0, y: 0, k: 1 },
    createdAt: now,
    updatedAt: now,
  };
  await putDiagram(record);
  return record;
}

export async function getCachedScenario(id: string): Promise<CachedScenario | undefined> {
  try {
    const db = await getDb();
    return await db.get(SCENARIO_STORE_NAME, id);
  } catch {
    return undefined;
  }
}

export async function putCachedScenario(record: CachedScenario): Promise<void> {
  try {
    const db = await getDb();
    await db.put(SCENARIO_STORE_NAME, record);
  } catch {
    /* storage unavailable — ignore */
  }
}

export async function deleteCachedScenario(id: string): Promise<void> {
  try {
    const db = await getDb();
    await db.delete(SCENARIO_STORE_NAME, id);
  } catch {
    /* ignore */
  }
}
