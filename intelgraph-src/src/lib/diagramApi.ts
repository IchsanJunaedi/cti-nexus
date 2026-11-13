import type { DiagramState, ViewState } from "../types";
import { getToken } from "./authToken";

export class DiagramAuthError extends Error {
  constructor() {
    super("Not authenticated with backend — reload /intelgraph to sign in again.");
  }
}

export class DiagramForbiddenError extends Error {
  constructor() {
    super("Only the owner or an admin can delete this diagram.");
  }
}

function headers(): HeadersInit {
  const token = getToken();
  const h: Record<string, string> = { "Content-Type": "application/json" };
  if (token) h.Authorization = `Bearer ${token}`;
  return h;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`/api/diagrams${path}`, { ...init, headers: headers() });
  if (res.status === 401) throw new DiagramAuthError();
  if (res.status === 403) throw new DiagramForbiddenError();
  if (!res.ok) throw new Error(`Diagram request failed: ${res.status}`);
  return (await res.json()) as T;
}

export interface DiagramSummary {
  id: string;
  name: string;
  owner: string;
  updatedAt: string;
}

export interface DiagramRemote {
  id: string;
  name: string;
  doc: DiagramState;
  view: ViewState;
  owner: string;
  createdAt: string;
  updatedAt: string;
}

interface DiagramSummaryWire {
  _id: string;
  name: string;
  owner: string;
  updated_at: string;
}

interface DiagramWire {
  _id: string;
  name: string;
  doc: DiagramState;
  view: ViewState;
  owner: string;
  created_at: string;
  updated_at: string;
}

function summaryFromWire(d: DiagramSummaryWire): DiagramSummary {
  return { id: d._id, name: d.name, owner: d.owner, updatedAt: d.updated_at };
}

function diagramFromWire(d: DiagramWire): DiagramRemote {
  return {
    id: d._id,
    name: d.name,
    doc: d.doc,
    view: d.view,
    owner: d.owner,
    createdAt: d.created_at,
    updatedAt: d.updated_at,
  };
}

export async function listDiagrams(): Promise<DiagramSummary[]> {
  const wire = await request<DiagramSummaryWire[]>("");
  return wire.map(summaryFromWire);
}

export async function getDiagram(id: string): Promise<DiagramRemote> {
  return diagramFromWire(await request<DiagramWire>(`/${id}`));
}

export async function createDiagram(name: string, doc?: DiagramState, view?: ViewState): Promise<DiagramRemote> {
  const wire = await request<DiagramWire>("", {
    method: "POST",
    body: JSON.stringify({
      name,
      doc: doc ?? { nodes: [], edges: [], zones: [] },
      view: view ?? { x: 0, y: 0, k: 1 },
    }),
  });
  return diagramFromWire(wire);
}

export async function saveDiagram(
  id: string,
  patch: { name?: string; doc?: DiagramState; view?: ViewState }
): Promise<DiagramRemote> {
  const wire = await request<DiagramWire>(`/${id}`, {
    method: "PUT",
    body: JSON.stringify(patch),
  });
  return diagramFromWire(wire);
}

export async function deleteDiagram(id: string): Promise<void> {
  await request<{ deleted: boolean }>(`/${id}`, { method: "DELETE" });
}
