import type { Scenario, ScenarioStep, ScenarioSummary } from "../types";
import { getToken } from "./authToken";

export class ScenarioAuthError extends Error {
  constructor() {
    super("Not authenticated with backend — reload /intelgraph to sign in again.");
  }
}

function headers(): HeadersInit {
  const token = getToken();
  const h: Record<string, string> = { "Content-Type": "application/json" };
  if (token) h.Authorization = `Bearer ${token}`;
  return h;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`/api/scenarios${path}`, { ...init, headers: headers() });
  if (res.status === 401) throw new ScenarioAuthError();
  if (!res.ok) throw new Error(`Scenario request failed: ${res.status}`);
  return (await res.json()) as T;
}

interface ScenarioStepWire {
  id: string;
  order: number;
  note: string;
  node_ids: string[];
  edge_ids: string[];
  created_at: string;
}

interface ScenarioWire {
  _id: string;
  name: string;
  description: string;
  diagram_id: string;
  steps: ScenarioStepWire[];
  version: number;
  created_at: string;
  updated_at: string;
}

interface ScenarioSummaryWire {
  _id: string;
  name: string;
  description: string;
  diagram_id: string;
  step_count: number;
  updated_at: string;
}

function stepFromWire(s: ScenarioStepWire): ScenarioStep {
  return {
    id: s.id,
    order: s.order,
    note: s.note ?? "",
    nodeIds: s.node_ids ?? [],
    edgeIds: s.edge_ids ?? [],
    createdAt: s.created_at ?? "",
  };
}

function stepToWire(s: ScenarioStep) {
  return {
    id: s.id,
    order: s.order,
    note: s.note,
    node_ids: s.nodeIds,
    edge_ids: s.edgeIds,
    created_at: s.createdAt,
  };
}

function scenarioFromWire(s: ScenarioWire): Scenario {
  return {
    id: s._id,
    name: s.name,
    description: s.description,
    diagramId: s.diagram_id,
    steps: (s.steps ?? []).map(stepFromWire),
    version: s.version,
    createdAt: s.created_at,
    updatedAt: s.updated_at,
  };
}

function summaryFromWire(s: ScenarioSummaryWire): ScenarioSummary {
  return {
    id: s._id,
    name: s.name,
    description: s.description,
    diagramId: s.diagram_id,
    stepCount: s.step_count,
    updatedAt: s.updated_at,
  };
}

export async function listScenarios(diagramId: string): Promise<ScenarioSummary[]> {
  const wire = await request<ScenarioSummaryWire[]>(`?diagram_id=${encodeURIComponent(diagramId)}`);
  return wire.map(summaryFromWire);
}

export async function getScenario(id: string): Promise<Scenario> {
  return scenarioFromWire(await request<ScenarioWire>(`/${id}`));
}

export async function createScenario(
  name: string,
  diagramId: string,
  description = "",
  steps: ScenarioStep[] = []
): Promise<Scenario> {
  const wire = await request<ScenarioWire>("", {
    method: "POST",
    body: JSON.stringify({ name, description, diagram_id: diagramId, steps: steps.map(stepToWire) }),
  });
  return scenarioFromWire(wire);
}

export async function replaceSteps(id: string, steps: ScenarioStep[]): Promise<Scenario> {
  const wire = await request<ScenarioWire>(`/${id}/steps`, {
    method: "PUT",
    body: JSON.stringify({ steps: steps.map(stepToWire) }),
  });
  return scenarioFromWire(wire);
}

export async function deleteScenario(id: string): Promise<void> {
  await request<{ deleted: boolean }>(`/${id}`, { method: "DELETE" });
}
