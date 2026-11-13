import type { DiagramNode, ViewState, Zone } from "../types";

export const MIN_K = 0.2;
export const MAX_K = 3;

function contentBounds(nodes: DiagramNode[], zones: Zone[]) {
  if (nodes.length === 0 && zones.length === 0) return null;
  const xs = [...nodes.flatMap((n) => [n.x, n.x + n.w]), ...zones.flatMap((z) => [z.x, z.x + z.w])];
  const ys = [...nodes.flatMap((n) => [n.y, n.y + n.h]), ...zones.flatMap((z) => [z.y, z.y + z.h])];
  return { minX: Math.min(...xs), maxX: Math.max(...xs), minY: Math.min(...ys), maxY: Math.max(...ys) };
}

export function computeFitView(nodes: DiagramNode[], zones: Zone[], w: number, h: number): ViewState {
  const bounds = contentBounds(nodes, zones);
  if (!bounds) return { x: 0, y: 0, k: 1 };
  const minX = bounds.minX - 40;
  const maxX = bounds.maxX + 40;
  const minY = bounds.minY - 40;
  const maxY = bounds.maxY + 40;
  const k = Math.min(MAX_K, Math.max(MIN_K, Math.min(w / (maxX - minX), h / (maxY - minY))));
  return { x: w / 2 - ((minX + maxX) / 2) * k, y: h / 2 - ((minY + maxY) / 2) * k, k };
}

/** True if at least part of the diagram content falls inside the visible w×h viewport at the given view. */
export function isContentVisible(nodes: DiagramNode[], zones: Zone[], view: ViewState, w: number, h: number): boolean {
  const bounds = contentBounds(nodes, zones);
  if (!bounds) return true;
  const screenMinX = bounds.minX * view.k + view.x;
  const screenMaxX = bounds.maxX * view.k + view.x;
  const screenMinY = bounds.minY * view.k + view.y;
  const screenMaxY = bounds.maxY * view.k + view.y;
  return screenMaxX >= 0 && screenMinX <= w && screenMaxY >= 0 && screenMinY <= h;
}
