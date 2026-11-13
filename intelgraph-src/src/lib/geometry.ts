import type { Anchor, DiagramNode } from "../types";

export function nodeCenter(n: DiagramNode): Anchor {
  return { x: n.x + n.w / 2, y: n.y + n.h / 2 };
}

/**
 * Anchor point on node `n`'s border closest to `toward`, clamped to the
 * rectangle edge (top/bottom/left/right side, not just nearest corner).
 */
export function anchor(n: DiagramNode, toward: Anchor): Anchor {
  const c = nodeCenter(n);
  const dx = toward.x - c.x;
  const dy = toward.y - c.y;
  if (dx === 0 && dy === 0) return c;

  const hw = n.w / 2;
  const hh = n.h / 2;
  const scaleX = hw / Math.abs(dx || 1e-6);
  const scaleY = hh / Math.abs(dy || 1e-6);
  const scale = Math.min(scaleX, scaleY);

  return { x: c.x + dx * scale, y: c.y + dy * scale };
}

export interface EdgeGeom {
  a: Anchor;
  b: Anchor;
  /** Label anchor (midpoint of the curve). */
  mid: Anchor;
  path: string;
  /** Quadratic bezier control point — the single draggable handle. */
  control: Anchor;
}

const DEFAULT_CURVE = 0.15;
// Cap the bulge in absolute world units so long edges don't sweep wide enough to cut through
// unrelated nodes off to the side — pure percentage curvature grows unbounded with distance.
const MAX_BULGE = 60;

/**
 * Smooth curved connector: a single quadratic bezier from `a`'s border to `b`'s border, bowed
 * perpendicular to the straight line between them by `curve` (signed fraction of the distance —
 * positive bows one way, negative the other, 0 is a straight line). One draggable point (the
 * bezier control point) reshapes the whole curve, no segment/turn bookkeeping needed.
 */
export function curvedEdge(a: DiagramNode, b: DiagramNode, curve = DEFAULT_CURVE): EdgeGeom {
  const ca = nodeCenter(a);
  const cb = nodeCenter(b);
  const pA = anchor(a, cb);
  const pB = anchor(b, ca);

  const dx = pB.x - pA.x;
  const dy = pB.y - pA.y;
  const dist = Math.hypot(dx, dy) || 1e-6;
  // Perpendicular unit vector.
  const nx = -dy / dist;
  const ny = dx / dist;

  const midX = (pA.x + pB.x) / 2;
  const midY = (pA.y + pB.y) / 2;
  // `curve` is the bulge of the VISIBLE curve (at t=0.5) as a fraction of a-to-b distance — the
  // quadratic control point has to sit twice as far out to produce that on-curve bulge, since a
  // quadratic bezier's midpoint is only halfway toward its control point.
  const bulge = Math.max(-MAX_BULGE, Math.min(MAX_BULGE, curve * dist));
  const mid = { x: midX + nx * bulge, y: midY + ny * bulge };
  const control = { x: midX + nx * bulge * 2, y: midY + ny * bulge * 2 };

  return {
    a: pA,
    b: pB,
    mid,
    control,
    path: `M ${pA.x} ${pA.y} Q ${control.x} ${control.y} ${pB.x} ${pB.y}`,
  };
}

/** `curve` value that would put the visible curve's midpoint (the drag handle) at `point`. */
export function curveAtPoint(a: DiagramNode, b: DiagramNode, point: Anchor): number {
  const ca = nodeCenter(a);
  const cb = nodeCenter(b);
  const pA = anchor(a, cb);
  const pB = anchor(b, ca);
  const dx = pB.x - pA.x;
  const dy = pB.y - pA.y;
  const dist = Math.hypot(dx, dy) || 1e-6;
  const nx = -dy / dist;
  const ny = dx / dist;
  const midX = (pA.x + pB.x) / 2;
  const midY = (pA.y + pB.y) / 2;
  // Project (point - mid) onto the perpendicular axis, express as a fraction of dist.
  const px = point.x - midX;
  const py = point.y - midY;
  return (px * nx + py * ny) / dist;
}

export function pointInRect(
  px: number,
  py: number,
  x: number,
  y: number,
  w: number,
  h: number
): boolean {
  return px >= x && px <= x + w && py >= y && py <= y + h;
}

export function rectsIntersect(
  ax: number,
  ay: number,
  aw: number,
  ah: number,
  bx: number,
  by: number,
  bw: number,
  bh: number
): boolean {
  return ax < bx + bw && ax + aw > bx && ay < by + bh && ay + ah > by;
}

export function nodeUnderPoint(
  nodes: DiagramNode[],
  x: number,
  y: number
): DiagramNode | undefined {
  for (let i = nodes.length - 1; i >= 0; i--) {
    const n = nodes[i];
    if (pointInRect(x, y, n.x, n.y, n.w, n.h)) return n;
  }
  return undefined;
}
