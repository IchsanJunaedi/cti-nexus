export interface AlignRect {
  x: number;
  y: number;
  w: number;
  h: number;
}

export interface Guide {
  x1: number;
  y1: number;
  x2: number;
  y2: number;
}

export interface AlignResult {
  /** Correction to add to the moving rect's position to snap it onto a guide (0 when no match). */
  dx: number;
  dy: number;
  guides: Guide[];
}

const EPS = 0.5;

/** Line positions of a rect on one axis: near edge, center, far edge. */
function linesX(r: AlignRect): number[] {
  return [r.x, r.x + r.w / 2, r.x + r.w];
}
function linesY(r: AlignRect): number[] {
  return [r.y, r.y + r.h / 2, r.y + r.h];
}
function centerX(r: AlignRect): number {
  return r.x + r.w / 2;
}
function centerY(r: AlignRect): number {
  return r.y + r.h / 2;
}

function bestMatch(movingLines: number[], othersLines: number[][], threshold: number) {
  let best: { delta: number; line: number } | null = null;
  for (const ml of movingLines) {
    for (const ol of othersLines) {
      for (const line of ol) {
        const diff = Math.abs(line - ml);
        if (diff <= threshold && (!best || diff < Math.abs(best.delta))) {
          best = { delta: line - ml, line };
        }
      }
    }
  }
  return best;
}

/**
 * Compare a single moving rect against the others and, when an edge/center lines up within
 * `threshold` (world units), return the snap correction plus guide segments spanning the aligned rects.
 */
export function computeAlignment(moving: AlignRect, others: AlignRect[], threshold: number): AlignResult {
  if (others.length === 0) return { dx: 0, dy: 0, guides: [] };

  const bx = bestMatch(linesX(moving), others.map(linesX), threshold);
  const by = bestMatch(linesY(moving), others.map(linesY), threshold);
  const dx = bx?.delta ?? 0;
  const dy = by?.delta ?? 0;

  const snapped: AlignRect = { ...moving, x: moving.x + dx, y: moving.y + dy };
  const guides: Guide[] = [];

  if (bx) {
    const aligned = [snapped, ...others.filter((o) => linesX(o).some((l) => Math.abs(l - bx.line) < EPS))];
    const y1 = Math.min(...aligned.map((r) => r.y));
    const y2 = Math.max(...aligned.map((r) => r.y + r.h));
    guides.push({ x1: bx.line, y1, x2: bx.line, y2 });
  }
  if (by) {
    const aligned = [snapped, ...others.filter((o) => linesY(o).some((l) => Math.abs(l - by.line) < EPS))];
    const x1 = Math.min(...aligned.map((r) => r.x));
    const x2 = Math.max(...aligned.map((r) => r.x + r.w));
    guides.push({ x1, y1: by.line, x2, y2: by.line });
  }

  return { dx, dy, guides };
}

export interface CornerAlignResult {
  point: { x: number; y: number };
  guides: Guide[];
}

/**
 * Snap a single resize-drag corner point onto nearby rects' edges/centers
 * (same line set as {@link computeAlignment}, but matched against a lone point
 * rather than a whole moving rect).
 */
export function computeCornerAlignment(point: { x: number; y: number }, others: AlignRect[], threshold: number): CornerAlignResult {
  if (others.length === 0) return { point, guides: [] };

  const bx = bestMatch([point.x], others.map(linesX), threshold);
  const by = bestMatch([point.y], others.map(linesY), threshold);
  const snapped = { x: point.x + (bx?.delta ?? 0), y: point.y + (by?.delta ?? 0) };
  const guides: Guide[] = [];

  if (bx) {
    const aligned = others.filter((o) => linesX(o).some((l) => Math.abs(l - bx.line) < EPS));
    const y1 = Math.min(snapped.y, ...aligned.map((r) => r.y));
    const y2 = Math.max(snapped.y, ...aligned.map((r) => r.y + r.h));
    guides.push({ x1: bx.line, y1, x2: bx.line, y2 });
  }
  if (by) {
    const aligned = others.filter((o) => linesY(o).some((l) => Math.abs(l - by.line) < EPS));
    const x1 = Math.min(snapped.x, ...aligned.map((r) => r.x));
    const x2 = Math.max(snapped.x, ...aligned.map((r) => r.x + r.w));
    guides.push({ x1, y1: by.line, x2, y2: by.line });
  }

  return { point: snapped, guides };
}

export interface DistributionResult {
  delta: number;
  guides: Guide[];
}

const NO_DISTRIBUTION: DistributionResult = { delta: 0, guides: [] };

/**
 * When the moving rect sits between two others that would become equally spaced (by center)
 * if nudged by a small amount, return that nudge plus guide segments linking the trio.
 */
export function computeDistributionX(moving: AlignRect, others: AlignRect[], threshold: number): DistributionResult {
  if (others.length < 2) return NO_DISTRIBUTION;
  const sorted = [...others].sort((a, b) => centerX(a) - centerX(b));
  const mc = centerX(moving);
  let prev: AlignRect | null = null;
  let next: AlignRect | null = null;
  for (const o of sorted) {
    if (centerX(o) <= mc) prev = o;
    else {
      next = o;
      break;
    }
  }
  if (!prev || !next) return NO_DISTRIBUTION;
  const expected = (centerX(prev) + centerX(next)) / 2;
  const delta = expected - mc;
  if (Math.abs(delta) > threshold) return NO_DISTRIBUTION;
  const my = centerY(moving);
  return {
    delta,
    guides: [
      { x1: centerX(prev), y1: centerY(prev), x2: expected, y2: my },
      { x1: expected, y1: my, x2: centerX(next), y2: centerY(next) },
    ],
  };
}

export function computeDistributionY(moving: AlignRect, others: AlignRect[], threshold: number): DistributionResult {
  if (others.length < 2) return NO_DISTRIBUTION;
  const sorted = [...others].sort((a, b) => centerY(a) - centerY(b));
  const mc = centerY(moving);
  let prev: AlignRect | null = null;
  let next: AlignRect | null = null;
  for (const o of sorted) {
    if (centerY(o) <= mc) prev = o;
    else {
      next = o;
      break;
    }
  }
  if (!prev || !next) return NO_DISTRIBUTION;
  const expected = (centerY(prev) + centerY(next)) / 2;
  const delta = expected - mc;
  if (Math.abs(delta) > threshold) return NO_DISTRIBUTION;
  const mx = centerX(moving);
  return {
    delta,
    guides: [
      { x1: centerX(prev), y1: centerY(prev), x2: mx, y2: expected },
      { x1: mx, y1: expected, x2: centerX(next), y2: centerY(next) },
    ],
  };
}
