import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useStore } from "../state/store";
import { useScenarioStore } from "../state/scenarioStore";
import { NodeView } from "./NodeView";
import { EdgeView } from "./EdgeView";
import { ZoneView } from "./ZoneView";
import { curvedEdge, curveAtPoint, rectsIntersect } from "../lib/geometry";
import { computeAlignment, computeCornerAlignment, computeDistributionX, computeDistributionY, type Guide } from "../lib/align";
import { MIN_NODE_W, MIN_NODE_H } from "../constants/nodeTypes";
import type { DiagramNode, Zone } from "../types";

const MIN_K = 0.2;
const MAX_K = 3;
const MIN_ZONE = 60;
const ALIGN_THRESHOLD_PX = 4;
const CLICK_DRAG_THRESHOLD_PX = 3;
// How close to a node's border counts as "grab this side to connect" vs. "grab the body to move it" —
// matches drawio: the whole perimeter is a generous connect target, not just a tiny port dot.
const BORDER_GRAB_PX = 6;

/** Border-grab zone, capped so it never eats most of a small node's body. */
function borderGrabPx(node: DiagramNode, k: number): number {
  return Math.min(BORDER_GRAB_PX, Math.min(node.w, node.h) * k * 0.25);
}

function distanceToBorder(n: DiagramNode, p: { x: number; y: number }): number {
  return Math.min(p.x - n.x, n.x + n.w - p.x, p.y - n.y, n.y + n.h - p.y);
}
const ARROW_KEYS = new Set(["ArrowUp", "ArrowDown", "ArrowLeft", "ArrowRight"]);

interface Rect {
  x0: number;
  y0: number;
  x1: number;
  y1: number;
}

interface Connecting {
  fromId: string;
  toPoint: { x: number; y: number };
}

interface Resizing {
  kind: "zone" | "node";
  id: string;
  corner: "nw" | "ne" | "sw" | "se";
  orig: { x: number; y: number; w: number; h: number };
}

function resizeRect(
  orig: { x: number; y: number; w: number; h: number },
  corner: string,
  pointer: { x: number; y: number },
  minW: number,
  minH: number
) {
  let x = orig.x;
  let y = orig.y;
  let x2 = orig.x + orig.w;
  let y2 = orig.y + orig.h;
  if (corner.includes("w")) x = pointer.x;
  if (corner.includes("e")) x2 = pointer.x;
  if (corner.includes("n")) y = pointer.y;
  if (corner.includes("s")) y2 = pointer.y;
  let w = x2 - x;
  let h = y2 - y;
  if (w < minW) {
    if (corner.includes("w")) x = x2 - minW;
    else x2 = x + minW;
    w = minW;
  }
  if (h < minH) {
    if (corner.includes("n")) y = y2 - minH;
    else y2 = y + minH;
    h = minH;
  }
  return { x, y, w, h };
}

export function Canvas() {
  const svgRef = useRef<SVGSVGElement>(null);
  const nodes = useStore((s) => s.nodes);
  const edges = useStore((s) => s.edges);
  const zones = useStore((s) => s.zones);
  const view = useStore((s) => s.view);
  const tool = useStore((s) => s.tool);
  const selectedNodeIds = useStore((s) => s.selectedNodeIds);
  const selectedEdgeIds = useStore((s) => s.selectedEdgeIds);
  const selectedZoneIds = useStore((s) => s.selectedZoneIds);
  const setView = useStore((s) => s.setView);
  const setSelection = useStore((s) => s.setSelection);
  const clearSelection = useStore((s) => s.clearSelection);
  const addEdge = useStore((s) => s.addEdge);
  const addZone = useStore((s) => s.addZone);
  const beginChange = useStore((s) => s.beginChange);
  const moveNodesLive = useStore((s) => s.moveNodesLive);
  const moveZonesLive = useStore((s) => s.moveZonesLive);
  const resizeZoneLive = useStore((s) => s.resizeZoneLive);
  const resizeNodeLive = useStore((s) => s.resizeNodeLive);
  const renameNode = useStore((s) => s.renameNode);
  const renameZone = useStore((s) => s.renameZone);
  const updateEdge = useStore((s) => s.updateEdge);
  const moveEdgeCurveLive = useStore((s) => s.moveEdgeCurveLive);
  const deleteSelection = useStore((s) => s.deleteSelection);
  const snap = useStore((s) => s.snap);
  const selectAll = useStore((s) => s.selectAll);
  const copySelection = useStore((s) => s.copySelection);
  const pasteClipboard = useStore((s) => s.pasteClipboard);
  const duplicateSelection = useStore((s) => s.duplicateSelection);
  const undo = useStore((s) => s.undo);
  const redo = useStore((s) => s.redo);

  const scenarioMode = useScenarioStore((s) => s.mode);
  const scenarioSubMode = useScenarioStore((s) => s.subMode);
  const currentScenario = useScenarioStore((s) => s.current);
  const scenarioPlayIndex = useScenarioStore((s) => s.playIndex);
  const scenarioCumulative = useScenarioStore((s) => s.cumulative);
  const scenarioActiveStepIndex = useScenarioStore((s) => s.activeStepIndex);

  function snapVal(v: number) {
    return snap ? Math.round(v / 20) * 20 : v;
  }

  const [spaceDown, setSpaceDown] = useState(false);
  const [panning, setPanning] = useState(false);
  const panRef = useRef<{ sx: number; sy: number; vx: number; vy: number } | null>(null);

  const activePointers = useRef<Map<number, { x: number; y: number }>>(new Map());
  const pinchState = useRef<{ dist: number; cx: number; cy: number } | null>(null);

  const [dragging, setDragging] = useState<string[] | null>(null);
  const [draggingZones, setDraggingZones] = useState<string[] | null>(null);
  const dragLastWorld = useRef<{ x: number; y: number } | null>(null);
  const dragMoved = useRef(false);
  const dragDownClient = useRef<{ x: number; y: number } | null>(null);

  const [marquee, setMarquee] = useState<Rect | null>(null);
  const marqueeStart = useRef<{ x: number; y: number } | null>(null);
  const marqueeAdditive = useRef(false);

  const [zoneDraw, setZoneDraw] = useState<Rect | null>(null);
  const zoneDrawStart = useRef<{ x: number; y: number } | null>(null);

  const [resizing, setResizing] = useState<Resizing | null>(null);

  const [guides, setGuides] = useState<Guide[]>([]);

  const [connecting, setConnecting] = useState<Connecting | null>(null);
  const [hoveredNodeId, setHoveredNodeId] = useState<string | null>(null);
  const [bendingCurveId, setBendingCurveId] = useState<string | null>(null);

  const [editingId, setEditingId] = useState<string | null>(null);
  const [editValue, setEditValue] = useState("");
  const [editingZoneId, setEditingZoneId] = useState<string | null>(null);
  const [editZoneValue, setEditZoneValue] = useState("");
  const [editingEdgeId, setEditingEdgeId] = useState<string | null>(null);
  const [editEdgeValue, setEditEdgeValue] = useState("");

  const isEditing = !!editingId || !!editingZoneId || !!editingEdgeId;
  const nudgeBurstActive = useRef(false);
  const nudgeIdleTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      const target = e.target as HTMLElement | null;
      const tag = target?.tagName;
      if (tag === "INPUT" || tag === "TEXTAREA" || target?.isContentEditable) return;
      if (e.code === "Space" && !isEditing) {
        setSpaceDown(true);
        e.preventDefault();
      }
      if ((e.key === "Delete" || e.key === "Backspace") && !isEditing) {
        deleteSelection();
      }
      if (ARROW_KEYS.has(e.key) && !isEditing && selectedNodeIds.length > 0) {
        e.preventDefault();
        const step = e.shiftKey ? 10 : 1;
        const dx = e.key === "ArrowLeft" ? -step : e.key === "ArrowRight" ? step : 0;
        const dy = e.key === "ArrowUp" ? -step : e.key === "ArrowDown" ? step : 0;
        if (!nudgeBurstActive.current) {
          nudgeBurstActive.current = true;
          beginChange();
        }
        if (nudgeIdleTimer.current) clearTimeout(nudgeIdleTimer.current);
        nudgeIdleTimer.current = setTimeout(() => {
          nudgeBurstActive.current = false;
          nudgeIdleTimer.current = null;
        }, 500);
        const deltas: Record<string, { x: number; y: number }> = {};
        for (const id of selectedNodeIds) deltas[id] = { x: dx, y: dy };
        moveNodesLive(deltas);
        useStore.getState().scheduleSave();
        return;
      }
      if ((e.metaKey || e.ctrlKey) && !isEditing) {
        if (e.key === "z" || e.key === "Z") {
          e.preventDefault();
          if (e.shiftKey) redo();
          else undo();
          return;
        }
        if (e.key === "y" || e.key === "Y") {
          e.preventDefault();
          redo();
          return;
        }
        if (e.key === "c" || e.key === "C") {
          e.preventDefault();
          copySelection();
          return;
        }
        if (e.key === "v" || e.key === "V") {
          e.preventDefault();
          pasteClipboard();
          return;
        }
        if (e.key === "d" || e.key === "D") {
          e.preventDefault();
          duplicateSelection();
          return;
        }
        if (e.key === "a" || e.key === "A") {
          e.preventDefault();
          selectAll();
          return;
        }
      }
      if (e.key === "Escape") {
        if (isEditing) return;
        setConnecting(null);
        setZoneDraw(null);
        zoneDrawStart.current = null;
        clearSelection();
        return;
      }
      if (isEditing) return;
      if (e.key === "v" || e.key === "V") useStore.getState().setTool("select");
      if (e.key === "c" || e.key === "C") useStore.getState().setTool("connect");
      if (e.key === "z" || e.key === "Z") useStore.getState().setTool("zone");
    }
    function onKeyUp(e: KeyboardEvent) {
      if (e.code === "Space") setSpaceDown(false);
      if (ARROW_KEYS.has(e.key)) {
        nudgeBurstActive.current = false;
        if (nudgeIdleTimer.current) {
          clearTimeout(nudgeIdleTimer.current);
          nudgeIdleTimer.current = null;
        }
      }
    }
    window.addEventListener("keydown", onKeyDown);
    window.addEventListener("keyup", onKeyUp);
    return () => {
      window.removeEventListener("keydown", onKeyDown);
      window.removeEventListener("keyup", onKeyUp);
    };
  }, [
    deleteSelection,
    isEditing,
    copySelection,
    pasteClipboard,
    duplicateSelection,
    undo,
    redo,
    selectAll,
    clearSelection,
    selectedNodeIds,
    beginChange,
    moveNodesLive,
  ]);

  useEffect(() => {
    if (scenarioMode !== "scenario" || scenarioSubMode !== "player" || !currentScenario) return;
    const steps = currentScenario.steps;
    if (steps.length === 0) return;
    const idx = Math.min(scenarioPlayIndex, steps.length - 1);
    const step = steps[idx];
    const targets = nodes.filter((n) => step.nodeIds.includes(n.id));
    if (targets.length === 0) return;
    const xs = targets.flatMap((n) => [n.x, n.x + n.w]);
    const ys = targets.flatMap((n) => [n.y, n.y + n.h]);
    const minX = Math.min(...xs) - 100;
    const maxX = Math.max(...xs) + 100;
    const minY = Math.min(...ys) - 100;
    const maxY = Math.max(...ys) + 100;
    const svg = svgRef.current;
    const w = svg?.clientWidth ?? 800;
    const h = svg?.clientHeight ?? 600;
    const k = Math.min(MAX_K, Math.max(MIN_K, Math.min(w / (maxX - minX), h / (maxY - minY))));
    setView({ x: w / 2 - ((minX + maxX) / 2) * k, y: h / 2 - ((minY + maxY) / 2) * k, k });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scenarioMode, scenarioSubMode, scenarioPlayIndex, currentScenario]);

  function toWorld(clientX: number, clientY: number) {
    const rect = svgRef.current!.getBoundingClientRect();
    const sx = clientX - rect.left;
    const sy = clientY - rect.top;
    return { x: (sx - view.x) / view.k, y: (sy - view.y) / view.k };
  }

  function toWorldMaybeSnap(clientX: number, clientY: number) {
    const w = toWorld(clientX, clientY);
    if (!snap) return w;
    return { x: snapVal(w.x), y: snapVal(w.y) };
  }

  function handleWheel(e: React.WheelEvent) {
    e.preventDefault();
    // Trackpad pinch synthesizes ctrlKey=true on the wheel event (Chrome/Safari/Firefox);
    // an actual Ctrl/Cmd+wheel does too. Plain 2-finger scroll has ctrlKey=false and should pan.
    if (e.ctrlKey || e.metaKey) {
      const factor = Math.exp(-e.deltaY * 0.008);
      const newK = Math.min(MAX_K, Math.max(MIN_K, view.k * factor));
      const rect = svgRef.current!.getBoundingClientRect();
      const sx = e.clientX - rect.left;
      const sy = e.clientY - rect.top;
      const worldX = (sx - view.x) / view.k;
      const worldY = (sy - view.y) / view.k;
      setView({ x: sx - worldX * newK, y: sy - worldY * newK, k: newK });
      return;
    }
    setView({ x: view.x - e.deltaX, y: view.y - e.deltaY, k: view.k });
  }

  function hitTest(target: EventTarget | null) {
    const el = target as SVGElement;
    if (!el || !el.getAttribute) return null;
    const kind = el.getAttribute("data-kind");
    const id = el.getAttribute("data-id");
    const side = el.getAttribute("data-side");
    const corner = el.getAttribute("data-corner");
    const indexAttr = el.getAttribute("data-index");
    const end = el.getAttribute("data-end");
    if (!kind || !id) return null;
    return { kind, id, side, corner, index: indexAttr === null ? null : Number(indexAttr), end };
  }

  function handlePointerDown(e: React.PointerEvent<SVGSVGElement>) {
    activePointers.current.set(e.pointerId, { x: e.clientX, y: e.clientY });
    if (activePointers.current.size >= 2) {
      const [p0, p1] = Array.from(activePointers.current.values()).slice(0, 2);
      pinchState.current = {
        dist: Math.hypot(p0.x - p1.x, p0.y - p1.y),
        cx: (p0.x + p1.x) / 2,
        cy: (p0.y + p1.y) / 2,
      };
      // a second touch landed mid-gesture: cancel whatever the first touch started
      setPanning(false);
      panRef.current = null;
      setDragging(null);
      setDraggingZones(null);
      setResizing(null);
      setMarquee(null);
      marqueeStart.current = null;
      setZoneDraw(null);
      zoneDrawStart.current = null;
      setBendingCurveId(null);
      dragLastWorld.current = null;
      dragDownClient.current = null;
      return;
    }
    if (isEditing) return;
    const hit = hitTest(e.target);
    const world = toWorld(e.clientX, e.clientY);

    if (spaceDown || tool === "pan") {
      setPanning(true);
      panRef.current = { sx: e.clientX, sy: e.clientY, vx: view.x, vy: view.y };
      return;
    }

    if (hit?.kind === "zone-handle" && hit.corner) {
      const zone = zones.find((z) => z.id === hit.id);
      if (zone) {
        beginChange();
        setResizing({
          kind: "zone",
          id: zone.id,
          corner: hit.corner as Resizing["corner"],
          orig: { x: zone.x, y: zone.y, w: zone.w, h: zone.h },
        });
      }
      return;
    }

    if (hit?.kind === "node-handle" && hit.corner) {
      const node = nodes.find((n) => n.id === hit.id);
      if (node) {
        beginChange();
        setResizing({
          kind: "node",
          id: node.id,
          corner: hit.corner as Resizing["corner"],
          orig: { x: node.x, y: node.y, w: node.w, h: node.h },
        });
      }
      return;
    }

    if (tool === "zone") {
      zoneDrawStart.current = world;
      setZoneDraw({ x0: world.x, y0: world.y, x1: world.x, y1: world.y });
      return;
    }

    // Drag straight off a hovered port in select mode too (drawio-style), not just the Connect tool.
    if (tool === "select" && hit?.kind === "port") {
      setConnecting({ fromId: hit.id, toPoint: world });
      return;
    }

    if (tool === "connect") {
      if (hit?.kind === "port" || hit?.kind === "node") {
        setConnecting({ fromId: hit.id, toPoint: world });
      }
      return;
    }

    // Grab anywhere near a hovered node's border (not just the small port dot) to start a
    // connection — matches drawio, where the whole perimeter is a connect target and only the
    // deep interior moves the shape.
    if (tool === "select" && hit?.kind === "node" && hoveredNodeId === hit.id) {
      const node = nodeMap.get(hit.id);
      if (node && distanceToBorder(node, world) * view.k <= borderGrabPx(node, view.k)) {
        setConnecting({ fromId: hit.id, toPoint: world });
        return;
      }
    }

    // select tool
    if (hit?.kind === "node") {
      const already = selectedNodeIds.includes(hit.id);
      if (e.shiftKey) {
        const nextSel = already ? selectedNodeIds.filter((id) => id !== hit.id) : [...selectedNodeIds, hit.id];
        setSelection(nextSel, selectedEdgeIds, selectedZoneIds);
        if (!already) {
          dragMoved.current = false;
          setDragging(nextSel);
          dragLastWorld.current = world;
          dragDownClient.current = { x: e.clientX, y: e.clientY };
        }
        return;
      }
      const nextSel = already ? selectedNodeIds : [hit.id];
      if (!already) setSelection(nextSel, []);
      dragMoved.current = false;
      setDragging(nextSel);
      // Mixed selection (nodes + zones): drag the zones along too, not just the nodes.
      if (already && selectedZoneIds.length) setDraggingZones(selectedZoneIds);
      dragLastWorld.current = world;
      dragDownClient.current = { x: e.clientX, y: e.clientY };
      return;
    }

    if (hit?.kind === "edge-curve") {
      beginChange();
      setBendingCurveId(hit.id);
      return;
    }

    if (hit?.kind === "edge") {
      setSelection([], [hit.id]);
      return;
    }

    if (hit?.kind === "zone" || hit?.kind === "zone-label") {
      const already = selectedZoneIds.includes(hit.id);
      if (!already) setSelection([], [], [hit.id]);
      dragMoved.current = false;
      setDraggingZones(already ? selectedZoneIds : [hit.id]);
      // Mixed selection (nodes + zones): drag the nodes along too, not just the zones.
      if (already && selectedNodeIds.length) setDragging(selectedNodeIds);
      dragLastWorld.current = world;
      dragDownClient.current = { x: e.clientX, y: e.clientY };
      return;
    }

    // empty canvas: start marquee
    marqueeAdditive.current = e.shiftKey;
    if (!e.shiftKey) clearSelection();
    marqueeStart.current = world;
    setMarquee({ x0: world.x, y0: world.y, x1: world.x, y1: world.y });
  }

  function handlePointerMove(e: React.PointerEvent<SVGSVGElement>) {
    if (activePointers.current.has(e.pointerId)) {
      activePointers.current.set(e.pointerId, { x: e.clientX, y: e.clientY });
    }

    if (pinchState.current && activePointers.current.size >= 2) {
      const [p0, p1] = Array.from(activePointers.current.values()).slice(0, 2);
      const dist = Math.hypot(p0.x - p1.x, p0.y - p1.y);
      const cx = (p0.x + p1.x) / 2;
      const cy = (p0.y + p1.y) / 2;
      if (pinchState.current.dist > 0 && dist > 0) {
        const newK = Math.min(MAX_K, Math.max(MIN_K, view.k * (dist / pinchState.current.dist)));
        const rect = svgRef.current!.getBoundingClientRect();
        const sx = cx - rect.left;
        const sy = cy - rect.top;
        const worldX = (sx - view.x) / view.k;
        const worldY = (sy - view.y) / view.k;
        setView({ x: sx - worldX * newK, y: sy - worldY * newK, k: newK });
      }
      pinchState.current = { dist, cx, cy };
      return;
    }

    if (panning && panRef.current) {
      const dx = e.clientX - panRef.current.sx;
      const dy = e.clientY - panRef.current.sy;
      setView({ x: panRef.current.vx + dx, y: panRef.current.vy + dy, k: view.k });
      return;
    }

    if (resizing) {
      const world = toWorldMaybeSnap(e.clientX, e.clientY);
      if (resizing.kind === "zone") {
        if (guides.length) setGuides([]);
        resizeZoneLive(resizing.id, resizeRect(resizing.orig, resizing.corner, world, MIN_ZONE, MIN_ZONE));
      } else {
        let point = world;
        if (!snap && !e.altKey) {
          const others: { x: number; y: number; w: number; h: number }[] = [
            ...nodes.filter((n) => n.id !== resizing.id),
            ...zones,
          ];
          const res = computeCornerAlignment(world, others, ALIGN_THRESHOLD_PX / view.k);
          point = res.point;
          setGuides(res.guides);
        } else if (guides.length) {
          setGuides([]);
        }
        resizeNodeLive(resizing.id, resizeRect(resizing.orig, resizing.corner, point, MIN_NODE_W, MIN_NODE_H));
      }
      return;
    }

    if ((dragging || draggingZones) && dragLastWorld.current) {
      // Don't move anything until the pointer has actually traveled past a small threshold —
      // a plain click (mousedown+mouseup with a stray sub-pixel jiggle) shouldn't nudge/snap
      // the node at all. While still under threshold, dragLastWorld is left at the down point
      // so once it's crossed the full cumulative delta applies in one go (no lost motion).
      if (!dragMoved.current && dragDownClient.current) {
        const travel = Math.hypot(e.clientX - dragDownClient.current.x, e.clientY - dragDownClient.current.y);
        if (travel < CLICK_DRAG_THRESHOLD_PX) return;
      }
      const world = toWorld(e.clientX, e.clientY);
      const dx = world.x - dragLastWorld.current.x;
      const dy = world.y - dragLastWorld.current.y;
      dragLastWorld.current = world;
      if (!dragMoved.current && (dx !== 0 || dy !== 0)) {
        dragMoved.current = true;
        beginChange();
      }
      // Single-node drag (no zones along for the ride): pure free move, cursor-accurate — no
      // position correction. Nearby nodes'/zones' edges/centers (and the grid, if Snap is on)
      // just draw a dashed alignment guide so you can see what lines up, without the node
      // actually jumping to it.
      if (dragging && dragging.length === 1 && !draggingZones && !e.altKey) {
        const all = useStore.getState().nodes;
        const moving = all.find((n) => n.id === dragging[0]);
        if (moving) {
          const threshold = ALIGN_THRESHOLD_PX / view.k;
          const otherNodes = all.filter((n) => n.id !== moving.id);
          const tentative = { x: moving.x + dx, y: moving.y + dy, w: moving.w, h: moving.h };
          const res = computeAlignment(tentative, [...otherNodes, ...zones], threshold);
          const allGuides = [...res.guides];
          if (res.dx === 0) {
            const distX = computeDistributionX(tentative, otherNodes, threshold);
            allGuides.push(...distX.guides);
          }
          if (res.dy === 0) {
            const distY = computeDistributionY(tentative, otherNodes, threshold);
            allGuides.push(...distY.guides);
          }
          if (snap && (res.dx === 0 || res.dy === 0)) {
            // No node/zone edge caught this axis — show the grid crosshair too.
            const rect = svgRef.current!.getBoundingClientRect();
            const worldTop = -view.y / view.k;
            const worldBottom = (rect.height - view.y) / view.k;
            const worldLeft = -view.x / view.k;
            const worldRight = (rect.width - view.x) / view.k;
            const gx = snapVal(tentative.x + tentative.w / 2);
            const gy = snapVal(tentative.y + tentative.h / 2);
            if (res.dx === 0 && Math.abs(gx - (tentative.x + tentative.w / 2)) * view.k <= ALIGN_THRESHOLD_PX)
              allGuides.push({ x1: gx, y1: worldTop, x2: gx, y2: worldBottom });
            if (res.dy === 0 && Math.abs(gy - (tentative.y + tentative.h / 2)) * view.k <= ALIGN_THRESHOLD_PX)
              allGuides.push({ x1: worldLeft, y1: gy, x2: worldRight, y2: gy });
          }
          setGuides(allGuides);
        }
      } else if (guides.length) {
        setGuides([]);
      }
      if (dragging) {
        const deltas: Record<string, { x: number; y: number }> = {};
        for (const id of dragging) deltas[id] = { x: dx, y: dy };
        moveNodesLive(deltas);
      }
      if (draggingZones) {
        const zoneDeltas: Record<string, { x: number; y: number }> = {};
        for (const id of draggingZones) zoneDeltas[id] = { x: dx, y: dy };
        moveZonesLive(zoneDeltas);
      }
      return;
    }

    if (bendingCurveId) {
      const edge = edges.find((ed) => ed.id === bendingCurveId);
      const fromNode = edge && nodeMap.get(edge.from);
      const toNode = edge && nodeMap.get(edge.to);
      if (fromNode && toNode) {
        const world = toWorld(e.clientX, e.clientY);
        moveEdgeCurveLive(bendingCurveId, curveAtPoint(fromNode, toNode, world));
      }
      return;
    }

    if (connecting) {
      const world = toWorld(e.clientX, e.clientY);
      setConnecting({ ...connecting, toPoint: world });
      return;
    }

    if (marquee && marqueeStart.current) {
      const world = toWorld(e.clientX, e.clientY);
      setMarquee({ x0: marqueeStart.current.x, y0: marqueeStart.current.y, x1: world.x, y1: world.y });
      return;
    }

    if (zoneDraw && zoneDrawStart.current) {
      const world = toWorld(e.clientX, e.clientY);
      setZoneDraw({ x0: zoneDrawStart.current.x, y0: zoneDrawStart.current.y, x1: world.x, y1: world.y });
      return;
    }

    // Idle hover in select mode: surface a node's ports on approach so a drag-from-port
    // connect (drawio-style) doesn't require switching to the Connect tool first.
    if (tool === "select") {
      const hit = hitTest(e.target);
      const id = hit?.kind === "node" || hit?.kind === "port" ? hit.id : null;
      if (id !== hoveredNodeId) setHoveredNodeId(id);
    } else if (hoveredNodeId) {
      setHoveredNodeId(null);
    }
  }

  function handlePointerUp() {
    if (panning) {
      setPanning(false);
      panRef.current = null;
      return;
    }

    if (bendingCurveId) {
      setBendingCurveId(null);
      useStore.getState().scheduleSave();
      return;
    }

    if (resizing) {
      setResizing(null);
      setGuides([]);
      useStore.getState().scheduleSave();
      return;
    }

    if (dragging || draggingZones) {
      setDragging(null);
      setDraggingZones(null);
      dragLastWorld.current = null;
      dragDownClient.current = null;
      setGuides([]);
      if (dragMoved.current) useStore.getState().scheduleSave();
      return;
    }

    if (connecting) {
      // handled in a separate pointerup-with-event branch below
      return;
    }

    if (marquee) {
      const x = Math.min(marquee.x0, marquee.x1);
      const y = Math.min(marquee.y0, marquee.y1);
      const w = Math.abs(marquee.x1 - marquee.x0);
      const h = Math.abs(marquee.y1 - marquee.y0);
      if (w > 3 || h > 3) {
        const hitNodes = nodes.filter((n) => rectsIntersect(x, y, w, h, n.x, n.y, n.w, n.h));
        const hitZones = zones.filter((z) => rectsIntersect(x, y, w, h, z.x, z.y, z.w, z.h));
        const hitEdges = edges.filter((e) => {
          const from = nodeMap.get(e.from);
          const to = nodeMap.get(e.to);
          return !!from && !!to && rectsIntersect(x, y, w, h, from.x, from.y, from.w, from.h) && rectsIntersect(x, y, w, h, to.x, to.y, to.w, to.h);
        });
        if (marqueeAdditive.current) {
          const nodeIds = Array.from(new Set([...selectedNodeIds, ...hitNodes.map((n) => n.id)]));
          const edgeIds = Array.from(new Set([...selectedEdgeIds, ...hitEdges.map((e) => e.id)]));
          const zoneIds = Array.from(new Set([...selectedZoneIds, ...hitZones.map((z) => z.id)]));
          setSelection(nodeIds, edgeIds, zoneIds);
        } else {
          setSelection(hitNodes.map((n) => n.id), hitEdges.map((e) => e.id), hitZones.map((z) => z.id));
        }
      }
      setMarquee(null);
      marqueeStart.current = null;
    }

    if (zoneDraw) {
      const w = zoneDraw.x1 - zoneDraw.x0;
      const h = zoneDraw.y1 - zoneDraw.y0;
      if (Math.abs(w) > 8 || Math.abs(h) > 8) {
        const id = addZone(zoneDraw.x0, zoneDraw.y0, w, h);
        setSelection([], [], [id]);
        useStore.getState().setTool("select");
      }
      setZoneDraw(null);
      zoneDrawStart.current = null;
    }
  }

  function handlePointerUpConnect(e: React.PointerEvent<SVGSVGElement>) {
    activePointers.current.delete(e.pointerId);
    if (activePointers.current.size < 2) pinchState.current = null;
    if (!connecting) {
      handlePointerUp();
      return;
    }
    const hit = hitTest(e.target);
    if (hit && (hit.kind === "node" || hit.kind === "port") && hit.id !== connecting.fromId) {
      addEdge(connecting.fromId, hit.id);
    }
    setConnecting(null);
  }

  function handleDoubleClick(e: React.MouseEvent<SVGSVGElement>) {
    const hit = hitTest(e.target);
    if (hit?.kind === "node") {
      const n = nodes.find((n) => n.id === hit.id);
      if (n) {
        setEditingId(n.id);
        setEditValue(n.label);
      }
    } else if (hit?.kind === "zone" || hit?.kind === "zone-label") {
      const z = zones.find((z) => z.id === hit.id);
      if (z) {
        setEditingZoneId(z.id);
        setEditZoneValue(z.label);
      }
    } else if (hit?.kind === "edge") {
      const ed = edges.find((ed) => ed.id === hit.id);
      if (ed) {
        setEditingEdgeId(ed.id);
        setEditEdgeValue(ed.label ?? "");
      }
    }
  }

  const commitEdit = useCallback(() => {
    if (editingId) renameNode(editingId, editValue.trim() || "Untitled");
    setEditingId(null);
  }, [editingId, editValue, renameNode]);

  const cancelEdit = useCallback(() => setEditingId(null), []);

  const commitZoneEdit = useCallback(() => {
    if (editingZoneId) renameZone(editingZoneId, editZoneValue.trim() || "Zone");
    setEditingZoneId(null);
  }, [editingZoneId, editZoneValue, renameZone]);

  const cancelZoneEdit = useCallback(() => setEditingZoneId(null), []);

  const commitEdgeEdit = useCallback(() => {
    if (editingEdgeId) updateEdge(editingEdgeId, { label: editEdgeValue.trim() });
    setEditingEdgeId(null);
  }, [editingEdgeId, editEdgeValue, updateEdge]);

  const cancelEdgeEdit = useCallback(() => setEditingEdgeId(null), []);

  function handleDragOver(e: React.DragEvent<SVGSVGElement>) {
    e.preventDefault();
  }

  function handleDrop(e: React.DragEvent<SVGSVGElement>) {
    e.preventDefault();
    const type = e.dataTransfer.getData("application/x-netdraw-type");
    if (!type) return;
    const world = toWorld(e.clientX, e.clientY);
    useStore.getState().addNode(type as DiagramNode["type"], world.x, world.y);
  }

  const nodeMap = useMemo(() => new Map(nodes.map((n) => [n.id, n])), [nodes]);

  let scenarioVisibleNodeIds: Set<string> | null = null;
  let scenarioVisibleEdgeIds: Set<string> | null = null;
  let scenarioNewNodeIds: Set<string> = new Set();
  let scenarioNewEdgeIds: Set<string> = new Set();

  if (scenarioMode === "scenario" && currentScenario) {
    if (scenarioSubMode === "player") {
      const steps = currentScenario.steps;
      const idx = Math.min(scenarioPlayIndex, Math.max(0, steps.length - 1));
      const included = scenarioCumulative ? steps.slice(0, idx + 1) : steps.slice(idx, idx + 1);
      scenarioVisibleNodeIds = new Set(included.flatMap((s) => s.nodeIds));
      scenarioVisibleEdgeIds = new Set(included.flatMap((s) => s.edgeIds));
      const currentStep = steps[idx];
      scenarioNewNodeIds = new Set(currentStep?.nodeIds ?? []);
      scenarioNewEdgeIds = new Set(currentStep?.edgeIds ?? []);
    } else if (scenarioActiveStepIndex >= 0) {
      const step = currentScenario.steps[scenarioActiveStepIndex];
      scenarioNewNodeIds = new Set(step?.nodeIds ?? []);
      scenarioNewEdgeIds = new Set(step?.edgeIds ?? []);
    }
  }

  function zoneRectFrom(r: Rect) {
    return {
      x: Math.min(r.x0, r.x1),
      y: Math.min(r.y0, r.y1),
      w: Math.abs(r.x1 - r.x0),
      h: Math.abs(r.y1 - r.y0),
    };
  }

  return (
    <svg
      ref={svgRef}
      id="canvas"
      className={
        tool === "connect"
          ? "tool-connect"
          : tool === "zone"
            ? "tool-zone"
            : spaceDown || tool === "pan"
              ? "tool-pan"
              : "tool-select"
      }
      onWheel={handleWheel}
      onPointerDown={handlePointerDown}
      onPointerMove={handlePointerMove}
      onPointerUp={handlePointerUpConnect}
      onPointerCancel={handlePointerUpConnect}
      onDoubleClick={handleDoubleClick}
      onDragOver={handleDragOver}
      onDrop={handleDrop}
    >
      <defs>
        <marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
          <path d="M 0 0 L 10 5 L 0 10 z" fill="var(--edge-dim)" />
        </marker>
        <pattern id="grid" width={24} height={24} patternUnits="userSpaceOnUse">
          <circle cx={1} cy={1} r={1} fill="var(--border)" />
        </pattern>
        <linearGradient id="nodeCardGrad" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="var(--node-grad-1)" />
          <stop offset="100%" stopColor="var(--node-grad-2)" />
        </linearGradient>
      </defs>
      <rect x={-5000} y={-5000} width={10000} height={10000} fill="var(--bg)" />
      <g
        className={scenarioMode === "scenario" && scenarioSubMode === "player" ? "view-anim" : undefined}
        transform={`translate(${view.x} ${view.y}) scale(${view.k})`}
      >
        <rect x={-2000} y={-2000} width={4000} height={4000} fill="url(#grid)" />
        {zones.map((z: Zone) => (
          <ZoneView
            key={z.id}
            zone={z}
            selected={selectedZoneIds.includes(z.id)}
            editing={editingZoneId === z.id}
            editValue={editZoneValue}
            onEditValueChange={setEditZoneValue}
            onEditCommit={commitZoneEdit}
            onEditCancel={cancelZoneEdit}
          />
        ))}
        {edges.map((e) => {
          const from = nodeMap.get(e.from);
          const to = nodeMap.get(e.to);
          if (!from || !to) return null;
          return (
            <EdgeView
              key={e.id}
              edge={e}
              from={from}
              to={to}
              selected={selectedEdgeIds.includes(e.id)}
              editing={editingEdgeId === e.id}
              editValue={editEdgeValue}
              onEditValueChange={setEditEdgeValue}
              onEditCommit={commitEdgeEdit}
              onEditCancel={cancelEdgeEdit}
              dim={scenarioVisibleEdgeIds ? !scenarioVisibleEdgeIds.has(e.id) : false}
              highlight={scenarioNewEdgeIds.has(e.id)}
            />
          );
        })}
        {nodes.map((n) => (
          <NodeView
            key={n.id}
            node={n}
            selected={selectedNodeIds.includes(n.id)}
            dim={scenarioVisibleNodeIds ? !scenarioVisibleNodeIds.has(n.id) : false}
            highlight={scenarioNewNodeIds.has(n.id)}
            showPorts={tool === "connect" || selectedNodeIds.includes(n.id) || hoveredNodeId === n.id}
            editing={editingId === n.id}
            editValue={editValue}
            onEditValueChange={setEditValue}
            onEditCommit={commitEdit}
            onEditCancel={cancelEdit}
          />
        ))}
        {scenarioMode === "scenario" &&
          scenarioSubMode === "player" &&
          currentScenario &&
          (() => {
            const steps = currentScenario.steps;
            if (steps.length === 0) return null;
            const idx = Math.min(scenarioPlayIndex, steps.length - 1);
            const step = steps[idx];
            if (!step?.note) return null;
            const anchor = nodes.find((n) => step.nodeIds.includes(n.id));
            if (!anchor) return null;
            const bw = 220;
            const bx = anchor.x + anchor.w / 2 - bw / 2;
            const by = anchor.y - 78;
            return (
              <foreignObject x={bx} y={by} width={bw} height={70} pointerEvents="none">
                <div className="scenario-note-bubble">{step.note}</div>
              </foreignObject>
            );
          })()}
        {connecting &&
          (() => {
            const from = nodeMap.get(connecting.fromId);
            if (!from) return null;
            const fakeTarget: DiagramNode = { ...from, x: connecting.toPoint.x - 1, y: connecting.toPoint.y - 1, w: 2, h: 2 };
            const geom = curvedEdge(from, fakeTarget, 0);
            return <path d={geom.path} fill="none" stroke="var(--accent)" strokeWidth={2} strokeDasharray="4 3" />;
          })()}
        {guides.map((g, i) => (
          <line
            key={i}
            x1={g.x1}
            y1={g.y1}
            x2={g.x2}
            y2={g.y2}
            stroke="var(--accent)"
            strokeWidth={1 / view.k}
            strokeDasharray={`${4 / view.k} ${3 / view.k}`}
            pointerEvents="none"
          />
        ))}
        {marquee && (
          <rect
            x={Math.min(marquee.x0, marquee.x1)}
            y={Math.min(marquee.y0, marquee.y1)}
            width={Math.abs(marquee.x1 - marquee.x0)}
            height={Math.abs(marquee.y1 - marquee.y0)}
            fill="var(--accent)"
            fillOpacity={0.12}
            stroke="var(--accent)"
            strokeWidth={1}
          />
        )}
        {zoneDraw &&
          (() => {
            const r = zoneRectFrom(zoneDraw);
            return (
              <rect
                x={r.x}
                y={r.y}
                width={r.w}
                height={r.h}
                rx={10}
                fill="var(--accent)"
                fillOpacity={0.1}
                stroke="var(--accent)"
                strokeWidth={1.5}
                strokeDasharray="6 4"
              />
            );
          })()}
      </g>
    </svg>
  );
}
