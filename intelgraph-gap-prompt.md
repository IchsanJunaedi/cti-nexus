# IntelGraph — feature-gap prompt (vs net_draw)

Reference app assessed: https://mr-r3b00t.github.io/net_draw/
Our app: `intelgraph-src/` (React+TS+Vite, Zustand stores: `state/store.ts`, `state/scenarioStore.ts`)

## Task
Implement missing features below in `intelgraph-src`. Match net_draw's UX, keep our existing node taxonomy/disposition/status system (already superset on Threats/TTP depth — don't touch that).

## Gaps to close, priority order

1. **GIF export** — add alongside existing PNG/SVG export in `src/lib/exportSvg.ts` + `TopBar.tsx` (currently only `exportPngFile`/`exportSvgFile`). Need frame-capture-over-time or canvas-to-gif encode (e.g. gif.js) since GIF here means an animated capture, not static.

2. **Live recording w/ narration** — new "Rec" feature: captures canvas live while user pans/zooms/selects/connects, similar to net_draw's screen-record. Options: no audio / mic narration / background music file. Likely `MediaRecorder` API on a canvas stream + optional `getUserMedia` audio track mux. New component, e.g. `components/RecordControls.tsx`.

3. **Camera auto-follow during scenario playback** — net_draw Journey has per-step "focus camera" checkbox: auto pan/zoom viewport to the step's revealed objects on Play. Our `scenarioStore.ts` + `ScenarioPlayerControls.tsx` have no camera/viewport-follow logic (confirmed zero hits grepping camera/focus/zoomTo/panTo). Add:
   - per-step `focusCamera: boolean` field in scenario step model (`types.ts`)
   - on play/next/prev, if step.focusCamera, compute bounding box of step.nodeIds via `lib/geometry.ts` and animate viewport (`lib/viewport.ts`) to fit it.
   - toggle checkbox in `ScenarioBuilder.tsx` per step card.

4. **Process-flow shape set** — net_draw has generic flowchart primitives: Start/End, Decision, Data I/O, Document, Subprocess, Preparation, Manual Input, Delay, Connector. Add as new palette group "Process Flow" in `constants/nodeTypes.ts` + matching render cases in `NodeView.tsx`/`NodeIcon.tsx`. Optional/lower priority — evaluate if in scope for our threat-diagram use case before building.

5. **Examples/template gallery** — net_draw ships an "Examples" dropdown with prebuilt diagrams (e.g. Stuxnet case study) users can load. We have none. Add a small JSON/TS fixture set + "Examples" menu in `TopBar.tsx` that loads a bundled scenario+diagram via existing `lib/persist.ts` load path.

## Not gaps — already ahead, don't rebuild
- Node taxonomy: our Threats/TTP category (Shodan, Google dork, privesc, AD, prompt injection, lateral movement, leaked creds, etc.) is deeper than net_draw's basic threat set (actor/insider/malware/ransomware/botnet/phishing/C2 only).
- Disposition tags (friendly/partner/neutral/unknown/suspicious/adversary/victim) — parity, already implemented (`DISPOSITIONS` in `nodeTypes.ts`).
- Effects/status tags (issue/vulnerable/outage/ddos/exploited/malware infection/data exfil/breach/compromised) — parity, already implemented (`STATUSES`).
- Scenario step builder + player (capture selection, reorder, prev/next/play/pause, cumulative, interval) — parity with net_draw's Journey step list; only the camera-follow behavior (#3) is the actual delta.
