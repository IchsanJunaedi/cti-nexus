import type { StatusId } from "../types";

/** Glyph paths only — caller supplies the <svg> wrapper (stroke/fill/size). */
export function StatusIconGlyph({ status }: { status: StatusId }) {
  switch (status) {
    case "issue":
      return (
        <>
          <path d="M12 4 L21 19 H3 Z" />
          <path d="M12 10v4" />
          <circle cx={12} cy={16.5} r={0.9} fill="currentColor" stroke="none" />
        </>
      );
    case "vulnerable":
      return (
        <>
          <path d="M7 11V8a5 5 0 0 1 10 0v3" />
          <rect x={5} y={11} width={14} height={9} rx={2} />
          <path d="M9 11l6 6M15 11l-6 6" />
        </>
      );
    case "suspicious_activity":
      return (
        <>
          <path d="M2 12s4-6 10-6 10 6 10 6-4 6-10 6-10-6-10-6z" />
          <circle cx={12} cy={12} r={3} />
        </>
      );
    case "outage":
      return (
        <>
          <path d="M13 3 5 14h6l-1 7 9-11h-6z" strokeLinejoin="round" />
          <path d="M4 4l16 16" />
        </>
      );
    case "ddos":
      return (
        <>
          <circle cx={12} cy={12} r={2.2} />
          <path d="M12 3v4M12 17v4M3 12h4M17 12h4M6 6l3 3M18 6l-3 3M6 18l3-3M18 18l-3-3" />
        </>
      );
    case "exploited":
      return (
        <>
          <path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z" />
          <path d="M9 3.5L12 8l-2 4.5 3 3.5" />
          <path d="M15 4L12 8l2 4.5-2.5 4" />
        </>
      );
    case "malware_infection":
      return (
        <>
          <ellipse cx={12} cy={13} rx={6} ry={7} />
          <path d="M12 6V3M8 5l-1.5-2M16 5l1.5-2M4 12H2M22 12h-2M5 17l-2 2M19 17l2 2" />
          <path d="M6 12h12" />
        </>
      );
    case "data_exfiltration":
      return (
        <>
          <rect x={2} y={5} width={11} height={4} rx={1} />
          <rect x={2} y={11} width={11} height={4} rx={1} />
          <rect x={2} y={17} width={8} height={4} rx={1} />
          <path d="M14 13h6" strokeDasharray="2.2 2.2" />
          <path d="M17 10l3 3-3 3" />
        </>
      );
    case "data_breach":
      return (
        <>
          <path d="M8 10V7a4 4 0 0 1 7.3-2.3" />
          <rect x={5} y={10} width={14} height={9} rx={2} />
          <circle cx={12} cy={13.8} r={1.3} fill="currentColor" stroke="none" />
          <path d="M12 15.1v2" />
        </>
      );
    case "compromised":
      return (
        <>
          <circle cx={12} cy={10} r={7} />
          <circle cx={9} cy={9} r={1.8} fill="currentColor" stroke="none" />
          <circle cx={15} cy={9} r={1.8} fill="currentColor" stroke="none" />
          <path d="M12 12l-1.4 2.3h2.8z" fill="currentColor" stroke="none" />
          <path d="M8 16h8M8.7 16v2M10.6 16v2.6M12 16v3M13.4 16v2.6M15.3 16v2" />
        </>
      );
    default:
      return null;
  }
}
