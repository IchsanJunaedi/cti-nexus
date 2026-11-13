import type { NodeTypeId } from "../types";

/** Glyph paths only — caller supplies the <svg> wrapper (stroke/fill/size). 48 of the 51
 * node types use the original hand-drawn glyphs recovered from the upstream net_draw
 * source (https://mr-r3b00t.github.io/net_draw/). `ids`/`siem`/`vpn` are IntelGraph-only
 * additions with no net_draw counterpart, drawn to match the same stroke style. */
export function NodeIconGlyph({ type }: { type: NodeTypeId }) {
  switch (type) {
    // ---------- Network ----------
    case "internet":
      return (
        <>
          <circle cx="12" cy="12" r="9"/><ellipse cx="12" cy="12" rx="4" ry="9"/><path d="M3 12h18"/>
        </>
      );
    case "cloud":
      return (
        <>
          <path d="M7 18h9.5a4 4 0 0 0 .9-7.9A6 6 0 0 0 6.3 9.6 4.3 4.3 0 0 0 7 18z"/>
        </>
      );
    case "router":
      return (
        <>
          <circle cx="12" cy="12" r="9"/><path d="M7 9.5h7.5M12.5 7 15 9.5l-2.5 2.5M17 14.5H9.5M11.5 12 9 14.5l2.5 2.5"/>
        </>
      );
    case "switch":
      return (
        <>
          <rect x="3" y="7.5" width="18" height="9" rx="2"/><path d="M7 10.5h4.2M9.6 8.7l1.8 1.8-1.8 1.8M17 13.5h-4.2M14.4 11.7l-1.8 1.8 1.8 1.8"/>
        </>
      );
    case "wifi":
      return (
        <>
          <path d="M4.5 9.8a11 11 0 0 1 15 0M7.5 13a7 7 0 0 1 9 0M10.4 16.1a3 3 0 0 1 3.2 0"/><circle cx="12" cy="19" r="1.3" fill="currentColor" stroke="none"/>
        </>
      );
    case "asn":
      return (
        <>
          <path d="M12 2.8 19.6 7.2v8.8L12 20.4 4.4 16V7.2z"/><text x="12" y="14.6" textAnchor="middle" fontSize="7" fontWeight="700" fill="currentColor" stroke="none">AS</text>
        </>
      );
    case "ipaddress":
      return (
        <>
          <rect x="3" y="7" width="18" height="10" rx="2.5"/><text x="12" y="14.8" textAnchor="middle" fontSize="7" fontWeight="700" fill="currentColor" stroke="none">IP</text>
        </>
      );
    // ---------- Security & Edge ----------
    case "firewall":
      return (
        <>
          <rect x="3" y="5" width="18" height="14" rx="2"/><path d="M3 9.7h18M3 14.3h18M9 5v4.7M15 9.7v4.6M9 14.3V19"/>
        </>
      );
    case "waf":
      return (
        <>
          <path d="M12 2.8 20 6v6c0 4.6-3.4 7.8-8 9.2C7.4 19.8 4 16.6 4 12V6z"/><path d="M4.6 9.5h14.8M5.2 14h13.6M8.5 5.5v4M15.5 5.5v4M12 9.5V14M8.5 14v4.6M15.5 14v4.6"/>
        </>
      );
    case "proxy":
      return (
        <>
          <rect x="9" y="9" width="6" height="6" rx="1.5"/><path d="M3 6.5h11.5M12 4l2.5 2.5L12 9M21 17.5H9.5M12 15l-2.5 2.5L12 20"/>
        </>
      );
    case "cdn":
      return (
        <>
          <circle cx="12" cy="12" r="4"/><circle cx="4.5" cy="6.5" r="2"/><circle cx="19.5" cy="6.5" r="2"/><circle cx="12" cy="20" r="1.9"/><path d="M8.8 9.7 6 7.9M15.2 9.7 18 7.9M12 16v2.1"/>
        </>
      );
    case "loadbalancer":
      return (
        <>
          <rect x="9.5" y="3" width="5" height="5" rx="1.5"/><path d="M12 8v2.5M12 10.5 5.5 14.8M12 10.5v5.8M12 10.5l6.5 4.3"/><circle cx="5.5" cy="17" r="2.2"/><circle cx="12" cy="18.6" r="2.2"/><circle cx="18.5" cy="17" r="2.2"/>
        </>
      );
    case "apigateway":
      return (
        <>
          <path d="M5 4v16M19 4v16"/><path d="M8 9.2h8M13.5 6.7 16 9.2l-2.5 2.5M16 15h-8M10.5 12.5 8 15l2.5 2.5"/>
        </>
      );
    case "ids":
      return (
        <>
          <circle cx={11} cy={11} r={6} />
          <path d="M15.5 15.5L21 21M11 8v3l2 2" />
        </>
      );
    case "siem":
      return (
        <>
          <rect x={3} y={4} width={18} height={13} rx={1.5} />
          <path d="M6 13l3-4 3 3 3-6 3 4" />
          <path d="M8 20h8" />
        </>
      );
    case "vpn":
      return (
        <>
          <rect x={5} y={11} width={14} height={9} rx={1.5} />
          <path d="M8 11V8a4 4 0 0 1 8 0v3" />
          <path d="M12 15v2" />
        </>
      );
    // ---------- Servers ----------
    case "server":
      return (
        <>
          <rect x="4" y="3.5" width="16" height="7.5" rx="2"/><rect x="4" y="13" width="16" height="7.5" rx="2"/><path d="M7.5 7.2h.01M7.5 16.8h.01M13 7.2h4M13 16.8h4"/>
        </>
      );
    case "webserver":
      return (
        <>
          <rect x="4" y="3.5" width="16" height="7" rx="2"/><path d="M7.5 7h.01"/><circle cx="12" cy="16.2" r="4.3"/><path d="M7.7 16.2h8.6M12 11.9c1.6 2.7 1.6 5.9 0 8.6-1.6-2.7-1.6-5.9 0-8.6"/>
        </>
      );
    case "appserver":
      return (
        <>
          <rect x="4" y="3.5" width="16" height="7" rx="2"/><path d="M7.5 7h.01"/><path d="M9.5 13.5 7 16.7l2.5 3.2M14.5 13.5 17 16.7l-2.5 3.2"/>
        </>
      );
    case "mgmtserver":
      return (
        <>
          <rect x="4" y="3.5" width="16" height="7" rx="2"/><path d="M7.5 7h.01"/><circle cx="12" cy="16.8" r="2.3"/><path d="M12 12.6v1.5M12 19.5V21M16.2 16.8h-1.5M9.3 16.8H7.8M15 13.8l-1.1 1.1M10.1 18.7 9 19.8M15 19.8l-1.1-1.1M10.1 14.9 9 13.8"/>
        </>
      );
    case "updateserver":
      return (
        <>
          <rect x="4" y="3.5" width="16" height="7" rx="2"/><path d="M7.5 7h.01"/><path d="M8.7 15.4a3.8 3.8 0 0 1 6.4-1.5M15.3 18.4a3.8 3.8 0 0 1-6.4 1.5"/><path d="M15.4 11.5v2.5h-2.5M8.6 22.2v-2.5h2.5"/>
        </>
      );
    case "backupserver":
      return (
        <>
          <rect x="4" y="3.5" width="16" height="7" rx="2"/><path d="M7.5 7h.01"/><circle cx="12" cy="17" r="3.6"/><path d="M12 15.2V17l1.5 1"/>
        </>
      );
    case "telephony":
      return (
        <>
          <rect x="4" y="3.5" width="16" height="7" rx="2"/><path d="M7.5 7h.01"/><path d="M8.7 13.6 10 15.7l-.9 1a7.4 7.4 0 0 0 2.3 2.3l1-.9 2.1 1.3-.6 1.4c-.3.7-1 1-1.7.7a9.6 9.6 0 0 1-5.2-5.2c-.3-.7 0-1.4.7-1.7z"/>
        </>
      );
    case "hypervisor":
      return (
        <>
          <rect x="3.5" y="4" width="17" height="16" rx="2"/><rect x="6.3" y="7" width="4.8" height="4.4" rx="1"/><rect x="12.9" y="7" width="4.8" height="4.4" rx="1"/><rect x="6.3" y="13.6" width="4.8" height="4.4" rx="1"/><path d="M12.9 15.8h4.8"/>
        </>
      );
    // ---------- Storage & Data ----------
    case "database":
      return (
        <>
          <ellipse cx="12" cy="5.5" rx="8" ry="3"/><path d="M4 5.5v13c0 1.7 3.6 3 8 3s8-1.3 8-3v-13"/><path d="M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3"/>
        </>
      );
    case "san":
      return (
        <>
          <ellipse cx="12" cy="5.4" rx="7" ry="2.5"/><path d="M5 5.4v4.3c0 1.4 3.1 2.5 7 2.5s7-1.1 7-2.5V5.4M5 9.7V14c0 1.4 3.1 2.5 7 2.5s7-1.1 7-2.5V9.7M5 14v4.3c0 1.4 3.1 2.5 7 2.5s7-1.1 7-2.5V14"/>
        </>
      );
    case "nas":
      return (
        <>
          <rect x="5" y="3" width="14" height="18" rx="2"/><path d="M8 7h8M8 10.5h8"/><circle cx="12" cy="16.5" r="1.6"/>
        </>
      );
    // ---------- Endpoints ----------
    case "workstation":
      return (
        <>
          <rect x="3.5" y="4" width="17" height="11.5" rx="2"/><path d="M12 15.5V19M8 19h8"/>
        </>
      );
    case "laptop":
      return (
        <>
          <rect x="5" y="4.5" width="14" height="9.5" rx="1.5"/><path d="M3 19h18l-2-3.5H5z"/>
        </>
      );
    case "phone":
      return (
        <>
          <rect x="7.5" y="3" width="9" height="18" rx="2.2"/><path d="M11 17.8h2"/>
        </>
      );
    case "printer":
      return (
        <>
          <path d="M7 8V3.5h10V8"/><rect x="3" y="8" width="18" height="8" rx="2"/><rect x="7" y="13.5" width="10" height="6.5" rx="1"/><path d="M17.3 10.8h.01"/>
        </>
      );
    case "scanner":
      return (
        <>
          <rect x="3" y="11" width="18" height="6.5" rx="2"/><path d="M5.5 11 8.5 5h7l3 6M6.5 14.2h.01M10 14.2h7.5"/>
        </>
      );
    case "fax":
      return (
        <>
          <rect x="4" y="10" width="16" height="9" rx="2"/><path d="M7.5 10V4.5h6L16.5 7.5V10"/><path d="M13.5 4.5v3h3"/><path d="M7.5 13.5h.01M10.5 13.5h.01M13.5 13.5h.01M7.5 16h9"/>
        </>
      );
    case "cardreader":
      return (
        <>
          <rect x="3.5" y="7.5" width="12.5" height="9" rx="1.8"/><path d="M3.5 10.8h12.5"/><path d="M18.5 9.6a4.8 4.8 0 0 1 0 4.8M20.8 7.7a8 8 0 0 1 0 8.6"/>
        </>
      );
    case "barcodereader":
      return (
        <>
          <path d="M4.5 6.5v11M8 6.5v11M11 6.5v7M11 16.2v1.3M14 6.5v11M17 6.5v7M17 16.2v1.3M19.5 6.5v11"/>
        </>
      );
    case "iot":
      return (
        <>
          <rect x="7" y="7" width="10" height="10" rx="2"/><path d="M10 7V4.5M14 7V4.5M10 19.5V17M14 19.5V17M7 10H4.5M7 14H4.5M19.5 10H17M19.5 14H17"/><circle cx="12" cy="12" r="1.6"/>
        </>
      );
    case "ot":
      return (
        <>
          <rect x="4" y="6" width="16" height="12" rx="2"/><path d="M7 18v2.5M12 18v2.5M17 18v2.5M7 6V3.5M12 6V3.5M17 6V3.5"/><path d="M7.5 10h4M7.5 13.5h2.5"/><circle cx="15.5" cy="12" r="2"/>
        </>
      );
    // ---------- People & Misc ----------
    case "person":
      return (
        <>
          <circle cx="12" cy="7.5" r="3.6"/><path d="M5 20.5a7 7 0 0 1 14 0"/>
        </>
      );
    case "email":
      return (
        <>
          <rect x="3" y="5.5" width="18" height="13" rx="2"/><path d="m3.5 7.5 8.5 5.8 8.5-5.8"/>
        </>
      );
    // ---------- Places & Orgs ----------
    case "org":
      return (
        <>
          <path d="M3 21h18"/><rect x="4.5" y="8.5" width="6.5" height="12.5"/><rect x="13" y="3.5" width="6.5" height="17.5"/><path d="M6.7 11.5h2.1M6.7 14.5h2.1M6.7 17.5h2.1M15.2 6.5h2.1M15.2 9.5h2.1M15.2 12.5h2.1M15.2 15.5h2.1"/>
        </>
      );
    case "building":
      return (
        <>
          <path d="M3 21h18"/><rect x="6" y="3" width="12" height="18"/><path d="M9 6.5h2M13 6.5h2M9 10h2M13 10h2M9 13.5h2M13 13.5h2M10.5 21v-3.5h3V21"/>
        </>
      );
    case "city":
      return (
        <>
          <path d="M2 21h20"/><path d="M4 21V10.5l4.5-3 4.5 3V21"/><rect x="14" y="6" width="6" height="15"/><path d="M6.5 12h.01M10.5 12h.01M6.5 15h.01M10.5 15h.01M6.5 18h.01M10.5 18h.01M16 9h.01M18 9h.01M16 12h.01M18 12h.01M16 15h.01M18 15h.01"/>
        </>
      );
    case "location":
      return (
        <>
          <path d="M12 21.5S5 14.7 5 9.5A7 7 0 0 1 19 9.5C19 14.7 12 21.5 12 21.5z"/><circle cx="12" cy="9.5" r="2.6"/>
        </>
      );
    case "poi":
      return (
        <>
          <path d="M6 21V3.5"/><path d="M6 4h11.5l-2.2 3.3L17.5 11H6"/>
        </>
      );
    // ---------- Threats ----------
    case "threatactor":
      return (
        <>
          <path d="M12 3C7.5 3 5 6.6 5 11v6.8c2-1.2 3-1.2 4.5-.3 1.6 1 3.4 1 5 0 1.5-.9 2.5-.9 4.5.3V11c0-4.4-2.5-8-7-8z"/><circle cx="9.4" cy="11.5" r="1.1" fill="currentColor" stroke="none"/><circle cx="14.6" cy="11.5" r="1.1" fill="currentColor" stroke="none"/>
        </>
      );
    case "insider":
      return (
        <>
          <circle cx="9.5" cy="7.5" r="3.2"/><path d="M3.5 20a6.3 6.3 0 0 1 11.4-2.4"/><path d="M17.5 12.8 21.3 19.5h-7.6z"/><path d="M17.5 15.2v1.7M17.5 18.1h.01"/>
        </>
      );
    case "malware":
      return (
        <>
          <path d="M12 7.5a4 4 0 0 1 4 4v3a4 4 0 0 1-8 0v-3a4 4 0 0 1 4-4z"/><path d="M12 7.5V5M9 5.5 10.3 7M15 5.5 13.7 7M8 12.5H5.5M18.5 12.5H16M8.6 16 6.5 18M15.4 16l2.1 2M12 10.5v8"/>
        </>
      );
    case "ransomware":
      return (
        <>
          <rect x="5" y="10" width="14" height="10" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/><text x="12" y="17.6" textAnchor="middle" fontSize="7.5" fontWeight="700" fill="currentColor" stroke="none">$</text>
        </>
      );
    case "botnet":
      return (
        <>
          <rect x="7.5" y="8.5" width="9" height="7" rx="2"/><path d="M10.5 12h.01M13.5 12h.01M12 8.5V6M5.5 19 8.5 15.5M18.5 19 15.5 15.5"/><circle cx="12" cy="4.6" r="1.4"/><circle cx="4.5" cy="20.2" r="1.4"/><circle cx="19.5" cy="20.2" r="1.4"/>
        </>
      );
    case "phishing":
      return (
        <>
          <path d="M12 4.5v8.5a4.5 4.5 0 0 0 8.8 1.4"/><path d="M21.5 11.6 20.8 14.6 18 13.4"/><circle cx="12" cy="3.6" r="1.5"/><path d="M6.5 8.5 3 12l3.5 3.5M9.5 8.5 6 12l3.5 3.5" strokeWidth="1.4"/>
        </>
      );
    case "c2":
      return (
        <>
          <rect x="3.5" y="12" width="13" height="6" rx="1.5"/><path d="M6.5 15h.01M10 15h4"/><path d="M17.8 6.8a5.5 5.5 0 0 1 1.7 4M20.5 4.5a9 9 0 0 1 2.6 6.3" strokeWidth="1.6"/><path d="M15.5 9a2.5 2.5 0 0 1 .8 1.8"/>
        </>
      );
    // ---------- Attack Techniques ----------
    case "googledork":
      return (
        <>
          <circle cx="12" cy="12" r="9"/><text x="12" y="15.5" textAnchor="middle" fontSize="10" fontWeight="700" fill="currentColor" stroke="none">G</text>
        </>
      );
    case "githubsearch":
      return (
        <>
          <circle cx="10" cy="10" r="6"/><path d="M14.5 14.5 20 20"/><text x="10" y="12.6" textAnchor="middle" fontSize="5.2" fontWeight="700" fill="currentColor" stroke="none">GH</text>
        </>
      );
    case "mobileapk":
      return (
        <>
          <rect x="8" y="9" width="8" height="8" rx="2"/><path d="M8 9a4 4 0 0 1 8 0"/><path d="M9.5 6.5 8.5 5M14.5 6.5l1-1.5"/><circle cx="10.3" cy="7.3" r=".3" fill="currentColor" stroke="none"/><circle cx="13.7" cy="7.3" r=".3" fill="currentColor" stroke="none"/><path d="M6.5 11v4M17.5 11v4M10 17v2.5M14 17v2.5"/>
        </>
      );
    case "shodan":
      return (
        <>
          <circle cx="10.5" cy="10.5" r="6.5"/><path d="M4 10.5h13"/><path d="M10.5 4a9 5 0 0 1 0 13M10.5 4a9 5 0 0 0 0 13" strokeWidth="1.3"/><path d="M15.5 15.5 21 21"/>
        </>
      );
    case "leakedcred":
      return (
        <>
          <rect x="5" y="10" width="14" height="10" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/><circle cx="9.3" cy="15" r=".8" fill="currentColor" stroke="none"/><circle cx="12" cy="15" r=".8" fill="currentColor" stroke="none"/><circle cx="14.7" cy="15" r=".8" fill="currentColor" stroke="none"/><path d="M4 4l16 16" strokeWidth="1.4"/>
        </>
      );
    case "webvulnscan":
      return (
        <>
          <rect x="3" y="5" width="18" height="14" rx="2"/><path d="M3 9h18"/><text x="12" y="15.3" textAnchor="middle" fontSize="5" fontWeight="700" fill="currentColor" stroke="none">WWW</text>
        </>
      );
    case "fileuploadvuln":
      return (
        <>
          <path d="M6 21V6l4-3h8v18z"/><path d="M10 3v4h4"/><path d="M12 17v-6M9.5 13.5 12 11l2.5 2.5" strokeWidth="1.4"/><circle cx="17.5" cy="16.5" r="2.6"/><path d="M17.5 15.2v1.6M17.5 17.9h.01"/>
        </>
      );
    case "exploit":
      return (
        <>
          <circle cx="12" cy="12" r="8"/><circle cx="12" cy="12" r="3"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3"/>
        </>
      );
    case "sensitivedoc":
      return (
        <>
          <path d="M6 21V6l4-3h8v18z"/><path d="M10 3v4h4"/><rect x="9" y="13" width="6" height="5" rx="1"/><path d="M10.5 13v-1.5a1.5 1.5 0 0 1 3 0V13"/>
        </>
      );
    case "enumeration":
      return (
        <>
          <rect x="3" y="4" width="13" height="9" rx="1.5"/><path d="M6.5 20h6M9.5 13v4"/><circle cx="17" cy="17" r="3.4"/><path d="M19.4 19.4 22 22"/>
        </>
      );
    case "exfiltrate":
      return (
        <>
          <path d="M7 17h9.5a4 4 0 0 0 .9-7.9A6 6 0 0 0 6.3 8.6 4.3 4.3 0 0 0 7 17z"/><path d="M12 20v-7M9.3 15.3 12 12.6l2.7 2.7" strokeWidth="1.4"/>
        </>
      );
    case "aiagent":
      return (
        <>
          <rect x="6" y="8" width="12" height="9" rx="2.5"/><circle cx="9.5" cy="12.5" r="1" fill="currentColor" stroke="none"/><circle cx="14.5" cy="12.5" r="1" fill="currentColor" stroke="none"/><path d="M12 8V5M9.5 5h5"/><circle cx="12" cy="3.6" r="1.1"/><path d="M3.5 12h2.5M18 12h2.5M9 17.5h6"/>
        </>
      );
    case "promptinjection":
      return (
        <>
          <rect x="3.5" y="5" width="17" height="10.5" rx="2"/><path d="M7 15.5v3.5l4-3.5"/><path d="M8 9.5h8M8 12.2h5"/><path d="M17 3l3 3M20 3l-3 3" strokeWidth="1.4"/>
        </>
      );
    case "fileshare3p":
      return (
        <>
          <rect x="4" y="4" width="16" height="5" rx="1.5"/><rect x="4" y="11" width="16" height="5" rx="1.5"/><path d="M7.5 6.5h.01M7.5 13.5h.01"/><circle cx="17" cy="19" r="2.2"/><path d="M17 17v-2M15.5 20.3 13 22M18.5 20.3 21 22" strokeWidth="1.3"/>
        </>
      );
    case "decrypt":
      return (
        <>
          <rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 0 1 7.8-1.2"/><circle cx="12" cy="15.5" r="1.4"/><path d="M12 16.9v1.6"/>
        </>
      );
    case "ssd":
      return (
        <>
          <rect x="3" y="8" width="18" height="8" rx="1.5"/><circle cx="7" cy="12" r="1.3"/><path d="M11 12h7M3 8l2-4h14l2 4"/>
        </>
      );
    case "domaincontroller":
      return (
        <>
          <rect x="5" y="3" width="14" height="18" rx="1.5"/><path d="M5 8.5h14M5 13.5h14M8 5.7h.01M8 10.7h.01M8 15.7h.01"/><path d="M12 17.3l2 1.1v2.2l-2 1.1-2-1.1v-2.2z"/>
        </>
      );
    case "smb":
      return (
        <>
          <rect x="4" y="4" width="16" height="16" rx="2"/><path d="M9.5 14.5a3 3 0 0 1 0-4.2l1.5-1.5a3 3 0 0 1 4.2 4.2l-.8.8"/><path d="M14.5 9.5a3 3 0 0 1 0 4.2l-1.5 1.5a3 3 0 0 1-4.2-4.2l.8-.8"/>
        </>
      );
    case "configfile":
      return (
        <>
          <path d="M5 21V6l4-3h7v18z"/><path d="M9 3v4h4"/><circle cx="13.5" cy="14.5" r="2.3"/><path d="M13.5 10.8v1.3M13.5 16.9v1.3M9.8 14.5h1.3M15.9 14.5h1.3M10.8 11.8l.9.9M15.3 17.3l.9.9M10.8 17.3l.9-.9M15.3 11.8l.9-.9" strokeWidth="1.2"/>
        </>
      );
    case "lateralmovement":
      return (
        <>
          <circle cx="12" cy="7" r="3.2"/><path d="M6.5 20a5.7 5.7 0 0 1 11 0"/><path d="M2 12h4M4.2 10l-2.2 2 2.2 2M18 12h4M15.8 10l2.2 2-2.2 2" strokeWidth="1.4"/>
        </>
      );
    case "privaccount":
      return (
        <>
          <circle cx="10" cy="7" r="3.2"/><path d="M4.5 20a6 6 0 0 1 11 0"/><circle cx="18" cy="17" r="2"/><path d="M18 15v-3M16.8 18.2l-1 1M19.2 18.2l1 1" strokeWidth="1.3"/>
        </>
      );
    case "privesc":
      return (
        <>
          <path d="M4 19h16"/><path d="M5 19 4 10l4 3 3-6 3 6 4-3-1 9"/>
        </>
      );
    case "activedirectory":
      return (
        <>
          <circle cx="12" cy="5" r="2.2"/><circle cx="5" cy="19" r="2.2"/><circle cx="12" cy="19" r="2.2"/><circle cx="19" cy="19" r="2.2"/><path d="M12 7.2V12M12 12H5v4.8M12 12v4.8M12 12h7v4.8"/>
        </>
      );
    case "defenseimpair":
      return (
        <>
          <path d="M12 3 19 6v6c0 4.6-3.4 7.8-7 9.2C8.4 19.8 5 16.6 5 12V6z"/><path d="M9 9l6 6M15 9l-6 6" strokeWidth="1.5"/>
        </>
      );
    case "lan":
      return (
        <>
          <rect x="10" y="3" width="4" height="4" rx="1"/><rect x="3" y="17" width="4" height="4" rx="1"/><rect x="10" y="17" width="4" height="4" rx="1"/><rect x="17" y="17" width="4" height="4" rx="1"/><path d="M12 7v6M5 17v-4h14v4"/>
        </>
      );
    case "defaultcred":
      return (
        <>
          <circle cx="8" cy="12" r="3.2"/><circle cx="8" cy="12" r=".9" fill="currentColor" stroke="none"/><path d="M11 12h9M17 12v3M20 12v2" strokeWidth="1.4"/>
        </>
      );
    case "physicalaccess":
      return (
        <>
          <path d="M12 21c-3.5-2-5-5-5-8.5V9a5 5 0 0 1 10 0v3.5c0 3.5-1.5 6.5-5 8.5z"/><path d="M12 6a3.5 3.5 0 0 1 3.5 3.5M9 15.5V9.5M15 15.5V9.5M12 17V6" strokeWidth="1.2"/>
        </>
      );
    case "masquerading":
      return (
        <>
          <circle cx="7.5" cy="13" r="3"/><circle cx="16.5" cy="13" r="3"/><path d="M10.5 13h3M4.5 13H2M22 13h-2.5"/><path d="M6 9.5c1-2 5-2 6 0" strokeWidth="1.3"/>
        </>
      );
    case "serverroomaccess":
      return (
        <>
          <rect x="4" y="4" width="12" height="16" rx="1.5"/><path d="M4 9h12M4 14h12M7 6.5h.01M7 11.5h.01M7 16.5h.01"/><circle cx="18.5" cy="17" r="2.3"/><path d="M18.5 14.7v-2" strokeWidth="1.3"/>
        </>
      );
    case "cloning":
      return (
        <>
          <rect x="3" y="6" width="13" height="15" rx="2"/><rect x="8" y="3" width="13" height="15" rx="2"/>
        </>
      );
    case "idcard":
      return (
        <>
          <rect x="3" y="5" width="18" height="14" rx="2"/><circle cx="8" cy="11" r="2.2"/><path d="M5 17a3 3 0 0 1 6 0"/><path d="M13 9.5h6M13 12.5h6M13 15.5h4"/>
        </>
      );
    case "networksniffing":
      return (
        <>
          <rect x="3" y="6" width="13" height="9" rx="1.5"/><path d="M3.5 7 9.5 11.5 15.5 7"/><circle cx="18" cy="17" r="3.2"/><path d="M20.3 19.3 22.5 21.5"/>
        </>
      );
    default:
      return <circle cx={12} cy={12} r={8} />;
  }
}
