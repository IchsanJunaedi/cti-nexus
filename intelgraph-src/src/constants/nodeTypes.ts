import type { DispositionId, NodeTypeDef, NodeTypeId, PaletteGroup, StatusId } from "../types";

export const NODE_TYPES: NodeTypeDef[] = [
  // Network
  { id: "internet", label: "Internet", accent: "#38bdf8" },
  { id: "cloud", label: "Cloud", accent: "#22d3ee" },
  { id: "router", label: "Router", accent: "#a78bfa" },
  { id: "switch", label: "Switch", accent: "#60a5fa" },
  { id: "wifi", label: "Access Point", accent: "#c084fc" },
  { id: "asn", label: "ASN", accent: "#818cf8" },
  { id: "ipaddress", label: "IP Address", accent: "#67e8f9" },
  // Security & Edge
  { id: "firewall", label: "Firewall", accent: "#f87171" },
  { id: "waf", label: "WAF", accent: "#f43f5e" },
  { id: "proxy", label: "Proxy Server", accent: "#e879f9" },
  { id: "cdn", label: "CDN", accent: "#38bdf8" },
  { id: "loadbalancer", label: "Load Balancer", accent: "#2dd4bf" },
  { id: "apigateway", label: "API Gateway", accent: "#22d3ee" },
  { id: "ids", label: "IDS / IPS", accent: "#fb923c" },
  { id: "siem", label: "SIEM", accent: "#c084fc" },
  { id: "vpn", label: "VPN Gateway", accent: "#34d399" },
  // Servers
  { id: "server", label: "Server", accent: "#94a3b8" },
  { id: "webserver", label: "Web Server", accent: "#38bdf8" },
  { id: "appserver", label: "Application Server", accent: "#818cf8" },
  { id: "mgmtserver", label: "Management Server", accent: "#a78bfa" },
  { id: "updateserver", label: "Update Server", accent: "#2dd4bf" },
  { id: "backupserver", label: "Backup Server", accent: "#4ade80" },
  { id: "telephony", label: "Telephony Server", accent: "#fbbf24" },
  { id: "hypervisor", label: "Hypervisor", accent: "#c084fc" },
  // Storage & Data
  { id: "database", label: "Database", accent: "#f472b6" },
  { id: "san", label: "SAN", accent: "#e879f9" },
  { id: "nas", label: "NAS", accent: "#f472b6" },
  // Endpoints
  { id: "workstation", label: "Workstation", accent: "#38bdf8" },
  { id: "laptop", label: "Laptop", accent: "#60a5fa" },
  { id: "phone", label: "Phone", accent: "#34d399" },
  { id: "printer", label: "Printer", accent: "#94a3b8" },
  { id: "scanner", label: "Scanner", accent: "#94a3b8" },
  { id: "fax", label: "Fax", accent: "#94a3b8" },
  { id: "cardreader", label: "Card Reader", accent: "#fbbf24" },
  { id: "barcodereader", label: "Barcode Reader", accent: "#fbbf24" },
  { id: "iot", label: "IoT Device", accent: "#4ade80" },
  { id: "ot", label: "OT Device", accent: "#fb923c" },
  // People & Misc
  { id: "person", label: "Person", accent: "#60a5fa" },
  { id: "email", label: "Email", accent: "#38bdf8" },
  // Places & Orgs
  { id: "org", label: "Organisation", accent: "#5eead4" },
  { id: "building", label: "Building", accent: "#a3e635" },
  { id: "city", label: "City", accent: "#38bdf8" },
  { id: "location", label: "Location / Site", accent: "#34d399" },
  { id: "poi", label: "Place of Interest", accent: "#f59e0b" },
  // Threats
  { id: "threatactor", label: "Threat Actor", accent: "#f87171" },
  { id: "insider", label: "Insider Threat", accent: "#fb923c" },
  { id: "malware", label: "Malware", accent: "#ef4444" },
  { id: "ransomware", label: "Ransomware", accent: "#dc2626" },
  { id: "botnet", label: "Botnet", accent: "#e11d48" },
  { id: "phishing", label: "Phishing", accent: "#f43f5e" },
  { id: "c2", label: "C2 Server", accent: "#991b1b" },
  // Attack Techniques
  { id: "googledork", label: "Google Dorking", accent: "#fbbf24" },
  { id: "githubsearch", label: "GitHub Search", accent: "#94a3b8" },
  { id: "mobileapk", label: "Mobile APK", accent: "#4ade80" },
  { id: "shodan", label: "Shodan Search", accent: "#f43f5e" },
  { id: "leakedcred", label: "Leaked Credential", accent: "#f87171" },
  { id: "webvulnscan", label: "Web Vulnerability Assessment", accent: "#fb923c" },
  { id: "fileuploadvuln", label: "File Upload Vulnerability", accent: "#f59e0b" },
  { id: "exploit", label: "Exploitation", accent: "#ef4444" },
  { id: "sensitivedoc", label: "Sensitive Document", accent: "#e879f9" },
  { id: "enumeration", label: "Enumeration", accent: "#60a5fa" },
  { id: "exfiltrate", label: "Exfiltrate Data", accent: "#e11d48" },
  { id: "aiagent", label: "AI Agent", accent: "#a78bfa" },
  { id: "promptinjection", label: "Prompt Injection", accent: "#c084fc" },
  { id: "fileshare3p", label: "3rd Party File Sharing", accent: "#2dd4bf" },
  { id: "decrypt", label: "Decrypt", accent: "#34d399" },
  { id: "ssd", label: "Storage Device", accent: "#94a3b8" },
  { id: "domaincontroller", label: "Domain Controller", accent: "#a78bfa" },
  { id: "smb", label: "SMB Share", accent: "#818cf8" },
  { id: "configfile", label: "Config File", accent: "#fbbf24" },
  { id: "lateralmovement", label: "Lateral Movement", accent: "#fb923c" },
  { id: "privaccount", label: "Privileged Account", accent: "#f87171" },
  { id: "privesc", label: "Privilege Escalation", accent: "#dc2626" },
  { id: "activedirectory", label: "Active Directory", accent: "#818cf8" },
  { id: "defenseimpair", label: "Defense Impairment", accent: "#991b1b" },
  { id: "lan", label: "LAN Network", accent: "#60a5fa" },
  { id: "defaultcred", label: "Default Credential", accent: "#fbbf24" },
  { id: "physicalaccess", label: "Physical Access", accent: "#34d399" },
  { id: "masquerading", label: "Masquerading", accent: "#c084fc" },
  { id: "serverroomaccess", label: "Server Room Access", accent: "#a78bfa" },
  { id: "cloning", label: "Cloning", accent: "#5eead4" },
  { id: "idcard", label: "Employee ID Card", accent: "#38bdf8" },
  { id: "networksniffing", label: "Network Sniffing", accent: "#60a5fa" },
];

export const NODE_TYPE_MAP: Record<NodeTypeId, NodeTypeDef> = Object.fromEntries(
  NODE_TYPES.map((t) => [t.id, t])
) as Record<NodeTypeId, NodeTypeDef>;

export const PALETTE_GROUPS: PaletteGroup[] = [
  {
    title: "Network & Security",
    items: [
      "internet",
      "cloud",
      "router",
      "switch",
      "wifi",
      "asn",
      "ipaddress",
      "lan",
      "firewall",
      "waf",
      "proxy",
      "cdn",
      "loadbalancer",
      "apigateway",
      "ids",
      "siem",
      "vpn",
    ],
  },
  {
    title: "Infrastructure",
    items: [
      "server",
      "webserver",
      "appserver",
      "mgmtserver",
      "updateserver",
      "backupserver",
      "telephony",
      "hypervisor",
      "domaincontroller",
      "activedirectory",
      "database",
      "san",
      "nas",
      "ssd",
      "smb",
      "fileshare3p",
      "configfile",
    ],
  },
  {
    title: "Endpoints",
    items: [
      "workstation",
      "laptop",
      "phone",
      "printer",
      "scanner",
      "fax",
      "cardreader",
      "barcodereader",
      "iot",
      "ot",
      "mobileapk",
    ],
  },
  {
    title: "People & Places",
    items: ["person", "email", "idcard", "org", "building", "city", "location", "poi"],
  },
  {
    title: "Threats & TTPs",
    items: [
      "threatactor",
      "insider",
      "malware",
      "ransomware",
      "botnet",
      "phishing",
      "c2",
      "exploit",
      "fileuploadvuln",
      "webvulnscan",
      "leakedcred",
      "defaultcred",
      "sensitivedoc",
      "enumeration",
      "networksniffing",
      "exfiltrate",
      "decrypt",
      "lateralmovement",
      "privaccount",
      "privesc",
      "defenseimpair",
      "aiagent",
      "promptinjection",
      "googledork",
      "githubsearch",
      "shodan",
      "physicalaccess",
      "masquerading",
      "serverroomaccess",
      "cloning",
    ],
  },
];

export const DEFAULT_NODE_W = 140;
export const DEFAULT_NODE_H = 60;
export const MIN_NODE_W = 90;
export const MIN_NODE_H = 44;

const PLACE_TYPES = new Set<NodeTypeId>(["org", "building", "city", "location", "poi"]);

export function isPlaceType(type: NodeTypeId): boolean {
  return PLACE_TYPES.has(type);
}

const NON_OWNABLE_TYPES = new Set<NodeTypeId>([
  "internet",
  "cloud",
  "asn",
  "person",
  "threatactor",
  "insider",
  "malware",
  "ransomware",
  "botnet",
  "phishing",
  "c2",
  ...PLACE_TYPES,
]);

export function isOwnableType(type: NodeTypeId): boolean {
  return !NON_OWNABLE_TYPES.has(type);
}

const NON_TECHNICAL_TYPES = new Set<NodeTypeId>(["person", "email", "threatactor", "insider", ...PLACE_TYPES]);

export function isTechnicalType(type: NodeTypeId): boolean {
  return !NON_TECHNICAL_TYPES.has(type);
}

const NODE_HEADER_H = 46;
const NODE_LINE_H = 14;
const NODE_BOTTOM_PAD = 10;

export function computeNodeHeight(lineCount: number): number {
  if (lineCount <= 0) return DEFAULT_NODE_H;
  return NODE_HEADER_H + lineCount * NODE_LINE_H + NODE_BOTTOM_PAD;
}

export const ZONE_COLORS = [
  "#38bdf8",
  "#a78bfa",
  "#34d399",
  "#f59e0b",
  "#f472b6",
  "#2dd4bf",
  "#f87171",
  "#c084fc",
];

export interface DispositionDef {
  id: DispositionId;
  label: string;
  color: string;
}

export const DISPOSITIONS: DispositionDef[] = [
  { id: "friendly", label: "Friendly", color: "#38bdf8" },
  { id: "partner", label: "Partner", color: "#2dd4bf" },
  { id: "neutral", label: "Neutral", color: "#8b9bb4" },
  { id: "unknown", label: "Unknown", color: "#facc15" },
  { id: "suspicious", label: "Suspicious", color: "#fb923c" },
  { id: "adversary", label: "Adversary", color: "#f87171" },
  { id: "victim", label: "Victim", color: "#c084fc" },
];

export const DISPOSITION_MAP: Record<DispositionId, DispositionDef> = Object.fromEntries(
  DISPOSITIONS.map((d) => [d.id, d])
) as Record<DispositionId, DispositionDef>;

export interface StatusDef {
  id: StatusId;
  label: string;
  color: string;
}

export const STATUSES: StatusDef[] = [
  { id: "issue", label: "Issue", color: "#fbbf24" },
  { id: "vulnerable", label: "Vulnerable", color: "#fb923c" },
  { id: "suspicious_activity", label: "Suspicious Activity", color: "#f59e0b" },
  { id: "outage", label: "Outage", color: "#94a3b8" },
  { id: "ddos", label: "DDoS", color: "#f87171" },
  { id: "exploited", label: "Exploited", color: "#ef4444" },
  { id: "malware_infection", label: "Malware Infection", color: "#dc2626" },
  { id: "data_exfiltration", label: "Data Exfiltration", color: "#e11d48" },
  { id: "data_breach", label: "Data Breach", color: "#be123c" },
  { id: "compromised", label: "Compromised", color: "#991b1b" },
];

export const STATUS_MAP: Record<StatusId, StatusDef> = Object.fromEntries(
  STATUSES.map((s) => [s.id, s])
) as Record<StatusId, StatusDef>;
