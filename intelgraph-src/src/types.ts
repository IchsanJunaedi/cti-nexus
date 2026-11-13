export type NodeTypeId =
  // Network
  | "internet"
  | "cloud"
  | "router"
  | "switch"
  | "wifi"
  | "asn"
  | "ipaddress"
  // Security & Edge
  | "firewall"
  | "waf"
  | "proxy"
  | "cdn"
  | "loadbalancer"
  | "apigateway"
  | "ids"
  | "siem"
  | "vpn"
  // Servers
  | "server"
  | "webserver"
  | "appserver"
  | "mgmtserver"
  | "updateserver"
  | "backupserver"
  | "telephony"
  | "hypervisor"
  // Storage & Data
  | "database"
  | "san"
  | "nas"
  // Endpoints
  | "workstation"
  | "laptop"
  | "phone"
  | "printer"
  | "scanner"
  | "fax"
  | "cardreader"
  | "barcodereader"
  | "iot"
  | "ot"
  // People & Misc
  | "person"
  | "email"
  // Places & Orgs
  | "org"
  | "building"
  | "city"
  | "location"
  | "poi"
  // Threats
  | "threatactor"
  | "insider"
  | "malware"
  | "ransomware"
  | "botnet"
  | "phishing"
  | "c2"
  // Attack Techniques
  | "googledork"
  | "githubsearch"
  | "mobileapk"
  | "shodan"
  | "leakedcred"
  | "webvulnscan"
  | "fileuploadvuln"
  | "exploit"
  | "sensitivedoc"
  | "enumeration"
  | "exfiltrate"
  | "aiagent"
  | "promptinjection"
  | "fileshare3p"
  | "decrypt"
  | "ssd"
  | "domaincontroller"
  | "smb"
  | "configfile"
  | "lateralmovement"
  | "privaccount"
  | "privesc"
  | "activedirectory"
  | "defenseimpair"
  | "lan"
  | "defaultcred"
  | "physicalaccess"
  | "masquerading"
  | "serverroomaccess"
  | "cloning"
  | "idcard"
  | "networksniffing";

export interface NodeTypeDef {
  id: NodeTypeId;
  label: string;
  accent: string;
}

export interface PaletteGroup {
  title: string;
  items: NodeTypeId[];
}

export interface NodeMeta {
  ip?: string;
  hostname?: string;
  owner?: string;
  address?: string;
  coords?: string;
  notes?: string;
}

export type DispositionId =
  | "friendly"
  | "partner"
  | "neutral"
  | "unknown"
  | "suspicious"
  | "adversary"
  | "victim";

export type StatusId =
  | "issue"
  | "vulnerable"
  | "suspicious_activity"
  | "outage"
  | "ddos"
  | "exploited"
  | "malware_infection"
  | "data_exfiltration"
  | "data_breach"
  | "compromised";

export interface DiagramNode {
  id: string;
  type: NodeTypeId;
  x: number;
  y: number;
  w: number;
  h: number;
  label: string;
  /** Set once the user drags a resize handle; height then stops auto-fitting to meta content. */
  manualSize?: boolean;
  meta?: NodeMeta;
  disposition?: DispositionId;
  status?: StatusId[];
}

export type ArrowStyle = "none" | "end" | "both";
export type LineStyle = "solid" | "dashed" | "dotted" | "sneakernet";
export type FlowDirection = "one" | "both";

export interface DiagramEdge {
  id: string;
  from: string;
  to: string;
  label?: string;
  arrow?: ArrowStyle;
  lineStyle?: LineStyle;
  animated?: boolean;
  flowDirection?: FlowDirection;
  /** Signed bow of the curve, as a fraction of the a-to-b distance. Absent = default gentle curve. */
  curve?: number;
}

export interface Zone {
  id: string;
  x: number;
  y: number;
  w: number;
  h: number;
  label: string;
  color: string;
}

export type Tool = "select" | "connect" | "pan" | "zone";

export interface ViewState {
  x: number;
  y: number;
  k: number;
}

export interface DiagramState {
  nodes: DiagramNode[];
  edges: DiagramEdge[];
  zones: Zone[];
}

export type Anchor = { x: number; y: number };

export interface ScenarioStep {
  id: string;
  order: number;
  note: string;
  nodeIds: string[];
  edgeIds: string[];
  createdAt: string;
}

export interface Scenario {
  id: string;
  name: string;
  description: string;
  diagramId: string;
  steps: ScenarioStep[];
  version: number;
  createdAt: string;
  updatedAt: string;
}

export interface ScenarioSummary {
  id: string;
  name: string;
  description: string;
  diagramId: string;
  stepCount: number;
  updatedAt: string;
}
