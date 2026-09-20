export type Level = "critical" | "high" | "medium" | "low";

export interface Summary {
  counts: Record<Level, number>;
  total_packages: number;
  direct_packages: number;
  vulnerable_packages: number;
  total_findings: number;
  overall_score: number;
  headline?: string;
  warnings?: string[];
}

export interface Scan {
  id: number;
  name: string;
  source_type: "github" | "upload";
  repo_url: string | null;
  sensitive: boolean;
  status: "queued" | "running" | "done" | "failed";
  error: string | null;
  summary: Summary | null;
  created_at: string;
}

export interface Finding {
  id: number;
  package_key: string;
  package: string;
  version: string;
  ecosystem: string;
  vuln_id: string;
  aliases: string[];
  summary: string;
  cvss: number;
  severity: string;
  fixed_versions: string[];
  recommended_fix: string | null;
  is_direct: boolean;
  is_dev: boolean;
  reachable: boolean;
  path: string[];
  apps: string[];
  anomaly: boolean;
  risk_score: number;
  risk_level: Level;
  reasons: string[];
  ai_explanation: string | null;
}

export interface GraphNode {
  key: string;
  name: string;
  version: string;
  ecosystem: string;
  direct: boolean;
  dev: boolean;
  depth: number;
  risk: number;
  level: Level | null;
  vuln_count: number;
}

export interface GraphData {
  truncated: boolean;
  nodes: GraphNode[];
  edges: { source: string; target: string }[];
}

export interface Simulation {
  before: { counts: Record<Level, number>; overall_score: number; total_findings: number };
  after: { counts: Record<Level, number>; overall_score: number; total_findings: number };
  resolved: string[];
  introduced: string[];
}
