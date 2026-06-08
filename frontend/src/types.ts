export type Playbook = {
  id: number;
  slug: string;
  title: string;
  hypothesis: string;
  severity: "low" | "medium" | "high" | "critical";
  tactic: string;
  technique: string;
  technique_id: string;
  data_sources: string;
  expected_evidence: string;
  false_positives: string;
  response: string;
  created_at: string;
  steps: { id: number; position: number; title: string; instruction: string }[];
  queries: { id: number; platform: string; query: string }[];
};

export type HuntSession = {
  id: number;
  title: string;
  analyst: string;
  scope: string;
  status: "running" | "completed" | "archived";
  started_at: string;
  playbook: Playbook;
  steps: {
    id: number;
    position: number;
    title: string;
    instruction: string;
    status: "pending" | "running" | "evidence_found" | "false_positive" | "no_finding";
    notes: string;
  }[];
  evidence: {
    id: number;
    title: string;
    note: string;
    artifact_ref: string;
    created_at: string;
  }[];
};

export type CoverageItem = {
  tactic: string;
  technique_id: string;
  technique: string;
  playbook_count: number;
};
