import type { CoverageItem, HuntSession, Playbook } from "./types";

const API_URL = (import.meta.env.VITE_API_URL ?? "/api").replace(/\/$/, "");

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_URL}${path}`, {
    headers: { "Content-Type": "application/json", ...init?.headers },
    ...init,
  });
  if (!response.ok) {
    throw new Error(`API request failed: ${response.status}`);
  }
  return response.json() as Promise<T>;
}

async function requestEmpty(path: string, init?: RequestInit): Promise<void> {
  const response = await fetch(`${API_URL}${path}`, {
    headers: { "Content-Type": "application/json", ...init?.headers },
    ...init,
  });
  if (!response.ok) {
    throw new Error(`API request failed: ${response.status}`);
  }
}

export type PlaybookPayload = Omit<Playbook, "id" | "created_at" | "steps" | "queries"> & {
  steps: { title: string; instruction: string }[];
  queries: { platform: string; query: string }[];
};

export const api = {
  playbooks: () => request<Playbook[]>("/playbooks"),
  sessions: () => request<HuntSession[]>("/sessions"),
  coverage: () => request<CoverageItem[]>("/coverage"),
  createPlaybook: (payload: PlaybookPayload) =>
    request<Playbook>("/playbooks", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  updatePlaybook: (playbookId: number, payload: PlaybookPayload) =>
    request<Playbook>(`/playbooks/${playbookId}`, {
      method: "PUT",
      body: JSON.stringify(payload),
    }),
  deletePlaybook: (playbookId: number) =>
    requestEmpty(`/playbooks/${playbookId}`, {
      method: "DELETE",
    }),
  startSession: (playbookId: number, analyst: string, scope: string) =>
    request<HuntSession>("/sessions", {
      method: "POST",
      body: JSON.stringify({
        playbook_id: playbookId,
        analyst,
        scope,
      }),
    }),
  updateSession: (
    sessionId: number,
    payload: Pick<HuntSession, "title" | "analyst" | "scope" | "status">,
  ) =>
    request<HuntSession>(`/sessions/${sessionId}`, {
      method: "PATCH",
      body: JSON.stringify(payload),
    }),
  deleteSession: (sessionId: number) =>
    requestEmpty(`/sessions/${sessionId}`, {
      method: "DELETE",
    }),
  updateStep: (stepId: number, status: HuntSession["steps"][number]["status"], notes: string) =>
    request<HuntSession["steps"][number]>(`/session-steps/${stepId}`, {
      method: "PATCH",
      body: JSON.stringify({ status, notes }),
    }),
  addEvidence: (sessionId: number, payload: { title: string; note: string; artifact_ref: string }) =>
    request<HuntSession["evidence"][number]>(`/sessions/${sessionId}/evidence`, {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  updateEvidence: (evidenceId: number, payload: { title: string; note: string; artifact_ref: string }) =>
    request<HuntSession["evidence"][number]>(`/evidence/${evidenceId}`, {
      method: "PATCH",
      body: JSON.stringify(payload),
    }),
  deleteEvidence: (evidenceId: number) =>
    requestEmpty(`/evidence/${evidenceId}`, {
      method: "DELETE",
    }),
  reportUrl: (sessionId: number) => `${API_URL}/sessions/${sessionId}/report.md`,
};
