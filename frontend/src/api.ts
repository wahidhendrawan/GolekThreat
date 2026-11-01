import type { CoverageItem, HuntSession, Playbook } from "./types";

const API_URL = (import.meta.env.VITE_API_URL ?? "/api").replace(/\/$/, "");

const TOKEN_KEY = "golekthreat.apiToken";

function apiToken(): string {
  let token = sessionStorage.getItem(TOKEN_KEY);
  if (!token) {
    token = window.prompt("GolekThreat API token (GOLEK_API_TOKEN)")?.trim() ?? "";
    if (token) sessionStorage.setItem(TOKEN_KEY, token);
  }
  return token;
}

async function send(path: string, init?: RequestInit, retry = true): Promise<Response> {
  const token = apiToken();
  const response = await fetch(`${API_URL}${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}`, ...init?.headers },
  });
  if (response.status === 401 && retry) {
    // Only forget the token this request used, so parallel 401s prompt once.
    if (sessionStorage.getItem(TOKEN_KEY) === token) sessionStorage.removeItem(TOKEN_KEY);
    return send(path, init, false);
  }
  if (!response.ok) {
    throw new Error(`API request failed: ${response.status}`);
  }
  return response;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  return (await send(path, init)).json() as Promise<T>;
}

async function requestEmpty(path: string, init?: RequestInit): Promise<void> {
  await send(path, init);
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
  report: async (sessionId: number) => (await send(`/sessions/${sessionId}/report.md`)).text(),
};
