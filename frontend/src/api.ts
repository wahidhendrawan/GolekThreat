import type { CoverageItem, HuntSession, Playbook } from "./types";

const API_URL = import.meta.env.VITE_API_URL ?? "http://localhost:8000";

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

export const api = {
  playbooks: () => request<Playbook[]>("/playbooks"),
  sessions: () => request<HuntSession[]>("/sessions"),
  coverage: () => request<CoverageItem[]>("/coverage"),
  startSession: (playbookId: number) =>
    request<HuntSession>("/sessions", {
      method: "POST",
      body: JSON.stringify({
        playbook_id: playbookId,
        analyst: "GolekThreat Analyst",
        scope: "Initial hunt scope",
      }),
    }),
  reportUrl: (sessionId: number) => `${API_URL}/sessions/${sessionId}/report.md`,
};
