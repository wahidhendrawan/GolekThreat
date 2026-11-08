import type { CoverageItem, HuntSession, Playbook } from "./types";

const API_URL = (import.meta.env.VITE_API_URL ?? "/api").replace(/\/$/, "");

const SESSION_KEY = "golekthreat.session";
export const UNAUTHORIZED_EVENT = "golekthreat:unauthorized";

export type Session = { token: string; username: string; role: "viewer" | "analyst" | "admin" };

export function storedSession(): Session | null {
  const raw = sessionStorage.getItem(SESSION_KEY);
  return raw ? (JSON.parse(raw) as Session) : null;
}

export function clearSession(): void {
  sessionStorage.removeItem(SESSION_KEY);
}

export async function login(username: string, password: string): Promise<Session> {
  const response = await fetch(`${API_URL}/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  if (!response.ok) {
    throw new Error(response.status === 401 ? "Invalid username or password" : `Login failed: ${response.status}`);
  }
  const session = (await response.json()) as Session;
  sessionStorage.setItem(SESSION_KEY, JSON.stringify(session));
  return session;
}

export async function logout(): Promise<void> {
  const session = storedSession();
  clearSession();
  if (session) {
    await fetch(`${API_URL}/auth/logout`, {
      method: "POST",
      headers: { Authorization: `Bearer ${session.token}` },
    }).catch(() => undefined);
  }
}

async function send(path: string, init?: RequestInit): Promise<Response> {
  const token = storedSession()?.token ?? "";
  const response = await fetch(`${API_URL}${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}`, ...init?.headers },
  });
  if (response.status === 401) {
    // Token expired or revoked: back to the sign-in screen.
    clearSession();
    window.dispatchEvent(new Event(UNAUTHORIZED_EVENT));
    throw new Error("Session expired, sign in again");
  }
  if (response.status === 403) {
    throw new Error("Your role does not allow this action");
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
