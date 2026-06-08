import {
  Activity,
  CheckCircle2,
  ClipboardList,
  Crosshair,
  Database,
  FileText,
  Loader2,
  Pencil,
  Play,
  Save,
  Search,
  ShieldCheck,
  Trash2,
} from "lucide-react";
import { StrictMode, type FormEvent, useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import { api, type PlaybookPayload } from "./api";
import { mitreCatalog } from "./mitreCatalog";
import "./styles.css";
import type { CoverageItem, HuntSession, Playbook } from "./types";

type StepStatus = HuntSession["steps"][number]["status"];
type SessionStatus = HuntSession["status"];

const stepStatuses: StepStatus[] = [
  "pending",
  "running",
  "evidence_found",
  "false_positive",
  "no_finding",
];
const sessionStatuses: SessionStatus[] = ["running", "completed", "archived"];

const emptyPlaybook = {
  id: 0,
  slug: "",
  title: "",
  hypothesis: "",
  severity: "medium" as Playbook["severity"],
  tactic: "",
  technique: "",
  technique_id: "",
  data_sources: "",
  expected_evidence: "",
  false_positives: "",
  response: "",
  stepsText: "Review relevant telemetry | Identify suspicious events and record context",
  queriesText: "Sigma | title: Suspicious activity",
};

function App() {
  const [playbooks, setPlaybooks] = useState<Playbook[]>([]);
  const [sessions, setSessions] = useState<HuntSession[]>([]);
  const [coverage, setCoverage] = useState<CoverageItem[]>([]);
  const [selectedSessionId, setSelectedSessionId] = useState<number | null>(null);
  const [selectedPlaybookId, setSelectedPlaybookId] = useState<number | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [stepNotes, setStepNotes] = useState<Record<number, string>>({});
  const [sessionForm, setSessionForm] = useState({
    title: "",
    analyst: "GolekThreat Analyst",
    scope: "Initial hunt scope",
    status: "running" as SessionStatus,
  });
  const [evidence, setEvidence] = useState({ title: "", note: "", artifact_ref: "" });
  const [evidenceDrafts, setEvidenceDrafts] = useState<Record<number, typeof evidence>>({});
  const [playbookForm, setPlaybookForm] = useState(emptyPlaybook);
  const [mitreFilter, setMitreFilter] = useState("");

  const load = async () => {
    setLoading(true);
    try {
      const [playbookData, sessionData, coverageData] = await Promise.all([
        api.playbooks(),
        api.sessions(),
        api.coverage(),
      ]);
      setPlaybooks(playbookData);
      setSessions(sessionData);
      setCoverage(coverageData);
      setSelectedSessionId((current) => current ?? sessionData[0]?.id ?? null);
      setSelectedPlaybookId((current) => current ?? playbookData[0]?.id ?? null);
      setStepNotes(Object.fromEntries(sessionData.flatMap((session) => session.steps.map((step) => [step.id, step.notes]))));
      setEvidenceDrafts(
        Object.fromEntries(
          sessionData.flatMap((session) =>
            session.evidence.map((item) => [
              item.id,
              { title: item.title, note: item.note, artifact_ref: item.artifact_ref },
            ]),
          ),
        ),
      );
      setError("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown API error");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void load();
  }, []);

  const selectedSession = useMemo(
    () => sessions.find((session) => session.id === selectedSessionId) ?? sessions[0],
    [selectedSessionId, sessions],
  );

  const selectedPlaybook = useMemo(
    () => playbooks.find((playbook) => playbook.id === selectedPlaybookId) ?? playbooks[0],
    [selectedPlaybookId, playbooks],
  );

  useEffect(() => {
    if (selectedSession) {
      setSessionForm({
        title: selectedSession.title,
        analyst: selectedSession.analyst,
        scope: selectedSession.scope,
        status: selectedSession.status,
      });
    }
  }, [selectedSession?.id]);

  useEffect(() => {
    if (selectedPlaybook) {
      setPlaybookForm({
        ...selectedPlaybook,
        stepsText: selectedPlaybook.steps.map((step) => `${step.title} | ${step.instruction}`).join("\n"),
        queriesText: selectedPlaybook.queries.map((query) => `${query.platform} | ${query.query}`).join("\n"),
      });
    }
  }, [selectedPlaybook?.id]);

  const criticalCount = playbooks.filter((playbook) => playbook.severity === "critical").length;
  const completedSteps = selectedSession?.steps.filter((step) => step.status !== "pending").length ?? 0;
  const runningSessions = sessions.filter((session) => session.status === "running").length;
  const completedSessions = sessions.filter((session) => session.status === "completed").length;
  const archivedSessions = sessions.filter((session) => session.status === "archived").length;
  const filteredMitreCatalog = mitreCatalog.filter((item) =>
    `${item.tactic} ${item.technique_id} ${item.technique}`.toLowerCase().includes(mitreFilter.toLowerCase()),
  );
  const selectedMitreTechnique = mitreCatalog.find((item) => item.technique_id === playbookForm.technique_id);

  const run = async (key: string, task: () => Promise<void>, success: string) => {
    setBusy(key);
    setNotice("");
    try {
      await task();
      setNotice(success);
      setError("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Request failed");
    } finally {
      setBusy("");
    }
  };

  const parseRows = (text: string) =>
    text
      .split("\n")
      .map((line) => line.trim())
      .filter(Boolean)
      .map((line) => {
        const [left, ...right] = line.split("|");
        return [left.trim(), right.join("|").trim()];
      });

  const playbookPayload = (): PlaybookPayload => ({
    slug: playbookForm.slug.trim(),
    title: playbookForm.title.trim(),
    hypothesis: playbookForm.hypothesis.trim(),
    severity: playbookForm.severity,
    tactic: playbookForm.tactic.trim(),
    technique: playbookForm.technique.trim(),
    technique_id: playbookForm.technique_id.trim(),
    data_sources: playbookForm.data_sources.trim(),
    expected_evidence: playbookForm.expected_evidence.trim(),
    false_positives: playbookForm.false_positives.trim(),
    response: playbookForm.response.trim(),
    steps: parseRows(playbookForm.stepsText).map(([title, instruction]) => ({ title, instruction })),
    queries: parseRows(playbookForm.queriesText).map(([platform, query]) => ({ platform, query })),
  });

  const applyMitreTechnique = (techniqueId: string) => {
    const mapping = mitreCatalog.find((item) => item.technique_id === techniqueId);
    if (!mapping) return;
    setPlaybookForm((current) => ({
      ...current,
      tactic: mapping.tactic,
      technique_id: mapping.technique_id,
      technique: mapping.technique,
      data_sources: current.data_sources || mapping.data_sources,
      expected_evidence: current.expected_evidence || mapping.expected_evidence,
      false_positives: current.false_positives || mapping.false_positives,
      response: current.response || mapping.response,
      stepsText: current.stepsText === emptyPlaybook.stepsText || !current.stepsText ? mapping.steps.join("\n") : current.stepsText,
      queriesText: current.queriesText === emptyPlaybook.queriesText || !current.queriesText ? mapping.queries.join("\n") : current.queriesText,
    }));
  };

  const savePlaybook = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    await run(
      "playbook-save",
      async () => {
        const payload = playbookPayload();
        const saved = playbookForm.id ? await api.updatePlaybook(playbookForm.id, payload) : await api.createPlaybook(payload);
        await load();
        setSelectedPlaybookId(saved.id);
      },
      playbookForm.id ? "Playbook updated." : "Playbook created.",
    );
  };

  const startSession = async () => {
    if (!selectedPlaybook) return;
    await run(
      "session-start",
      async () => {
        const session = await api.startSession(selectedPlaybook.id, sessionForm.analyst, sessionForm.scope);
        await load();
        setSelectedSessionId(session.id);
      },
      "Hunt session started.",
    );
  };

  const saveSession = async () => {
    if (!selectedSession) return;
    await run(
      "session-save",
      async () => {
        await api.updateSession(selectedSession.id, sessionForm);
        await load();
        setSelectedSessionId(selectedSession.id);
      },
      "Session updated.",
    );
  };

  const deleteSession = async () => {
    if (!selectedSession || !confirm(`Delete session "${selectedSession.title}"?`)) return;
    await run(
      "session-delete",
      async () => {
        await api.deleteSession(selectedSession.id);
        setSelectedSessionId(null);
        await load();
      },
      "Session deleted.",
    );
  };

  const updateStep = async (stepId: number, status: StepStatus) => {
    await run(
      `step-${stepId}`,
      async () => {
        await api.updateStep(stepId, status, stepNotes[stepId] ?? "");
        await load();
      },
      "Step updated.",
    );
  };

  const addEvidence = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!selectedSession || !evidence.title.trim() || !evidence.note.trim()) return;
    await run(
      "evidence-add",
      async () => {
        await api.addEvidence(selectedSession.id, evidence);
        setEvidence({ title: "", note: "", artifact_ref: "" });
        await load();
        setSelectedSessionId(selectedSession.id);
      },
      "Evidence added.",
    );
  };

  const updateEvidence = async (evidenceId: number) => {
    await run(
      `evidence-${evidenceId}`,
      async () => {
        await api.updateEvidence(evidenceId, evidenceDrafts[evidenceId]);
        await load();
      },
      "Evidence updated.",
    );
  };

  const deleteEvidence = async (evidenceId: number) => {
    if (!confirm("Delete this evidence item?")) return;
    await run(
      `evidence-${evidenceId}`,
      async () => {
        await api.deleteEvidence(evidenceId);
        await load();
      },
      "Evidence deleted.",
    );
  };

  const deletePlaybook = async () => {
    if (!selectedPlaybook || !confirm(`Delete playbook "${selectedPlaybook.title}"?`)) return;
    await run(
      "playbook-delete",
      async () => {
        await api.deletePlaybook(selectedPlaybook.id);
        setSelectedPlaybookId(null);
        setPlaybookForm(emptyPlaybook);
        await load();
      },
      "Playbook deleted.",
    );
  };

  return (
    <main>
      <header className="topbar">
        <div>
          <p className="eyebrow">GolekThreat</p>
          <h1>Threat hunt management console</h1>
        </div>
        <div className="health">
          {loading ? <Loader2 size={16} className="spin" /> : <ShieldCheck size={16} />}
          <span>{loading ? "Loading API data" : "API connected"}</span>
        </div>
      </header>

      {error && <div className="alert">API error: {error}</div>}
      {notice && <div className="notice">{notice}</div>}

      <section className="metrics">
        <Metric icon={<ClipboardList />} label="Playbooks" value={playbooks.length} />
        <Metric icon={<Crosshair />} label="Critical Hunts" value={criticalCount} />
        <Metric icon={<Activity />} label="Running Hunts" value={runningSessions} />
        <Metric icon={<Database />} label="ATT&CK Coverage" value={coverage.length} />
      </section>

      <section className="management-grid">
        <section className="panel">
          <div className="panel-header">
            <div>
              <p className="eyebrow">Playbook Management</p>
              <h2>Library</h2>
            </div>
            <button className="button secondary inline" onClick={() => setPlaybookForm(emptyPlaybook)}>
              <Pencil size={16} />
              New
            </button>
          </div>

          <div className="selector-list">
            {playbooks.map((playbook) => (
              <button
                key={playbook.id}
                className={playbook.id === selectedPlaybook?.id ? "active" : ""}
                onClick={() => setSelectedPlaybookId(playbook.id)}
              >
                <span className={`severity ${playbook.severity}`}>{playbook.severity}</span>
                <strong>{playbook.title}</strong>
                <small>{playbook.technique_id}</small>
              </button>
            ))}
          </div>

          <form className="form-grid" onSubmit={(event) => void savePlaybook(event)}>
            <input value={playbookForm.slug} onChange={(event) => setPlaybookForm((current) => ({ ...current, slug: event.target.value }))} placeholder="Slug" required />
            <input value={playbookForm.title} onChange={(event) => setPlaybookForm((current) => ({ ...current, title: event.target.value }))} placeholder="Title" required />
            <select value={playbookForm.severity} onChange={(event) => setPlaybookForm((current) => ({ ...current, severity: event.target.value as Playbook["severity"] }))}>
              {["low", "medium", "high", "critical"].map((severity) => (
                <option key={severity} value={severity}>{severity}</option>
              ))}
            </select>
            <div className="mitre-picker">
              <div className="search-field">
                <Search size={16} />
                <input value={mitreFilter} onChange={(event) => setMitreFilter(event.target.value)} placeholder="Search MITRE tactic or technique" />
              </div>
              <select value={playbookForm.technique_id} onChange={(event) => applyMitreTechnique(event.target.value)} required>
                <option value="">Select ATT&CK technique</option>
                {playbookForm.technique_id && !filteredMitreCatalog.some((item) => item.technique_id === playbookForm.technique_id) && (
                  <option value={playbookForm.technique_id}>
                    {playbookForm.technique_id} - {playbookForm.technique} ({playbookForm.tactic})
                  </option>
                )}
                {filteredMitreCatalog.map((item) => (
                  <option key={item.technique_id} value={item.technique_id}>
                    {item.technique_id} - {item.technique} ({item.tactic})
                  </option>
                ))}
              </select>
              <div className="mapping-preview">
                <span>{playbookForm.tactic || "No tactic selected"}</span>
                <strong>{playbookForm.technique_id || "Technique ID"}</strong>
                <p>{playbookForm.technique || "Select a MITRE ATT&CK technique to auto-fill the mapping and hunting helper fields."}</p>
                <small>{filteredMitreCatalog.length} ATT&CK techniques match the current filter.</small>
                {selectedMitreTechnique && (
                  <a href={selectedMitreTechnique.url} target="_blank" rel="noreferrer">
                    Open MITRE reference
                  </a>
                )}
              </div>
            </div>
            <textarea value={playbookForm.hypothesis} onChange={(event) => setPlaybookForm((current) => ({ ...current, hypothesis: event.target.value }))} placeholder="Hypothesis" required />
            <textarea value={playbookForm.data_sources} onChange={(event) => setPlaybookForm((current) => ({ ...current, data_sources: event.target.value }))} placeholder="Data sources" required />
            <textarea value={playbookForm.expected_evidence} onChange={(event) => setPlaybookForm((current) => ({ ...current, expected_evidence: event.target.value }))} placeholder="Expected evidence" required />
            <textarea value={playbookForm.false_positives} onChange={(event) => setPlaybookForm((current) => ({ ...current, false_positives: event.target.value }))} placeholder="False positives" required />
            <textarea value={playbookForm.response} onChange={(event) => setPlaybookForm((current) => ({ ...current, response: event.target.value }))} placeholder="Response recommendation" required />
            <textarea value={playbookForm.stepsText} onChange={(event) => setPlaybookForm((current) => ({ ...current, stepsText: event.target.value }))} placeholder="Steps: Title | Instruction" required />
            <textarea value={playbookForm.queriesText} onChange={(event) => setPlaybookForm((current) => ({ ...current, queriesText: event.target.value }))} placeholder="Queries: Platform | Query" />
            <div className="action-row">
              <button className="button inline" disabled={busy === "playbook-save"}>
                {busy === "playbook-save" ? <Loader2 size={16} className="spin" /> : <Save size={16} />}
                Save playbook
              </button>
              {playbookForm.id > 0 && (
                <button type="button" className="button danger inline" onClick={() => void deletePlaybook()} disabled={busy === "playbook-delete"}>
                  <Trash2 size={16} />
                  Delete
                </button>
              )}
            </div>
          </form>
        </section>

        <section className="panel">
          <div className="panel-header">
            <div>
              <p className="eyebrow">Session Management</p>
              <h2>Hunts</h2>
            </div>
            <button className="button secondary inline" onClick={() => void startSession()} disabled={!selectedPlaybook || busy === "session-start"}>
              {busy === "session-start" ? <Loader2 size={16} className="spin" /> : <Play size={16} />}
              Start
            </button>
          </div>

          <div className="session-tabs" aria-label="Hunt sessions">
            {sessions.length === 0 && <p className="muted">No sessions yet.</p>}
            {sessions.map((session) => (
              <button key={session.id} className={session.id === selectedSession?.id ? "active" : ""} onClick={() => setSelectedSessionId(session.id)}>
                {session.playbook.technique_id}
                <span>{session.status}</span>
              </button>
            ))}
          </div>

          <div className="task-summary">
            <div>
              <strong>{runningSessions}</strong>
              <span>running</span>
            </div>
            <div>
              <strong>{completedSessions}</strong>
              <span>completed</span>
            </div>
            <div>
              <strong>{archivedSessions}</strong>
              <span>archived</span>
            </div>
          </div>

          <div className="task-list">
            {sessions.length === 0 && <div className="empty-state">No hunt tasks yet. Select a playbook and start a session.</div>}
            {sessions.map((session) => {
              const done = session.steps.filter((step) => step.status !== "pending").length;
              const progress = session.steps.length ? Math.round((done / session.steps.length) * 100) : 0;
              return (
                <button
                  key={session.id}
                  className={session.id === selectedSession?.id ? "task-card active" : "task-card"}
                  onClick={() => setSelectedSessionId(session.id)}
                >
                  <div>
                    <span className={`task-status ${session.status}`}>{session.status}</span>
                    <strong>{session.title}</strong>
                    <small>{session.analyst} | {session.scope}</small>
                  </div>
                  <div className="task-meta">
                    <span>{session.playbook.technique_id}</span>
                    <b>{progress}%</b>
                  </div>
                </button>
              );
            })}
          </div>

          <div className="session-editor">
            <input value={sessionForm.analyst} onChange={(event) => setSessionForm((current) => ({ ...current, analyst: event.target.value }))} placeholder="Analyst" />
            <input value={sessionForm.scope} onChange={(event) => setSessionForm((current) => ({ ...current, scope: event.target.value }))} placeholder="Scope" />
            {selectedSession && (
              <>
                <input value={sessionForm.title} onChange={(event) => setSessionForm((current) => ({ ...current, title: event.target.value }))} placeholder="Session title" />
                <select value={sessionForm.status} onChange={(event) => setSessionForm((current) => ({ ...current, status: event.target.value as SessionStatus }))}>
                  {sessionStatuses.map((status) => (
                    <option key={status} value={status}>{status}</option>
                  ))}
                </select>
                <button className="button inline" onClick={() => void saveSession()} disabled={busy === "session-save"}>
                  <Save size={16} />
                  Save session
                </button>
                <button className="button danger inline" onClick={() => void deleteSession()} disabled={busy === "session-delete"}>
                  <Trash2 size={16} />
                  Delete session
                </button>
              </>
            )}
          </div>

          {selectedSession ? (
            <>
              <div className="session-summary">
                <div>
                  <h3>{selectedSession.title}</h3>
                  <p>{selectedSession.playbook.technique} across {selectedSession.playbook.data_sources}</p>
                </div>
                <div className="progress">
                  <strong>{completedSteps}/{selectedSession.steps.length}</strong>
                  <span>steps touched</span>
                </div>
                <a href={api.reportUrl(selectedSession.id)} target="_blank" rel="noreferrer" className="button secondary inline">
                  <FileText size={16} />
                  Report
                </a>
              </div>

              <div className="step-list">
                {selectedSession.steps.map((step) => (
                  <article className="step" key={step.id}>
                    <div className="step-title">
                      <CheckCircle2 size={18} />
                      <div>
                        <span>Step {step.position}</span>
                        <h3>{step.title}</h3>
                        <p>{step.instruction}</p>
                      </div>
                    </div>
                    <div className="step-controls">
                      <select value={step.status} onChange={(event) => void updateStep(step.id, event.target.value as StepStatus)}>
                        {stepStatuses.map((status) => (
                          <option value={status} key={status}>{status.replace("_", " ")}</option>
                        ))}
                      </select>
                      <input value={stepNotes[step.id] ?? ""} onChange={(event) => setStepNotes((current) => ({ ...current, [step.id]: event.target.value }))} placeholder="Analyst notes" />
                      <button className="icon-button" onClick={() => void updateStep(step.id, step.status)} disabled={busy === `step-${step.id}`} title="Save notes">
                        {busy === `step-${step.id}` ? <Loader2 size={16} className="spin" /> : <Save size={16} />}
                      </button>
                    </div>
                  </article>
                ))}
              </div>

              <div className="evidence-grid">
                <form className="evidence-form" onSubmit={(event) => void addEvidence(event)}>
                  <h3>Add evidence</h3>
                  <input value={evidence.title} onChange={(event) => setEvidence((current) => ({ ...current, title: event.target.value }))} placeholder="Evidence title" />
                  <textarea value={evidence.note} onChange={(event) => setEvidence((current) => ({ ...current, note: event.target.value }))} placeholder="Finding, context, and analyst judgement" />
                  <input value={evidence.artifact_ref} onChange={(event) => setEvidence((current) => ({ ...current, artifact_ref: event.target.value }))} placeholder="Artifact reference" />
                  <button className="button" disabled={busy === "evidence-add" || !evidence.title.trim() || !evidence.note.trim()}>
                    {busy === "evidence-add" ? <Loader2 size={16} className="spin" /> : <Save size={16} />}
                    Save evidence
                  </button>
                </form>
                <div className="evidence-list">
                  <h3>Evidence log</h3>
                  {selectedSession.evidence.length === 0 && <p className="muted">No evidence recorded.</p>}
                  {selectedSession.evidence.map((item) => (
                    <article key={item.id}>
                      <input value={evidenceDrafts[item.id]?.title ?? ""} onChange={(event) => setEvidenceDrafts((current) => ({ ...current, [item.id]: { ...current[item.id], title: event.target.value } }))} />
                      <textarea value={evidenceDrafts[item.id]?.note ?? ""} onChange={(event) => setEvidenceDrafts((current) => ({ ...current, [item.id]: { ...current[item.id], note: event.target.value } }))} />
                      <input value={evidenceDrafts[item.id]?.artifact_ref ?? ""} onChange={(event) => setEvidenceDrafts((current) => ({ ...current, [item.id]: { ...current[item.id], artifact_ref: event.target.value } }))} placeholder="Artifact reference" />
                      <div className="action-row">
                        <button className="button inline" onClick={() => void updateEvidence(item.id)} disabled={busy === `evidence-${item.id}`}>
                          <Save size={16} />
                          Save
                        </button>
                        <button className="button danger inline" onClick={() => void deleteEvidence(item.id)} disabled={busy === `evidence-${item.id}`}>
                          <Trash2 size={16} />
                          Delete
                        </button>
                      </div>
                    </article>
                  ))}
                </div>
              </div>
            </>
          ) : (
            <div className="empty-state">Start a playbook to create the first hunt session.</div>
          )}
        </section>
      </section>

      <section className="coverage-panel">
        <div className="panel-header">
          <div>
            <p className="eyebrow">ATT&CK Coverage</p>
            <h2>Library coverage</h2>
          </div>
        </div>
        <div className="coverage-table">
          {coverage.map((item) => (
            <div key={`${item.technique_id}-${item.tactic}`}>
              <span>{item.tactic}</span>
              <strong>{item.technique_id}</strong>
              <p>{item.technique}</p>
              <em>{item.playbook_count} playbook</em>
            </div>
          ))}
        </div>
      </section>
    </main>
  );
}

function Metric({ icon, label, value }: { icon: React.ReactNode; label: string; value: number }) {
  return (
    <div className="metric">
      {icon}
      <strong>{value}</strong>
      <span>{label}</span>
    </div>
  );
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
