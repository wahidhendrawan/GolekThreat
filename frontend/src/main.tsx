import { Activity, Crosshair, Database, FileText, Play, Radar, ShieldCheck } from "lucide-react";
import { StrictMode, useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import { api } from "./api";
import "./styles.css";
import type { CoverageItem, HuntSession, Playbook } from "./types";

function App() {
  const [playbooks, setPlaybooks] = useState<Playbook[]>([]);
  const [sessions, setSessions] = useState<HuntSession[]>([]);
  const [coverage, setCoverage] = useState<CoverageItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

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

  const criticalCount = useMemo(
    () => playbooks.filter((playbook) => playbook.severity === "critical").length,
    [playbooks],
  );

  const startSession = async (playbookId: number) => {
    await api.startSession(playbookId);
    await load();
  };

  return (
    <main>
      <section className="hero">
        <div>
          <p className="eyebrow">GolekThreat</p>
          <h1>Threat hunting playbooks that turn hypotheses into evidence.</h1>
          <p>
            Build repeatable hunts, track analyst evidence, map MITRE ATT&CK coverage, and
            generate report-ready investigation notes.
          </p>
          <div className="hero-actions">
            <a href="#playbooks" className="button">
              <Crosshair size={18} /> Browse playbooks
            </a>
            <a href="#sessions" className="text-link">
              <Activity size={18} /> View sessions
            </a>
          </div>
        </div>
        <div className="hero-panel" aria-label="GolekThreat summary">
          <div className="panel-bar">
            <span></span>
            <span></span>
            <span></span>
            <b>hunt workspace</b>
          </div>
          <div className="radar-card">
            <Radar size={82} />
            <div>
              <strong>{playbooks.length || 3}</strong>
              <span>playbooks loaded</span>
            </div>
            <div>
              <strong>{coverage.length || 3}</strong>
              <span>ATT&CK techniques</span>
            </div>
          </div>
        </div>
      </section>

      {error && <div className="alert">API error: {error}</div>}
      {loading && <div className="loading">Loading GolekThreat workspace...</div>}

      <section className="metrics">
        <Metric icon={<ShieldCheck />} label="Playbooks" value={playbooks.length} />
        <Metric icon={<Crosshair />} label="Critical Hunts" value={criticalCount} />
        <Metric icon={<Activity />} label="Sessions" value={sessions.length} />
        <Metric icon={<Database />} label="ATT&CK Coverage" value={coverage.length} />
      </section>

      <section id="playbooks" className="section">
        <div className="section-heading">
          <p className="eyebrow">Playbook Library</p>
          <h2>Structured hunts by tactic, technique, evidence, and query.</h2>
        </div>
        <div className="playbook-grid">
          {playbooks.map((playbook) => (
            <article className="card" key={playbook.id}>
              <div className="card-top">
                <span className={`severity ${playbook.severity}`}>{playbook.severity}</span>
                <span>{playbook.technique_id}</span>
              </div>
              <h3>{playbook.title}</h3>
              <p>{playbook.hypothesis}</p>
              <dl>
                <div>
                  <dt>Tactic</dt>
                  <dd>{playbook.tactic}</dd>
                </div>
                <div>
                  <dt>Data Sources</dt>
                  <dd>{playbook.data_sources}</dd>
                </div>
              </dl>
              <div className="query-row">
                {playbook.queries.map((query) => (
                  <span key={query.id}>{query.platform}</span>
                ))}
              </div>
              <button className="button compact" onClick={() => void startSession(playbook.id)}>
                <Play size={16} /> Start hunt
              </button>
            </article>
          ))}
        </div>
      </section>

      <section id="sessions" className="section split">
        <div>
          <p className="eyebrow">Hunt Sessions</p>
          <h2>Evidence-driven execution.</h2>
          <p>
            Each hunt session copies playbook steps into a trackable checklist so analysts can
            record findings without changing the original playbook.
          </p>
        </div>
        <div className="session-list">
          {sessions.length === 0 && <p className="muted">No sessions yet. Start a hunt above.</p>}
          {sessions.slice(0, 5).map((session) => (
            <article className="session" key={session.id}>
              <div>
                <span>{session.status}</span>
                <h3>{session.title}</h3>
                <p>{session.playbook.technique_id} - {session.playbook.technique}</p>
              </div>
              <a href={api.reportUrl(session.id)} target="_blank" rel="noreferrer" className="icon-link">
                <FileText size={18} /> Report
              </a>
            </article>
          ))}
        </div>
      </section>

      <section className="section">
        <div className="section-heading">
          <p className="eyebrow">ATT&CK Coverage</p>
          <h2>Know what your hunt library can cover.</h2>
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
