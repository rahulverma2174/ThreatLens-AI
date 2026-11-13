import { useCallback, useEffect, useState } from "react";
import { Beaker, Check, Clock3, Play, RefreshCw, ShieldAlert, SlidersHorizontal, X } from "lucide-react";
import { apiRequest } from "../api";

const DISPOSITIONS = [
  ["true_positive", "True positive"], ["false_positive", "False positive"], ["expected_behavior", "Expected behavior"], ["needs_tuning", "Needs tuning"],
];
const fmtDate = (value) => value ? new Date(value).toLocaleString() : "—";

export default function DetectionLabPage({ onError, onSuccess }) {
  const [scenarios, setScenarios] = useState([]);
  const [history, setHistory] = useState([]);
  const [summary, setSummary] = useState(null);
  const [selected, setSelected] = useState(null);
  const [reviews, setReviews] = useState([]);
  const [reviewDrafts, setReviewDrafts] = useState({});
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [scenarioRows, runs, stats] = await Promise.all([
        apiRequest("/api/detection-lab/scenarios"), apiRequest("/api/detection-lab/runs?limit=50"), apiRequest("/api/detection-lab/summary"),
      ]);
      setScenarios(scenarioRows); setHistory(runs); setSummary(stats);
      setSelected((current) => current ? (runs.find((run) => run.id === current.id) || current) : (runs[0] || null));
    } catch (error) { onError?.(`Detection Lab could not load: ${error.message}`); }
    finally { setLoading(false); }
  }, [onError]);
  useEffect(() => { load(); }, [load]);

  const selectRun = async (run) => {
    setSelected(run);
    try {
      const entries = await apiRequest(`/api/detection-lab/runs/${run.id}/reviews`);
      setReviews(entries);
      setReviewDrafts(Object.fromEntries(entries.map((item) => [item.detection_key, { disposition: item.disposition, notes: item.notes }])));
    } catch (error) { onError?.(`Finding reviews could not load: ${error.message}`); }
  };
  useEffect(() => { if (selected?.id) selectRun(selected); /* load selected history review */ }, [selected?.id]);

  const execute = async (scenarioId) => {
    setRunning(scenarioId);
    try {
      const run = await apiRequest("/api/detection-lab/runs", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ scenario_id: scenarioId }) });
      setSelected(run);
      onSuccess?.(`Scenario validation finished: ${run.status.replaceAll("_", " ")}.`);
      await load();
      setSelected(run);
      await selectRun(run);
    } catch (error) { onError?.(`Scenario could not run: ${error.message}`); }
    finally { setRunning(null); }
  };

  const reviewFinding = async (detectionKey) => {
    const draft = reviewDrafts[detectionKey] || { disposition: "needs_tuning", notes: "" };
    try {
      const reviewed = await apiRequest(`/api/detection-lab/runs/${selected.id}/reviews`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ detection_key: detectionKey, disposition: draft.disposition, notes: draft.notes }),
      });
      setReviews((current) => [reviewed, ...current.filter((item) => item.detection_key !== detectionKey)]);
      const stats = await apiRequest("/api/detection-lab/summary"); setSummary(stats);
      onSuccess?.("Finding review saved to audit history.");
    } catch (error) { onError?.(`Finding review could not be saved: ${error.message}`); }
  };

  const result = selected?.result;
  const reviewFor = (key) => reviews.find((item) => item.detection_key === key);
  return <section className="page-content detection-lab-page">
    <div className="page-heading lab-heading"><div><span className="eyebrow">DETECTION ENGINEERING · CONTROLLED SIMULATION</span><h1>Detection Validation Lab</h1><p>Replay deterministic synthetic authentication scenarios against the current detection configuration.</p></div><div className="lab-scope-chip"><Beaker size={16} /> ISOLATED TEMPORARY SQLITE</div></div>

    <div className="lab-scope-banner"><ShieldAlert size={16} /><span><strong>Scenario validation only.</strong> Results measure whether the captured rules and thresholds detect these synthetic fixtures. They do not represent real-world accuracy, precision, recall or attack prevalence.</span></div>

    <div className="lab-summary-grid">
      <div className="lab-summary-card"><span>Total runs</span><strong>{summary?.total_runs ?? "—"}</strong><small>Most recent 1,000 persisted runs</small></div>
      <div className="lab-summary-card passed"><span>Passed</span><strong>{summary?.passed_runs ?? "—"}</strong><small>Expected signals observed</small></div>
      <div className="lab-summary-card failed"><span>Failed</span><strong>{summary?.failed_runs ?? "—"}</strong><small>Expected signals not observed</small></div>
      <div className="lab-summary-card pending"><span>Needs review</span><strong>{summary?.rule_summaries?.reduce((sum, item) => sum + item.scenario_observations - item.reviewed_count, 0) ?? "—"}</strong><small>Synthetic findings without review</small></div>
    </div>

    <div className="lab-workspace-grid">
      <section className="panel lab-scenarios-panel">
        <div className="panel-heading"><div><h2>Authentication scenarios</h2><p>Each run snapshots thresholds, enabled custom rules and a reproducible synthetic fixture.</p></div><button className="lab-icon-button" onClick={load} aria-label="Refresh lab data"><RefreshCw size={14} /></button></div>
        {loading ? <div className="lab-empty">Loading scenarios…</div> : <div className="lab-scenario-list">{scenarios.map((scenario) => <article className="lab-scenario-card" key={scenario.scenario_id}><div className="lab-scenario-icon"><Beaker size={16} /></div><div className="lab-scenario-copy"><div><h3>{scenario.name}</h3><span>v{scenario.version}</span></div><p>{scenario.description}</p><div className="lab-scenario-meta"><span>Minimum baseline <b>{scenario.minimum_baseline_events}</b></span>{scenario.technique_candidates.map((technique) => <span className="lab-technique" key={technique}>ATT&amp;CK {technique}</span>)}</div></div><button className="lab-run-button" disabled={running !== null} onClick={() => execute(scenario.scenario_id)}><Play size={13} />{running === scenario.scenario_id ? "Running" : "Run"}</button></article>)}</div>}
        <div className="lab-scenario-footnote">Synthetic IPs use documentation-only TEST-NET address ranges. No live authentication attempts are made.</div>
      </section>

      <section className="panel lab-history-panel">
        <div className="panel-heading"><div><h2>Execution history</h2><p>Stored scenario runs and captured configuration snapshots.</p></div><span className="lab-history-count">{history.length}</span></div>
        {history.length ? <div className="lab-history-list">{history.map((run) => <button className={`lab-history-row ${selected?.id === run.id ? "selected" : ""}`} key={run.id} onClick={() => selectRun(run)}><span className={`lab-status-dot ${run.status}`} /><span className="lab-history-copy"><strong>{run.scenario_id.replaceAll("_", " ")}</strong><small>{fmtDate(run.created_at)} · {run.execution_metadata.synthetic_event_count} synthetic events</small></span><span className={`lab-status-label ${run.status}`}>{run.status.replaceAll("_", " ")}</span></button>)}</div> : <div className="lab-empty">No scenarios have been run.</div>}
      </section>
    </div>

    {selected && result && <section className="panel lab-detail-panel">
      <div className="panel-heading lab-detail-heading"><div><span className="eyebrow">RUN #{selected.id} · SCENARIO v{selected.scenario_version}</span><h2>{selected.scenario_id.replaceAll("_", " ")}</h2><p>Executed {fmtDate(selected.execution_metadata.started_at)} · {selected.execution_metadata.duration_ms} ms · {selected.execution_metadata.synthetic_event_count} generated records</p></div><span className={`lab-result-status ${result.status}`}>{result.status === "passed" ? <Check size={14} /> : result.status === "failed" ? <X size={14} /> : <Clock3 size={14} />}{result.status.replaceAll("_", " ")}</span></div>
      <div className="lab-snapshot-grid"><div><span>Threshold snapshot</span><strong>Brute force {selected.settings_snapshot.brute_force_threshold} · {selected.settings_snapshot.window_minutes} min window · Targeted accounts {selected.settings_snapshot.targeted_username_threshold}</strong></div><div><span>Enabled custom rule snapshot</span><strong>{selected.enabled_rules_snapshot.length ? selected.enabled_rules_snapshot.map((rule) => `${rule.name} v${rule.version} (${rule.threshold})`).join(" · ") : "No enabled custom rules"}</strong></div><div><span>Baseline requirement</span><strong>{result.status === "insufficient_baseline" ? "Evidence insufficient" : `${selected.result.expected_risk_factors.length ? "User behavior history" : "Not required"} · ${selected.fixture_snapshot.length} fixture events`}</strong></div></div>
      {result.status === "insufficient_baseline" && <div className="lab-insufficient-note"><Clock3 size={15} />Evidence is below the configured minimum historical baseline. No unfamiliar-source finding was asserted.</div>}
      {result.status === "not_evaluable" && <div className="lab-insufficient-note"><SlidersHorizontal size={15} />This scenario could not be generated within the safe fixture limit using the captured thresholds. Thresholds were not changed.</div>}
      <div className="lab-compare-grid"><div><h3>Expected detections</h3><div className="lab-key-list">{result.expected_detection_keys.length ? result.expected_detection_keys.map((key) => <span className={result.missing_detection_keys.includes(key) ? "missing" : "matched"} key={key}>{result.missing_detection_keys.includes(key) ? <X size={12} /> : <Check size={12} />}{key}</span>) : <small>No rule alert expected; scenario checks behavior risk factors.</small>}</div></div><div><h3>Actual detections</h3><div className="lab-key-list">{result.actual_detection_keys.length ? result.actual_detection_keys.map((key) => <span className={result.unexpected_detection_keys.includes(key) ? "unexpected" : "matched"} key={key}><Check size={12} />{key}</span>) : <small>No detection keys were observed.</small>}</div></div></div>
      {result.expected_risk_factors.length > 0 && <div className="lab-risk-factors"><h3>Expected behavior signals</h3>{result.expected_risk_factors.map((key) => <span className={result.actual_risk_factors.includes(key) ? "matched" : "missing"} key={key}>{key}</span>)}</div>}
      <div className="lab-evidence"><h3>Evidence and execution findings</h3>{result.evidence.map((item, index) => <p key={index}>{item}</p>)}</div>
      <div className="lab-fixture-disclosure"><strong>Reproducibility snapshot:</strong> scenario v{selected.scenario_version}, settings, enabled rules and all {selected.fixture_snapshot.length} synthetic event records are stored with this execution.</div>
      {result.actual_detection_keys.length > 0 && <div className="lab-review-section"><div className="lab-review-heading"><div><h3>Finding review</h3><p>Review an observed synthetic result. Every saved review writes an audit entry.</p></div></div><div className="lab-review-list">{result.actual_detection_keys.map((key) => { const draft = reviewDrafts[key] || { disposition: "needs_tuning", notes: "" }; const existing = reviewFor(key); return <div className="lab-review-row" key={key}><div className="lab-review-key"><strong>{key}</strong>{existing && <small>Reviewed {fmtDate(existing.reviewed_at)} by {existing.reviewer}</small>}</div><select aria-label={`Review disposition for ${key}`} value={draft.disposition} onChange={(event) => setReviewDrafts((current) => ({ ...current, [key]: { ...draft, disposition: event.target.value } }))}>{DISPOSITIONS.map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select><input maxLength={2000} aria-label={`Review notes for ${key}`} placeholder="Analyst rationale (optional)" value={draft.notes} onChange={(event) => setReviewDrafts((current) => ({ ...current, [key]: { ...draft, notes: event.target.value } }))} /><button onClick={() => reviewFinding(key)}>{existing ? "Update review" : "Save review"}</button></div>; })}</div></div>}
    </section>}

    <section className="panel lab-performance-panel"><div className="panel-heading"><div><h2>Scenario observations by detection</h2><p>Counts are based on saved synthetic test runs only.</p></div></div>{summary?.rule_summaries?.length ? <div className="lab-performance-table-wrap" role="region" aria-label="Detection validation performance table. Scroll horizontally to view all columns." tabIndex={0}><table className="lab-performance-table"><thead><tr><th>Detection key</th><th>Scenario observations</th><th>Reviewed</th><th>False-positive reviews</th></tr></thead><tbody>{summary.rule_summaries.map((item) => <tr key={item.detection_key}><td>{item.detection_key}</td><td>{item.scenario_observations}</td><td>{item.reviewed_count}</td><td>{item.false_positive_reviews}</td></tr>)}</tbody></table></div> : <div className="lab-empty">Run scenarios to build a local validation history.</div>}<div className="lab-scenario-footnote">{summary?.notice || "Synthetic scenario observations are not real-world accuracy metrics."}</div></section>
  </section>;
}
