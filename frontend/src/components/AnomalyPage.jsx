import { useEffect, useMemo, useState } from "react";
import { AlertTriangle, BrainCircuit, ChartNoAxesColumnIncreasing, RefreshCw, Sparkles } from "lucide-react";
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

import { apiRequest, formatDate } from "../api";

const riskOrder = { critical: 0, high: 1, moderate: 2, low: 3 };

export default function AnomalyPage({ onError }) {
  const [result, setResult] = useState(null);
  const [behavior, setBehavior] = useState(null);
  const [loading, setLoading] = useState(false);
  const [loadingBehavior, setLoadingBehavior] = useState(true);

  useEffect(() => {
    let active = true;
    apiRequest("/api/analytics/behavior?window_hours=720")
      .then((data) => { if (active) setBehavior(data); })
      .catch((error) => { if (active) onError(error.message); })
      .finally(() => { if (active) setLoadingBehavior(false); });
    return () => { active = false; };
  }, [onError]);

  async function analyze() {
    setLoading(true);
    try {
      setResult(await apiRequest("/api/analytics/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
      }));
    } catch (error) {
      onError(error.message);
    } finally {
      setLoading(false);
    }
  }

  const rankedResults = useMemo(() => result
    ? [...result.results].sort((a, b) => riskOrder[a.risk_level] - riskOrder[b.risk_level] || b.risk_score - a.risk_score)
    : [], [result]);
  const distribution = useMemo(() => ["critical", "high", "moderate", "low"].map((level) => ({
    level,
    events: result?.results.filter((item) => item.risk_level === level).length ?? 0,
  })), [result]);
  const anomalyCount = result?.results.filter((item) => item.anomaly_classification === "suspicious").length ?? 0;

  return (
    <div className="page-content">
      <div className="page-heading"><div><div className="eyebrow"><BrainCircuit size={13} />BEHAVIORAL ANALYTICS <span className="heading-divider">/</span> EXPLAINABLE RISK</div><h1>AI analysis</h1><p>Behavior profiles, deterministic risk factors, and optional unsupervised anomaly signals from local events.</p></div><button className="button primary" onClick={analyze} disabled={loading}><Sparkles size={14} />{loading ? "Analyzing…" : "Run risk analysis"}</button></div>
      <section className="model-card"><div className="model-orb"><BrainCircuit size={22} /></div><div className="model-copy"><span className="model-label"><span className="status-pulse" />LOCAL CPU ANALYTICS</span><h2>Behavior + Isolation Forest</h2><p>Uses bounded event history, per-user/source frequency, failure behavior, UTC login-hour prevalence, configured detection thresholds, local analyst indicators, and rule-generated evidence.</p><div className="model-pills"><span>CPU-only</span><span>No external APIs</span><span>Review signal only</span></div></div></section>
      <div className="model-notice"><AlertTriangle size={14} /><span>Risk scores prioritize review; model anomalies and analyst-managed indicators are not confirmed attacks or independently verified threat intelligence.</span></div>
      {result && <>
        <div className="score-summary"><div><span>EVENTS ANALYZED</span><strong>{result.events_analyzed}</strong></div><div><span>MODEL ANOMALIES</span><strong className="model-flag-number">{anomalyCount}</strong></div><div><span>ANALYSIS RUN</span><strong className="model-name">#{result.analysis_run_id}</strong></div><div><span>SCORING ENGINE</span><strong className="model-name">{result.model ?? "Rules + behavior"}</strong></div></div>
        <div className="analytics-result-grid">
          <section className="panel analytics-chart-panel"><div className="panel-heading"><div><div className="section-kicker">RISK DISTRIBUTION</div><h2>Analyst review priority</h2><p>Deterministic 0–100 scores; not attack verdicts</p></div></div><div className="analytics-chart" role="img" aria-label={`Risk distribution from analysis run ${result.analysis_run_id}: ${distribution.map(({ level, events }) => `${level} ${events}`).join(", ")}`}><ResponsiveContainer width="100%" height="100%"><BarChart data={distribution} margin={{ top: 8, right: 12, left: -18, bottom: 0 }}><CartesianGrid stroke="#202b3b" strokeDasharray="3 5" vertical={false} /><XAxis dataKey="level" tick={{ fill: "#8391a7", fontSize: 9 }} axisLine={false} tickLine={false} /><YAxis allowDecimals={false} tick={{ fill: "#8391a7", fontSize: 9 }} axisLine={false} tickLine={false} /><Tooltip contentStyle={{ background: "#111b2b", border: "1px solid #29384d", borderRadius: 3, color: "#e8eef9", fontSize: 10 }} /><Bar dataKey="events" fill="#00c8ed" radius={[2, 2, 0, 0]} /></BarChart></ResponsiveContainer></div></section>
          <section className="panel analytics-chart-panel"><div className="panel-heading"><div><div className="section-kicker">USER BASELINES</div><h2>Observed behavior</h2><p>{behavior?.events_analyzed ?? 0} events · 30-day current vs prior baseline</p></div><button className="icon-quiet" onClick={() => { setLoadingBehavior(true); apiRequest("/api/analytics/behavior?window_hours=720").then(setBehavior).catch((error) => onError(error.message)).finally(() => setLoadingBehavior(false)); }} aria-label="Refresh behavior profiles"><RefreshCw size={13} /></button></div><div className="behavior-profile-list">{loadingBehavior ? <div className="table-loading"><span className="status-pulse" />Building local profiles…</div> : behavior?.users.slice(0, 6).map((profile) => <div key={profile.entity} className="behavior-profile-row"><span><strong>{profile.entity}</strong><small>{profile.event_count} current · {profile.previous_window_events} previous · {profile.distinct_source_ips} IPs</small>{profile.anomaly_factors?.length > 0 && <small className="profile-factor">{profile.anomaly_factors.join(" · ")}</small>}</span><b className={profile.entity_risk_score >= 40 ? "profile-risk" : ""}>{profile.entity_risk_score} risk</b><i>{Math.round(profile.failure_rate * 100)}% failed</i></div>)}</div></section>
        </div>
        <section className="panel anomaly-results-panel" aria-label={`Risk assessments from analysis run ${result.analysis_run_id}`}><div className="panel-heading"><div><div className="section-kicker">RISK ASSESSMENTS</div><h2>Ranked event evidence</h2><p>{result.results.length} events · {result.model ? `${result.model} optional anomaly signal` : "too few events for model inference"}</p></div><span className="model-tag">ANALYSIS #{result.analysis_run_id}</span></div><div className="anomaly-list">
          {rankedResults.slice(0, 50).map((item, index) => <article className="anomaly-row risk-result-row" key={item.event.id}><span className={`anomaly-indicator ${item.risk_level}`} /><span className="anomaly-rank">{String(index + 1).padStart(2, "0")}</span><div className="anomaly-details"><strong>{item.event.username} <code>{item.event.source_ip}</code></strong><span>{item.factors.length ? item.factors.map((factor) => `${factor.explanation} (+${factor.points})`).join(" ") : "No configured risk factor was observed in the available local context."}</span></div><div className="risk-score-cell"><strong>{item.risk_score}<small>/100</small></strong><span>{item.risk_level}</span></div><div className="anomaly-score"><strong>{item.anomaly_score === null ? "—" : item.anomaly_score.toFixed(3)}</strong><small><time dateTime={item.event.timestamp}>{formatDate(item.event.timestamp)}</time></small></div><span className={`model-label-pill ${item.anomaly_classification ?? "normal"}`}>{item.anomaly_classification ?? "no model"}</span></article>)}
          {!rankedResults.length && <div className="empty-inline">No events were available for the analysis run.</div>}
        </div></section>
        <div className="model-notice"><ChartNoAxesColumnIncreasing size={14} /><span>{result.notice} {rankedResults.some((item) => item.prior_analysis_runs) ? "Previous-run risk scores are compared for repeated local source-IP patterns." : "Run analysis again to establish a comparison baseline."}</span></div>
      </>}
    </div>
  );
}
