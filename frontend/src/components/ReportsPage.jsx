import { useEffect, useState } from "react";
import { Download, FileBarChart2 } from "lucide-react";
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

import { apiRequest } from "../api";

export default function ReportsPage({ onError }) {
  const [summary, setSummary] = useState(null);
  useEffect(() => {
    let active = true;
    apiRequest("/api/reports/summary").then((value) => { if (active) setSummary(value); }).catch((error) => onError(error.message));
    return () => { active = false; };
  }, [onError]);
  const data = summary ? Object.entries(summary.alerts_by_severity).map(([name, value]) => ({ name, alerts: value })) : [];
  return (
    <div className="page-content">
      <div className="page-heading"><div><div className="eyebrow"><FileBarChart2 size={13} />SECURITY ANALYTICS</div><h1>Reports</h1><p>Activity summaries generated from records stored in this local workspace.</p></div><a className="button primary" href="/api/reports/events.csv"><Download size={14} />Export event CSV</a></div>
      <div className="report-stats">{[["Total events", summary?.total_events], ["Successful logins", summary?.successful_logins], ["Failed logins", summary?.failed_logins], ["Total alerts", summary ? Object.values(summary.alerts_by_severity).reduce((a, b) => a + b, 0) : null]].map(([label, value]) => <div key={label} className="stat-card"><span className="stat-label">{label}</span><strong className="stat-value">{value?.toLocaleString() ?? "—"}</strong><small className="report-stat-scope">Local records</small></div>)}</div>
      <section className="panel report-chart-panel"><div className="panel-heading"><div><div className="section-kicker">DETECTION OUTPUT</div><h2>Alerts by severity</h2><p>All generated rules signals by priority</p></div></div><div className="report-chart" role="img" aria-label="Bar chart of alerts by severity from the local report summary"><ResponsiveContainer width="100%" height="100%"><BarChart data={data} margin={{ top: 10, right: 15, left: -20, bottom: 0 }}><CartesianGrid stroke="#202b3b" strokeDasharray="3 5" vertical={false} /><XAxis dataKey="name" tick={{ fill: "#8391a7", fontSize: 10 }} axisLine={false} tickLine={false} /><YAxis allowDecimals={false} tick={{ fill: "#8391a7", fontSize: 9 }} axisLine={false} tickLine={false} /><Tooltip contentStyle={{ background: "#111b2b", border: "1px solid #29384d", borderRadius: 3, color: "#e8eef9", fontSize: 10 }} /><Bar dataKey="alerts" fill="#00c8ed" radius={[2, 2, 0, 0]} /></BarChart></ResponsiveContainer></div></section>
      <div className="page-note">Exports are generated locally by the API. Only authorized local or synthetic event records should be imported.</div>
    </div>
  );
}
