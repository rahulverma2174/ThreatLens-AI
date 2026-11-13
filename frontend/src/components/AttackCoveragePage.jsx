import { useEffect, useState } from "react";
import { ArrowUpRight, Crosshair, ShieldCheck } from "lucide-react";
import { apiRequest } from "../api";

export default function AttackCoveragePage({ onError }) {
  const [coverage, setCoverage] = useState(null);
  const [selected, setSelected] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let active = true;
    apiRequest("/api/attack/coverage")
      .then((data) => { if (active) { setCoverage(data); setSelected(data.techniques[0]?.technique_id ?? null); } })
      .catch((error) => { if (active) onError(error.message); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [onError]);

  const current = coverage?.techniques.find((item) => item.technique_id === selected);
  return <div className="page-content attack-coverage-page">
    <div className="page-heading"><div><div className="eyebrow"><Crosshair size={13} />DETECTION COVERAGE <span className="heading-divider">/</span> MITRE ATT&CK</div><h1>ATT&CK coverage</h1><p>Technique candidates derived from configured local rules and stored detection evidence.</p></div><span className="coverage-count"><ShieldCheck size={14} />{coverage?.techniques.filter((item) => item.mapping_status === "candidate").length ?? 0} candidates</span></div>
    <div className="model-notice"><ShieldCheck size={14} /><span>{coverage?.notice ?? "Loading locally evidenced mappings…"}</span></div>
    <section className="panel attack-matrix-panel"><div className="panel-heading"><div><div className="section-kicker">TACTIC MATRIX</div><h2>Credential Access · TA0006</h2><p>Interactive technique cells open the local rule and alert evidence.</p></div><span className="model-tag">LOCAL EVIDENCE</span></div>
      <div className="attack-matrix" role="list" aria-label="MITRE technique coverage">
        {(coverage?.techniques ?? []).map((technique) => <button key={technique.technique_id} role="listitem" aria-pressed={selected === technique.technique_id} className={`attack-technique-cell ${technique.mapping_status} ${selected === technique.technique_id ? "selected" : ""}`} onClick={() => setSelected(technique.technique_id)}><span>{technique.tactic_id} · {technique.tactic}</span><strong>{technique.technique_id}</strong><b>{technique.name}</b><small>{technique.evidence_count} evidence record{technique.evidence_count === 1 ? "" : "s"}</small></button>)}
        {!loading && !coverage?.techniques.length && <div className="empty-inline">No mapped techniques.</div>}
      </div>
    </section>
    {current && <section className="panel attack-evidence-panel"><div className="panel-heading"><div><div className="section-kicker">EVIDENCE REVIEW</div><h2>{current.technique_id} · {current.name}</h2><p>{current.qualification}</p></div><a className="inline-action" href={current.url} target="_blank" rel="noreferrer">MITRE reference <ArrowUpRight size={13} /></a></div>
      <div className="table-wrap" role="region" aria-label="ATT&CK evidence table. Scroll horizontally to view all evidence columns." tabIndex={0}><table className="data-table"><thead><tr><th>Evidence source</th><th>Local record</th><th>Pattern / status</th><th>Observed entities</th></tr></thead><tbody>{current.evidence.map((item) => <tr key={`${item.source}-${item.id}`}><td><span className={`evidence-source ${item.source}`}>{item.source.replace("_", " ")}</span></td><td>{item.source === "stored_alert" ? <strong>{item.title}</strong> : <strong>{item.name}</strong>}<small className="detection-key">#{item.id}{item.source === "stored_alert" ? ` · ${item.detection_key}` : ` · ${item.aggregation}`}</small></td><td>{item.source === "stored_alert" ? item.status : `${item.enabled ? "Enabled" : "Disabled"} · threshold ${item.threshold} in ${item.window_minutes}m`}</td><td>{item.source === "stored_alert" ? <><code>{item.source_ip}</code><small className="detection-key">Event IDs: {item.related_event_ids.join(", ") || "none attached"}</small></> : <span>Rule configuration</span>}</td></tr>)}{!current.evidence.length && <tr><td colSpan="4" className="muted-cell">No rule or alert evidence is stored for this technique yet.</td></tr>}</tbody></table></div>
      <div className="coverage-provenance">Evidence is read from local rule definitions and alert records. ATT&CK association remains a candidate; confirm each mapping before reporting coverage.</div>
    </section>}
  </div>;
}
