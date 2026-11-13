import { useCallback, useEffect, useState } from "react";
import { Activity, ArrowDown, ArrowRight, Check, CircleDot, Clock3, Plus, ShieldAlert, Workflow } from "lucide-react";
import { apiRequest, formatDate } from "../api";

const emptyForm = { name: "", description: "", trigger_type: "alert_created", condition_field: "", condition_operator: "equals", condition_value: "", action: "simulate_isolation", approval_required: true };

export default function SoarPage({ onError, onSuccess }) {
  const [workflows, setWorkflows] = useState([]);
  const [executions, setExecutions] = useState([]);
  const [form, setForm] = useState(emptyForm);
  const [entityIds, setEntityIds] = useState({});
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);

  const refresh = useCallback(async () => {
    try {
      const [items, runs] = await Promise.all([apiRequest("/api/soar/workflows"), apiRequest("/api/soar/executions")]);
      setWorkflows(items);
      setExecutions(runs);
    } catch (error) { onError(error.message); }
    finally { setLoading(false); }
  }, [onError]);
  useEffect(() => { refresh(); }, [refresh]);

  async function createWorkflow(event) {
    event.preventDefault();
    setSaving(true);
    try {
      const saved = await apiRequest("/api/soar/workflows", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ ...form, condition_field: form.condition_field, condition_operator: form.condition_field ? form.condition_operator : "", condition_value: form.condition_field ? form.condition_value : "" }) });
      setWorkflows((current) => [saved, ...current]);
      setForm(emptyForm);
      onSuccess("SOAR workflow saved locally.");
    } catch (error) { onError(error.message); }
    finally { setSaving(false); }
  }

  async function simulate(workflow) {
    const entityType = workflow.trigger_type === "event_failure" ? "event" : "alert";
    const entityId = Number(entityIds[workflow.id]);
    if (!Number.isInteger(entityId) || entityId < 1) { onError("Enter an existing local event or alert ID."); return; }
    try {
      await apiRequest(`/api/soar/workflows/${workflow.id}/simulate`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ entity_type: entityType, entity_id: entityId }) });
      await refresh();
      onSuccess("Workflow simulation recorded.");
    } catch (error) { onError(error.message); }
  }

  async function approve(execution) {
    try {
      await apiRequest(`/api/soar/executions/${execution.id}/approve`, { method: "PATCH" });
      await refresh();
      onSuccess("Simulation approval recorded; no response action was executed.");
    } catch (error) { onError(error.message); }
  }

  return <div className="page-content soar-page">
    <div className="page-heading"><div><div className="eyebrow"><Workflow size={13} />RESPONSE ORCHESTRATION <span className="heading-divider">/</span> LOCAL SIMULATION</div><h1>SOAR workflow builder</h1><p>Build trigger, condition, and action flows. Execution is a local simulation with a persistent approval trail.</p></div><span className="coverage-count"><ShieldAlert size={14} />SAFE SIMULATION ONLY</span></div>
    <div className="model-notice"><ShieldAlert size={14} /><span>Approvals record analyst intent only. No endpoint isolation, account changes, network blocking, or other destructive response action is connected to this builder.</span></div>
    <section className="panel soar-builder-panel"><div className="panel-heading"><div><div className="section-kicker">WORKFLOW DESIGN</div><h2>Create a response workflow</h2><p>Workflow definitions and execution evidence are stored in the local database.</p></div></div>
      <form className="soar-builder-form" onSubmit={createWorkflow}>
        <label className="soar-name-field">Workflow name<input required minLength="3" maxLength="120" value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} placeholder="Repeated login failure review" /></label>
        <label className="soar-description-field">Description<input maxLength="500" value={form.description} onChange={(event) => setForm({ ...form, description: event.target.value })} placeholder="Optional analyst context" /></label>
        <div className="soar-flow-nodes">
          <div className="soar-flow-node"><span><CircleDot size={13} />TRIGGER</span><label>When<select value={form.trigger_type} onChange={(event) => setForm({ ...form, trigger_type: event.target.value })}><option value="alert_created">Alert evidence</option><option value="event_failure">Failed authentication event</option><option value="indicator_match">Local indicator match</option></select></label></div><ArrowRight className="soar-flow-arrow" size={18} />
          <div className="soar-flow-node"><span><Activity size={13} />CONDITION <small>OPTIONAL</small></span><label>Field<select value={form.condition_field} onChange={(event) => setForm({ ...form, condition_field: event.target.value })}><option value="">No condition</option><option value="severity">Severity</option><option value="source_ip">Source IP</option><option value="status">Status</option></select></label>{form.condition_field && <div className="soar-condition-fields"><select value={form.condition_operator} onChange={(event) => setForm({ ...form, condition_operator: event.target.value })}><option value="equals">equals</option><option value="contains">contains</option></select><input required value={form.condition_value} onChange={(event) => setForm({ ...form, condition_value: event.target.value })} placeholder="Value" /></div>}</div><ArrowRight className="soar-flow-arrow" size={18} />
          <div className="soar-flow-node"><span><Check size={13} />ACTION</span><label>Simulate<select value={form.action} onChange={(event) => setForm({ ...form, action: event.target.value })}><option value="simulate_isolation">Containment proposal</option><option value="add_case_note">Case note proposal</option></select></label><label className="approval-toggle"><input type="checkbox" checked={form.approval_required} onChange={(event) => setForm({ ...form, approval_required: event.target.checked })} />Require analyst approval</label></div>
        </div>
        <div className="soar-form-footer"><small>Runs are bound to an existing alert or event ID and retain a snapshot of its local evidence.</small><button className="button primary" disabled={saving}><Plus size={13} />{saving ? "Saving…" : "Save workflow"}</button></div>
      </form>
    </section>
    <div className="soar-workspace-grid"><section className="panel"><div className="panel-heading"><div><div className="section-kicker">SAVED DEFINITIONS</div><h2>Workflows</h2></div><span className="model-tag">{workflows.length} TOTAL</span></div><div className="soar-workflow-list">{loading ? <div className="table-loading">Loading workflows…</div> : workflows.map((workflow) => <article className="soar-workflow-row" key={workflow.id}><div className="soar-workflow-copy"><strong>{workflow.name}</strong><small>{workflow.description || "No description"}</small><div className="soar-workflow-tags"><span>{workflow.trigger_type.replaceAll("_", " ")}</span><span>{workflow.condition_field ? `${workflow.condition_field} ${workflow.condition_operator} ${workflow.condition_value}` : "No condition"}</span><span>{workflow.action.replaceAll("_", " ")}</span><span>{workflow.approval_required ? "Approval required" : "Simulation only"}</span></div></div><div className="soar-run-control"><input inputMode="numeric" value={entityIds[workflow.id] ?? ""} onChange={(event) => setEntityIds((current) => ({ ...current, [workflow.id]: event.target.value }))} placeholder={workflow.trigger_type === "event_failure" ? "Event ID" : "Alert ID"} aria-label={`Local evidence ID for ${workflow.name}`} /><button className="button secondary small-button" onClick={() => simulate(workflow)}>Simulate</button></div></article>)}{!loading && !workflows.length && <div className="empty-inline">Create a workflow to begin a local simulation.</div>}</div></section>
      <section className="panel"><div className="panel-heading"><div><div className="section-kicker">EXECUTION AUDIT</div><h2>Simulation history</h2><p>Approval state and referenced local evidence</p></div><span className="model-tag">{executions.length} RUNS</span></div><div className="soar-execution-list">{executions.map((execution) => <article className="soar-execution-row" key={execution.id}><span className={`soar-execution-status ${execution.status}`}>{execution.status.replaceAll("_", " ")}</span><strong>Workflow #{execution.workflow_id} · {execution.entity_type} #{execution.entity_id}</strong><small>{execution.outcome}</small><code>{JSON.stringify(execution.evidence)}</code><time dateTime={execution.created_at}><Clock3 size={11} />{formatDate(execution.created_at)}</time>{execution.status === "awaiting_approval" && <button className="button secondary small-button" onClick={() => approve(execution)}>Approve simulation</button>}{execution.approved_by && <small>Approved by {execution.approved_by}</small>}</article>)}{!executions.length && <div className="empty-inline">No executions have been recorded.</div>}</div></section></div>
  </div>;
}
