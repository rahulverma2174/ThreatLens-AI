import { AnimatePresence, motion, useReducedMotion } from "framer-motion";
import { Fragment, useEffect, useRef, useState } from "react";
import { Activity, AlertCircle, Bot, Braces, Check, Database, FileSearch, Send, ShieldCheck, Sparkles, Trash2, UserRound } from "lucide-react";

import { apiRequest } from "../api";
import "./copilot.css";

const suggestedQuestions = [
  "Show the top 10 suspicious IP addresses",
  "Explain the highest-risk alert",
  "Summarize today's failed login events",
  "Find accounts targeted by multiple IPs",
  "Explain unusual authentication activity",
];

function AnswerText({ text = "" }) {
  // Render only lightweight, literal formatting. No HTML from the response is executed.
  const chunks = String(text).split(/(```[\s\S]*?```|`[^`]+`)/g).filter(Boolean);
  return <>{chunks.map((chunk, index) => {
    if (chunk.startsWith("```") && chunk.endsWith("```")) {
      const block = chunk.slice(3, -3);
      const language = block.match(/^([\w+-]+)\n/);
      const body = language ? block.slice(language[0].length) : block;
      return <pre className="copilot-code" key={index}>{language && <span className="copilot-code-language">{language[1]}</span>}<code>{body}</code></pre>;
    }
    if (chunk.startsWith("`") && chunk.endsWith("`")) return <code className="copilot-inline-code" key={index}>{chunk.slice(1, -1)}</code>;
    const lines = chunk.split("\n");
    const content = [];
    for (let line = 0; line < lines.length;) {
      const cells = (value) => value.trim().replace(/^\|/, "").replace(/\|$/, "").split("|").map((cell) => cell.trim());
      if (lines[line]?.includes("|") && lines[line + 1]?.match(/^\s*\|?\s*:?-{3,}/)) {
        const headers = cells(lines[line]);
        line += 2;
        const rows = [];
        while (line < lines.length && lines[line].includes("|")) rows.push(cells(lines[line++]));
        content.push(<div className="copilot-table-wrap" key={`table-${index}-${line}`}><table className="copilot-result-table"><thead><tr>{headers.map((header, cell) => <th key={cell}>{header}</th>)}</tr></thead><tbody>{rows.map((row, rowIndex) => <tr key={rowIndex}>{headers.map((_, cell) => <td key={cell}>{row[cell] ?? ""}</td>)}</tr>)}</tbody></table></div>);
      } else {
        content.push(<span key={`text-${index}-${line}`}>{lines[line]}{line < lines.length - 1 ? "\n" : ""}</span>);
        line += 1;
      }
    }
    return <Fragment key={index}>{content}</Fragment>;
  })}</>;
}

function optionalSection(response, field, title) {
  const value = response?.[field];
  if (!Array.isArray(value) || value.length === 0) return null;
  return <section className="copilot-optional-section"><h4>{title}</h4><ul>{value.map((item, index) => <li key={`${field}-${index}`}><AnswerText text={typeof item === "string" ? item : JSON.stringify(item, null, 2)} /></li>)}</ul></section>;
}

function AssistantResult({ response }) {
  return <div className="assistant-answer">
    <div className="copilot-result-title"><span><Sparkles size={13} /> INVESTIGATION SUMMARY</span>{response.intent && <code>{response.intent.replaceAll("_", " ")}</code>}</div>
    <div className="copilot-answer-copy"><AnswerText text={response.answer} /></div>
    {response.facts?.length > 0 && <section className="copilot-evidence"><h4><FileSearch size={13} /> Returned evidence</h4><ul>{response.facts.map((fact, index) => <li key={`${index}-${fact}`}><AnswerText text={fact} /></li>)}</ul></section>}
    {optionalSection(response, "linked_alerts", "Linked alerts")}
    {optionalSection(response, "linked_incidents", "Linked incidents")}
    {optionalSection(response, "risk_factors", "Risk factors")}
    {optionalSection(response, "entities", "Relevant entities")}
    {optionalSection(response, "errors", "Limitations and errors")}
    {response.suggested_actions?.length > 0 && <div className="copilot-actions"><strong>INVESTIGATION ACTIONS</strong>{response.suggested_actions.map((action, index) => <span key={`${index}-${action}`}><Check size={12} /><AnswerText text={action} /></span>)}</div>}
    {response.data_scope && <small className="copilot-scope"><Database size={12} />{response.data_scope}</small>}
    {response.execution_ms != null && <small className="copilot-execution"><Activity size={12} />Query completed in {response.execution_ms} ms</small>}
  </div>;
}

export default function CopilotPage({ onError }) {
  const reduceMotion = useReducedMotion();
  const [messages, setMessages] = useState(() => {
    try {
      const saved = JSON.parse(sessionStorage.getItem("threatlens.copilot-history") ?? "[]");
      return Array.isArray(saved) ? saved.slice(-40) : [];
    } catch {
      return [];
    }
  });
  const [question, setQuestion] = useState("");
  const [sending, setSending] = useState(false);
  const [modelStatus, setModelStatus] = useState(null);
  const [selectedModel, setSelectedModel] = useState(() => localStorage.getItem("threatlens.copilot-model") ?? "qwen2.5:3b");
  const endRef = useRef(null);
  const qwenModels = modelStatus?.available_qwen_models ?? [];
  const selectedModelReady = qwenModels.includes(selectedModel);
  useEffect(() => {
    let active = true;
    apiRequest("/api/copilot/status").then((status) => { if (active) setModelStatus(status); }).catch(() => { if (active) setModelStatus({ connected: false, model_ready: false }); });
    return () => { active = false; };
  }, []);
  useEffect(() => {
    if (!modelStatus) return;
    const preferred = localStorage.getItem("threatlens.copilot-model");
    const available = modelStatus.available_qwen_models ?? [];
    setSelectedModel((current) => available.includes(current)
      ? current
      : available.includes(preferred)
        ? preferred
        : available.includes(modelStatus.model)
          ? modelStatus.model
          : available[0] ?? modelStatus.model ?? "qwen2.5:3b");
  }, [modelStatus]);
  useEffect(() => { localStorage.setItem("threatlens.copilot-model", selectedModel); }, [selectedModel]);
  useEffect(() => { sessionStorage.setItem("threatlens.copilot-history", JSON.stringify(messages.slice(-40))); }, [messages]);
  useEffect(() => { endRef.current?.scrollIntoView({ behavior: reduceMotion ? "auto" : "smooth", block: "end" }); }, [messages, sending, reduceMotion]);

  async function ask(rawQuestion) {
    const text = rawQuestion.trim();
    if (!text || sending) return;
    setQuestion("");
    setMessages((current) => [...current, { role: "user", text }]);
    setSending(true);
    try {
      const response = await apiRequest("/api/copilot/ask", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ question: text, ...(selectedModelReady ? { model: selectedModel } : {}) }),
      });
      setMessages((current) => [...current, { role: "assistant", response }]);
    } catch (error) {
      onError?.(error.message);
      setMessages((current) => [...current, { role: "error", text: error.message || "The local Copilot request failed." }]);
    } finally {
      setSending(false);
    }
  }

  return (
    <div className="page-content copilot-page copilot-premium">
      <div className="page-heading"><div><div className="eyebrow"><Bot size={13} />LOCAL ANALYST ASSISTANCE <span className="heading-divider">/</span> GROUNDED LOCAL AI</div><h1>Security Copilot</h1><p>Database-backed investigation results, with optional explanation wording from a local Ollama model.</p></div><div className="data-scope"><i />LOCAL DATA ONLY</div></div>
      <div className="copilot-layout">
        <section className="panel copilot-chat-panel" aria-label="Security Copilot chat">
          <div className="copilot-chat-head">
            <div className="copilot-orb" aria-hidden="true"><span /><span /><span /></div>
            <div className="copilot-assistant-identity"><strong>ThreatLens Copilot</strong><span><i />{selectedModelReady ? `Local Ollama · ${selectedModel}` : "Grounded database answers · local model unavailable"}</span></div>
            <label className="copilot-model-picker"><span>QWEN MODEL</span><select value={qwenModels.length ? selectedModel : "unavailable"} onChange={(event) => setSelectedModel(event.target.value)} disabled={!qwenModels.length || sending} aria-label="Select Qwen chat model">{qwenModels.length ? qwenModels.map((model) => <option key={model} value={model}>{model}</option>) : <option value="unavailable">{selectedModel} · not installed</option>}</select></label>
            <span className="local-only">{selectedModelReady ? "LOCAL QWEN" : "DETERMINISTIC MODE"}</span>
            {messages.length > 0 && <button type="button" className="copilot-clear" onClick={() => setMessages([])} disabled={sending}><Trash2 size={13} />Clear session</button>}
          </div>
          <div className="copilot-transcript" role="log" aria-label="Copilot conversation" aria-live="polite" aria-relevant="additions">
            {!messages.length && <div className="copilot-welcome"><div className="copilot-welcome-mark"><ShieldCheck size={19} /></div><span className="copilot-welcome-kicker">LOCAL SECURITY INVESTIGATION</span><strong>Evidence first. No invented telemetry.</strong><p>Choose a supported investigation or ask about local records. Unsupported questions and missing evidence are identified explicitly.</p><div className="copilot-suggestions">{suggestedQuestions.map((item) => <button type="button" key={item} onClick={() => ask(item)} disabled={sending}>{item}<span>↗</span></button>)}</div></div>}
            <AnimatePresence initial={false}>
              {messages.map((message, index) => message.role === "user" ? (
                <motion.article className="copilot-message user-message" key={`user-${index}`} initial={reduceMotion ? false : { opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.18 }}><div className="message-avatar"><UserRound size={14} /></div><p>{message.text}</p></motion.article>
              ) : message.role === "error" ? (
                <motion.article className="copilot-message assistant-message copilot-error-message" key={`error-${index}`} initial={reduceMotion ? false : { opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.18 }}><div className="message-avatar"><AlertCircle size={14} /></div><div className="copilot-request-error"><strong>Request not completed</strong><p>{message.text}</p><small>No investigation result was returned.</small></div></motion.article>
              ) : (
                <motion.article className="copilot-message assistant-message" key={`assistant-${index}`} initial={reduceMotion ? false : { opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.18 }}><div className="message-avatar"><Bot size={14} /></div><AssistantResult response={message.response} /></motion.article>
              ))}
            </AnimatePresence>
            {sending && <div className="copilot-thinking" role="status"><span className="copilot-typing-dots" aria-hidden="true"><i /><i /><i /></span><span>Querying local records…</span></div>}
            <div ref={endRef} />
          </div>
          <form className="copilot-compose" onSubmit={(event) => { event.preventDefault(); ask(question); }}>
            <label className="copilot-compose-label" htmlFor="copilot-question">INVESTIGATION QUERY</label>
            <input id="copilot-question" value={question} onChange={(event) => setQuestion(event.target.value)} placeholder="Ask about your local authentication data…" maxLength={500} aria-describedby="copilot-query-hint" />
            <span id="copilot-query-hint" className="copilot-character-count">{question.length}/500</span>
            <button className="button primary" type="submit" disabled={!question.trim() || sending} aria-label="Send investigation query">{sending ? <span className="copilot-send-spinner" aria-hidden="true" /> : <Send size={15} />}<span>{sending ? "Querying" : "Ask Copilot"}</span></button>
          </form>
          <div className="copilot-disclaimer">Facts come from local database queries. Ollama, when available, only rewrites explanations from those facts; it does not run detection rules or actions. Conversation history remains in this browser session.</div>
        </section>
        <aside className="panel copilot-capabilities"><div className="section-kicker">SUPPORTED QUERIES</div><h2>Investigation shortcuts</h2><p>Each prompt runs the same database-backed query as the chat.</p>{suggestedQuestions.map((item, index) => <button type="button" key={item} onClick={() => ask(item)} disabled={sending}><span>0{index + 1}</span>{item}</button>)}<div className="copilot-boundary"><ShieldCheck size={15} /><span><strong>Scope boundary</strong><small>Copilot does not infer reputation, location, or attack attribution. It reports when data is missing.</small></span></div><div className="copilot-query-note"><Braces size={14} /><span>Results preserve the query intent, returned evidence and data scope.</span></div></aside>
      </div>
    </div>
  );
}
