import { useMemo, useRef, useState } from "react";
import { ArrowDown, ArrowUp, CircleCheck, CircleX } from "lucide-react";

import { formatDate } from "../api";
import Badge from "./ui/Badge";
import DataTable from "./ui/DataTable";
import EmptyState from "./ui/EmptyState";

function eventRisk(event, alerts) {
  const ipAlerts = alerts.filter((alert) => alert.source_ip === event.source_ip && alert.status !== "resolved");
  if (ipAlerts.some((alert) => alert.severity === "critical")) return "critical";
  if (ipAlerts.some((alert) => alert.severity === "high")) return "high";
  if (event.status === "failure") return "elevated";
  return "low";
}

const columnDefinitions = [
  { key: "timestamp", label: "TIME", value: (event) => new Date(event.timestamp).getTime() },
  { key: "source_ip", label: "SOURCE IP", value: (event) => event.source_ip },
  { key: "username", label: "IDENTITY", value: (event) => event.username },
  { key: "event_type", label: "AUTH TYPE", value: (event) => event.event_type },
  { key: "status", label: "RESULT", value: (event) => event.status },
  { key: "risk", label: "RISK", value: (event, alerts) => eventRisk(event, alerts) },
];

export function EventsTable({
  events, compact = false, alerts = [], onSelect, selectable = false,
  selectedIds = new Set(), onToggleSelect, onToggleSelectAll, visibleColumns,
}) {
  const [sort, setSort] = useState({ key: "timestamp", direction: "desc" });
  const [widths, setWidths] = useState({});
  const resizeStart = useRef(null);
  const columns = columnDefinitions.filter(({ key }) =>
    (!compact || key !== "risk") && (!visibleColumns || visibleColumns.includes(key)),
  );
  const sortedEvents = useMemo(() => [...(events ?? [])].sort((a, b) => {
    const column = columnDefinitions.find((item) => item.key === sort.key);
    if (!column) return 0;
    const left = column.value(a, alerts);
    const right = column.value(b, alerts);
    const compare = typeof left === "number" && typeof right === "number"
      ? left - right
      : String(left).localeCompare(String(right));
    return sort.direction === "asc" ? compare : -compare;
  }), [alerts, events, sort]);
  if (!events?.length) return <EmptyState title="No authentication events found" description="Import a CSV or adjust the current search and filters." />;
  const allSelected = selectable && events.every((event) => selectedIds.has(event.id));
  function resizeColumn(event, key, phase) {
    if (phase === "start") {
      event.preventDefault();
      event.currentTarget.setPointerCapture(event.pointerId);
      resizeStart.current = { key, pointerX: event.clientX, width: widths[key] ?? event.currentTarget.parentElement.getBoundingClientRect().width };
    } else if (phase === "move" && resizeStart.current?.key === key) {
      const { pointerX, width } = resizeStart.current;
      setWidths((current) => ({ ...current, [key]: Math.max(84, width + event.clientX - pointerX) }));
    } else if (phase === "end") {
      resizeStart.current = null;
    }
  }

  return (
    <DataTable wrapperClassName="table-wrap" label="Authentication event table. Scroll horizontally to view all columns." className={`data-table ${selectable ? "selectable-data-table" : ""}`}>
        <thead><tr>{selectable && <th className="event-select-cell"><input type="checkbox" checked={allSelected} onChange={() => onToggleSelectAll?.(events, allSelected)} aria-label="Select all events on this page" /></th>}{columns.map(({ key, label }) => <th key={key} aria-sort={sort.key === key ? (sort.direction === "asc" ? "ascending" : "descending") : "none"} style={widths[key] ? { width: widths[key] } : undefined}><button className="table-sort-button" onClick={() => setSort((current) => ({ key, direction: current.key === key && current.direction === "asc" ? "desc" : "asc" }))}>{label}{sort.key === key && (sort.direction === "asc" ? <ArrowUp size={10} /> : <ArrowDown size={10} />)}</button>{!compact && <button className="column-resizer" aria-label={`Resize ${label.toLowerCase()} column`} onPointerDown={(event) => resizeColumn(event, key, "start")} onPointerMove={(event) => resizeColumn(event, key, "move")} onPointerUp={(event) => resizeColumn(event, key, "end")} onPointerCancel={(event) => resizeColumn(event, key, "end")} />}</th>)}</tr></thead>
        <tbody>
          {sortedEvents.map((event) => {
            const risk = eventRisk(event, alerts);
            const cells = {
              timestamp: <td className="muted-cell"><time dateTime={event.timestamp}>{formatDate(event.timestamp)}</time></td>,
              source_ip: <td><code>{event.source_ip}</code></td>,
              username: <td className="user-cell">{event.username}</td>,
              event_type: <td><span className="event-type">{event.event_type}</span></td>,
              status: <td><Badge variant={event.status === "success" ? "success" : "failure"} className="result-pill" icon={event.status === "success" ? <CircleCheck size={11} /> : <CircleX size={11} />}>{event.status}</Badge></td>,
              risk: <td><span className={`risk-chip ${risk}`}><i />{risk}</span></td>,
            };
            const selected = selectedIds.has(event.id);
            return <tr key={event.id} className={`${onSelect ? "selectable-row" : ""} ${selected ? "is-selected" : ""}`.trim()} aria-selected={selectable ? selected : undefined} onClick={() => onSelect?.(event)} onKeyDown={(keyboardEvent) => {
              if ((keyboardEvent.key === "Enter" || keyboardEvent.key === " ") && keyboardEvent.target === keyboardEvent.currentTarget) {
                keyboardEvent.preventDefault();
                onSelect?.(event);
              }
            }} tabIndex={onSelect ? 0 : undefined}>
              {selectable && <td className="event-select-cell" onClick={(clickEvent) => clickEvent.stopPropagation()}><input type="checkbox" checked={selectedIds.has(event.id)} onChange={() => onToggleSelect?.(event)} aria-label={`Select event ${event.id}`} /></td>}
              {columns.map(({ key }) => <td key={key} className={cells[key].props.className} style={widths[key] ? { width: widths[key] } : undefined}>{cells[key].props.children}</td>)}
            </tr>;
          })}
        </tbody>
    </DataTable>
  );
}
