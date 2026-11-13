export default function DataTable({
  children,
  className = "data-table",
  wrapperClassName = "table-wrap",
  label,
  busy = false,
  tabIndex = 0,
  ...tableProps
}) {
  return (
    <div className={wrapperClassName} role="region" aria-label={label || "Data table"} tabIndex={tabIndex}>
      <table className={className} aria-busy={busy || undefined} {...tableProps}>{children}</table>
    </div>
  );
}
