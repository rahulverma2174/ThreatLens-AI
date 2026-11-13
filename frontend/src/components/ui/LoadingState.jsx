export function Skeleton({ className = "", width, height, ...props }) {
  const style = { ...(width ? { width } : {}), ...(height ? { height } : {}), ...props.style };
  return <span className={`skeleton ${className}`.trim()} style={style} aria-hidden="true" />;
}

export default function LoadingState({ label = "Loading…", variant = "inline", className = "" }) {
  if (variant === "workspace") {
    return (
      <div className={`workspace-loading ${className}`.trim()} role="status" aria-live="polite" aria-label={label}>
        <div className="workspace-loading-heading"><Skeleton /><Skeleton /></div>
        <div className="workspace-loading-metrics"><Skeleton /><Skeleton /><Skeleton /></div>
        <span className="workspace-loading-label"><span className="status-pulse" aria-hidden="true" />{label}</span>
        <Skeleton className="workspace-loading-panel" />
      </div>
    );
  }
  return <div className={`loading-state ${className}`.trim()} role="status" aria-live="polite"><span className="status-pulse" aria-hidden="true" />{label}</div>;
}
