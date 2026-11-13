export default function Badge({ variant = "neutral", className = "", icon, dot = false, children, ...props }) {
  return (
    <span className={`ui-badge ${variant} ${className}`.trim()} {...props}>
      {dot && <span className="ui-badge-dot" aria-hidden="true" />}
      {icon && <span className="ui-badge-icon" aria-hidden="true">{icon}</span>}
      {children}
    </span>
  );
}
