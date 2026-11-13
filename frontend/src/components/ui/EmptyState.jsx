export default function EmptyState({ icon, title, description, action, className = "", compact = false }) {
  return (
    <div className={`empty-state ${compact ? "empty-state-compact" : ""} ${className}`.trim()}>
      {icon && <span className="empty-icon">{icon}</span>}
      {title && <strong>{title}</strong>}
      {description && <span>{description}</span>}
      {action}
    </div>
  );
}
