import { AlertTriangle } from "lucide-react";

export default function ErrorState({ title, message, action, className = "", variant = "inline" }) {
  if (variant === "banner") {
    return (
      <div className={`error-banner ${className}`.trim()} role="alert">
        <AlertTriangle size={14} aria-hidden="true" />
        <span>{message}</span>
        {action}
      </div>
    );
  }
  return (
    <div className={`error-state ${className}`.trim()} role="alert">
      <AlertTriangle size={16} aria-hidden="true" />
      {title && <strong>{title}</strong>}
      <span>{message}</span>
      {action}
    </div>
  );
}
