import { cloneElement, isValidElement } from "react";

export default function FormField({ label, htmlFor, help, error, required = false, className = "", children }) {
  const helpId = help && htmlFor ? `${htmlFor}-help` : undefined;
  const errorId = error && htmlFor ? `${htmlFor}-error` : undefined;
  const control = isValidElement(children)
    ? cloneElement(children, {
      id: children.props.id ?? htmlFor,
      required: required || children.props.required,
      "aria-required": required ? true : children.props["aria-required"],
      "aria-invalid": error ? true : children.props["aria-invalid"],
      "aria-describedby": [children.props["aria-describedby"], helpId, errorId].filter(Boolean).join(" ") || undefined,
    })
    : children;
  return (
    <div className={`form-field ${error ? "has-error" : ""} ${className}`.trim()}>
      {label && <label className="form-field-label" htmlFor={htmlFor}>{label}{required && <span aria-hidden="true"> *</span>}</label>}
      {control}
      {help && <small className="form-field-help" id={helpId}>{help}</small>}
      {error && <small className="form-field-error" id={errorId} role="alert">{error}</small>}
    </div>
  );
}
