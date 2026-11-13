import { forwardRef } from "react";
import { LoaderCircle } from "lucide-react";

const Button = forwardRef(function Button({
  variant = "secondary",
  size = "medium",
  loading = false,
  loadingLabel,
  icon,
  iconOnly = false,
  className = "",
  type = "button",
  disabled = false,
  children,
  ...props
}, ref) {
  const classes = ["button", ["primary", "secondary", "danger", "ghost"].includes(variant) ? variant : "secondary", size === "small" ? "small-button" : "", iconOnly ? "button-icon-only" : "", loading ? "is-loading" : "", className].filter(Boolean).join(" ");
  return (
    <button ref={ref} type={type} className={classes} disabled={disabled || loading} aria-busy={loading || undefined} {...props}>
      {loading ? <LoaderCircle className="button-spinner" size={14} aria-hidden="true" /> : icon}
      {iconOnly ? children : <span>{loading ? (loadingLabel ?? children) : children}</span>}
    </button>
  );
});

export default Button;
