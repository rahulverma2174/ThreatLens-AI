import { ArrowDown, ArrowUp, Minus } from "lucide-react";
import { AnimatePresence, motion, useReducedMotion } from "framer-motion";

export default function MetricCard({ label, value, description, icon: Icon, tone = "cyan", loading = false, index = 0, trend, status }) {
  const reduceMotion = useReducedMotion();
  const displayValue = loading ? "—" : (typeof value === "number" ? value.toLocaleString() : (value ?? 0));
  return (
    <motion.article
      className={`metric-cell metric-${tone}`}
      initial={reduceMotion ? false : { opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: reduceMotion ? .01 : .16, delay: reduceMotion ? 0 : index * .035, ease: "easeOut" }}
      aria-label={`${label}: ${displayValue}${description ? `. ${description}` : ""}${status ? `. Status: ${status}` : ""}${trend?.text ? `. ${trend.text}` : ""}`}
    >
      <div className="metric-top">
        {Icon && <span className="metric-icon"><Icon size={15} aria-hidden="true" /></span>}
        <span className="metric-label">{label}</span>
      </div>
      <AnimatePresence mode="wait" initial={false}>
        <motion.strong key={String(displayValue)} className="metric-value" initial={reduceMotion ? false : { opacity: 0, y: 2 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: reduceMotion ? 0 : -2 }} transition={{ duration: reduceMotion ? .01 : .12, ease: "easeOut" }}>
          {displayValue}
        </motion.strong>
      </AnimatePresence>
      {description && <small className="metric-scope">{description}</small>}
      {status && <span className="metric-status"><i aria-hidden="true" />{status}</span>}
      {trend?.text && <span className={`metric-trend ${["positive", "negative", "neutral"].includes(trend.tone) ? trend.tone : "neutral"}`} aria-label={trend.text}>
        {trend.direction === "up" ? <ArrowUp size={12} aria-hidden="true" /> : trend.direction === "down" ? <ArrowDown size={12} aria-hidden="true" /> : <Minus size={12} aria-hidden="true" />}
        <span>{trend.text}</span>
      </span>}
    </motion.article>
  );
}
