import { ChevronLeft, ChevronRight } from "lucide-react";

export default function Pagination({
  total,
  offset,
  limit,
  onOffsetChange,
  loading = false,
  className = "table-pagination",
  ariaLabel = "Pagination",
  summaryPrefix = "Showing",
  showPageCount = false,
  iconButtons = false,
  previousLabel = "Previous",
  nextLabel = "Next",
}) {
  if (!Number.isFinite(total) || !Number.isFinite(limit) || limit <= 0 || total <= limit) return null;
  const pageCount = Math.max(1, Math.ceil(total / limit));
  const page = Math.min(pageCount - 1, Math.floor(offset / limit));
  const start = Math.min(total, offset + 1);
  const end = Math.min(offset + limit, total);
  const previousOffset = Math.max(0, (page - 1) * limit);
  const nextOffset = Math.min((pageCount - 1) * limit, (page + 1) * limit);
  const summary = `${summaryPrefix ? `${summaryPrefix} ` : ""}${start}–${end} of ${total.toLocaleString()}`;
  return (
    <nav className={className} aria-label={ariaLabel}>
      <span>{summary}</span>
      <div>
        <button type="button" onClick={() => onOffsetChange(previousOffset)} disabled={page === 0 || loading} aria-label={previousLabel}>
          {iconButtons ? <ChevronLeft size={15} aria-hidden="true" /> : previousLabel}
        </button>
        {showPageCount && <span aria-current="page">Page {page + 1} of {pageCount}</span>}
        <button type="button" onClick={() => onOffsetChange(nextOffset)} disabled={page >= pageCount - 1 || loading} aria-label={nextLabel}>
          {iconButtons ? <ChevronRight size={15} aria-hidden="true" /> : nextLabel}
        </button>
      </div>
    </nav>
  );
}
