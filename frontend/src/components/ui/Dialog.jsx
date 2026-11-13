import { useEffect, useRef } from "react";
import { AnimatePresence, motion, useReducedMotion } from "framer-motion";

const focusableSelector = 'a[href], button:not(:disabled), input:not(:disabled), select:not(:disabled), textarea:not(:disabled), [contenteditable="true"], [tabindex]:not([tabindex="-1"])';
const visibleFocusable = (root) => [...root.querySelectorAll(focusableSelector)].filter((element) => element.getClientRects().length > 0 && element.getAttribute("aria-hidden") !== "true");

export default function Dialog({
  open,
  onClose,
  children,
  className = "modal-backdrop",
  dialogClassName = "modal",
  labelledBy,
  label,
  initialFocusRef,
  as = "section",
}) {
  const dialogRef = useRef(null);
  const previousFocusRef = useRef(null);
  const previousOverflowRef = useRef("");
  const onCloseRef = useRef(onClose);
  const reduceMotion = useReducedMotion();
  const DialogElement = motion[as] ?? motion.section;

  useEffect(() => { onCloseRef.current = onClose; }, [onClose]);

  useEffect(() => {
    if (!open) return undefined;
    previousFocusRef.current = document.activeElement;
    previousOverflowRef.current = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    const focusTarget = initialFocusRef?.current ?? (dialogRef.current && visibleFocusable(dialogRef.current)[0]) ?? dialogRef.current;
    window.requestAnimationFrame(() => focusTarget?.focus?.({ preventScroll: true }));

    const handleKeyDown = (event) => {
      if (event.key === "Escape") {
        event.preventDefault();
        onCloseRef.current?.();
        return;
      }
      if (event.key !== "Tab" || !dialogRef.current) return;
      const focusable = visibleFocusable(dialogRef.current);
      if (!focusable.length) {
        event.preventDefault();
        dialogRef.current.focus();
        return;
      }
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && (document.activeElement === first || !dialogRef.current.contains(document.activeElement))) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && (document.activeElement === last || !dialogRef.current.contains(document.activeElement))) {
        event.preventDefault();
        first.focus();
      }
    };
    document.addEventListener("keydown", handleKeyDown);
    return () => {
      document.removeEventListener("keydown", handleKeyDown);
      document.body.style.overflow = previousOverflowRef.current;
      if (previousFocusRef.current?.isConnected) previousFocusRef.current.focus?.({ preventScroll: true });
    };
  }, [initialFocusRef, open]);

  return (
    <AnimatePresence>
      {open && (
        <motion.div
          className={className}
          role="presentation"
          onMouseDown={(event) => { if (event.target === event.currentTarget) onCloseRef.current?.(); }}
          initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
          transition={{ duration: reduceMotion ? .01 : .14, ease: "easeOut" }}
        >
          <DialogElement
            ref={dialogRef}
            className={dialogClassName}
            role="dialog"
            aria-modal="true"
            aria-labelledby={labelledBy}
            aria-label={labelledBy ? undefined : label}
            tabIndex={-1}
            initial={reduceMotion ? { opacity: 0 } : { opacity: 0, y: 5, scale: .995 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={reduceMotion ? { opacity: 0 } : { opacity: 0, y: 3, scale: .995 }}
            transition={{ duration: reduceMotion ? .01 : .15, ease: "easeOut" }}
          >
            {children}
          </DialogElement>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
