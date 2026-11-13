import Dialog from "./Dialog";

export default function Drawer({ open, onClose, children, className = "ti-drawer-scrim", drawerClassName = "ti-drawer", labelledBy, label, initialFocusRef }) {
  return <Dialog open={open} onClose={onClose} as="aside" className={className} dialogClassName={drawerClassName} labelledBy={labelledBy} label={label} initialFocusRef={initialFocusRef}>{children}</Dialog>;
}
