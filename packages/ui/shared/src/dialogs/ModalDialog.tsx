import { X } from "@phosphor-icons/react";
import { type ReactNode, useEffect, useId, useRef } from "react";
import { IconActionButton } from "../buttons/IconActionButton";

export function ModalDialog({
  open,
  title,
  description,
  onClose,
  children,
  className,
}: {
  open: boolean;
  title: string;
  description?: string;
  onClose: () => void;
  children: ReactNode;
  className?: string;
}) {
  const dialogRef = useRef<HTMLDialogElement>(null);
  const titleId = useId();
  const descriptionId = useId();

  useEffect(() => {
    const dialog = dialogRef.current;
    if (!dialog) return;
    if (open && !dialog.open) dialog.showModal();
    else if (!open && dialog.open) dialog.close();
  }, [open]);

  return (
    // biome-ignore lint/a11y/useKeyWithClickEvents: Escape and the close button provide keyboard dismissal; this click only dismisses the native dialog backdrop.
    <dialog
      ref={dialogRef}
      className={["lattice-dialog", className].filter(Boolean).join(" ")}
      aria-labelledby={titleId}
      aria-describedby={description ? descriptionId : undefined}
      onCancel={(event) => {
        event.preventDefault();
        onClose();
      }}
      onClick={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <header className="lattice-dialog__header">
        <div>
          <h2 id={titleId}>{title}</h2>
          {description && <p id={descriptionId}>{description}</p>}
        </div>
        <IconActionButton label={`Close ${title}`} onClick={onClose}>
          <X aria-hidden="true" size={18} weight="bold" />
        </IconActionButton>
      </header>
      <div className="lattice-dialog__content">{children}</div>
    </dialog>
  );
}
