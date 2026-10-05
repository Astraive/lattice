import { CheckCircle, Info, WarningCircle, XCircle } from "@phosphor-icons/react";
import type { ReactNode } from "react";

export function StatusNotice({
  kind,
  title,
  children,
}: {
  kind: "info" | "success" | "warning" | "error";
  title?: string;
  children: ReactNode;
}) {
  return (
    <div
      className={`lattice-notice lattice-notice--${kind}`}
      role={kind === "error" ? "alert" : "status"}
    >
      {kind === "success" && <CheckCircle aria-hidden="true" size={18} weight="bold" />}
      {kind === "info" && <Info aria-hidden="true" size={18} weight="bold" />}
      {kind === "warning" && <WarningCircle aria-hidden="true" size={18} weight="bold" />}
      {kind === "error" && <XCircle aria-hidden="true" size={18} weight="bold" />}
      {title && <strong>{title}</strong>}
      <div>{children}</div>
    </div>
  );
}
