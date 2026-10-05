import type { ReactNode } from "react";

export function WebProfileGate({
  isOpen,
  setup,
  workspace,
}: {
  isOpen: boolean;
  setup: ReactNode;
  workspace: ReactNode;
}) {
  return <>{isOpen ? workspace : setup}</>;
}
