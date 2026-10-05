import type { ReactNode } from "react";

export function Panel({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <section className={["lattice-panel", className].filter(Boolean).join(" ")}>{children}</section>
  );
}
