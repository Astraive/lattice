import { type ReactNode, useId } from "react";

export function EmptyState({
  title,
  body,
  action,
}: {
  title: string;
  body: ReactNode;
  action?: ReactNode;
}) {
  const titleId = useId();
  return (
    <section className="lattice-empty-state" aria-labelledby={titleId}>
      <h2 id={titleId}>{title}</h2>
      <div>{body}</div>
      {action && <div className="lattice-empty-state__action">{action}</div>}
    </section>
  );
}
