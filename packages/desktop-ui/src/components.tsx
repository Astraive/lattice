export type DeliveryState = "queued" | "forwarded" | "delivered" | "error";

const deliveryStateLabels: Record<DeliveryState, string> = {
  queued: "Queued",
  forwarded: "Forwarded",
  delivered: "Delivered",
  error: "Error",
};

export interface DeliveryStatusProps {
  state: DeliveryState;
  className?: string;
}

/** A textual delivery state indicator; presentation does not imply authentication. */
export function DeliveryStatus({ state, className }: DeliveryStatusProps) {
  const classes = ["delivery-status", `delivery-status--${state}`, className]
    .filter(Boolean)
    .join(" ");
  const label = deliveryStateLabels[state];

  return (
    <span className={classes} role="status" aria-label={`Delivery status: ${label}`}>
      <span className="delivery-status__indicator" aria-hidden="true" />
      <span className="delivery-status__label">{label}</span>
    </span>
  );
}

export interface PlainTextProps {
  children: string;
  className?: string;
}

/** Displays untrusted user content as React text, never as parsed HTML. */
export function PlainText({ children, className }: PlainTextProps) {
  return <span className={className}>{children}</span>;
}
