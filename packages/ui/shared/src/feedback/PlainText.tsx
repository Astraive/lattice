export interface PlainTextProps {
  children: string;
  className?: string;
}

/** Displays untrusted user content as React text, never as parsed HTML. */
export function PlainText({ children, className }: PlainTextProps) {
  return <span className={className}>{children}</span>;
}
