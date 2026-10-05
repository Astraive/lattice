import type { ButtonHTMLAttributes, ReactNode } from "react";

export interface IconActionButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  label: string;
}

export function IconActionButton({
  label,
  className,
  children,
  ...buttonProps
}: IconActionButtonProps) {
  return (
    <button
      {...buttonProps}
      type={buttonProps.type ?? "button"}
      className={["lattice-icon-action", className].filter(Boolean).join(" ")}
      aria-label={label}
      title={buttonProps.title ?? label}
    >
      {children as ReactNode}
    </button>
  );
}
