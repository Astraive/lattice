import type { ButtonHTMLAttributes } from "react";

export interface ActionButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  tone?: "primary" | "quiet" | "danger";
}

export function ActionButton({ tone = "quiet", className, ...buttonProps }: ActionButtonProps) {
  return (
    <button
      {...buttonProps}
      className={["lattice-action", `lattice-action--${tone}`, className].filter(Boolean).join(" ")}
    />
  );
}
