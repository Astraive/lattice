import { cloneElement, isValidElement, type ReactElement, type ReactNode } from "react";

export function FormField({
  label,
  htmlFor,
  hint,
  error,
  children,
}: {
  label: string;
  htmlFor: string;
  hint?: string | undefined;
  error?: string | undefined;
  children: ReactNode;
}) {
  const descriptionId = `${htmlFor}-description`;
  const control = isValidElement(children)
    ? cloneElement(children as ReactElement<Record<string, unknown>>, {
        "aria-describedby": error || hint ? descriptionId : undefined,
        "aria-invalid": error ? true : undefined,
      })
    : children;
  return (
    <div className="lattice-field">
      <label htmlFor={htmlFor}>{label}</label>
      {control}
      {(error || hint) && (
        <span id={descriptionId} className={error ? "lattice-field__error" : "lattice-field__hint"}>
          {error || hint}
        </span>
      )}
    </div>
  );
}
