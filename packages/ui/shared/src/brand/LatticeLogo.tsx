export function LatticeLogo({ className }: { className?: string }) {
  return (
    <img
      className={["lattice-logo", className].filter(Boolean).join(" ")}
      src="/lattice-logo.svg"
      alt=""
      aria-hidden="true"
    />
  );
}
