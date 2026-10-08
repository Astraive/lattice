export function LatticeMark({ className }: { className?: string }) {
  return (
    <img
      className={["lattice-mark", className].filter(Boolean).join(" ")}
      src="/lattice-mark.svg"
      alt=""
      aria-hidden="true"
    />
  );
}
