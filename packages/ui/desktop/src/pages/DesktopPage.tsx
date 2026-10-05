import { ArrowsClockwise, ChatCircleText, Fingerprint, SquaresFour } from "@phosphor-icons/react";
import type { ReactNode } from "react";

const pageIcons = {
  spaces: SquaresFour,
  "direct-messages": ChatCircleText,
  connections: ArrowsClockwise,
  identity: Fingerprint,
} as const;

export function DesktopPage({
  id,
  title,
  description,
  children,
}: {
  id: keyof typeof pageIcons;
  title: string;
  description?: string;
  children: ReactNode;
}) {
  const Icon = pageIcons[id];
  return (
    <section className={`desktop-page desktop-page--${id}`} aria-label={title}>
      <header className="desktop-page__heading">
        <Icon size={22} weight="regular" aria-hidden="true" />
        <div>
          <h1>{title}</h1>
          {description && <p>{description}</p>}
        </div>
      </header>
      {children}
    </section>
  );
}
