import { PageHeading } from "@lattice/ui-shared";
import type { WebPageProps } from "../profile/WebPageProps";

export function WebDestinationPage({
  title,
  description,
  children,
  notice,
  error,
  className = "",
}: WebPageProps & { title: string; description: string; className?: string }) {
  return (
    <section className={`lattice-web-page ${className}`} aria-label={title}>
      <PageHeading title={title} description={description} />
      {error}
      {notice}
      {children}
    </section>
  );
}
