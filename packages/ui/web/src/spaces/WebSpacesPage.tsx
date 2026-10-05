import type { WebPageProps } from "../profile/WebPageProps";
import { WebDestinationPage } from "../workspace/WebDestinationPage";

export function WebSpacesPage(props: WebPageProps) {
  return (
    <WebDestinationPage
      {...props}
      title="Spaces"
      description="Local groups, channels, and encrypted message history."
      className="lattice-web-spaces"
    />
  );
}
