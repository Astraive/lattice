import type { WebPageProps } from "../profile/WebPageProps";
import { WebDestinationPage } from "../workspace/WebDestinationPage";

export function WebConnectionsPage(props: WebPageProps) {
  return (
    <WebDestinationPage
      {...props}
      title="Connections"
      description="Peer transports validate signed events independently; transport acceptance is not recipient delivery."
      className="lattice-web-connections"
    />
  );
}
