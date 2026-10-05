import type { WebPageProps } from "../profile/WebPageProps";
import { WebDestinationPage } from "../workspace/WebDestinationPage";

export function WebIdentityPage(props: WebPageProps) {
  return (
    <WebDestinationPage
      {...props}
      title="Your local identity"
      description="Profile details and issuer enrollment."
      className="lattice-web-identity"
    />
  );
}
