// biome-ignore-all lint/a11y/noNoninteractiveTabindex: the scrollable workspace must be keyboard-focusable
import {
  ActionButton,
  EmptyState,
  LatticeLogo,
  type WorkspaceShellProps,
} from "@lattice/ui-shared";
import { Hash, List, Megaphone, X } from "@phosphor-icons/react";
import { useState } from "react";

export function WebWorkspaceShell({
  destinations,
  activeDestination,
  onDestinationChange,
  spaces,
  activeSpace,
  onSpaceChange,
  channels,
  activeChannel,
  onChannelChange,
  onLockProfile,
  children,
}: WorkspaceShellProps & { onLockProfile: () => void }) {
  const [drawerOpen, setDrawerOpen] = useState(false);
  const chooseDestination = (id: string) => {
    onDestinationChange(id);
    setDrawerOpen(false);
  };
  return (
    <div className="lattice-workspace lattice-workspace--web">
      <header className="lattice-web-topbar">
        <ActionButton
          aria-label={drawerOpen ? "Close spaces and channels" : "Open spaces and channels"}
          aria-expanded={drawerOpen}
          aria-controls="lattice-space-drawer"
          className="lattice-web-menu"
          onClick={() => setDrawerOpen((open) => !open)}
          tone="quiet"
          type="button"
        >
          {drawerOpen ? <X size={20} aria-hidden="true" /> : <List size={20} aria-hidden="true" />}
        </ActionButton>
        <span className="lattice-workspace__brand" role="img" aria-label="Lattice">
          <LatticeLogo />
        </span>
        <ActionButton
          className="lattice-web-lock"
          onClick={onLockProfile}
          tone="quiet"
          type="button"
        >
          Lock profile
        </ActionButton>
      </header>
      <nav className="lattice-web-destinations" aria-label="Main navigation">
        {destinations.map((destination) => (
          <button
            key={destination.id}
            type="button"
            aria-current={destination.id === activeDestination ? "page" : undefined}
            onClick={() => chooseDestination(destination.id)}
          >
            <span aria-hidden="true">{destination.icon}</span>
            <span>{destination.label}</span>
          </button>
        ))}
      </nav>
      <aside
        id="lattice-space-drawer"
        className={`lattice-web-sidebar${drawerOpen ? " is-open" : ""}`}
        aria-label="Space and channel navigation"
      >
        {spaces.length === 0 ? (
          <EmptyState title="No Spaces yet" body="Create or join one on the Spaces page." />
        ) : (
          <nav className="lattice-workspace__spaces" aria-label="Spaces">
            {spaces.map((space) => (
              <button
                key={space.id}
                type="button"
                aria-current={space.id === activeSpace ? "page" : undefined}
                onClick={() => {
                  onSpaceChange(space.id);
                  setDrawerOpen(false);
                }}
              >
                {space.label}
              </button>
            ))}
          </nav>
        )}
        {activeSpace && (
          <nav className="lattice-workspace__channels" aria-label="Channels">
            <h2>Channels</h2>
            {channels.map((channel) => (
              <button
                key={channel.id}
                type="button"
                aria-current={channel.id === activeChannel ? "page" : undefined}
                onClick={() => {
                  onChannelChange(channel.id);
                  setDrawerOpen(false);
                }}
              >
                <span aria-hidden="true">
                  {channel.kind === "announcement" ? (
                    <Megaphone size={16} weight="regular" />
                  ) : (
                    <Hash size={16} weight="regular" />
                  )}
                </span>
                {channel.label}
              </button>
            ))}
          </nav>
        )}
      </aside>
      <main
        aria-label="Workspace content"
        className="lattice-workspace__content"
        id="workspace-content"
        tabIndex={0}
      >
        {children}
      </main>
      <nav className="lattice-web-bottom-nav" aria-label="Main navigation">
        {destinations.map((destination) => (
          <button
            key={destination.id}
            type="button"
            aria-current={destination.id === activeDestination ? "page" : undefined}
            onClick={() => chooseDestination(destination.id)}
          >
            <span aria-hidden="true">{destination.icon}</span>
            <span>{destination.label}</span>
          </button>
        ))}
      </nav>
    </div>
  );
}
