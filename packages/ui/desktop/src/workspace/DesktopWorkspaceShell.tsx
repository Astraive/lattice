// biome-ignore-all lint/a11y/noNoninteractiveTabindex: The scrollable workspace region must be keyboard-focusable.
import { LatticeMark, type WorkspaceShellProps } from "@lattice/ui-shared";
import { Hash, Megaphone, Minus, Plus } from "@phosphor-icons/react";
import { useState } from "react";

export function DesktopWorkspaceShell({
  destinations,
  activeDestination,
  onDestinationChange,
  spaces,
  activeSpace,
  onSpaceChange,
  channels,
  activeChannel,
  onChannelChange,
  children,
}: WorkspaceShellProps) {
  const [showSpaceTools, setShowSpaceTools] = useState(true);

  return (
    <div
      className={`lattice-workspace lattice-workspace--desktop${activeDestination === "spaces" ? " lattice-workspace--spaces-active" : ""}`}
    >
      <nav className="lattice-workspace__rail" aria-label="Main navigation">
        <span className="lattice-workspace__brand" aria-label="Lattice" role="img">
          <LatticeMark />
        </span>
        {destinations.map((destination) => (
          <button
            aria-current={destination.id === activeDestination ? "page" : undefined}
            aria-label={destination.label}
            className="lattice-workspace__destination"
            key={destination.id}
            onClick={() => onDestinationChange(destination.id)}
            title={destination.label}
            type="button"
          >
            <span aria-hidden="true">{destination.icon}</span>
            <span>{destination.label}</span>
          </button>
        ))}
      </nav>
      <aside className="lattice-workspace__sidebar" aria-label="Space navigation">
        <header className="lattice-workspace__sidebar-heading">
          <span>Spaces</span>
          <button
            aria-expanded={showSpaceTools}
            aria-label="Toggle Space navigation"
            onClick={() => setShowSpaceTools((shown) => !shown)}
            type="button"
          >
            {showSpaceTools ? (
              <Minus size={15} aria-hidden="true" />
            ) : (
              <Plus size={15} aria-hidden="true" />
            )}
          </button>
        </header>
        {showSpaceTools && (
          <>
            <nav className="lattice-workspace__spaces" aria-label="Spaces">
              {spaces.map((space) => (
                <button
                  key={space.id}
                  type="button"
                  aria-current={space.id === activeSpace ? "page" : undefined}
                  onClick={() => onSpaceChange(space.id)}
                >
                  {space.label}
                </button>
              ))}
            </nav>
            {activeSpace && (
              <nav className="lattice-workspace__channels" aria-label="Channels">
                <h2>Channels</h2>
                {channels.map((channel) => (
                  <button
                    key={channel.id}
                    type="button"
                    aria-current={channel.id === activeChannel ? "page" : undefined}
                    onClick={() => onChannelChange(channel.id)}
                  >
                    <span aria-hidden="true">
                      {channel.kind === "announcement" ? (
                        <Megaphone size={15} />
                      ) : (
                        <Hash size={15} />
                      )}
                    </span>
                    {channel.label}
                  </button>
                ))}
              </nav>
            )}
          </>
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
    </div>
  );
}
