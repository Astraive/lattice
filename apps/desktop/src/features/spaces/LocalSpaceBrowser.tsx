import { invoke } from "@tauri-apps/api/core";
import { useState } from "react";

type LocalSpaceSummary = {
  spaceId: string;
  groupReference: string;
};

type LocalSpacePage = {
  spaces: LocalSpaceSummary[];
  nextCursor: string | null;
};

type LocalSpaceBrowserProps = {
  runtimeAvailable: boolean;
};

export function LocalSpaceBrowser({ runtimeAvailable }: LocalSpaceBrowserProps) {
  const [spaces, setSpaces] = useState<LocalSpaceSummary[]>([]);
  const [spaceCursor, setSpaceCursor] = useState<string | null>(null);
  const [spaceError, setSpaceError] = useState<string | null>(null);
  const [spacesBusy, setSpacesBusy] = useState(false);
  const [spacesLoaded, setSpacesLoaded] = useState(false);

  async function runSpacesCommand(after: string | null = null) {
    setSpacesBusy(true);
    setSpaceError(null);
    try {
      const page = await invoke<LocalSpacePage>("list_local_spaces", { after });
      setSpaces((current) => (after ? [...current, ...page.spaces] : page.spaces));
      setSpaceCursor(page.nextCursor);
      setSpacesLoaded(true);
    } catch (cause) {
      setSpaceError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setSpacesBusy(false);
    }
  }

  return (
    <section className="space-browser" aria-labelledby="spaces-title">
      <div className="space-browser-heading">
        <div>
          <h3 id="spaces-title">Local Spaces</h3>
          <p>Verified local Genesis snapshots only; this does not imply current membership.</p>
        </div>
        {runtimeAvailable && (
          <button
            type="button"
            disabled={spacesBusy}
            onClick={() => void runSpacesCommand(spacesLoaded ? spaceCursor : null)}
          >
            {spacesBusy
              ? "Loading…"
              : spaceCursor
                ? "Load next page"
                : spacesLoaded
                  ? "Refresh Spaces"
                  : "Load local Spaces"}
          </button>
        )}
      </div>
      {!runtimeAvailable && <p>Open the desktop app to inspect its protected local Space store.</p>}
      {spaceError && <p role="alert">{spaceError}</p>}
      {spacesLoaded && spaces.length === 0 && <p>No local Space snapshots were found.</p>}
      {spaces.length > 0 && (
        <ul className="space-list" aria-live="polite">
          {spaces.map((space) => (
            <li key={`${space.spaceId}:${space.groupReference}`}>
              <span>Space</span>
              <code>{space.spaceId}</code>
              <span>MLS group</span>
              <code>{space.groupReference}</code>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
