import { invoke } from "@tauri-apps/api/core";
import { type FormEvent, useCallback, useEffect, useState } from "react";

type LocalPathCapabilities = {
  localIpAddressObserved: boolean;
};

type RelayListStatus = { relayUrls: string[] };
type RelayMutationStatus = { relayUrl: string; changed: boolean };
type LocalLanEndpoint = { address: string };
type LocalLanDiscovery = {
  state: "endpoint_observed" | "no_endpoint_observed";
  networkContacted: boolean;
  identityAuthenticated: boolean;
  reachabilityVerified: boolean;
  endpoints: LocalLanEndpoint[];
};

type Props = { runtimeAvailable: boolean };

export function LocalNetworkSettings({ runtimeAvailable }: Props) {
  const [pathCapabilities, setPathCapabilities] = useState<LocalPathCapabilities | null>(null);
  const [relayUrls, setRelayUrls] = useState<string[]>([]);
  const [relayInput, setRelayInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [status, setStatus] = useState("");
  const [lanDiscovery, setLanDiscovery] = useState<LocalLanDiscovery | null>(null);

  const refresh = useCallback(async () => {
    setBusy(true);
    setError(null);
    try {
      const [paths, relays] = await Promise.all([
        invoke<LocalPathCapabilities>("scan_local_path_capabilities"),
        invoke<RelayListStatus>("list_local_relays"),
      ]);
      setPathCapabilities(paths);
      setRelayUrls(relays.relayUrls);
      setStatus("Local path status and saved relays refreshed.");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setBusy(false);
    }
  }, []);

  useEffect(() => {
    if (runtimeAvailable) void refresh();
  }, [refresh, runtimeAvailable]);

  async function addRelay(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    setStatus("");
    try {
      const result = await invoke<RelayMutationStatus>("add_local_relay", { url: relayInput });
      setRelayUrls((current) =>
        current.includes(result.relayUrl) ? current : [...current, result.relayUrl].sort(),
      );
      setRelayInput("");
      setStatus(result.changed ? "Relay saved to this local profile." : "Relay is already saved.");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setBusy(false);
    }
  }

  async function removeRelay(url: string) {
    setBusy(true);
    setError(null);
    setStatus("");
    try {
      await invoke<RelayMutationStatus>("remove_local_relay", { url });
      setRelayUrls((current) => current.filter((candidate) => candidate !== url));
      setStatus("Relay removed from this local profile.");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setBusy(false);
    }
  }

  async function discoverLanEndpoints() {
    setBusy(true);
    setError(null);
    setStatus("");
    setLanDiscovery(null);
    try {
      const result = await invoke<LocalLanDiscovery>("discover_local_lan_endpoints");
      setLanDiscovery(result);
      setStatus(
        result.endpoints.length > 0
          ? `Observed ${result.endpoints.length} LAN endpoint candidate(s).`
          : "LAN scan completed; no endpoint was observed.",
      );
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setBusy(false);
    }
  }
  return (
    <section className="local-network-settings" aria-labelledby="local-network-title">
      <div className="section-heading">
        <div>
          <p className="eyebrow">Connectivity</p>
          <h3 id="local-network-title">Local paths and relays</h3>
        </div>
        {runtimeAvailable && (
          <button type="button" disabled={busy} onClick={() => void refresh()}>
            Refresh local status
          </button>
        )}
      </div>
      {!runtimeAvailable ? (
        <p>Open the Tauri desktop app to inspect local path readiness and edit relay settings.</p>
      ) : (
        <>
          <div className="local-path-status" aria-live="polite">
            <strong>
              LAN address {pathCapabilities?.localIpAddressObserved ? "observed" : "not observed"}
            </strong>
            <span>Interface names and addresses are not exposed.</span>
            <span>Reachability: not checked. LAN endpoint scan: not run in this session.</span>
            <span>BLE, Wi-Fi Aware, and Wi-Fi Direct are not probed on desktop.</span>
          </div>
          <div className="identity-actions">
            <button type="button" disabled={busy} onClick={() => void discoverLanEndpoints()}>
              Scan LAN for Lattice endpoints
            </button>
          </div>
          {lanDiscovery && (
            <div className="relay-settings" aria-labelledby="lan-discovery-title">
              <h4 id="lan-discovery-title">LAN endpoint observations</h4>
              <p>
                {lanDiscovery.state === "endpoint_observed"
                  ? "The scan observed these endpoints in mDNS records."
                  : "The scan completed without observing a Lattice endpoint."}
              </p>
              {lanDiscovery.endpoints.length > 0 && (
                <ul className="relay-settings-list">
                  {lanDiscovery.endpoints.map(({ address }) => (
                    <li key={address}>
                      <code>{address}</code>
                    </li>
                  ))}
                </ul>
              )}
              <p>
                Network contacted: {lanDiscovery.networkContacted ? "yes" : "no"}. Identity
                authenticated: {lanDiscovery.identityAuthenticated ? "yes" : "no"}. Reachability
                verified: {lanDiscovery.reachabilityVerified ? "yes" : "no"}. No connection was
                attempted; verify a peer pin before connecting.
              </p>
            </div>
          )}
          <div className="relay-settings">
            <div className="relay-settings-heading">
              <div>
                <h4>Optional relay URLs</h4>
                <p>
                  Stored only in this local profile. Saving or removing a URL makes no connection.
                </p>
              </div>
              <span>{relayUrls.length}/64</span>
            </div>
            <form className="relay-settings-form" onSubmit={(event) => void addRelay(event)}>
              <label htmlFor="local-relay-url">Secure relay URL</label>
              <div>
                <input
                  autoComplete="url"
                  id="local-relay-url"
                  maxLength={2048}
                  onChange={(event) => setRelayInput(event.target.value)}
                  placeholder="wss://relay.example"
                  type="text"
                  value={relayInput}
                />
                <button type="submit" disabled={busy || relayInput.length === 0}>
                  Add relay
                </button>
              </div>
              <small>Only wss:// URLs are accepted; credentials and fragments are rejected.</small>
            </form>
            {relayUrls.length > 0 ? (
              <ul className="relay-settings-list">
                {relayUrls.map((url) => (
                  <li key={url}>
                    <code>{url}</code>
                    <button type="button" disabled={busy} onClick={() => void removeRelay(url)}>
                      Remove
                    </button>
                  </li>
                ))}
              </ul>
            ) : (
              <p>No relay URLs are configured.</p>
            )}
          </div>
        </>
      )}
      {busy && <p role="status">Working with local connectivity settings…</p>}
      {status && <p role="status">{status}</p>}
      {error && <p role="alert">{error}</p>}
    </section>
  );
}
