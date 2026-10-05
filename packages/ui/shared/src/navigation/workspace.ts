import type { ReactNode } from "react";

export type WorkspaceDestination = { id: string; label: string; icon: ReactNode };
export type WorkspaceSpace = { id: string; label: string };
export type WorkspaceChannel = { id: string; label: string; kind: "text" | "announcement" };

export type WorkspaceShellProps = {
  destinations: readonly WorkspaceDestination[];
  activeDestination: string;
  onDestinationChange: (id: string) => void;
  spaces: readonly WorkspaceSpace[];
  activeSpace: string | null;
  onSpaceChange: (id: string) => void;
  channels: readonly WorkspaceChannel[];
  activeChannel: string | null;
  onChannelChange: (id: string) => void;
  children: ReactNode;
};
