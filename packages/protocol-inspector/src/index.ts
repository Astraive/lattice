export type InspectionResult = {
  readonly accepted: boolean;
  readonly reason: string;
};

export const protocolInspectorPackage = "@lattice/protocol-inspector" as const;
