type DeepReadonly<T> = T extends string | number | boolean
  ? T
  : { readonly [K in keyof T]: DeepReadonly<T[K]> };

type TokenTree = { [key: string]: string | number | TokenTree };

function deepFreeze<T extends TokenTree>(value: T): DeepReadonly<T> {
  for (const child of Object.values(value)) {
    if (typeof child === "object" && child !== null) deepFreeze(child);
  }
  return Object.freeze(value) as DeepReadonly<T>;
}

/** Presentation tokens only; values do not describe transport or security state. */
export const latticeTheme = deepFreeze({
  color: {
    background: "#0b100d",
    foreground: "#e8efe9",
    surface: "#101713",
    surfaceRaised: "#151f19",
    line: "rgba(221, 237, 224, 0.12)",
    muted: "#9daaa0",
    accent: "#a8ffbf",
    accentStrong: "#66e98b",
    status: {
      success: { color: "#66e98b", label: "Success" },
      warning: { color: "#f2c66d", label: "Warning" },
      danger: { color: "#ff8f86", label: "Error" },
      info: { color: "#8fc8ff", label: "Information" },
    },
  },
  spacing: {
    none: "0",
    xs: "4px",
    sm: "8px",
    md: "12px",
    lg: "16px",
    xl: "24px",
    "2xl": "32px",
    "3xl": "48px",
  },
  type: {
    family: {
      sans: 'Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
      mono: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace",
    },
    size: {
      xs: "0.75rem",
      sm: "0.875rem",
      md: "1rem",
      lg: "1.25rem",
      xl: "1.5rem",
      "2xl": "2rem",
    },
    weight: { regular: 400, medium: 500, semibold: 600, bold: 700 },
    lineHeight: { tight: 1.2, normal: 1.5, relaxed: 1.7 },
  },
  radius: {
    none: "0",
    sm: "4px",
    md: "8px",
    lg: "12px",
    pill: "9999px",
  },
  motion: {
    duration: { instant: "0ms", fast: "120ms", normal: "200ms", slow: "320ms" },
    easing: { standard: "cubic-bezier(0.2, 0, 0, 1)", emphasized: "cubic-bezier(0.2, 0, 0, 1)" },
  },
} as const);

function flattenTokens(tree: TokenTree, prefix: string, rows: string[]): void {
  for (const [key, value] of Object.entries(tree)) {
    const segment = key.replace(/[A-Z]/g, (letter) => `-${letter.toLowerCase()}`);
    const name = prefix ? `${prefix}-${segment}` : segment;
    if (typeof value === "object" && value !== null) {
      flattenTokens(value, name, rows);
    } else {
      rows.push(`  --lattice-${name}: ${value};`);
    }
  }
}

/** Serialize all tokens in stable declaration order, including reduced-motion overrides. */
export function latticeThemeCss(): string {
  const declarations: string[] = [];
  flattenTokens(latticeTheme, "", declarations);
  const base = `:root {\n${declarations.join("\n")}\n}`;
  return `${base}\n\n@media (prefers-reduced-motion: reduce) {\n  :root {\n    --lattice-motion-duration-fast: 0ms;\n    --lattice-motion-duration-normal: 0ms;\n    --lattice-motion-duration-slow: 0ms;\n  }\n}`;
}
