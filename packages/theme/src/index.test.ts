import { expect, test } from "bun:test";
import { latticeTheme, latticeThemeCss } from "./index";

test("theme tokens are frozen at every level", () => {
  expect(Object.isFrozen(latticeTheme)).toBe(true);
  expect(Object.isFrozen(latticeTheme.color)).toBe(true);
  expect(Object.isFrozen(latticeTheme.color.status)).toBe(true);
  expect(Object.isFrozen(latticeTheme.motion.duration)).toBe(true);
  expect(() => {
    Object.assign(latticeTheme.color.status.success, { label: "Changed" });
  }).toThrow();
  expect(latticeTheme.color.status.success.label).toBe("Success");
});

test("status tokens carry distinct labels as well as colors", () => {
  const statusTokens = Object.values(latticeTheme.color.status);
  expect(new Set(statusTokens.map(({ color }) => color)).size).toBe(statusTokens.length);
  expect(statusTokens.map(({ label }) => label)).toEqual([
    "Success",
    "Warning",
    "Error",
    "Information",
  ]);
});

test("CSS serialization is stable and honors reduced motion", () => {
  const css = latticeThemeCss();

  expect(latticeThemeCss()).toBe(css);
  expect(css).toContain("--lattice-color-background: #000000;");
  expect(css).toContain("--lattice-color-surface: #090F0B;");
  expect(css).toContain("--lattice-color-surface-raised: #121A14;");
  expect(css).toContain("--lattice-color-accent: #8FE3A4;");
  expect(css).toContain("--lattice-radius-none: 0px;");
  expect(css).toContain("--lattice-radius-sm: 0px;");
  expect(css).toContain("--lattice-radius-md: 0px;");
  expect(css).toContain("--lattice-radius-lg: 0px;");
  expect(css).toContain("--lattice-type-family-sans: system-ui,");
  expect(css).toContain("--lattice-motion-duration-normal: 200ms;");
  expect(css).toContain("@media (prefers-reduced-motion: reduce)");
  expect(css).toContain("--lattice-motion-duration-normal: 0ms;");
  expect(css).not.toContain("--lattice--");
});
