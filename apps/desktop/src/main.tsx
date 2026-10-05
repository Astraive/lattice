import { latticeThemeCss } from "@lattice/theme";
import React from "react";
import ReactDOM from "react-dom/client";
import "@lattice/ui-shared/styles.css";
import "@lattice/ui-desktop/styles.css";
import App from "./App";

if (!document.getElementById("lattice-theme-tokens")) {
  const theme = document.createElement("style");
  theme.id = "lattice-theme-tokens";
  theme.textContent = latticeThemeCss();
  document.head.append(theme);
}

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
