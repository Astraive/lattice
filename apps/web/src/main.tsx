import { latticeThemeCss } from "@lattice/theme";
import "@lattice/ui-shared/styles.css";
import "@lattice/ui-web/styles.css";
import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";

const theme = document.createElement("style");
theme.dataset.latticeTheme = "true";
theme.textContent = latticeThemeCss();
document.head.append(theme);

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
