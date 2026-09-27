import { latticeThemeCss } from "@lattice/theme";
import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";

const theme = document.createElement("style");
theme.textContent = latticeThemeCss();
document.head.append(theme);

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
