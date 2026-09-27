import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [react()],
  worker: { format: "es" },
  server: { host: "127.0.0.1", port: 1430, strictPort: true },
  preview: { host: "127.0.0.1", port: 1430, strictPort: true },
});
