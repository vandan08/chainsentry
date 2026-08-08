import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Dev-time API proxy; override the backend with BACKEND_URL
// (this machine runs the backend on 8081 via the `local` profile).
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": process.env.BACKEND_URL ?? "http://localhost:8080",
      "/auth": process.env.BACKEND_URL ?? "http://localhost:8080",
    },
  },
});
