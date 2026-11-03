import { defineConfig } from "vite";

export default defineConfig({
  // Relative paths, so the build works on GitHub Pages and as an nsite.
  base: "./",
  optimizeDeps: { exclude: ["@evolu/sqlite-wasm"] },
  worker: { format: "es" },
  build: { target: "es2022" },
});
