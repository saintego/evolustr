import { defineConfig } from "vitest/config";

// Use the TypeScript sources of workspace packages, not their build output:
// inline them so Vite resolves them with the "source" export condition.
export default defineConfig({
  resolve: { conditions: ["source"] },
  ssr: { resolve: { conditions: ["source"] } },
  test: {
    include: ["packages/*/test/**/*.test.ts"],
    server: { deps: { inline: [/@evolustr\//] } },
  },
});
