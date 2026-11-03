import { defineConfig } from "vitest/config";

export default defineConfig({
  // Use the TypeScript sources of workspace packages, not their build output.
  resolve: { conditions: ["source"] },
  test: {
    include: ["packages/*/test/**/*.test.ts"],
  },
});
