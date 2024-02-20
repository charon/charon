/// <reference types="vitest" />
import { defineConfig } from "vite"
import vue from "@vitejs/plugin-vue"

// https://vitejs.dev/config/
// https://vitest.dev/config/
export default defineConfig({
  plugins: [vue()],
  server: {
    strictPort: true,
    hmr: {
      // We use a different port for HMR so that it goes
      // through our Go development proxy.
      clientPort: 8080,
    },
  },
  resolve: {
    alias: {
      "@": "/src",
    },
  },
  build: {
    target: ["esnext"],
  },
  test: {
    coverage: {
      provider: "v8",
      reporter: ["text", "cobertura", "html"],
      all: true,
    },
  },
  esbuild: {
    legalComments: "none",
  },
  assetsInclude: ["**/argon2id/dist/*.wasm"],
})
