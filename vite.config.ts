/// <reference types="vitest" />
import { defineConfig } from "vite"
import vue from "@vitejs/plugin-vue"
import license from "rollup-plugin-license"
import path from "path"

// https://vitejs.dev/config/
// https://vitest.dev/config/
export default defineConfig({
  plugins: [
    vue(),
    license({
      sourcemap: true,
      thirdParty: {
        output: {
          file: path.join(__dirname, "dist", "NOTICE.txt"),
        },
      },
    }),
  ],
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
    sourcemap: true,
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
