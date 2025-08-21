import { defineConfig } from "vitest/config"
import vue from "@vitejs/plugin-vue"
import license from "rollup-plugin-license"
import VueI18n from "@intlify/unplugin-vue-i18n/vite"
import path from "path"

// https://vitejs.dev/config/
// https://vitest.dev/config/
export default defineConfig({
  plugins: [
    vue(),
    VueI18n({
      include: [path.resolve(__dirname, "src/locales/**")],
      runtimeOnly: true,
      compositionOnly: true,
      dropMessageCompiler: true,
      fullInstall: false,
      forceStringify: true,
    }),
    license({
      sourcemap: true,
      thirdParty: {
        includeSelf: true,
        allow: {
          test: "(Apache-2.0 OR MIT OR BSD-2-Clause OR BSD-3-Clause OR ISC)",
          failOnUnlicensed: true,
          failOnViolation: true,
        },
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
