import { defineConfig, configDefaults } from "vitest/config"
import vue from "@vitejs/plugin-vue"
import istanbul from "vite-plugin-istanbul"
import license from "rollup-plugin-license"
import VueI18n from "@intlify/unplugin-vue-i18n/vite"
import tailwindcss from "@tailwindcss/vite";
import path from "path"

// https://vite.dev/config/
// https://vitest.dev/config/
export default defineConfig({
  define: {
    __VUE_OPTIONS_API__: false,
  },
  plugins: [
    vue(),
    VueI18n({
      include: [path.resolve(__dirname, "src/locales/**")],
      runtimeOnly: true,
      compositionOnly: true,
      dropMessageCompiler: true,
      fullInstall: true,
      forceStringify: true,
    }),
    istanbul({
      include: "src/**/*",
      exclude: ["node_modules", "tests/"],
      extension: [".js", ".ts", ".vue"],
      // Only instrument for E2E coverage when VITE_COVERAGE is set to "true".
      requireEnv: true,
      forceBuildInstrument: true,
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
    tailwindcss(),
  ],
  server: {
    strictPort: true,
    hmr: {
      // We use a different port for HMR so that it goes
      // through our Go development proxy.
      clientPort: 8080,
    },
    // Used for testing SIPASS integration.
    allowedHosts: ["sipasstest.peer.id"],
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
    exclude: [...configDefaults.exclude, "**/tests/*"],
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
