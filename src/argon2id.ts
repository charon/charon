import setupWasm from "argon2id/lib/setup.js"
import simdURL from "argon2id/dist/simd.wasm?url"
import noSimdURL from "argon2id/dist/no-simd.wasm?url"
import { toBase64Raw } from "@/utils"

const simdModule = await WebAssembly.compileStreaming(fetch(simdURL))
const noSimdModule = await WebAssembly.compileStreaming(fetch(noSimdURL))

// Same as argon2idParams in auth_password.go.
const argon2idParams = {
  Memory: 19 * 1024,
  Iterations: 2,
  Parallelism: 1,
  SaltLength: 16,
  KeyLength: 32,
}

export async function setupArgon2id() {
  async function getSIMD(importObject: WebAssembly.Imports) {
    return { instance: await WebAssembly.instantiate(simdModule, importObject), module: simdModule }
  }
  async function getNoSIMD(importObject: WebAssembly.Imports) {
    return { instance: await WebAssembly.instantiate(noSimdModule, importObject), module: noSimdModule }
  }

  const argon2id = await setupWasm(getSIMD, getNoSIMD)
  return function (password: Uint8Array): string {
    const salt = crypto.getRandomValues(new Uint8Array(argon2idParams.SaltLength))
    const hash = argon2id({
      password,
      salt,
      parallelism: argon2idParams.Parallelism,
      passes: argon2idParams.Iterations,
      memorySize: argon2idParams.Memory,
      tagLength: argon2idParams.KeyLength,
    })
    return "$".concat(
      [
        "argon2id",
        `v=${0x13}`,
        [`m=${argon2idParams.Memory}`, `t=${argon2idParams.Iterations}`, `p=${argon2idParams.Parallelism}`].join(","),
        toBase64Raw(salt),
        toBase64Raw(hash),
      ].join("$"),
    )
  }
}
