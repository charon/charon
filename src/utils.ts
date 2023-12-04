import type { AuthFlowResponse } from "@/types"

export function locationRedirect(response: AuthFlowResponse): boolean {
  // We do not use Vue Router to force a server-side request which might return updated cookies
  // or redirect on its own somewhere because of new (or lack thereof) cookies.
  if (response.location) {
    if (response.location.replace) {
      window.location.replace(response.location.url)
    } else {
      window.location.assign(response.location.url)
    }
    return true
  }
  return false
}

export function fromBase64(input: string): Uint8Array {
  const binary = atob(input)
  const buffer = new ArrayBuffer(binary.length)
  const bytes = new Uint8Array(buffer)
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes
}

export function toBase64(input: Uint8Array): string {
  const str = String.fromCharCode(...input)
  return btoa(str)
}
