import type { AuthFlowResponse, Flow, LocationResponse } from "@/types"

export function processCompleted(flow: Flow, location: LocationResponse, name: string, completed: "signin" | "signup" | "failed") {
  flow.updateLocation(location)
  flow.updateName(name)
  if (completed === "failed") {
    flow.forward("failure")
  } else {
    // "completed" on the front-end is used only when not a failure.
    flow.updateCompleted(completed)
    flow.forward("complete")
  }
}

export function locationRedirect(response: AuthFlowResponse, flow?: Flow): boolean {
  // We do not use Vue Router to force a server-side request which might return updated cookies
  // or redirect on its own somewhere because of new (or lack thereof) cookies.
  if ("location" in response) {
    if ("completed" in response && flow) {
      processCompleted(flow, response.location, response.name, response.completed)
    } else if (response.location.replace) {
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

export function isEmail(emailOrUsername: string): boolean {
  return emailOrUsername.indexOf("@") >= 0
}

export function replaceLocationHash(hash: string) {
  if (hash) {
    history.replaceState ? history.replaceState(null, "", window.location.href.split("#")[0] + "#" + hash) : (window.location.hash = "#" + hash)
  } else {
    history.replaceState ? history.replaceState(null, "", window.location.href.split("#")[0]) : (window.location.hash = "")
  }
}
