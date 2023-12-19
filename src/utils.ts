import type { InjectionKey } from "vue"
import type { AuthFlowResponse, Flow, Provider } from "@/types"
// It is OK that We fetch siteContext here because the server sends preload header
// so we have to fetch it always anyway. Generally this is already cached.
import siteContext from "@/context"

export function locationRedirect(response: AuthFlowResponse, flow?: Flow): boolean {
  // We do not use Vue Router to force a server-side request which might return updated cookies
  // or redirect on its own somewhere because of new (or lack thereof) cookies.
  if ("location" in response) {
    if (response.completed && flow) {
      flow.updateLocation(response.location)
      flow.updateName(response.name!)
      flow.forward("complete")
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

export function getProvider(provider: string): Provider | null {
  for (const p of siteContext.providers) {
    if (p.key === provider) {
      return p
    }
  }
  return null
}

export function providerName(provider: string): string {
  const p = getProvider(provider)
  if (p) {
    return p.name
  }
  throw new Error(`provider "${provider}" not found among providers`)
}

export const flowKey = Symbol() as InjectionKey<Flow>

export function updateStepsCodeNotPossible(flow: Flow) {
  flow.updateSteps([
    {
      key: "start",
      name: "Charon sign-in or sign-up",
    },
    { key: "password", name: "Provide password or passphrase" },
    { key: "complete", name: `Redirect to ${flow.getName()}` },
  ])
}

export function updateSteps(flow: Flow, targetStep: string) {
  if (targetStep === "passkeySignin") {
    flow.updateSteps([
      {
        key: "start",
        name: "Charon sign-in or sign-up",
      },
      { key: "passkeySignin", name: "Passkey sign-in" },
      { key: "complete", name: `Redirect to ${flow.getName()}` },
    ])
  } else if (targetStep === "passkeySignup") {
    flow.updateSteps([
      {
        key: "start",
        name: "Charon sign-in or sign-up",
      },
      { key: "passkeySignin", name: "Passkey sign-in" },
      { key: "passkeySignup", name: "Passkey sign-up" },
      { key: "complete", name: `Redirect to ${flow.getName()}` },
    ])
  } else if (targetStep === "password" || targetStep === "code") {
    flow.updateSteps([
      {
        key: "start",
        name: "Charon sign-in or sign-up",
      },
      { key: "password", name: "Provide password or passphrase" },
      { key: "code", name: "Provide code" },
      { key: "complete", name: `Redirect to ${flow.getName()}` },
    ])
  } else if (targetStep === "oidcProvider") {
    flow.updateSteps([
      {
        key: "start",
        name: "Charon sign-in or sign-up",
      },
      { key: "oidcProvider", name: `Redirect to ${providerName(flow.getProvider())}` },
      { key: "complete", name: `Redirect to ${flow.getName()}` },
    ])
  }
}
