import type { InjectionKey } from "vue"
import type { Flow, Provider } from "@/types"
// It is OK that we fetch siteContext here because the server sends preload header
// so we have to fetch it always anyway. Generally this is already cached.
import siteContext from "@/context"

export const flowKey = Symbol() as InjectionKey<Flow>

export function updateStepsNoCode(flow: Flow) {
  if (!flow.getName()) {
    throw new Error("name is missing")
  }
  flow.updateSteps([
    {
      key: "start",
      name: "Charon sign-in or sign-up",
    },
    { key: "password", name: "Provide password or passphrase" },
    { key: "complete", name: `Redirect to ${flow.getName()}` },
  ])
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

export function updateSteps(flow: Flow, targetStep: string) {
  if (!flow.getName()) {
    throw new Error("name is missing")
  }
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
  } else if (targetStep === "failure") {
    const steps = flow.getSteps()
    if (!steps.length) {
      throw new Error("steps are missing")
    }
    steps[steps.length - 1].key = "failure"
  }
}
