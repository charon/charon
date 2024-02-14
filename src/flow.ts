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
  const steps = flow.getSteps()
  for (const [i, step] of steps.entries()) {
    if (step.key === "code") {
      // We found the code step. We remove it.
      steps.splice(i, 1)
      break
    }
  }
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

export function updateSteps(flow: Flow, targetStep: string, force?: boolean) {
  if (!flow.getTarget()) {
    throw new Error("target is missing")
  }
  if (!flow.getName()) {
    throw new Error("name is missing")
  }

  const newSteps = [
    {
      key: "start",
      name: "Charon sign-in or sign-up",
    },
  ]

  if (targetStep === "passkeySignin") {
    newSteps.push({ key: "passkeySignin", name: "Passkey sign-in" })
  } else if (targetStep === "passkeySignup") {
    newSteps.push({ key: "passkeySignin", name: "Passkey sign-in" }, { key: "passkeySignup", name: "Passkey sign-up" })
  } else if (targetStep === "password" || targetStep === "code") {
    newSteps.push({ key: "password", name: "Provide password or passphrase" }, { key: "code", name: "Provide code" })
  } else if (targetStep === "oidcProvider") {
    newSteps.push({ key: "oidcProvider", name: `Redirect to ${providerName(flow.getProvider())}` })
  }

  // We update steps only if additional steps were generated above.
  // This effectively means that we update steps only for target steps above,
  // while for other target steps we do not update steps (unless "force" is set).
  if (newSteps.length > 1 || force) {
    if (flow.getTarget() === "oidc") {
      newSteps.push({ key: "identity", name: "Choose identity or decline" })
    }
    newSteps.push({ key: "redirect", name: `Redirect to ${flow.getName()}` })
    flow.updateSteps(newSteps)
    return
  }

  // For failed target step we keep the steps, we just change the key/component
  // used for the last step.
  if (targetStep === "failed") {
    const steps = flow.getSteps()
    if (!steps.length) {
      throw new Error("steps are missing")
    }
    steps[steps.length - 1].key = "failed"
  }
}
