import type { Ref } from "vue"
import type { Router } from "vue-router"
import type { Flow, SiteProvider, AuthFlowResponse, Completed } from "@/types"

// It is OK that we fetch siteContext here because the server sends preload header
// so we have to fetch it always anyway. Generally this is already cached.
import siteContext from "@/context"
import { equals, redirectServerSide } from "@/utils"

export function getThirdPartyProvider(providers: string[]): SiteProvider | null {
  for (const provider of providers) {
    for (const p of siteContext.providers) {
      if ((p.type === "oidc" || p.type === "saml") && p.key === provider) {
        return p
      }
    }
  }
  return null
}

export function getProviderName(t: (key: string) => string, provider: string): string {
  switch (provider) {
    case "code":
      return t("common.providers.code")
    case "passkey":
      return t("common.providers.passkey")
    case "password":
      return t("common.providers.password")
  }
  const siteProvider = getThirdPartyProvider([provider])
  if (siteProvider) {
    return siteProvider.name
  }
  throw new Error(`unknown provider: ${provider}`)
}

export function removeSteps(flow: Flow, targetSteps: string[]) {
  const steps = flow.getSteps()
  for (const [i, step] of steps.entries()) {
    if (targetSteps.includes(step.key)) {
      // We found the step. We remove it in-place.
      steps.splice(i, 1)
    }
  }
}

export async function updateSteps(flow: Flow, targetStep: string, force?: boolean) {
  const newSteps = [
    {
      key: "start",
      name: "Charon sign-in or sign-up",
    },
  ]

  switch (targetStep) {
    case "passkeySignin":
      newSteps.push({ key: "passkeySignin", name: "Passkey sign-in" })
      break
    case "passkeySignup":
      newSteps.push({ key: "passkeySignin", name: "Passkey sign-in" }, { key: "passkeySignup", name: "Passkey sign-up" })
      break
    case "password":
    case "code":
      // Currently we always push both password and code steps and possibly
      // later on remove the code step if it is not necessary.
      newSteps.push({ key: "password", name: "Provide password or passphrase" }, { key: "code", name: "Provide code" })
      break
    case "thirdPartyProvider":
      newSteps.push({ key: "thirdPartyProvider", name: `Redirect to ${flow.getThirdPartyProvider()!.name}` })
      break
  }

  // We update steps only if additional steps were generated above.
  // This effectively means that we update steps only for target steps above,
  // while for other target steps we do not update steps (unless "force" is set).
  if (newSteps.length > 1 || force) {
    newSteps.push({ key: "identity", name: "Choose identity or decline" })
    // TODO: Show the app name like "Redirect to <app name>".
    newSteps.push({ key: "autoRedirect", name: `Redirect back to the app` })
    flow.setSteps(newSteps)
    return
  }

  // For manualRedirect target step we keep the steps, we just change the autoRedirect into manualRedirect.
  if (targetStep === "manualRedirect") {
    const steps = flow.getSteps()
    for (const step of steps) {
      if (step.key === "autoRedirect") {
        step.key = "manualRedirect"
      }
    }
  }
}

export function processCompleted(router: Router, flow: Flow, progress: Ref<number>, completed: Completed[]) {
  const oldCompleted = flow.getCompleted()
  flow.setCompleted(completed)
  if (completed.length > 0) {
    const redirectUrl = router.resolve({
      name: "AuthFlowGet",
      params: {
        id: flow.getId(),
      },
    }).href
    switch (completed[completed.length - 1]) {
      case "finished":
      case "failed":
        flow.forward("manualRedirect")
        break
      case "signin":
      case "signup":
        flow.forward("identity")
        break
      case "declined":
      case "identity":
        flow.forward("autoRedirect")
        break
      case "finishReady":
        // Flow is now marked as ready for redirect (completed finishReady),
        // so we reload it for redirect to happen.
        redirectServerSide(redirectUrl, true, progress)
        break
      default:
        throw new Error(`unknown completed: ${completed}`)
    }
  } else if (oldCompleted.length > 0) {
    // New completed is empty, but old completed is not, so we have to move back to the start.
    updateSteps(flow, "start", true)
    flow.backward("start")
  }
}

export function processResponse(router: Router, response: AuthFlowResponse, flow: Flow, progress: Ref<number>, abortController: AbortController | null): boolean {
  flow.setOrganizationId(response.organizationId)
  flow.setAppId(response.appId)
  if (response.providers) {
    flow.setThirdPartyProvider(getThirdPartyProvider(response.providers))
  } else {
    flow.setThirdPartyProvider(null)
  }
  if (response.emailOrUsername) {
    flow.setEmailOrUsername(response.emailOrUsername)
  } else {
    flow.setEmailOrUsername("")
  }
  if (!equals(flow.getCompleted(), response.completed)) {
    processCompleted(router, flow, progress, response.completed)
    if (abortController) {
      abortController.abort()
    }
    return true
  }
  return false
}

export function processFirstResponse(router: Router, response: AuthFlowResponse, flow: Flow, progress: Ref<number>) {
  if (response.providers && response.providers.length > 0) {
    const targetSteps = []
    for (const provider of response.providers) {
      const thirdPartyProvider = getThirdPartyProvider([provider])
      if (provider === "code" || provider === "password") {
        targetSteps.push(provider)
      } else if (provider === "passkey") {
        targetSteps.push("passkeySignin")
      } else if (thirdPartyProvider) {
        // processResponse below will set the OIDC provider again,
        // but we set it here so that updateSteps can use it.
        flow.setThirdPartyProvider(thirdPartyProvider)
        targetSteps.push("thirdPartyProvider")
      } else {
        throw new Error(`unknown provider: ${provider}`)
      }
    }
    // There should be at least one step at this point.
    const lastStep = targetSteps[targetSteps.length - 1]
    updateSteps(flow, lastStep)
    // We might move current step further in processResponse based on completed steps.
    flow.forward(lastStep)
  } else {
    updateSteps(flow, "start", true)
  }
  processResponse(router, response, flow, progress, null)
  if (
    (response.completed.includes("signin") || response.completed.includes("signup")) &&
    response.providers &&
    response.providers.includes("password") &&
    !response.providers.includes("code")
  ) {
    // Authentication step has completed with only password provider and no code provider.
    // We remove the code step we might have added above.
    removeSteps(flow, ["code"])
  }
  if ("error" in response && response.error) {
    throw new Error(`unexpected error: ${response.error}`)
  }
}
