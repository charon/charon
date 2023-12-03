import type { Router } from "vue-router"
import type { AuthFlowResponse } from "@/types"

export function locationRedirect(router: Router, response: AuthFlowResponse): boolean {
  if (response.replaceLocation) {
    if (response.replaceLocation.startsWith("/")) {
      router.replace({ path: response.replaceLocation, force: true })
    } else {
      window.location.replace(response.replaceLocation)
    }
    return true
  } else if (response.pushLocation) {
    if (response.pushLocation.startsWith("/")) {
      router.push({ path: response.pushLocation, force: true })
    } else {
      window.location.assign(response.pushLocation)
    }
    return true
  }
  return false
}