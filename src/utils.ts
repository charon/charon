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