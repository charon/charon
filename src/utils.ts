import type { Ref } from "vue"
import type { Mutable, AuthFlowResponse, Completed, Flow, LocationResponse, QueryValuesWithOptional, QueryValues } from "@/types"

import { cloneDeep, isEqual } from "lodash-es"
import { toRaw } from "vue"

export function processCompleted(
  flow: Flow,
  target: "session" | "oidc",
  location: LocationResponse,
  name: string,
  completed: Completed,
) {
  flow.updateTarget(target)
  flow.updateLocation(location)
  flow.updateName(name)
  flow.updateCompleted(completed)
  switch (completed) {
    case "redirect":
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
    default:
      throw new Error(`unknown completed "${completed}"`)
  }
}

export function processCompletedAndLocationRedirect(
  response: AuthFlowResponse,
  flow: Flow | undefined,
  progress: Ref<number>,
  abortController: AbortController | null,
): boolean {
  // We do not use Vue Router to force a server-side request which might return updated cookies
  // or redirect on its own somewhere because of new (or lack thereof) cookies.
  if ("location" in response) {
    if ("completed" in response && flow) {
      // "location" and "completed" are provided together only for session target.
      processCompleted(flow, response.target, response.location, response.name, response.completed)
      if (abortController) {
        abortController.abort()
      }
    } else {
      redirectServerSide(response.location.url, response.location.replace, progress)
    }
    return true
  } else if ("completed" in response && flow && flow.getCompleted() !== response.completed) {
    // If "completed" is provided, but "location" is not, we are in OIDC target or session target choosing
    // an identity, in any case we pass an empty location response as it is not used.
    if ("homepage" in response) {
      flow.updateHomepage(response.homepage)
    }
    if ("organizationId" in response) {
      flow.updateOrganizationId(response.organizationId)
    }
    processCompleted(flow, response.target, { url: "", replace: false }, response.name, response.completed)
    if (abortController) {
      abortController.abort()
    }
    return true
  }
  return false
}

export function redirectServerSide(url: string, replace: boolean, progress: Ref<number>) {
  // We increase the progress and never decrease it to wait for browser to do the redirect.
  progress.value += 1

  // We do not use Vue Router to force a server-side request which might return updated cookies
  // or redirect on its own somewhere because of new (or lack thereof) cookies.
  if (replace) {
    window.location.replace(url)
  } else {
    window.location.assign(url)
  }
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

const paddingRegexp = /=+$/

export function toBase64Raw(input: Uint8Array): string {
  const str = String.fromCharCode(...input)
  return btoa(str).replace(paddingRegexp, "")
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

export function clone<T>(input: T): Mutable<T> {
  return cloneDeep(toRaw(input))
}

export function equals<T>(a: T, b: T): boolean {
  return isEqual(a, b)
}

// encodeQuery should match implementation on the backend.
export function encodeQuery(query: QueryValuesWithOptional): QueryValues {
  const keys = []
  for (const key in query) {
    keys.push(key)
  }
  // We want keys in an alphabetical order (default in Go).
  keys.sort()

  const values: QueryValues = {}
  for (const key of keys) {
    const value = query[key]
    if (value === undefined) {
      continue
    } else if (value === null) {
      // In contrast with Vue Router, we convert null values to an empty string because Go
      // does not support bare parameters without = and waf would then normalize them anyway.
      values[key] = ""
    } else if (Array.isArray(value)) {
      const vs: string[] = []
      for (const v in value) {
        if (v === null) {
          vs.push("")
        } else {
          vs.push(v)
        }
      }
      if (vs.length > 0) {
        values[key] = vs
      }
    } else {
      values[key] = value
    }
  }

  return values
}
