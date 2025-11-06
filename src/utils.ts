import type { DeepReadonly, Ref } from "vue"

import type {
    DeriveOptions,
    EncryptedPasswordData,
    EncryptOptions,
    Identity,
    IdentityOrganization,
    IdentityPublic,
    Mutable,
    OrganizationApplicationPublic,
    QueryValues,
    QueryValuesWithOptional
} from "@/types"

import { cloneDeep, isEqual } from "lodash-es"
import { toRaw } from "vue"

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

export function getHomepage(doc: DeepReadonly<OrganizationApplicationPublic>): string {
  const homepageTemplate = doc.applicationTemplate.homepageTemplate
  const values = new Map<string, string>()
  for (const v of doc.values) {
    values.set(v.name, v.value)
  }
  return interpolateVariables(homepageTemplate, values)
}

export function fromBase64(input: string): Uint8Array<ArrayBuffer> {
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
    if (history.replaceState) {
      const url = new URL(window.location.href)
      url.hash = "#" + hash
      history.replaceState(null, "", url)
    } else {
      window.location.hash = "#" + hash
    }
  } else {
    if (history.replaceState) {
      const url = new URL(window.location.href)
      url.hash = ""
      history.replaceState(null, "", url)
    } else {
      window.location.hash = ""
    }
  }
}

export function replaceLocationSearch(search: string) {
  if (search) {
    if (history.replaceState) {
      const url = new URL(window.location.href)
      url.search = "?" + search
      history.replaceState(null, "", url)
    } else {
      window.location.search = "?" + search
    }
  } else {
    if (history.replaceState) {
      const url = new URL(window.location.href)
      url.search = ""
      history.replaceState(null, "", url)
    } else {
      window.location.search = ""
    }
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
      for (const v of value) {
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

const variableRegexp = /\{([^}]+)\}/g

// interpolateVariables should match implementation on the backend.
export function interpolateVariables(template: string, values: Map<string, string>): string {
  const unmatchedVariables: string[] = []
  const result = template.replace(variableRegexp, (match) => {
    const varName = match.slice(1, -1) // Removing the curly braces.
    if (values.has(varName)) {
      return values.get(varName)!
    }
    // Unmatched variable.
    unmatchedVariables.push(varName)
    return ""
  })

  if (unmatchedVariables.length > 0) {
    const uniqueUnmatchedVariables = Array.from(new Set(unmatchedVariables))
    uniqueUnmatchedVariables.sort()
    throw new Error(`unknown variables: ${uniqueUnmatchedVariables.join(", ")}`)
  }

  return result
}

export function currentAbsoluteURL(): string {
  // We remove origin prefix from full URL to get absolute URL.
  return document.location.href.slice(document.location.origin.length)
}

// getIdentityOrganization should match implementation on the backend.
export function getIdentityOrganization(identity: Identity, id: string | undefined): IdentityOrganization | null {
  if (id === undefined) {
    return null
  }

  for (const identityOrganization of identity.organizations) {
    if (identityOrganization.id === id) {
      return identityOrganization
    }
  }

  return null
}

// getOrganization should match implementation on the backend.
export function getOrganization(identity: Identity, id: string | undefined): IdentityOrganization | null {
  if (id === undefined) {
    return null
  }

  for (const identityOrganization of identity.organizations) {
    if (identityOrganization.organization.id === id) {
      return identityOrganization
    }
  }

  return null
}

export function getFormattedTimestamp(timestamp: string): string {
  // TODO: Change so that it is formatted based on the current selected locale in Charon and not browser's locale.
  const date = new Date(timestamp)
  return date.toLocaleString()
}

// getIdentityDisplayName returns a string display name of an identity.
//
// This should be similar in what is show as main piece of information in
// IdentityPublic and IdentityFull components.
export function getIdentityDisplayName(identity: IdentityPublic | DeepReadonly<IdentityPublic>): string {
  return identity.username || identity.email || identity.givenName || identity.fullName || identity.id
}

export async function encryptPasswordECDHAESGCM(
    password: string,
    publicKey: Uint8Array<ArrayBuffer>,
    deriveOptions: DeriveOptions,
    encryptOptions: EncryptOptions,
    abortController: AbortController,
): Promise<EncryptedPasswordData> {
    const encoder = new TextEncoder()
    const keyPair = await crypto.subtle.generateKey(deriveOptions, false, ["deriveKey"])
    if (abortController.signal.aborted) {
        throw new Error("Aborted")
    }

    const remotePublicKey = await crypto.subtle.importKey("raw", publicKey, deriveOptions, false, [])
    if (abortController.signal.aborted) {
        throw new Error("Aborted")
    }

    const secret = await crypto.subtle.deriveKey(
        {
            ...deriveOptions,
            public: remotePublicKey,
        },
        keyPair.privateKey,
        encryptOptions,
        false,
        ["encrypt"],
    )
    if (abortController.signal.aborted) {
        throw new Error("Aborted")
    }

    const ciphertext = await crypto.subtle.encrypt(encryptOptions, secret, encoder.encode(password))
    if (abortController.signal.aborted) {
        throw new Error("Aborted")
    }

    const publicKeyBytes = await crypto.subtle.exportKey("raw", keyPair.publicKey)
    if (abortController.signal.aborted) {
        throw new Error("Aborted")
    }

    return {
        ciphertext,
        publicKeyBytes,
    }
}