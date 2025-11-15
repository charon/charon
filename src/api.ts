import type { Ref } from "vue"
import type { Router } from "vue-router"

import type {
  AllIdentity,
  AuthFlowPasswordStartRequest,
  AuthFlowResponse,
  AuthFlowResponsePassword,
  Flow,
  Identities,
  Identity,
  Metadata,
  OrganizationBlockedStatus,
} from "@/types"

import { accessToken } from "@/auth"
import { processResponse } from "@/flow"
import { decodeMetadata } from "@/metadata"
import { encodeQuery, fromBase64, getOrganization } from "@/utils"

export class FetchError extends Error {
  cause?: Error
  status: number
  body: string
  url: string
  requestID: string | null

  constructor(msg: string, options: { cause?: Error; status: number; body: string; url: string; requestID: string | null }) {
    // Cause gets set by super.
    super(msg, options)
    this.status = options.status
    this.body = options.body
    this.url = options.url
    this.requestID = options.requestID
  }
}

// TODO: Improve priority with "el".
export async function getURL<T>(
  url: string,
  el: Ref<Element | null> | null,
  abortSignal: AbortSignal | null,
  progress: Ref<number> | null,
): Promise<{ doc: T; metadata: Metadata }> {
  if (progress) {
    progress.value += 1
  }
  try {
    const headers = new Headers()
    if (accessToken.value) {
      headers.set("Authorization", `Bearer ${accessToken.value}`)
    }
    const response = await fetch(url, {
      method: "GET",
      // Mode and credentials match crossorigin=anonymous in link preload header.
      mode: "cors",
      credentials: "same-origin",
      referrer: document.location.href,
      referrerPolicy: "strict-origin-when-cross-origin",
      signal: abortSignal,
      headers,
    })
    const contentType = response.headers.get("Content-Type")
    if (!contentType || !contentType.includes("application/json")) {
      const body = await response.text()
      throw new FetchError(`fetch GET error ${response.status}: ${body}`, {
        status: response.status,
        body,
        url,
        requestID: response.headers.get("Request-ID"),
      })
    }
    return { doc: (await response.json()) as T, metadata: decodeMetadata(response.headers) }
  } finally {
    if (progress) {
      progress.value -= 1
    }
  }
}

export async function postJSON<T>(url: string, data: object, abortSignal: AbortSignal, progress: Ref<number> | null): Promise<T> {
  if (progress) {
    progress.value += 1
  }
  try {
    const headers = new Headers()
    headers.set("Content-Type", "application/json")
    if (accessToken.value) {
      headers.set("Authorization", `Bearer ${accessToken.value}`)
    }
    const response = await fetch(url, {
      method: "POST",
      body: JSON.stringify(data),
      mode: "same-origin",
      credentials: "same-origin",
      redirect: "error",
      referrer: document.location.href,
      referrerPolicy: "strict-origin-when-cross-origin",
      signal: abortSignal,
      headers,
    })
    const contentType = response.headers.get("Content-Type")
    if (!contentType || !contentType.includes("application/json")) {
      const body = await response.text()
      throw new FetchError(`fetch POST error ${response.status}: ${body}`, {
        status: response.status,
        body,
        url,
        requestID: response.headers.get("Request-ID"),
      })
    }
    return (await response.json()) as T
  } finally {
    if (progress) {
      progress.value -= 1
    }
  }
}

export async function startPassword(
  router: Router,
  flow: Flow,
  abortController: AbortController,
  keyProgress: Ref<number>,
  progress: Ref<number>,
): Promise<AuthFlowResponsePassword | { error: string } | null> {
  keyProgress.value += 1
  try {
    const url = router.apiResolve({
      name: "AuthFlowPasswordStart",
      params: {
        id: flow.getId(),
      },
    }).href

    const response = await postJSON<AuthFlowResponse>(
      url,
      {
        emailOrUsername: flow.getEmailOrUsername(),
      } as AuthFlowPasswordStartRequest,
      abortController.signal,
      keyProgress,
    )
    if (abortController.signal.aborted) {
      return null
    }
    // processResponse should not really do anything here.
    if (processResponse(router, response, flow, progress, abortController)) {
      return null
    }
    if ("error" in response && ["invalidEmailOrUsername", "shortEmailOrUsername"].includes(response.error)) {
      return {
        error: response.error,
      }
    }
    if ("password" in response) {
      return {
        publicKey: fromBase64(response.password.publicKey),
        deriveOptions: response.password.deriveOptions,
        encryptOptions: {
          ...response.password.encryptOptions,
          iv: fromBase64(response.password.encryptOptions.iv),
        },
      }
    }
    throw new Error("unexpected response")
  } finally {
    keyProgress.value -= 1
  }
}

export async function restartAuth(router: Router, flow: Flow, abort: AbortSignal | AbortController, progress: Ref<number>) {
  if (flow.getCompleted().includes("finished")) {
    throw new Error(`cannot restart finished flow`)
  }
  if (flow.getCompleted().includes("failed")) {
    throw new Error(`cannot restart failed authentication`)
  }

  const abortSignal = abort instanceof AbortController ? abort.signal : abort

  progress.value += 1
  try {
    const url = router.apiResolve({
      name: "AuthFlowRestartAuth",
      params: {
        id: flow.getId(),
      },
    }).href

    const response = await postJSON<AuthFlowResponse>(url, {}, abortSignal, progress)
    if (abortSignal.aborted) {
      return
    }
    // processResponse should update steps and move the flow back to the start.
    if (processResponse(router, response, flow, progress, abort instanceof AbortController ? abort : null)) {
      return
    }
    throw new Error("unexpected response")
  } finally {
    progress.value -= 1
  }
}

export async function redirectThirdPartyProvider(router: Router, flow: Flow, abortController: AbortController, progress: Ref<number>) {
  progress.value += 1
  try {
    const url = router.apiResolve({
      name: "AuthFlowRedirect",
      params: {
        id: flow.getId(),
      },
    }).href

    const response = await postJSON<AuthFlowResponse>(url, {}, abortController.signal, progress)
    if (abortController.signal.aborted) {
      return
    }
    // processResponse should reload the flow for final redirect to happen.
    if (processResponse(router, response, flow, progress, abortController)) {
      return
    }
    throw new Error("unexpected response")
  } finally {
    progress.value -= 1
  }
}

export async function getAllIdentities(
  router: Router,
  organizationId: string,
  flowId: string | null,
  abortController: AbortController,
  progress: Ref<number>,
): Promise<AllIdentity[] | null> {
  const query = flowId ? encodeQuery({ flow: flowId }) : undefined

  progress.value += 1
  try {
    const allIdentities: AllIdentity[] = []

    const url = router.apiResolve({
      name: "IdentityList",
      query,
    }).href

    const response = await getURL<Identities>(url, null, abortController.signal, progress)
    if (abortController.signal.aborted) {
      return null
    }

    for (const identity of response.doc) {
      const identityURL = router.apiResolve({
        name: "IdentityGet",
        params: {
          id: identity.id,
        },
        query,
      }).href

      const identityResponse = await getURL<Identity>(identityURL, null, abortController.signal, progress)
      if (abortController.signal.aborted) {
        return null
      }

      let blockedStatus: OrganizationBlockedStatus = { blocked: "notBlocked" }
      const idOrg = getOrganization(identityResponse.doc, organizationId)
      if (idOrg) {
        const blockedStatusURL = router.apiResolve({
          name: "OrganizationBlockedStatus",
          params: {
            id: organizationId,
            identityId: idOrg.id,
          },
          query,
        }).href

        const blockedStatusResponse = await getURL<OrganizationBlockedStatus>(blockedStatusURL, null, abortController.signal, progress)
        if (abortController.signal.aborted) {
          return null
        }

        blockedStatus = blockedStatusResponse.doc
      }

      allIdentities.push({
        identity: identityResponse.doc,
        url: identityURL,
        isCurrent: !!identityResponse.metadata.is_current,
        canUpdate: !!identityResponse.metadata.can_update,
        isShared: identityResponse.doc.admins.length + (identityResponse.doc.users?.length || 0) > 1,
        blocked: blockedStatus.blocked,
      })
    }

    return allIdentities
  } finally {
    progress.value -= 1
  }
}
