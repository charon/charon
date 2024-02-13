import type { Ref } from "vue"
import type { Router } from "vue-router"
import type { AuthFlowRequest, AuthFlowResponse, Flow, Metadata, PasswordResponse } from "@/types"

import { fromBase64, processCompletedAndLocationRedirect } from "@/utils"
import { decodeMetadata } from "./metadata"

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
  abortSignal: AbortSignal,
  progress: Ref<number> | null,
): Promise<{ doc: T; metadata: Metadata }> {
  if (progress) {
    progress.value += 1
  }
  try {
    const response = await fetch(url, {
      method: "GET",
      // Mode and credentials match crossorigin=anonymous in link preload header.
      mode: "cors",
      credentials: "same-origin",
      referrer: document.location.href,
      referrerPolicy: "strict-origin-when-cross-origin",
      signal: abortSignal,
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
    return { doc: await response.json(), metadata: decodeMetadata(response.headers) }
  } finally {
    if (progress) {
      progress.value -= 1
    }
  }
}

export async function postURL<T>(url: string, data: object, abortSignal: AbortSignal, progress: Ref<number> | null): Promise<T> {
  if (progress) {
    progress.value += 1
  }
  try {
    const response = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(data),
      mode: "same-origin",
      credentials: "same-origin",
      redirect: "error",
      referrer: document.location.href,
      referrerPolicy: "strict-origin-when-cross-origin",
      signal: abortSignal,
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
    return await response.json()
  } finally {
    if (progress) {
      progress.value -= 1
    }
  }
}

export async function deleteURL<T>(url: string, abortSignal: AbortSignal, progress: Ref<number> | null): Promise<T> {
  if (progress) {
    progress.value += 1
  }
  try {
    const response = await fetch(url, {
      method: "DELETE",
      mode: "same-origin",
      credentials: "same-origin",
      redirect: "error",
      referrer: document.location.href,
      referrerPolicy: "strict-origin-when-cross-origin",
      signal: abortSignal,
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
    return await response.json()
  } finally {
    if (progress) {
      progress.value -= 1
    }
  }
}

export async function startPassword(
  router: Router,
  flowId: string,
  emailOrUsername: string,
  flow: Flow,
  abortSignal: AbortSignal,
  progress: Ref<number>,
  mainProgress: Ref<number>,
): Promise<(PasswordResponse & { emailOrUsername: string }) | { error: string } | null> {
  progress.value += 1
  try {
    const url = router.apiResolve({
      name: "AuthFlow",
      params: {
        id: flowId,
      },
    }).href

    const response = await postURL<AuthFlowResponse>(
      url,
      {
        provider: "password",
        step: "start",
        password: {
          start: {
            emailOrUsername,
          },
        },
      } as AuthFlowRequest,
      abortSignal,
      progress,
    )
    if (abortSignal.aborted) {
      return null
    }
    if (processCompletedAndLocationRedirect(response, flow, mainProgress)) {
      return null
    }
    if ("error" in response && ["invalidEmailOrUsername", "shortEmailOrUsername"].includes(response.error)) {
      return {
        error: response.error,
      }
    }
    if ("password" in response) {
      return {
        emailOrUsername: response.emailOrUsername!,
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
    progress.value -= 1
  }
}

export async function restartAuth(router: Router, flowId: string, flow: Flow, abortSignal: AbortSignal, mainProgress: Ref<number>) {
  if (flow.getCompleted() === "failed") {
    throw new Error(`cannot restart failed auth`)
  }

  mainProgress.value += 1
  try {
    const url = router.apiResolve({
      name: "AuthFlow",
      params: {
        id: flowId,
      },
    }).href

    const response = await postURL<AuthFlowResponse>(
      url,
      {
        step: "restartAuth",
      } as AuthFlowRequest,
      abortSignal,
      mainProgress,
    )
    if (abortSignal.aborted) {
      return
    }
    if (processCompletedAndLocationRedirect(response, flow, mainProgress)) {
      return
    }
    if (!("error" in response) && !("provider" in response) && !("completed" in response)) {
      flow.backward("start")
      return
    }
    throw new Error("unexpected response")
  } finally {
    mainProgress.value -= 1
  }
}
