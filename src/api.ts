import type { Ref } from "vue"
import type { Router } from "vue-router"
import type { AuthFlowRequest, AuthFlowResponse, PasswordResponse } from "@/types"
import { fromBase64, locationRedirect } from "@/utils"

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

export async function postURL(url: string, data: object, abortSignal: AbortSignal, progress: Ref<number> | null): Promise<object> {
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

export async function deleteURL(url: string, abortSignal: AbortSignal, progress: Ref<number> | null): Promise<object> {
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
  flowID: string,
  emailOrUsername: string,
  abortSignal: AbortSignal,
  progress: Ref<number>,
  mainProgress: Ref<number>,
): Promise<PasswordResponse | { error: string } | null> {
  progress.value += 1
  try {
    const url = router.apiResolve({
      name: "AuthFlow",
      params: {
        id: flowID,
      },
    }).href

    const response = (await postURL(
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
    )) as AuthFlowResponse
    if (locationRedirect(response)) {
      // We increase the progress and never decrease it to wait for browser to do the redirect.
      mainProgress.value += 1
      return null
    }
    // We do not list "shortEmailOrUsername" here because UI does not allow too short emailOrUsername.
    if ("error" in response && ["invalidEmailOrUsername"].includes(response.error)) {
      return {
        error: response.error,
      }
    }
    if ("password" in response) {
      return {
        emailOrUsername: response.password.emailOrUsername,
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
