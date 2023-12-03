import type { Ref } from "vue"

export class FetchError extends Error {
  constructor(msg: string, options?: { cause?: Error; status: number; body: string; url: string; requestID: string | null }) {
    super(msg, options)
    Object.assign(this, options)
  }
}

export async function postURL(url: string, data: object, progress: Ref<number>): Promise<object> {
  progress.value += 1
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
    })
    if (!response.ok) {
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
    progress.value -= 1
  }
}

export async function deleteURL(url: string, progress: Ref<number>): Promise<object> {
  progress.value += 1
  try {
    const response = await fetch(url, {
      method: "DELETE",
      mode: "same-origin",
      credentials: "same-origin",
      redirect: "error",
      referrer: document.location.href,
      referrerPolicy: "strict-origin-when-cross-origin",
    })
    if (!response.ok) {
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
    progress.value -= 1
  }
}