import type { Ref } from "vue"

export class FetchError extends Error {
  constructor(msg: string, options?: { cause?: Error; status: number; body: string; url: string; requestID: string | null }) {
    super(msg, options)
    Object.assign(this, options)
  }
}

export async function postURL(url: string, data: object | null, progress: Ref<number>): Promise<object> {
  progress.value += 1
  try {
    const response = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: data === null ? '' : JSON.stringify(data),
      mode: "same-origin",
      credentials: "omit",
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
