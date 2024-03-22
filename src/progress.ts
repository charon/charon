import type { InjectionKey, Ref } from "vue"

import { ref, inject, watch } from "vue"

export const progressKey = Symbol() as InjectionKey<Ref<number>>

// injectProgress returns a reactive and mutable local view of the
// main progress. It starts at 0 but increasing or decreasing it
// increases or decreases main progress for the same amount.
export function injectProgress(): Ref<number> {
  const mainProgress = inject(progressKey, ref(0))
  const localProgress = ref(0)
  watch(
    localProgress,
    (newProgress, oldProgress) => {
      mainProgress.value += newProgress - oldProgress
    },
    {
      flush: "sync",
    },
  )
  return localProgress
}
