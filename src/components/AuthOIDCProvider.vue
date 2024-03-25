<script setup lang="ts">
import type { AuthFlowProviderStartRequest, AuthFlowResponse } from "@/types"

import { ref, onBeforeUnmount, onMounted, getCurrentInstance, inject } from "vue"
import { useRouter } from "vue-router"
import Button from "@/components/Button.vue"
import { postURL } from "@/api"
import { processCompletedAndLocationRedirect } from "@/utils"
import { flowKey, providerName } from "@/flow"
import { injectProgress } from "@/progress"

const props = defineProps<{
  id: string
  provider: string
}>()

const router = useRouter()

const flow = inject(flowKey)
const progress = injectProgress()

const abortController = new AbortController()

const unexpectedError = ref("")
const paused = ref(false)
const seconds = ref(3)

function resetOnInteraction() {
  // We reset the error on interaction.
  unexpectedError.value = ""
}

let interval: number
function initInterval() {
  if (interval) {
    clearInterval(interval)
  }
  interval = setInterval(() => {
    seconds.value -= 1
    if (seconds.value === 0) {
      onRedirect()
    }
  }, 1000) as unknown as number // ms
}

// Define transition hooks to be called by the parent component.
// See: https://github.com/vuejs/rfcs/discussions/613
onMounted(() => {
  const vm = getCurrentInstance()!
  vm.vnode.el!.__vue_exposed = vm.exposeProxy
})

defineExpose({
  onAfterEnter,
  onBeforeLeave,
})

onBeforeUnmount(onBeforeLeave)

function onAfterEnter() {
  if (!paused.value) {
    // User might already paused using the esc key.
    initInterval()
  }
  document.getElementById("redirect")?.focus()
}

function onBeforeLeave() {
  abortController.abort()
}

async function onBack() {
  if (abortController.signal.aborted) {
    return
  }

  clearInterval(interval)
  interval = 0
  abortController.abort()
  flow!.backward("start")
}

async function onPauseResume() {
  if (abortController.signal.aborted) {
    return
  }

  resetOnInteraction()

  if (paused.value) {
    initInterval()
    paused.value = false
  } else {
    clearInterval(interval)
    interval = 0
    paused.value = true
  }
}

async function onRedirect() {
  if (abortController.signal.aborted) {
    return
  }

  clearInterval(interval)
  interval = 0
  resetOnInteraction()

  progress.value += 1
  try {
    const url = router.apiResolve({
      name: "AuthFlowProviderStart",
      params: {
        id: props.id,
      },
    }).href

    const response = await postURL<AuthFlowResponse>(
      url,
      {
        provider: props.provider,
      } as AuthFlowProviderStartRequest,
      abortController.signal,
      progress,
    )
    if (abortController.signal.aborted) {
      return
    }
    if (processCompletedAndLocationRedirect(response, flow, progress, abortController)) {
      return
    }
    throw new Error("unexpected response")
  } catch (error) {
    if (abortController.signal.aborted) {
      return
    }
    console.error("AuthOIDCProvider.onRedirect", error)
    unexpectedError.value = `${error}`
    // We reset the counter and pause it on an error.
    seconds.value = 3
    paused.value = true
  } finally {
    progress.value -= 1
  }
}

function onPause(event: KeyboardEvent) {
  if (abortController.signal.aborted) {
    return
  }
  // We disable this event handler because it is a keyboard event handler and
  // disabling UI elements do not disable keyboard events.
  if (progress.value > 0) {
    return
  }

  if (event.key === "Escape") {
    resetOnInteraction()

    clearInterval(interval)
    interval = 0
    paused.value = true
  }
}

onMounted(() => {
  document.addEventListener("keydown", onPause, {
    signal: abortController.signal,
  })
})

onBeforeUnmount(() => {
  document.removeEventListener("keydown", onPause)
})
</script>

<template>
  <div class="flex flex-col rounded border bg-white p-4 shadow w-full">
    <div>
      You will be redirected to <strong>{{ providerName(provider) }}</strong> in {{ seconds === 1 ? "1 second" : `${seconds} seconds` }}{{ paused ? " (paused)" : "" }}.
    </div>
    <div class="mt-4">Please follow instructions there to sign-in into Charon. Afterwards, you will be redirected back here.</div>
    <div class="mt-4">
      You might have to sign-in into {{ providerName(provider) }} first. You might be redirected back by {{ providerName(provider) }} immediately, without showing you
      anything.
    </div>
    <div v-if="unexpectedError" class="mt-4 text-error-600">Unexpected error. Please try again.</div>
    <div class="mt-4 flex flex-row justify-between gap-4">
      <Button type="button" tabindex="3" @click.prevent="onBack">Back</Button>
      <div class="flex flex-row gap-4">
        <Button type="button" tabindex="2" :progress="progress" @click.prevent="onPauseResume">{{ paused ? "Resume" : "Pause" }}</Button>
        <Button id="redirect" primary type="button" tabindex="1" :progress="progress" @click.prevent="onRedirect">Redirect</Button>
      </div>
    </div>
  </div>
</template>
