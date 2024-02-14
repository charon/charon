<script setup lang="ts">
import type { Completed, LocationResponse } from "@/types"

import { ref, onUnmounted, onMounted, getCurrentInstance, inject } from "vue"
import Button from "@/components/Button.vue"
import { progressKey } from "@/progress"
import { redirectServerSide } from "@/utils"
import { flowKey } from "@/flow"

const props = defineProps<{
  id: string
  name: string
  completed: Completed
  location: LocationResponse
  target: "session" | "oidc"
}>()

const flow = inject(flowKey)
const mainProgress = inject(progressKey, ref(0))

const abortController = new AbortController()

const paused = ref(false)
const seconds = ref(3)

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

onUnmounted(onBeforeLeave)

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
  flow!.backward("identity")
}

async function onPauseResume() {
  if (abortController.signal.aborted) {
    return
  }

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

  redirectServerSide(props.location.url, props.location.replace, mainProgress)
}

function onPause(event: KeyboardEvent) {
  if (abortController.signal.aborted) {
    return
  }
  // We disable this event handler because it is a keyboard event handler and
  // disabling UI elements do not disable keyboard events.
  if (mainProgress.value > 0) {
    return
  }

  if (event.key === "Escape") {
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

onUnmounted(() => {
  document.removeEventListener("keydown", onPause)
})
</script>

<template>
  <div class="flex flex-col rounded border bg-white p-4 shadow w-full">
    <div v-if="completed === 'signin'"><strong>Congratulations.</strong> You successfully signed in.</div>
    <div v-else-if="completed === 'signup'"><strong>Congratulations.</strong> You successfully signed up.</div>
    <div v-else-if="completed === 'identity'"><strong>Congratulations.</strong> You successfully used Charon to chose your identity for {{ name }}.</div>
    <div v-else-if="completed === 'declined'">You decided to <strong>decline sign-in or sign-up</strong> using Charon for {{ name }}.</div>
    <div class="mt-4">You will be now redirected to {{ name }} in {{ seconds === 1 ? "1 second" : `${seconds} seconds` }}{{ paused ? " (paused)" : "" }}.</div>
    <div
      class="mt-4 flex flex-row gap-4"
      :class="{
        'justify-between': target === 'oidc',
        'justify-end': target === 'session',
      }"
    >
      <Button v-if="target === 'oidc'" type="button" tabindex="3" @click.prevent="onBack">Back</Button>
      <div class="flex flex-row gap-4">
        <Button type="button" tabindex="2" :disabled="mainProgress > 0" @click.prevent="onPauseResume">{{ paused ? "Resume" : "Pause" }}</Button>
        <Button id="redirect" primary type="button" tabindex="1" :disabled="mainProgress > 0" @click.prevent="onRedirect">Redirect</Button>
      </div>
    </div>
  </div>
</template>
