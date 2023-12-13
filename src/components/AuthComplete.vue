<script setup lang="ts">
import type { LocationResponse } from "@/types"
import { ref, onUnmounted, onMounted, getCurrentInstance } from "vue"
import Button from "@/components/Button.vue"

const props = defineProps<{
  location: LocationResponse
}>()

const mainProgress = ref(0)
const abortController = new AbortController()
const paused = ref(false)

const seconds = ref(3)

let interval: number
function initInterval() {
  interval = setInterval(() => {
    seconds.value -= 1
    if (seconds.value === 0) {
      onRedirect()
    }
  }, 1000) as unknown as number // ms
}
initInterval()

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
  document.getElementById("redirect")?.focus()
}

function onBeforeLeave() {
  abortController.abort()
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
    paused.value = true
  }
}

async function onRedirect() {
  if (abortController.signal.aborted) {
    return
  }

  clearInterval(interval)

  // We increase the progress and never decrease it to wait for browser to do the redirect.
  mainProgress.value += 1

  // We do not use Vue Router to force a server-side request which might return updated cookies
  // or redirect on its own somewhere because of new (or lack thereof) cookies.
  if (props.location.replace) {
    window.location.replace(props.location.url)
  } else {
    window.location.assign(props.location.url)
  }
}
</script>

<template>
  <div class="flex flex-col rounded border bg-white p-4 shadow w-full float-left first:ml-0 ml-[-100%]">
    <h2 class="text-center mx-4 mb-4 text-xl font-bold uppercase">Sign-in or sign-up</h2>
    <div>
      Congratulations. You successfully signed in or signed up to <strong>{{ location.name }}</strong
      >.
    </div>
    <div class="mt-4">You will be now redirected to {{ location.name }} in {{ seconds === 1 ? "1 second" : `${seconds} seconds` }}{{ paused ? " (paused)" : "" }}.</div>
    <div class="mt-4 flex flex-row justify-end gap-4">
      <Button type="button" tabindex="2" :disabled="mainProgress > 0" @click.prevent="onPauseResume">{{ paused ? "Resume" : "Pause" }}</Button>
      <Button id="redirect" primary type="button" tabindex="1" :disabled="mainProgress > 0" @click.prevent="onRedirect">Redirect</Button>
    </div>
  </div>
</template>
