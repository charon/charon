<script setup lang="ts">
import type { LocationResponse } from "@/types"

import { ref, onUnmounted, onMounted, getCurrentInstance } from "vue"
import Button from "@/components/Button.vue"

const props = defineProps<{
  name: string
  location: LocationResponse
}>()

const mainProgress = ref(0)
const abortController = new AbortController()

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

async function onRedirect() {
  if (abortController.signal.aborted) {
    return
  }

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
  <div class="flex flex-col rounded border bg-white p-4 shadow w-full">
    <div class="text-error-600"><strong>Sorry.</strong> Signing in or signing up failed.</div>
    <div class="mt-4">You can return to {{ name }} and try again.</div>
    <div class="mt-4 flex flex-row justify-end gap-4">
      <Button id="redirect" primary type="button" tabindex="1" :disabled="mainProgress > 0" @click.prevent="onRedirect">Redirect</Button>
    </div>
  </div>
</template>
