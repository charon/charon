<script setup lang="ts">
import type { LocationResponse } from "@/types"

import { ref, onUnmounted, onMounted, getCurrentInstance, inject } from "vue"
import Button from "@/components/Button.vue"
import { progressKey } from "@/progress"
import { redirectServerSide } from "@/utils"

const props = defineProps<{
  name: string
  location: LocationResponse
}>()

const mainProgress = inject(progressKey, ref(0))

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

  redirectServerSide(props.location.url, props.location.replace, mainProgress)
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
