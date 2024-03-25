<script setup lang="ts">
import type { Completed, LocationResponse } from "@/types"

import { ref, onBeforeUnmount, onMounted, getCurrentInstance, inject } from "vue"
import { useRouter } from "vue-router"
import Button from "@/components/Button.vue"
import { injectProgress } from "@/progress"
import { redirectServerSide } from "@/utils"
import { flowKey } from "@/flow"
import { redirectOIDC } from "@/api"

const props = defineProps<{
  id: string
  name: string
  completed: Completed
  location: LocationResponse
  target: "session" | "oidc"
  homepage: string
}>()

const router = useRouter()

const flow = inject(flowKey)
const progress = injectProgress()

const abortController = new AbortController()

const unexpectedError = ref("")

function resetOnInteraction() {
  // We reset the error on interaction.
  unexpectedError.value = ""
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
  document.getElementById("redirect")?.focus()
}

function onBeforeLeave() {
  abortController.abort()
}

async function onRedirect() {
  if (abortController.signal.aborted) {
    return
  }

  resetOnInteraction()

  if (props.target === "session") {
    await onRedirectSession()
  } else if (props.completed === "failed") {
    await doRedirectOIDC()
  } else {
    await doRedirectHomepage()
  }
}

async function onRedirectSession() {
  redirectServerSide(props.location.url, props.location.replace, progress)
}

async function doRedirectOIDC() {
  try {
    await redirectOIDC(router, props.id, flow!, abortController, progress)
  } catch (error) {
    if (abortController.signal.aborted) {
      return
    }
    console.error(error)
    unexpectedError.value = `${error}`
  }
}

async function doRedirectHomepage() {
  redirectServerSide(props.homepage, true, progress)
}
</script>

<template>
  <div class="flex flex-col rounded border bg-white p-4 shadow w-full">
    <template v-if="completed === 'failed'">
      <div class="text-error-600 mb-4"><strong>Sorry.</strong> Signing in or signing up failed.</div>
      <div class="mb-4">You can return to {{ name }} and try again.</div>
    </template>
    <div v-else-if="completed === 'redirect'" class="mb-4">
      You have already been redirected to {{ name }} and completed the flow. You can now instead go to its homepage.
    </div>
    <div v-if="unexpectedError" class="mb-4 text-error-600">Unexpected error. Please try again.</div>
    <div class="flex flex-row justify-end gap-4">
      <Button id="redirect" primary type="button" tabindex="1" :progress="progress" @click.prevent="onRedirect">{{
        completed === "redirect" ? "Homepage" : "Return"
      }}</Button>
    </div>
  </div>
</template>
