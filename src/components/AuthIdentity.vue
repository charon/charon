<script setup lang="ts">
import type { AuthFlowResponse, Completed } from "@/types"

import { ref, onUnmounted, onMounted, getCurrentInstance, inject } from "vue"
import { useRouter } from "vue-router"
import Button from "@/components/Button.vue"
import { injectProgress } from "@/progress"
import { postURL, restartAuth } from "@/api"
import { flowKey } from "@/flow"
import { processCompletedAndLocationRedirect } from "@/utils"

const props = defineProps<{
  id: string
  name: string
  completed: Completed
  organizationId: string
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

onUnmounted(onBeforeLeave)

function onAfterEnter() {
  document.getElementById("choose-identity")?.focus()
}

function onBeforeLeave() {
  abortController.abort()
}

async function onNext() {
  if (abortController.signal.aborted) {
    return
  }

  resetOnInteraction()

  progress.value += 1
  try {
    const url = router.apiResolve({
      name: "AuthFlowChooseIdentity",
      params: {
        id: props.id,
      },
    }).href

    const response = await postURL<AuthFlowResponse>(url, {}, abortController.signal, progress)
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
    console.error(error)
    unexpectedError.value = `${error}`
  } finally {
    progress.value -= 1
  }
}

async function onBack() {
  if (abortController.signal.aborted) {
    return
  }

  resetOnInteraction()

  progress.value += 1
  try {
    // restartAuth calls abortController.abort so we do not have to do it here.
    await restartAuth(router, props.id, flow!, abortController, progress)
  } catch (error) {
    if (abortController.signal.aborted) {
      return
    }
    console.error(error)
    unexpectedError.value = `${error}`
  } finally {
    progress.value -= 1
  }
}

async function onDecline() {
  if (abortController.signal.aborted) {
    return
  }

  resetOnInteraction()

  progress.value += 1
  try {
    const url = router.apiResolve({
      name: "AuthFlowDecline",
      params: {
        id: props.id,
      },
    }).href

    const response = await postURL<AuthFlowResponse>(url, {}, abortController.signal, progress)
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
    console.error(error)
    unexpectedError.value = `${error}`
  } finally {
    progress.value -= 1
  }
}
</script>

<template>
  <div class="flex flex-col rounded border bg-white p-4 shadow w-full">
    <div class="flex flex-col">
      <div v-if="completed === 'signin'" class="mb-4"><strong>Congratulations.</strong> You successfully signed in into Charon.</div>
      <div v-else-if="completed === 'signup'" class="mb-4"><strong>Congratulations.</strong> You successfully signed up into Charon.</div>
      <div class="flex flew-row items-start gap-4">
        <div>TODO: Choose between existing identities or create a new identity for this organization.</div>
        <Button id="choose-identity" primary type="button" tabindex="1" :progress="progress" @click.prevent="onNext">Next</Button>
      </div>
      <div v-if="unexpectedError" class="mt-4 text-error-600">Unexpected error. Please try again.</div>
      <div class="mt-4 flex flex-row justify-between gap-4">
        <Button type="button" tabindex="3" @click.prevent="onBack">Back</Button>
        <Button type="button" tabindex="2" :progress="progress" @click.prevent="onDecline">Decline</Button>
      </div>
    </div>
  </div>
</template>
