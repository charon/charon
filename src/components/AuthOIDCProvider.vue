<script setup lang="ts">
import type { AuthFlowRequest, AuthFlowResponse, Providers } from "@/types"
import { ref, computed, onUnmounted, onMounted, getCurrentInstance, inject } from "vue"
import { useRouter } from "vue-router"
import Button from "@/components/Button.vue"
import { postURL } from "@/api"
import { flowKey, locationRedirect } from "@/utils"

const props = defineProps<{
  id: string
  provider: string
  providers: Providers
}>()

const router = useRouter()

const flow = inject(flowKey)

const mainProgress = ref(0)
const abortController = new AbortController()
const paused = ref(false)

const providerName = computed(() => {
  for (const p of props.providers) {
    if (p.key === props.provider) {
      return p.name
    }
  }
  throw new Error(`provider "${props.provider}" not found among providers`)
})
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

async function onBack() {
  if (abortController.signal.aborted) {
    return
  }

  clearInterval(interval)
  abortController.abort()
  flow!.backward("start")
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

  mainProgress.value += 1
  try {
    const response = (await postURL(
      router.apiResolve({
        name: "AuthFlow",
        params: {
          id: props.id,
        },
      }).href,
      {
        provider: props.provider,
        step: "start",
      } as AuthFlowRequest,
      abortController.signal,
      mainProgress,
    )) as AuthFlowResponse
    if (abortController.signal.aborted) {
      return
    }
    if (locationRedirect(response, flow)) {
      // We increase the progress and never decrease it to wait for browser to do the redirect.
      mainProgress.value += 1
    } else {
      throw new Error("unexpected response")
    }
  } catch (error) {
    if (abortController.signal.aborted) {
      return
    }
    throw error
  } finally {
    mainProgress.value -= 1
  }
}
</script>

<template>
  <div class="flex flex-col rounded border bg-white p-4 shadow w-full float-left first:ml-0 ml-[-100%]">
    <div>
      You will be redirected to <strong>{{ providerName }}</strong> in {{ seconds === 1 ? "1 second" : `${seconds} seconds` }}{{ paused ? " (paused)" : "" }}.
    </div>
    <div class="mt-4">Please follow instructions there to sign-in into Charon. Afterwards, you will be redirected back here.</div>
    <div class="mt-4">
      You might have to sign-in into {{ providerName }} first. You might be redirected back by {{ providerName }} immediately, without showing you anything.
    </div>
    <div class="mt-4 flex flex-row justify-between gap-4">
      <Button type="button" tabindex="3" :disabled="mainProgress > 0" @click.prevent="onBack">Back</Button>
      <div class="flex flex-row gap-4">
        <Button type="button" tabindex="2" :disabled="mainProgress > 0" @click.prevent="onPauseResume">{{ paused ? "Resume" : "Pause" }}</Button>
        <Button id="redirect" primary type="button" tabindex="1" :disabled="mainProgress > 0" @click.prevent="onRedirect">Redirect</Button>
      </div>
    </div>
  </div>
</template>
