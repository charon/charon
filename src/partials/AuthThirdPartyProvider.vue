<script setup lang="ts">
import type { AuthFlowProviderStartRequest, AuthFlowResponse, Flow } from "@/types"

import { ref, onBeforeUnmount, onMounted, getCurrentInstance } from "vue"
import { useI18n } from "vue-i18n"
import { useRouter } from "vue-router"
import Button from "@/components/Button.vue"
import { postJSON } from "@/api"
import { redirectServerSide } from "@/utils"
import { injectProgress } from "@/progress"
import { processResponse } from "@/flow"

const props = defineProps<{
  flow: Flow
}>()

const router = useRouter()

const { t } = useI18n({ useScope: "global" })

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
  props.flow.backward("start")
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
        id: props.flow.getId(),
      },
    }).href

    const provider = props.flow.getThirdPartyProvider()

    const response = await postJSON<AuthFlowResponse>(
      url,
      {
        provider: provider!.key,
      } as AuthFlowProviderStartRequest,
      abortController.signal,
      progress,
    )
    if (abortController.signal.aborted) {
      return
    }
    // processResponse should not really do anything here.
    if (processResponse(router, response, props.flow, progress, abortController)) {
      return
    }
    if ("thirdPartyProvider" in response) {
      redirectServerSide(response.thirdPartyProvider.location, true, progress)
      return
    }
    throw new Error("unexpected response")
  } catch (error) {
    if (abortController.signal.aborted) {
      return
    }
    console.error("AuthThirdPartyProvider.onRedirect", error)
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
      <i18n-t
        keypath="partials.AuthThirdPartyProvider.redirectMessage"
        scope="global"
        :provider="flow.getThirdPartyProvider()!.name"
        :time="seconds === 1 ? t('partials.AuthThirdPartyProvider.oneSecond') : t('partials.AuthThirdPartyProvider.seconds', { count: seconds })"
        :paused-text="paused ? t('partials.AuthThirdPartyProvider.paused') : ''"
      >
        <template #strong
          ><strong>{{ flow.getThirdPartyProvider()!.name }}</strong></template
        >
      </i18n-t>
    </div>
    <div class="mt-4">{{ t("partials.AuthThirdPartyProvider.instructions") }}</div>
    <div class="mt-4">
      {{ t("partials.AuthThirdPartyProvider.additionalInfo", { provider: flow.getThirdPartyProvider()!.name }) }}
    </div>
    <div v-if="unexpectedError" class="mt-4 text-error-600">{{ t("common.errors.unexpected") }}</div>
    <div class="mt-4 flex flex-row justify-between gap-4">
      <Button type="button" tabindex="3" @click.prevent="onBack">{{ t("common.buttons.back") }}</Button>
      <div class="flex flex-row gap-4">
        <Button type="button" tabindex="2" :progress="progress" @click.prevent="onPauseResume">{{
          paused ? t("partials.AuthThirdPartyProvider.resume") : t("partials.AuthThirdPartyProvider.pause")
        }}</Button>
        <Button id="redirect" primary type="button" tabindex="1" :progress="progress" @click.prevent="onRedirect">{{ t("partials.AuthThirdPartyProvider.redirect") }}</Button>
      </div>
    </div>
  </div>
</template>
