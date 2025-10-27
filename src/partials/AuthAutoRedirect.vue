<script setup lang="ts">
import type { Flow, OrganizationApplicationPublic } from "@/types"

import { getCurrentInstance, onBeforeUnmount, onMounted, ref } from "vue"
import { useI18n } from "vue-i18n"
import { useRouter } from "vue-router"

import { redirectThirdPartyProvider } from "@/api"
import Button from "@/components/Button.vue"
import WithDocument from "@/components/WithDocument.vue"
import { injectProgress } from "@/progress"

const props = defineProps<{
  flow: Flow
}>()

const { t } = useI18n({ useScope: "global" })
const router = useRouter()
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
  // Going back to identity step means removing steps after the completed identity step.
  const completed = props.flow.getCompleted()
  props.flow.setCompleted(completed.filter((c) => c !== "identity" && c !== "finishReady" && c !== "declined"))
  props.flow.backward("identity")
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

  await doRedirectThirdPartyProvider()
}

async function doRedirectThirdPartyProvider() {
  try {
    await redirectThirdPartyProvider(router, props.flow, abortController, progress)
  } catch (error) {
    if (abortController.signal.aborted) {
      return
    }
    console.error("AuthAutoRedirect.doRedirectThirdPartyProvider", error)
    unexpectedError.value = `${error}`
    // We reset the counter and pause it on an error.
    seconds.value = 3
    paused.value = true
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

const WithOrganizationApplicationDocument = WithDocument<OrganizationApplicationPublic>
</script>

<template>
  <div class="flex flex-col rounded-sm border border-gray-200 bg-white p-4 shadow-sm w-full">
    <WithOrganizationApplicationDocument :params="{ id: flow.getOrganizationId(), appId: flow.getAppId() }" name="OrganizationApp">
      <template #default="{ doc }">
        <div v-if="flow.getCompleted().includes('identity')" class="mb-4">
          <i18n-t keypath="partials.AuthAutoRedirect.congratulations" scope="global">
            <template #appName>{{ doc.applicationTemplate.name }}</template>
            <template #strongCongratulations
              ><strong>{{ t("common.messages.congratulations") }}</strong></template
            >
          </i18n-t>
        </div>
        <div v-else-if="flow.getCompleted().includes('declined')" class="mb-4">
          <i18n-t keypath="partials.AuthAutoRedirect.declined" scope="global">
            <template #appName>{{ doc.applicationTemplate.name }}</template>
            <template #strongDeclineSignInOrSignUp
              ><strong>{{ t("partials.AuthAutoRedirect.declineSignInOrSignUp") }}</strong></template
            >
          </i18n-t>
        </div>
        <div>
          {{
            t("partials.AuthAutoRedirect.redirectMessage", {
              appName: doc.applicationTemplate.name,
              time: t("common.time.seconds", seconds),
              pausedText: paused ? t("common.time.paused") : "",
            })
          }}
        </div>
      </template>
    </WithOrganizationApplicationDocument>
    <div v-if="unexpectedError" class="mt-4 text-error-600">{{ t("common.errors.unexpected") }}</div>
    <div class="mt-4 flex flex-row gap-4 justify-between">
      <Button type="button" tabindex="3" @click.prevent="onBack">{{ t("common.buttons.back") }}</Button>
      <div class="flex flex-row gap-4">
        <Button type="button" tabindex="2" :progress="progress" @click.prevent="onPauseResume">{{
          paused ? t("common.buttons.resume") : t("common.buttons.pause")
        }}</Button>
        <Button id="redirect" primary type="button" tabindex="1" :progress="progress" @click.prevent="onRedirect">{{ t("common.buttons.redirect") }}</Button>
      </div>
    </div>
  </div>
</template>
