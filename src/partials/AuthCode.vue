<script setup lang="ts">
import type { AuthFlowCodeCompleteRequest, AuthFlowCodeStartRequest, AuthFlowResponse, Flow, OrganizationApplicationPublic } from "@/types"

import { getCurrentInstance, onBeforeUnmount, onMounted, ref, watch } from "vue"
import { useI18n } from "vue-i18n"
import { useRoute, useRouter } from "vue-router"

import { postJSON } from "@/api"
import Button from "@/components/Button.vue"
import InputCode from "@/components/InputCode.vue"
import WithDocument from "@/components/WithDocument.vue"
import { processResponse } from "@/flow"
import { useProgress } from "@/progress"
import { isEmail } from "@/utils"

const props = defineProps<{
  flow: Flow
}>()

const { t } = useI18n({ useScope: "global" })
const router = useRouter()
const route = useRoute()
const progress = useProgress()

const abortController = new AbortController()
const code = ref("")
const sendCounter = ref(1)
const codeError = ref("")
const unexpectedError = ref("")
const codeFromHash = ref(false)

function getErrorMessage(errorCode: string) {
  switch (errorCode) {
    case "invalidCode":
      return t("common.errors.invalidCode")
    default:
      throw new Error(`unexpected error code: ${errorCode}`)
  }
}

function resetOnInteraction() {
  // We reset errors on interaction.
  codeError.value = ""
  unexpectedError.value = ""
}

watch([code], resetOnInteraction)

watch(
  () => route.hash,
  (h) => {
    if (!h || h.substring(0, 1) !== "#") {
      return
    }
    const params = new URLSearchParams(h.substring(1))
    const c = params.get("code")
    if (c) {
      code.value = c
      codeFromHash.value = true
      resetOnInteraction()
    }
  },
  { immediate: true },
)

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
  if (codeFromHash.value) {
    document.getElementById("authcode-button-submitcode")?.focus()
  } else {
    document.getElementById("code")?.focus()
  }
}

function onBeforeLeave() {
  abortController.abort()
}

function onBack() {
  if (abortController.signal.aborted) {
    return
  }

  abortController.abort()
  props.flow.backward("password")
}

function onRedo() {
  if (abortController.signal.aborted) {
    return
  }
  // We disable this event handler because this event handler is called from a link.
  if (progress.value > 0) {
    return
  }

  abortController.abort()
  props.flow.backward("start")
}

function canNext(): boolean {
  // Submission is on purpose not disabled on unexpectedError so that user can retry.
  if (codeError.value) {
    return false
  }

  // We enable submission when non-whitespace content is not empty even if we tell users what is
  // expected upfront. If they try a too short or too long code we will tell them after submission.
  // We prefer this so that they do not wonder why the button is not enabled.
  return !!code.value.replaceAll(/\s/g, "")
}

async function onNext() {
  if (abortController.signal.aborted) {
    return
  }

  resetOnInteraction()

  progress.value += 1
  try {
    const url = router.apiResolve({
      name: "AuthFlowCodeComplete",
      params: {
        id: props.flow.getId(),
      },
    }).href

    const response = await postJSON<AuthFlowResponse>(
      url,
      {
        code: code.value,
      } as AuthFlowCodeCompleteRequest,
      abortController.signal,
      progress,
    )
    if (abortController.signal.aborted) {
      return
    }
    // processResponse should move the flow to the next step.
    if (processResponse(router, response, props.flow, progress, abortController)) {
      return
    }
    if ("error" in response) {
      // We check if it is an expected error code by trying to get the error message.
      getErrorMessage(response.error)
      codeError.value = response.error
      return
    }
    throw new Error("unexpected response")
  } catch (error) {
    if (abortController.signal.aborted) {
      return
    }
    console.error("AuthCode.onNext", error)
    // eslint-disable-next-line @typescript-eslint/restrict-template-expressions
    unexpectedError.value = `${error}`
  } finally {
    progress.value -= 1
  }
}

async function onResend() {
  if (abortController.signal.aborted) {
    return
  }

  resetOnInteraction()

  progress.value += 1
  try {
    code.value = ""
    codeFromHash.value = false
    const url = router.apiResolve({
      name: "AuthFlowCodeStart",
      params: {
        id: props.flow.getId(),
      },
    }).href

    const response = await postJSON<AuthFlowResponse>(
      url,
      {
        emailOrUsername: props.flow.getEmailOrUsername(),
      } as AuthFlowCodeStartRequest,
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
    // No error is expected in the response because code has already been generated in the past
    // for the same request, so we do not check response.error here.
    if (response.providers && response.providers.length > 0 && response.providers[response.providers.length - 1] === "code") {
      sendCounter.value += 1
      document.getElementById("code")?.focus()
      return
    }
    throw new Error("unexpected response")
  } catch (error) {
    if (abortController.signal.aborted) {
      return
    }
    console.error("AuthCode.onResend", error)
    // eslint-disable-next-line @typescript-eslint/restrict-template-expressions
    unexpectedError.value = `${error}`
  } finally {
    progress.value -= 1
  }
}

const WithOrganizationApplicationDocument = WithDocument<OrganizationApplicationPublic>
</script>

<template>
  <div class="flex w-full flex-col rounded-sm border border-gray-200 bg-white p-4 shadow-sm">
    <div class="flex flex-col">
      <label v-if="codeFromHash && isEmail(flow.getEmailOrUsername())" for="code" class="mb-1">
        <i18n-t keypath="partials.AuthCode.codeFromHashEmail" scope="global">
          <template #strongEmail
            ><strong>{{ flow.getEmailOrUsername() }}</strong></template
          >
        </i18n-t>
      </label>
      <label v-else-if="codeFromHash" for="code" class="mb-1">
        <i18n-t keypath="partials.AuthCode.codeFromHashUsername" scope="global">
          <template #strongUsername
            ><strong>{{ flow.getEmailOrUsername() }}</strong></template
          >
        </i18n-t>
      </label>
      <label v-else-if="!codeFromHash && isEmail(flow.getEmailOrUsername())" for="code" class="mb-1">
        <i18n-t keypath="partials.AuthCode.codeSentEmail" scope="global">
          <template #sentCount>{{ t("partials.AuthCode.sentCount", sendCounter) }}</template>
          <template #strongEmail
            ><strong>{{ flow.getEmailOrUsername() }}</strong></template
          >
        </i18n-t>
      </label>
      <label v-else-if="!codeFromHash" for="code" class="mb-1">
        <i18n-t keypath="partials.AuthCode.codeSentUsername" scope="global">
          <template #sentCount>{{ t("partials.AuthCode.sentCount", sendCounter) }}</template>
          <template #strongUsername
            ><strong>{{ flow.getEmailOrUsername() }}</strong></template
          >
        </i18n-t>
      </label>
      <!--
        We set novalidate because we do not want UA to show hints.
        We show them ourselves when we want them.
      -->
      <form class="flex flex-row gap-4" novalidate @submit.prevent="onNext">
        <!-- We do not set maxlength so that users can paste too long text and clean it up. -->
        <InputCode
          id="code"
          v-model="code"
          tabindex="1"
          class="min-w-0 flex-auto grow"
          :progress="progress"
          inputmode="numeric"
          pattern="[0-9]*"
          :code-length="6"
          required
        />
        <Button id="authcode-button-submitcode" primary type="submit" tabindex="2" :disabled="!canNext()" :progress="progress">{{ t("common.buttons.next") }}</Button>
      </form>
    </div>
    <div v-if="codeError" class="mt-4 text-error-600">{{ getErrorMessage(codeError) }}</div>
    <div v-else-if="unexpectedError" class="mt-4 text-error-600">{{ t("common.errors.unexpected") }}</div>
    <div v-else-if="codeFromHash" class="mt-4">{{ t("partials.AuthCode.confirmCode") }}</div>
    <div v-else class="mt-4">{{ t("partials.AuthCode.waitForCode") }}</div>
    <div v-if="codeFromHash" class="mt-4">
      <WithOrganizationApplicationDocument :params="{ id: flow.getOrganizationId(), appId: flow.getAppId() }" name="OrganizationApp">
        <template #default="{ doc }">
          <i18n-t keypath="partials.AuthCode.securityWarning" scope="global">
            <template #appName>{{ doc.applicationTemplate.name }}</template>
            <template #strongDont
              ><strong>{{ t("partials.AuthCode.dont") }}</strong></template
            >
          </i18n-t>
        </template>
      </WithOrganizationApplicationDocument>
    </div>
    <div v-else class="mt-4">
      <i18n-t keypath="partials.AuthCode.troubleEmail" scope="global">
        <template #linkDifferentMethod>
          <a href="" class="link" @click.prevent="onRedo">{{ t("partials.AuthCode.differentMethod") }}</a>
        </template>
      </i18n-t>
    </div>
    <div class="mt-4 flex flex-row justify-between gap-4">
      <Button type="button" tabindex="4" @click.prevent="onBack">{{ t("common.buttons.back") }}</Button>
      <Button id="authcode-button-resendcode" type="button" tabindex="3" :progress="progress" @click.prevent="onResend">{{ t("partials.AuthCode.resendButton") }}</Button>
    </div>
  </div>
</template>
