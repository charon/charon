<script setup lang="ts">
import type { AuthFlowCodeCompleteRequest, AuthFlowCodeStartRequest, AuthFlowResponse, Flow, OrganizationApplicationPublic } from "@/types"

import { ref, watch, onBeforeUnmount, onMounted, getCurrentInstance } from "vue"
import { useRoute, useRouter } from "vue-router"
import WithDocument from "@/components/WithDocument.vue"
import Button from "@/components/Button.vue"
import InputCode from "@/components/InputCode.vue"
import { postJSON } from "@/api"
import { isEmail } from "@/utils"
import { injectProgress } from "@/progress"
import { processResponse } from "@/flow"

const props = defineProps<{
  flow: Flow
}>()

const router = useRouter()
const route = useRoute()

const progress = injectProgress()

const abortController = new AbortController()

const code = ref("")
const sendCounter = ref(1)
const codeError = ref("")
const unexpectedError = ref("")
const codeFromHash = ref(false)

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
    document.getElementById("submit-code")?.focus()
  } else {
    document.getElementById("code")?.focus()
  }
}

function onBeforeLeave() {
  abortController.abort()
}

async function onBack() {
  if (abortController.signal.aborted) {
    return
  }

  abortController.abort()
  props.flow.backward("password")
}

async function onRedo() {
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
    if ("error" in response && ["invalidCode"].includes(response.error)) {
      codeError.value = response.error
      return
    }
    throw new Error("unexpected response")
  } catch (error) {
    if (abortController.signal.aborted) {
      return
    }
    console.error("AuthCode.onNext", error)
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
    if (response.providers && response.providers.length > 0 && response.providers[response.providers.length-1] === "code") {
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
    unexpectedError.value = `${error}`
  } finally {
    progress.value -= 1
  }
}

const WithOrganizationApplicationDocument = WithDocument<OrganizationApplicationPublic>
</script>

<template>
  <div class="flex flex-col rounded border bg-white p-4 shadow w-full">
    <div class="flex flex-col">
      <label v-if="codeFromHash && isEmail(flow.getEmailOrUsername())" for="code" class="mb-1"
        >We sent the following 6-digit code to <strong>{{ flow.getEmailOrUsername() }}</strong> e-mail address:</label
      >
      <label v-else-if="codeFromHash" for="code" class="mb-1">
        We sent the following 6-digit code to e-mail address(es) associated with the Charon username
        <strong>{{ flow.getEmailOrUsername() }}</strong
        >:</label
      >
      <label v-else-if="!codeFromHash && isEmail(flow.getEmailOrUsername())" for="code" class="mb-1"
        >We {{ sendCounter > 1 ? `sent (${sendCounter}x)` : "sent" }} a 6-digit code
        to <strong>{{ flow.getEmailOrUsername() }}</strong> e-mail address. Please enter it to
        continue:</label
      >
      <label v-else-if="!codeFromHash" for="code" class="mb-1">
        We {{ sendCounter > 1 ? `sent (${sendCounter}x)` : "sent" }} a 6-digit code to
        e-mail address(es) associated with the Charon username
        <strong>{{ flow.getEmailOrUsername() }}</strong
        >. Please enter it to continue:</label
      >
      <!--
        We set novalidate because we do not UA to show hints.
        We show them ourselves when we want them.
      -->
      <form class="flex flex-row gap-4" novalidate @submit.prevent="onNext">
        <!-- We do not set maxlength so that users can paste too long text and clean it up. -->
        <InputCode
          id="code"
          v-model="code"
          tabindex="1"
          class="flex-grow flex-auto min-w-0"
          :progress="progress"
          inputmode="numeric"
          pattern="[0-9]*"
          :code-length="6"
          required
        />
        <!--
          Here we enable button when non-whitespace content is not empty even if we tell users
          what is expected upfront. We prefer this so that they do not wonder why the button
          is not enabled.
          Button is on purpose not disabled on unexpectedError so that user can retry.
        -->
        <Button id="submit-code" primary type="submit" tabindex="2" :disabled="!code.replaceAll(/\s/g, '') || !!codeError" :progress="progress">Next</Button>
      </form>
    </div>
    <div v-if="codeError === 'invalidCode'" class="mt-4 text-error-600">Code is invalid. Please try again.</div>
    <div v-else-if="unexpectedError" class="mt-4 text-error-600">Unexpected error. Please try again.</div>
    <div v-else-if="codeFromHash" class="mt-4">Please confirm the code to continue.</div>
    <div v-else class="mt-4">Please allow few minutes for the code to arrive. Check spam or junk folder.</div>
    <div v-if="codeFromHash" class="mt-4">
      <WithOrganizationApplicationDocument :params="{ id: flow.getOrganizationId(), appId: flow.getAppId() }" name="OrganizationAppGet">
        <template #default="{ doc }">
          If you were not signing in or signing up into {{ doc.applicationTemplate.name }},
          please disregard the e-mail and <strong>do not</strong> confirm the code.
        </template>
      </WithOrganizationApplicationDocument>
    </div>
    <div v-else class="mt-4">
      If you have trouble accessing your e-mail, try a
      <a href="" class="link" @click.prevent="onRedo">different sign-in or sign-up method</a>.
    </div>
    <div class="mt-4 flex flex-row justify-between gap-4">
      <Button type="button" tabindex="4" @click.prevent="onBack">Back</Button>
      <Button type="button" tabindex="3" :progress="progress" @click.prevent="onResend">Resend code</Button>
    </div>
  </div>
</template>
