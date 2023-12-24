<script setup lang="ts">
import type { AuthFlowRequest, AuthFlowResponse } from "@/types"
import { ref, watch, onUnmounted, onMounted, getCurrentInstance, inject } from "vue"
import { useRoute, useRouter } from "vue-router"
import Button from "@/components/Button.vue"
import InputCode from "@/components/InputCode.vue"
import { postURL } from "@/api"
import { locationRedirect, isEmail } from "@/utils"
import { flowKey } from "@/flow"

const props = defineProps<{
  id: string
  name: string
  emailOrUsername: string
}>()

const router = useRouter()
const route = useRoute()

const flow = inject(flowKey)

const code = ref("")
const mainProgress = ref(0)
const abortController = new AbortController()
const sendCounter = ref(1)
const codeError = ref("")
const unexpectedError = ref("")
const codeProvided = ref(false)

watch(code, () => {
  // We reset errors when input box value changes.
  codeError.value = ""
  unexpectedError.value = ""
})

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
      codeProvided.value = true
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

onUnmounted(onBeforeLeave)

function onAfterEnter() {
  if (codeProvided.value) {
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
  flow!.backward("password")
}

async function onRedo() {
  if (abortController.signal.aborted) {
    return
  }

  abortController.abort()
  flow!.backward("start")
}

async function onNext() {
  if (abortController.signal.aborted) {
    return
  }

  mainProgress.value += 1
  try {
    unexpectedError.value = ""
    const url = router.apiResolve({
      name: "AuthFlow",
      params: {
        id: props.id,
      },
    }).href

    const response = (await postURL(
      url,
      {
        provider: "code",
        step: "complete",
        code: {
          complete: {
            code: code.value,
          },
        },
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
      return
    }
    if ("error" in response && response.error && ["invalidCode"].includes(response.error)) {
      codeError.value = response.error
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
    mainProgress.value -= 1
  }
}

async function onResend() {
  if (abortController.signal.aborted) {
    return
  }

  mainProgress.value += 1
  try {
    codeError.value = ""
    unexpectedError.value = ""
    code.value = ""
    codeProvided.value = false
    const url = router.apiResolve({
      name: "AuthFlow",
      params: {
        id: props.id,
      },
    }).href

    const response = (await postURL(
      url,
      {
        provider: "code",
        step: "start",
        code: {
          start: {
            emailOrUsername: props.emailOrUsername,
          },
        },
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
      return
    }
    // No error is expected in the response because code has already been generated in the past
    // for the same request, so we do not check response.error here.
    if ("provider" in response && response.provider === "code") {
      sendCounter.value += 1
      document.getElementById("code")?.focus()
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
    mainProgress.value -= 1
  }
}
</script>

<template>
  <div class="flex flex-col rounded border bg-white p-4 shadow w-full">
    <div class="flex flex-col">
      <label v-if="codeProvided && isEmail(emailOrUsername)" for="code" class="mb-1"
        >We sent the following 6-digit code to <strong>{{ emailOrUsername }}</strong> e-mail address:</label
      >
      <label v-else-if="codeProvided" for="code" class="mb-1">
        We sent the following 6-digit code to e-mail address(es) associated with the Charon username
        <strong>{{ emailOrUsername }}</strong
        >:</label
      >
      <label v-else-if="!codeProvided && isEmail(emailOrUsername)" for="code" class="mb-1"
        >We {{ sendCounter > 1 ? `sent (${sendCounter}x)` : "sent" }} a 6-digit code to <strong>{{ emailOrUsername }}</strong> e-mail address. Please enter it to
        continue:</label
      >
      <label v-else-if="!codeProvided" for="code" class="mb-1">
        We {{ sendCounter > 1 ? `sent (${sendCounter}x)` : "sent" }} a 6-digit code to e-mail address(es) associated with the Charon username
        <strong>{{ emailOrUsername }}</strong
        >. Please enter it to continue:</label
      >
      <!--
        We set novalidate because we do not UA to show hints.
        We show them ourselves when we want them.
      -->
      <form class="flex flex-row" novalidate @submit.prevent="onNext">
        <!-- We do not set maxlength so that users can paste too long text and clean it up. -->
        <InputCode
          id="code"
          v-model="code"
          tabindex="1"
          class="flex-grow flex-auto min-w-0"
          :readonly="mainProgress > 0"
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
        <Button id="submit-code" primary type="submit" class="ml-4" tabindex="2" :disabled="code.replaceAll(/\s/g, '').length === 0 || mainProgress > 0 || !!codeError"
          >Next</Button
        >
      </form>
    </div>
    <div v-if="codeError === 'invalidCode'" class="mt-4 text-error-600">Code is invalid. Please try again.</div>
    <div v-else-if="unexpectedError" class="mt-4 text-error-600">Unexpected error. Please try again.</div>
    <div v-else-if="codeProvided" class="mt-4">Please confirm the code to continue.</div>
    <div v-else class="mt-4">Please allow few minutes for the code to arrive. Check spam or junk folder.</div>
    <div v-if="codeProvided" class="mt-4">
      If you were not signing in or signing up into {{ name }}, please disregard the e-mail and <strong>do not</strong> confirm the code.
    </div>
    <div v-else class="mt-4">
      If you have trouble accessing your e-mail, try a
      <a href="" class="link" @click.prevent="onRedo">different sign-in or sign-up method</a>.
    </div>
    <div class="mt-4 flex flex-row justify-between gap-4">
      <Button type="button" tabindex="4" @click.prevent="onBack">Back</Button>
      <Button type="button" tabindex="3" :disabled="mainProgress > 0" @click.prevent="onResend">Resend code</Button>
    </div>
  </div>
</template>
