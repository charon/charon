<script setup lang="ts">
import type { AuthFlowRequest, AuthFlowResponse } from "@/types"
import { ref, computed, watch, onUnmounted, onMounted, getCurrentInstance, inject } from "vue"
import { useRouter } from "vue-router"
import Button from "@/components/Button.vue"
import InputText from "@/components/InputText.vue"
import { postURL } from "@/api"
import { flowKey, locationRedirect } from "@/utils"

const props = defineProps<{
  id: string
  emailOrUsername: string
}>()

const isEmail = computed(() => {
  return props.emailOrUsername.indexOf("@") >= 0
})

const router = useRouter()

const flow = inject(flowKey)

const code = ref("")
const mainProgress = ref(0)
const abortController = new AbortController()
const sendCounter = ref(1)
const codeError = ref("")

watch(code, () => {
  // We reset the flag when input box value changes.
  codeError.value = ""
})

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
  document.getElementById("code")?.focus()
}

function onBeforeLeave() {
  abortController.abort()
}

async function onBack() {
  if (abortController.signal.aborted) {
    return
  }
  if (mainProgress.value > 0) {
    // Clicking on disabled links.
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
    if ("error" in response && ["invalidCode"].includes(response.error)) {
      codeError.value = response.error
      return
    }
    throw new Error("unexpected response")
  } catch (error) {
    if (abortController.signal.aborted) {
      return
    }
    throw error
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
    code.value = ""
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
    if ("code" in response) {
      sendCounter.value += 1
      document.getElementById("code")?.focus()
      return
    }
    throw new Error("unexpected response")
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
    <div class="flex flex-col">
      <label v-if="isEmail" for="code" class="mb-1"
        >We {{ sendCounter > 1 ? `sent (${sendCounter}x)` : "sent" }} a 6-digit code to <strong>{{ emailOrUsername }}</strong> e-mail address. Please enter it to
        continue:</label
      >
      <label v-else for="code" class="mb-1">
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
        <InputText
          id="code"
          v-model="code"
          tabindex="1"
          class="flex-grow flex-auto min-w-0"
          :readonly="mainProgress > 0"
          autocomplete="one-time-code"
          spellcheck="false"
          inputmode="numeric"
          pattern="[0-9]*"
          minlength="6"
          required
        />
        <!--
          Here we enable button only if the length of non-whitespace content is exactly
          6 characters because we tell users what is expected upfront.
        -->
        <Button primary type="submit" class="ml-4" tabindex="2" :disabled="code.replace(/\s/g, '').length !== 6 || mainProgress > 0 || !!codeError">Next</Button>
      </form>
    </div>
    <div v-if="codeError === 'invalidCode'" class="mt-4 text-error-600">Code is invalid. Please try again.</div>
    <div v-else class="mt-4">Please allow few minutes for the code to arrive. Check spam or junk folder.</div>
    <div class="mt-4">
      If you have trouble accessing your e-mail, try a
      <a :href="mainProgress > 0 ? undefined : ''" class="link" :class="mainProgress > 0 ? 'disabled' : ''" @click.prevent="onBack">different sign-in method</a>.
    </div>
    <div class="mt-4 flex flex-row justify-between gap-4">
      <Button type="button" tabindex="4" :disabled="mainProgress > 0" @click.prevent="onBack">Back</Button>
      <Button type="button" tabindex="3" :disabled="mainProgress > 0" @click.prevent="onResend">Resend code</Button>
    </div>
  </div>
</template>
