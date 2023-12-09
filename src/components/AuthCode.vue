<script setup lang="ts">
import type { AuthFlowRequest, AuthFlowResponse } from "@/types"
import { ref, nextTick, computed, watch } from "vue"
import { useRouter } from "vue-router"
import Button from "@/components/Button.vue"
import InputText from "@/components/InputText.vue"
import { postURL } from "@/api"
import { locationRedirect } from "@/utils"

const props = defineProps<{
  modelValue: string
  id: string
  emailOrUsername: string
}>()

const emit = defineEmits<{
  "update:modelValue": [value: string]
}>()

const isEmail = computed(() => {
  return props.emailOrUsername.indexOf("@") >= 0
})

const router = useRouter()

const code = ref("")
const progress = ref(0)
const sendCounter = ref(1)
const codeError = ref("")

watch(code, () => {
  // We reset the flag when input box value changes.
  codeError.value = ""
})

async function onBack() {
  if (progress.value > 0) {
    // Clicking on disabled links.
    return
  }
  emit("update:modelValue", "start")
  await nextTick()
  document.getElementById("email-or-username")?.focus()
}

async function onNext() {
  progress.value += 1
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
      progress,
    )) as AuthFlowResponse
    if (locationRedirect(response)) {
      // We increase the progress and never decrease it to wait for browser to do the redirect.
      progress.value += 1
      return
    }
    if ("error" in response && ["invalidCode"].includes(response.error)) {
      codeError.value = response.error
      return
    }
    throw new Error("unexpected response")
  } finally {
    progress.value -= 1
  }
}

async function onResend() {
  progress.value += 1
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
      progress,
    )) as AuthFlowResponse
    if (locationRedirect(response)) {
      // We increase the progress and never decrease it to wait for browser to do the redirect.
      progress.value += 1
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
  } finally {
    progress.value -= 1
  }
}
</script>

<template>
  <div class="flex flex-col self-center rounded border bg-white p-4 shadow m-1 w-[65ch]">
    <h2 class="text-center mx-4 mb-4 text-xl font-bold uppercase">Sign-in or sign-up</h2>
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
      <form class="flex flex-row" novalidate @submit.prevent="onNext">
        <InputText
          id="code"
          v-model="code"
          tabindex="1"
          class="flex-grow flex-auto min-w-0"
          :readonly="progress > 0"
          autocomplete="one-time-code"
          spellcheck="false"
          inputmode="numeric"
          pattern="[0-9]*"
          minlength="6"
          maxlength="6"
          required
        />
        <Button primary type="submit" class="ml-4" tabindex="2" :disabled="code.trim().length < 6 || progress > 0 || !!codeError">Next</Button>
      </form>
    </div>
    <div v-if="codeError === 'invalidCode'" class="mt-4 text-error-600">Code is invalid. Please try again.</div>
    <div v-else class="mt-4">Please allow few minutes for the code to arrive. Check spam or junk folder.</div>
    <div class="mt-4">
      If you have trouble accessing your e-mail, try a
      <a :href="progress > 0 ? undefined : ''" class="link" :class="progress > 0 ? 'disabled' : ''" @click.prevent="onBack">different sign-in method</a>.
    </div>
    <div class="mt-4 flex flex-row justify-between gap-4">
      <Button type="button" tabindex="4" :disabled="progress > 0" @click.prevent="onBack">Back</Button>
      <Button type="button" tabindex="3" :disabled="progress > 0" @click.prevent="onResend">Resend code</Button>
    </div>
  </div>
</template>
