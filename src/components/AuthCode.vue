<script setup lang="ts">
import type { AuthFlowResponse } from "@/types"
import { ref, nextTick, computed, watch } from "vue"
import { useRouter } from "vue-router"
import Button from "@/components/Button.vue"
import InputText from "@/components/InputText.vue"
import { FetchError, postURL } from "@/api"
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
const resendCounter = ref(0)
const invalidCode = ref(false)

watch(code, () => {
  // We reset the flag when input box value changes.
  invalidCode.value = false
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

    try {
      const response: AuthFlowResponse = await postURL(
        url,
        {
          step: "complete",
          provider: "code",
          codeComplete: {
            code: code.value,
          },
        },
        progress,
      )
      if (locationRedirect(response)) {
        // We increase the progress and never decrease it to wait for browser to do the redirect.
        progress.value += 1
      } else {
        throw new Error("unexpected response")
      }
    } catch (error) {
      if (error instanceof FetchError && error.status === 401) {
        invalidCode.value = true
        return
      }
      throw error
    }
  } finally {
    progress.value -= 1
  }
}

async function onResend() {
  progress.value += 1
  try {
    invalidCode.value = false
    code.value = ""
    const url = router.apiResolve({
      name: "AuthFlow",
      params: {
        id: props.id,
      },
    }).href

    const response: AuthFlowResponse = await postURL(
      url,
      {
        step: "start",
        provider: "code",
        codeStart: {
          emailOrUsername: props.emailOrUsername,
        },
      },
      progress,
    )
    if (locationRedirect(response)) {
      // We increase the progress and never decrease it to wait for browser to do the redirect.
      progress.value += 1
    } else if (response.code) {
      resendCounter.value += 1
      document.getElementById("code")?.focus()
    } else {
      throw new Error("unexpected response")
    }
  } finally {
    progress.value -= 1
  }
}
</script>

<template>
  <div class="flex flex-col">
    <label v-if="isEmail" for="code" class="mb-1"
      >We {{ resendCounter > 1 ? `resent (${resendCounter}x)` : resendCounter > 0 ? "resent" : "sent" }} a 6-digit code to <strong>{{ emailOrUsername }}</strong> e-mail
      address. Please enter it to continue:</label
    >
    <label v-else for="code" class="mb-1">
      We {{ resendCounter > 1 ? `resent (${resendCounter}x)` : resendCounter > 0 ? "resent" : "sent" }} a 6-digit code to e-mail address(es) associated with the Charon
      username <strong>{{ emailOrUsername }}</strong
      >. Please enter it to continue:</label
    >
    <form class="flex flex-row" @submit.prevent="onNext">
      <InputText id="code" v-model="code" tabindex="1" class="flex-grow flex-auto min-w-0" :readonly="progress > 0" />
      <Button type="submit" class="ml-4" tabindex="2" :disabled="code.trim().length == 0 || progress > 0 || invalidCode">Next</Button>
    </form>
  </div>
  <div v-if="invalidCode" class="mt-4 text-error-600">Code is invalid. Please try again.</div>
  <div v-else class="mt-4">Please allow few minutes for the code to arrive. Check spam or junk folder.</div>
  <div class="mt-4">
    If you have trouble accessing your e-mail, try a
    <a :href="progress > 0 ? undefined : ''" class="link" :class="progress > 0 ? 'disabled' : ''" @click.prevent="onBack">different sign-in method</a>.
  </div>
  <div class="mt-4 flex flex-row justify-between gap-4">
    <Button type="button" tabindex="4" :disabled="progress > 0" @click.prevent="onBack">Back</Button>
    <Button type="button" tabindex="3" :disabled="progress > 0" @click.prevent="onResend">Resend code</Button>
  </div>
</template>
