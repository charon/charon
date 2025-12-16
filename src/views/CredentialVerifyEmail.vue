<script setup lang="ts">
import type { CredentialPublic, CredentialResponse, CredentialVerifyEmailCompleteRequest } from "@/types"

import { onBeforeUnmount, onMounted, ref, watch } from "vue"
import { useI18n } from "vue-i18n"
import { useRoute, useRouter } from "vue-router"

import { getURL, postJSON } from "@/api"
import Button from "@/components/Button.vue"
import InputCode from "@/components/InputCode.vue"
import Footer from "@/partials/Footer.vue"
import NavBar from "@/partials/NavBar.vue"
import { useProgress } from "@/progress"

const props = defineProps<{
  id: string
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
const email = ref("")

function getErrorMessage(errorCode: string) {
  switch (errorCode) {
    case "invalidCode":
      return t("common.errors.invalidCode")
    case "verificationSessionExpired":
      return t("common.errors.verificationSessionExpired")
    case "maxVerifyAttempts":
      return t("common.errors.maxVerifyAttempts")
    case "credentialInUse":
      return t("common.errors.credentialInUse.email")
    default:
      throw new Error(`unexpected error code: ${errorCode}`)
  }
}

function resetOnInteraction() {
  // We reset errors on interaction.
  if (codeError.value === "invalidCode") {
    codeError.value = ""
  }
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

onBeforeUnmount(() => {
  abortController.abort()
})

onMounted(async () => {
  await fetchCredential()
  await startVerification()

  if (codeFromHash.value) {
    document.getElementById("credentialverifyemail-button-submitcode")?.focus()
  } else {
    document.getElementById("code")?.focus()
  }
})

function canResend(): boolean {
  return !codeError.value || codeError.value === "invalidCode"
}

function canSubmit(): boolean {
  return canResend() && !!code.value.replaceAll(/\s/g, "")
}

async function fetchCredential() {
  if (abortController.signal.aborted) {
    return
  }

  progress.value += 1
  try {
    const url = router.apiResolve({
      name: "CredentialGet",
      params: { id: props.id },
    }).href

    const response = await getURL<CredentialPublic>(url, null, abortController.signal, progress)
    if (abortController.signal.aborted) {
      return
    }

    email.value = response.doc.displayName
  } catch (error) {
    if (abortController.signal.aborted) {
      return
    }
    console.error("CredentialVerifyEmail.fetchCredential", error)
    // eslint-disable-next-line @typescript-eslint/restrict-template-expressions
    unexpectedError.value = `${error}`
  } finally {
    progress.value -= 1
  }
}

async function startVerification() {
  if (abortController.signal.aborted) {
    return
  }

  resetOnInteraction()
  progress.value += 1

  try {
    const url = router.apiResolve({
      name: "CredentialVerifyEmail",
      params: { id: props.id },
    }).href

    const response = await postJSON<CredentialResponse>(url, {}, abortController.signal, progress)
    if (abortController.signal.aborted) {
      return
    }
    if ("error" in response) {
      // We check if it is an expected error code by trying to get the error message.
      getErrorMessage(response.error)
      codeError.value = response.error
      return
    }
  } catch (error) {
    if (abortController.signal.aborted) {
      return
    }
    console.error("CredentialVerifyEmail.startVerification", error)
    // eslint-disable-next-line @typescript-eslint/restrict-template-expressions
    unexpectedError.value = `${error}`
  } finally {
    progress.value -= 1
  }
}

async function onBack() {
  if (abortController.signal.aborted) {
    return
  }

  abortController.abort()
  await router.push({ name: "CredentialList" })
}

async function onSubmit() {
  if (abortController.signal.aborted) {
    return
  }

  resetOnInteraction()

  progress.value += 1
  try {
    const url = router.apiResolve({
      name: "CredentialVerifyEmailComplete",
      params: { id: props.id },
    }).href

    const response = await postJSON<CredentialResponse>(
      url,
      {
        code: code.value,
      } as CredentialVerifyEmailCompleteRequest,
      abortController.signal,
      progress,
    )
    if (abortController.signal.aborted) {
      return
    }
    if ("error" in response && response.error) {
      // We check if it is an expected error code by trying to get the error message.
      getErrorMessage(response.error)
      codeError.value = response.error
      return
    }

    await router.push({ name: "CredentialList" })
  } catch (error) {
    if (abortController.signal.aborted) {
      return
    }
    console.error("CredentialVerifyEmail.onSubmit", error)
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
      name: "CredentialVerifyEmail",
      params: { id: props.id },
    }).href

    const response = await postJSON<CredentialResponse>(url, {}, abortController.signal, progress)
    if (abortController.signal.aborted) {
      return
    }

    if ("error" in response) {
      getErrorMessage(response.error)
      codeError.value = response.error
      return
    }

    if (!response.success) {
      throw new Error("unexpected response")
    }

    sendCounter.value += 1
    document.getElementById("code")?.focus()
  } catch (error) {
    if (abortController.signal.aborted) {
      return
    }
    console.error("CredentialVerifyEmail.onResend", error)
    // eslint-disable-next-line @typescript-eslint/restrict-template-expressions
    unexpectedError.value = `${error}`
  } finally {
    progress.value -= 1
  }
}
</script>

<template>
  <Teleport to="header">
    <NavBar />
  </Teleport>
  <div class="mt-12 flex w-full flex-col items-center border-t border-transparent sm:mt-[4.5rem]">
    <div class="m-1 grid auto-rows-auto grid-cols-[minmax(0,65ch)] gap-1 sm:m-4 sm:gap-4">
      <div class="flex w-full flex-col gap-4 rounded-sm border border-gray-200 bg-white p-4 shadow-sm">
        <h1 class="text-2xl font-bold">{{ t("views.CredentialVerifyEmail.verifyEmail") }}</h1>
      </div>
      <div class="flex w-full flex-col rounded-sm border border-gray-200 bg-white p-4 shadow-sm">
        <template v-if="!!codeError && codeError !== 'invalidCode'">
          <div class="mb-4 text-error-600">
            <template v-if="codeError === 'credentialInUse'">
              {{ t("common.errors.credentialInUse.email") }}
            </template>
            <template v-else>
              <i18n-t keypath="views.CredentialVerifyEmail.verificationFailed" scope="global">
                <template #strongSorry
                ><strong>{{ t("common.messages.sorry") }}</strong></template
                >
              </i18n-t>
            </template>
          </div>
          <div class="mb-4">{{ t("views.CredentialVerifyEmail.tryAgain") }}</div>
          <div class="flex flex-row justify-end">
            <Button primary type="button" @click.prevent="onBack">{{ t("common.buttons.back") }}</Button>
          </div>
        </template>
        <template v-else>
        <div class="flex flex-col">
          <label v-if="codeFromHash" for="code" class="mb-1">
            <i18n-t keypath="views.CredentialVerifyEmail.codeFromHashEmail" scope="global">
              <template #strongEmail
                ><strong>{{ email }}</strong></template
              >
            </i18n-t>
          </label>
          <label v-else-if="email" for="code" class="mb-1">
            <i18n-t keypath="views.CredentialVerifyEmail.codeSentEmail" scope="global">
              <template #sentCount>{{ t("views.CredentialVerifyEmail.sentCount", sendCounter) }}</template>
              <template #strongEmail
                ><strong>{{ email }}</strong></template
              >
            </i18n-t>
          </label>
          <!--
            We set novalidate because we do not want UA to show hints.
            We show them ourselves when we want them.
          -->
          <form class="flex flex-row gap-4" novalidate @submit.prevent="onSubmit">
            <!-- We do not set maxlength so that users can paste too long text and clean it up. -->
            <InputCode
              id="code"
              v-model="code"
              class="min-w-0 flex-auto grow"
              :progress="progress"
              :disabled="!!codeError && codeError !== 'invalidCode'"
              inputmode="numeric"
              pattern="[0-9]*"
              :code-length="6"
              required
            />
            <!--Button is on purpose not disabled on unexpectedError so that user can retry.-->
            <Button id="credentialverifyemail-button-submitcode" primary type="submit" :disabled="!canSubmit()" :progress="progress">
              {{ t("common.buttons.verify") }}
            </Button>
          </form>
        </div>
        <div v-if="codeError" class="mt-4 text-error-600">{{ getErrorMessage(codeError) }}</div>
        <div v-else-if="unexpectedError" class="mt-4 text-error-600">{{ t("common.errors.unexpected") }}</div>
        <div v-else-if="codeFromHash" class="mt-4">{{ t("views.CredentialVerifyEmail.confirmCode") }}</div>
        <div v-else class="mt-4">{{ t("views.CredentialVerifyEmail.waitForCode") }}</div>
        <div class="mt-4 flex flex-row justify-between gap-4">
          <Button type="button" @click.prevent="onBack">{{ t("common.buttons.back") }}</Button>
          <Button id="credentialverifyemail-button-resendcode" type="button" :disabled="!canResend()" :progress="progress" @click.prevent="onResend">{{
            t("views.CredentialVerifyEmail.resendButton")
          }}</Button>
        </div>
        </template>
      </div>
    </div>
  </div>
  <Teleport to="footer">
    <Footer />
  </Teleport>
</template>
