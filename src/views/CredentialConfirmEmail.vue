<script setup lang="ts">
import type { CredentialConfirmEmailCompleteRequest, CredentialPublic, CredentialResponse } from "@/types"

import { onBeforeUnmount, ref, watch } from "vue"
import { useI18n } from "vue-i18n"
import { useRouter } from "vue-router"

import { postJSON, sendCredentialConfirmationEmail } from "@/api"
import Button from "@/components/Button.vue"
import InputCode from "@/components/InputCode.vue"
import WithDocument from "@/components/WithDocument.vue"
import Footer from "@/partials/Footer.vue"
import NavBar from "@/partials/NavBar.vue"
import { useProgress } from "@/progress"
import { useHashParam } from "@/utils"

const props = defineProps<{
  id: string
}>()

const { t } = useI18n({ useScope: "global" })
const router = useRouter()
const progress = useProgress()

const abortController = new AbortController()
const sendCounter = ref(1)
const codeError = ref("")
const unexpectedError = ref("")

const { param: code, paramFromHash: codeFromHash } = useHashParam("code")

function getErrorMessage(errorCode: string) {
  switch (errorCode) {
    case "invalidCode":
      return t("common.errors.invalidCode")
    case "credentialInUse":
      return t("common.errors.credentialInUse.email")
    case "confirmationFailed":
      return t("common.errors.confirmationFailed")
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

// flush: "post" is required because useAuthCode sets code.value from empty to the
// extracted code in the same tick that flips codeFromHash, which makes canSubmit()
// switch from false to true and clears the submit button's :disabled prop. Post-flush
// waits for that re-render, otherwise focus() could land on a still-disabled button.
// immediate: true gives this view its initial focus.
watch(
  codeFromHash,
  (hasCode) => {
    const targetId = hasCode ? "credentialconfirmemail-button-submitcode" : "code"
    document.getElementById(targetId)?.focus()
  },
  { flush: "post", immediate: true },
)

onBeforeUnmount(() => {
  abortController.abort()
})

function canSubmit(): boolean {
  // Submission is on purpose not disabled on unexpectedError so that user can retry.
  if (codeError.value) {
    return false
  }

  // We enable submission when non-whitespace content is not empty even if we tell users what is
  // expected upfront. If they try a too short or too long code we will tell them after submission.
  // We prefer this so that they do not wonder why the button is not enabled.
  return !!code.value.replaceAll(/\s/g, "")
}

async function onSubmit() {
  if (abortController.signal.aborted) {
    return
  }

  resetOnInteraction()

  progress.value += 1
  try {
    const payload: CredentialConfirmEmailCompleteRequest = {
      code: code.value,
    }

    const url = router.apiResolve({
      name: "CredentialConfirmEmailComplete",
      params: { id: props.id },
    }).href

    const response = await postJSON<CredentialResponse>(url, payload, abortController.signal, progress)
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
    console.error("CredentialConfirmEmail.onSubmit", error)
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

    const response = await sendCredentialConfirmationEmail(router, props.id, abortController, progress)
    if (abortController.signal.aborted) {
      return
    }
    if (response.error) {
      // We check if it is an expected error code by trying to get the error message.
      getErrorMessage(response.error)
      codeError.value = response.error
      return
    }
    sendCounter.value += 1
    document.getElementById("code")?.focus()
  } catch (error) {
    if (abortController.signal.aborted) {
      return
    }
    console.error("CredentialConfirmEmail.startConfirmation", error)
    // eslint-disable-next-line @typescript-eslint/restrict-template-expressions
    unexpectedError.value = `${error}`
  } finally {
    progress.value -= 1
  }
}

async function onResendAfterFailure() {
  if (abortController.signal.aborted) {
    return
  }
  // All codes reached maxEmailConfirmationAttempts or expired, so we set the counter to 0.
  // onResend increments the counter, so UI will show 1.
  sendCounter.value = 0
  await onResend()
}

const WithCredentialDocument = WithDocument<CredentialPublic>
</script>

<template>
  <Teleport to="header">
    <NavBar />
  </Teleport>
  <div class="mt-12 flex w-full flex-col items-center border-t border-transparent sm:mt-[4.5rem]">
    <div class="m-1 grid auto-rows-auto grid-cols-[minmax(0,65ch)] gap-1 sm:m-4 sm:gap-4">
      <div class="flex w-full flex-col gap-4 rounded-sm border border-gray-200 bg-white p-4 shadow-sm">
        <div class="flex flex-row items-center justify-between gap-4">
          <h1 class="text-2xl font-bold">{{ t("views.CredentialConfirmEmail.confirmEmail") }}</h1>
        </div>
      </div>

      <div class="flex w-full flex-col gap-4 rounded-sm border border-gray-200 bg-white p-4 shadow-sm">
        <div v-if="codeError === 'credentialInUse'" class="text-error-600">{{ getErrorMessage("credentialInUse") }}</div>
        <div v-else-if="codeError === 'confirmationFailed'" class="text-error-600">{{ getErrorMessage("confirmationFailed") }}</div>
        <template v-if="codeError === 'credentialInUse' || codeError === 'confirmationFailed'">
          <div class="flex flex-row justify-end gap-4">
            <Button
              v-if="codeError === 'confirmationFailed'"
              id="credentialconfirmemail-button-resendonfailed"
              type="button"
              primary
              :progress="progress"
              @click.prevent="onResendAfterFailure"
              >{{ t("views.CredentialConfirmEmail.resendButton") }}</Button
            >
          </div>
        </template>

        <template v-else>
          <div class="flex flex-col">
            <WithCredentialDocument :key="`${props.id}`" :params="{ id: props.id }" name="CredentialGet">
              <template #default="{ doc }">
                <label v-if="codeFromHash" for="code" class="mb-1">
                  <i18n-t keypath="views.CredentialConfirmEmail.codeFromHashEmail" scope="global">
                    <template #strongEmail
                      ><strong>{{ doc.displayName }}</strong></template
                    >
                  </i18n-t>
                </label>
                <label v-else-if="doc.displayName" for="code" class="mb-1">
                  <i18n-t keypath="views.CredentialConfirmEmail.codeSentEmail" scope="global">
                    <template #sentCount>{{ t("views.CredentialConfirmEmail.sentCount", sendCounter) }}</template>
                    <template #strongEmail
                      ><strong>{{ doc.displayName }}</strong></template
                    >
                  </i18n-t>
                </label>
              </template>
            </WithCredentialDocument>
            <!--
             We set novalidate because we do not want UA to show hints.
             We show them ourselves when we want them.
           -->
            <form class="flex flex-row gap-4" novalidate @submit.prevent="onSubmit">
              <!-- We do not set maxlength so that users can paste too long text and clean it up. -->
              <InputCode id="code" v-model="code" class="min-w-0 flex-auto grow" :progress="progress" inputmode="numeric" pattern="[0-9]*" :code-length="6" required />
              <!--
              Button is on purpose not disabled on unexpectedError so that user can retry.
              -->
              <Button id="credentialconfirmemail-button-submitcode" type="submit" primary :disabled="!canSubmit()" :progress="progress">{{
                t("common.buttons.confirm")
              }}</Button>
            </form>
          </div>
          <div v-if="codeError" class="mt-4 text-error-600">{{ getErrorMessage(codeError) }}</div>
          <div v-else-if="unexpectedError" class="mt-4 text-error-600">{{ t("common.errors.unexpected") }}</div>
          <div v-else-if="codeFromHash" class="mt-4">{{ t("views.CredentialConfirmEmail.confirmCode") }}</div>
          <div v-else class="mt-4">{{ t("views.CredentialConfirmEmail.waitForCode") }}</div>
          <div class="mt-4 flex flex-row justify-end gap-4">
            <Button id="credentialconfirmemail-button-resend" type="button" :progress="progress" @click.prevent="onResend">{{
              t("views.CredentialConfirmEmail.resendButton")
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
