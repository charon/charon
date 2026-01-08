<script setup lang="ts">
import type { DeepReadonly } from "vue"

import type { CredentialPublic, CredentialRenameRequest, CredentialResponse, SignalCurrentUserDetails } from "@/types"

import { nextTick, onBeforeUnmount, ref, watch } from "vue"
import { useI18n } from "vue-i18n"
import { useRouter } from "vue-router"

import { postJSON } from "@/api"
import Button from "@/components/Button.vue"
import InputText from "@/components/InputText.vue"
import { getProviderNameTitle } from "@/flow.ts"
import { useProgress } from "@/progress"

const props = defineProps<{
  credential: CredentialPublic | DeepReadonly<CredentialPublic>
  url?: string
  isRenaming: boolean
}>()

const emit = defineEmits<{
  renamed: []
  canceled: []
}>()

const { t } = useI18n({ useScope: "global" })
const router = useRouter()

const abortController = new AbortController()
const progress = useProgress()

const displayName = ref("")
const renameError = ref("")
const unexpectedError = ref("")

function getErrorMessage(errorCode: string) {
  switch (errorCode) {
    case "credentialDisplayNameMissing":
      return t("common.errors.credentialDisplayNameMissing")
    case "credentialDisplayNameInUse":
      return t("common.errors.credentialDisplayNameInUse")
    default:
      throw new Error(`unexpected error code: ${errorCode}`)
  }
}

function resetOnInteraction() {
  // We reset the error on interaction.
  renameError.value = ""
  unexpectedError.value = ""
}

watch([displayName], resetOnInteraction)

watch(
  () => props.isRenaming,
  async (isRenaming) => {
    if (isRenaming) {
      displayName.value = props.credential.displayName
      resetOnInteraction()
      await nextTick(() => {
        // Only one can be open at a time.
        document.querySelector<HTMLInputElement>(".credentialfull-input")?.focus()
      })
    } else {
      resetOnInteraction()
    }
  },
)

onBeforeUnmount(() => {
  abortController.abort()
})

function canSubmit(): boolean {
  // Submission is on purpose not disabled on unexpectedError so that user can retry.
  if (renameError.value) {
    return false
  }

  // Required fields.
  return !!displayName.value
}

function onCancel() {
  if (abortController.signal.aborted) {
    return
  }

  abortController.abort()
  resetOnInteraction()
  emit("canceled")
}

async function onSubmit() {
  if (abortController.signal.aborted) {
    return
  }

  resetOnInteraction()

  progress.value += 1
  try {
    const url = router.apiResolve({
      name: "CredentialRename",
      params: { id: props.credential.id },
    }).href

    const response = await postJSON<CredentialResponse>(
      url,
      {
        displayName: displayName.value,
      } as CredentialRenameRequest,
      abortController.signal,
      progress,
    )
    if (abortController.signal.aborted) {
      return
    }
    if ("error" in response) {
      // We check if it is an expected error code by trying to get the error message.
      getErrorMessage(response.error)
      renameError.value = response.error
      return
    }

    if (!response.success) {
      throw new Error("unexpected response")
    }

    // When renaming a passkey, we try signaling to the authenticator about the updated user credential.
    if (response.signal && "update" in response.signal) {
      await signalPasskeyUpdate(response.signal.update)
      if (abortController.signal.aborted) {
        return
      }
    }

    emit("renamed")
  } catch (error) {
    if (abortController.signal.aborted) {
      return
    }
    console.error("CredentialFull.onSubmit", error)
    // eslint-disable-next-line @typescript-eslint/restrict-template-expressions
    unexpectedError.value = `${error}`
  } finally {
    progress.value -= 1
  }
}

async function signalPasskeyUpdate(signal: SignalCurrentUserDetails) {
  // PublicKeyCredential.signalCurrentUserDetails might not be available and this is fine.
  await PublicKeyCredential.signalCurrentUserDetails?.(signal)
}
</script>

<template>
  <div v-if="!isRenaming" class="flex flex-row items-center justify-between gap-4">
    <div class="grow">
      <h2 class="credentialfull-provider text-xl">{{ getProviderNameTitle(t, credential.provider) }}</h2>
      <div class="mt-1 flex flex-row items-center gap-1">
        <span class="credentialfull-displayname">{{ credential.displayName }}</span>
        <span v-if="credential.verified" class="rounded-xs bg-slate-100 px-1.5 py-0.5 text-sm leading-none text-gray-600 shadow-xs">{{
          t("common.labels.verified")
        }}</span>
      </div>
    </div>
    <slot :credential="credential" />
  </div>
  <div v-else class="flex flex-row items-center justify-between gap-4">
    <div class="grow">
      <h2 class="credentialfull-provider text-xl">{{ getProviderNameTitle(t, credential.provider) }}</h2>
      <!--
        We set novalidate because we do not want UA to show hints.
        We show them ourselves when we want them.
      -->
      <form class="mt-1 flex flex-row items-center gap-4" novalidate @submit.prevent="onSubmit" @keydown.esc="onCancel">
        <InputText v-model="displayName" class="credentialfull-input min-w-0 flex-auto grow" :progress="progress" required />
        <Button class="credentialfull-button-rename" type="submit" primary :disabled="!canSubmit()" :progress="progress">{{ t("common.buttons.rename") }}</Button>
        <Button class="credentialfull-button-cancel" type="button" :progress="progress" @click.prevent="onCancel">{{ t("common.buttons.cancel") }}</Button>
      </form>
    </div>
  </div>
  <div v-if="renameError" class="mt-4 text-error-600">{{ getErrorMessage(renameError) }}</div>
  <div v-else-if="unexpectedError" class="mt-4 text-error-600">{{ t("common.errors.unexpected") }}</div>
</template>
