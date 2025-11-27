<script setup lang="ts">
import type { DeepReadonly } from "vue"

import type { CredentialPublic } from "@/types"

import { computed, ref } from "vue"
import { useI18n } from "vue-i18n"
import { useRouter } from "vue-router"

import { postJSON } from "@/api"
import Button from "@/components/Button.vue"
import InputText from "@/components/InputText.vue"
import { getProviderNameTitle } from "@/flow.ts"

const props = defineProps<{
  credential: CredentialPublic | DeepReadonly<CredentialPublic>
  url?: string
  progress: number
}>()

const emit = defineEmits<{
  updated: []
}>()

const { t } = useI18n({ useScope: "global" })
const router = useRouter()

const isEditing = ref(false)
const editedDisplayName = ref("")
const updateProgress = ref(0)
const updateError = ref("")

const abortController = ref(new AbortController())

const canEdit = computed(() => {
  return props.credential.provider !== "email" && props.credential.provider !== "username"
})

const canSubmitUpdate = computed(() => {
  const trimmed = editedDisplayName.value.trim()
  return trimmed !== "" && trimmed !== props.credential.displayName
})

function startEdit() {
  editedDisplayName.value = props.credential.displayName
  isEditing.value = true
  updateError.value = ""
}

function cancelEdit() {
  isEditing.value = false
  editedDisplayName.value = ""
  updateError.value = ""
}

async function submitUpdate() {
  if (!canSubmitUpdate.value || abortController.value.signal.aborted) {
    return
  }

  updateError.value = ""
  updateProgress.value += 1

  try {
    const url = router.apiResolve({
      name: "CredentialUpdateDisplayName",
      params: { id: props.credential.id },
    }).href

    await postJSON(url, { displayName: editedDisplayName.value.trim() }, abortController.value.signal, updateProgress)

    if (abortController.value.signal.aborted) {
      return
    }

    isEditing.value = false
    editedDisplayName.value = ""
    emit("updated")
  } catch (error) {
    if (abortController.value.signal.aborted) {
      return
    }
    console.error("CredentialFull.submitUpdate", error)
    updateError.value = t("common.errors.unexpected")
  } finally {
    updateProgress.value -= 1
  }
}
</script>

<template>
  <div class="flex flex-row items-center justify-between gap-4" :data-url="url">
    <div class="grow">
      <h2 :id="`credentialfull-provider-${credential.id}`" class="text-xl">
        {{ getProviderNameTitle(t, credential.provider) }}
      </h2>
      <div v-if="isEditing" class="mt-1 flex flex-row items-center gap-2">
        <InputText
          :id="`credentialedit-input-${credential.id}`"
          v-model="editedDisplayName"
          class="min-w-0 flex-auto grow"
          :progress="updateProgress"
          autocomplete="off"
          autocorrect="off"
          autocapitalize="none"
          spellcheck="false"
          minlength="1"
          required
        />
      </div>
      <div v-else class="mt-1 flex flex-row items-center gap-2">
        <span>{{ credential.displayName }}</span>
        <span v-if="credential.verified" class="rounded-xs bg-slate-100 px-1.5 py-0.5 text-sm leading-none text-gray-600 shadow-xs">
          {{ t("common.labels.verified") }}
        </span>
      </div>
      <div v-if="updateError" class="mt-2 text-error-600">{{ updateError }}</div>
    </div>
    <div class="flex flex-row gap-4">
      <template v-if="isEditing">
        <Button :id="`credentialfull-button-update-${credential.id}`" type="button" :disabled="!canSubmitUpdate" :progress="updateProgress" @click="submitUpdate">
          {{ t("common.buttons.rename") }}
        </Button>
        <Button :id="`credentialfull-button-cancel-${credential.id}`" type="button" :progress="updateProgress" @click="cancelEdit">
          {{ t("common.buttons.cancel") }}
        </Button>
      </template>
      <template v-else>
        <Button v-if="canEdit" :id="`credentialfull-button-rename-${credential.id}`" type="button" :progress="progress" @click="startEdit">
          {{ t("common.buttons.rename") }}
        </Button>
        <slot :credential="credential" />
      </template>
    </div>
  </div>
</template>
