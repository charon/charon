<script setup lang="ts">
import type { CredentialPublic, Credentials } from "@/types"

import { onBeforeMount, onBeforeUnmount, ref } from "vue"
import { useI18n } from "vue-i18n"
import { useRouter } from "vue-router"

import { getURL, postJSON } from "@/api"
import { isSignedIn } from "@/auth"
import Button from "@/components/Button.vue"
import ButtonLink from "@/components/ButtonLink.vue"
import WithDocument from "@/components/WithDocument.vue"
import CredentialFull from "@/partials/credentials/CredentialFull.vue"
import Footer from "@/partials/Footer.vue"
import NavBar from "@/partials/NavBar.vue"
import { useProgress } from "@/progress"

const { t } = useI18n({ useScope: "global" })
const router = useRouter()
const progress = useProgress()

const abortController = new AbortController()
const unexpectedError = ref("")
const currentActionCredentialId = ref<string | null>(null)
const dataLoading = ref(true)
const dataLoadingError = ref("")
const credentials = ref<Credentials>([])

const refreshKey = ref(0)
const renamingCredentialId = ref<string | null>(null)

function canRename(provider: string) {
  // Code provider is not exposed to the frontend so we do not check for it here.
  return provider !== "email" && provider !== "username"
}

function onRename(credentialId: string) {
  if (abortController.signal.aborted) {
    return
  }

  resetOnInteraction()

  renamingCredentialId.value = credentialId
}

function onRenameCancelled() {
  if (abortController.signal.aborted) {
    return
  }

  renamingCredentialId.value = null
}

function onRenamed() {
  if (abortController.signal.aborted) {
    return
  }

  renamingCredentialId.value = null
  refreshKey.value++
}

onBeforeUnmount(() => {
  abortController.abort()
})

// TODO: If user is not signed-in, this will show "unexpected error".

onBeforeMount(async () => {
  progress.value += 1
  try {
    const url = router.apiResolve({
      name: "CredentialList",
    }).href

    const result = await getURL<Credentials>(url, null, abortController.signal, progress)
    if (abortController.signal.aborted) {
      return
    }

    credentials.value = result.doc
  } catch (error) {
    if (abortController.signal.aborted) {
      return
    }
    console.error("CredentialList.onBeforeMount", error)
    // eslint-disable-next-line @typescript-eslint/restrict-template-expressions
    dataLoadingError.value = `${error}`
  } finally {
    dataLoading.value = false
    progress.value -= 1
  }
})

function resetOnInteraction() {
  // We reset the error on interaction.
  unexpectedError.value = ""
  currentActionCredentialId.value = null
}

async function onRemove(credentialId: string) {
  if (abortController.signal.aborted) {
    return
  }

  resetOnInteraction()

  progress.value += 1
  try {
    currentActionCredentialId.value = credentialId

    const url = router.apiResolve({
      name: "CredentialRemove",
      params: { id: credentialId },
    }).href

    await postJSON(url, {}, abortController.signal, progress)
    if (abortController.signal.aborted) {
      return
    }

    credentials.value = credentials.value.filter((c) => c.id !== credentialId)
    currentActionCredentialId.value = null
  } catch (error) {
    if (abortController.signal.aborted) {
      return
    }
    console.error("CredentialList.onRemove", error)
    // eslint-disable-next-line @typescript-eslint/restrict-template-expressions
    unexpectedError.value = `${error}`
  } finally {
    progress.value -= 1
  }
}

const WithCredentialDocument = WithDocument<CredentialPublic>
</script>

<template>
  <Teleport to="header">
    <NavBar></NavBar>
  </Teleport>
  <div class="mt-12 flex w-full flex-col items-center border-t border-transparent sm:mt-[4.5rem]">
    <div class="m-1 grid auto-rows-auto grid-cols-[minmax(0,65ch)] gap-1 sm:m-4 sm:gap-4">
      <div class="flex w-full flex-col gap-4 rounded-sm border border-gray-200 bg-white p-4 shadow-sm">
        <div class="flex flex-row items-center justify-between gap-4">
          <h1 class="text-2xl font-bold">{{ t("common.entities.credentials") }}</h1>
          <ButtonLink v-if="isSignedIn()" :to="{ name: 'CredentialAdd' }" :progress="progress" primary>{{ t("common.buttons.add") }}</ButtonLink>
        </div>
      </div>
      <div v-if="dataLoading" class="w-full rounded-sm border border-gray-200 bg-white p-4 shadow-sm">{{ t("common.data.dataLoading") }}</div>
      <div v-else-if="dataLoadingError" class="w-full rounded-sm border border-gray-200 bg-white p-4 text-error-600 shadow-sm">{{ t("common.errors.unexpected") }}</div>
      <template v-else>
        <div v-if="!credentials.length" class="w-full rounded-sm border border-gray-200 bg-white p-4 italic shadow-sm">
          {{ isSignedIn() ? t("views.CredentialList.noCredentialsCreate") : t("views.CredentialList.noCredentialsSignIn") }}
        </div>
        <div v-for="credential in credentials" :key="credential.id" class="w-full rounded-sm border border-gray-200 bg-white p-4 shadow-sm">
          <!--
            We use key to force reloading of the credential after we know the credential has been updated (e.g., renamed).
            TODO: Remove this once we will subscribe reactively to updates to the credential document.
          -->
          <WithCredentialDocument :key="`${credential.id}-${refreshKey}`" :params="{ id: credential.id }" name="CredentialGet">
            <template #default="{ doc, url }">
              <CredentialFull :credential="doc" :url="url" :is-renaming="renamingCredentialId === credential.id" @renamed="onRenamed" @canceled="onRenameCancelled">
                <div class="flex flex-row gap-4">
                  <Button v-if="doc.provider === 'email' && !doc.verified" :id="`credentiallist-button-verify-${doc.id}`" type="button" secondary disabled>{{
                    t("views.CredentialList.verify")
                  }}</Button>
                  <!--
                    Button is on purpose not disabled on unexpectedError so that user can retry.
                  -->
                  <Button
                    v-if="canRename(doc.provider)"
                    :id="`credentiallist-button-rename-${doc.id}`"
                    type="button"
                    :progress="progress"
                    @click.prevent="onRename(doc.id)"
                    >{{ t("common.buttons.rename") }}</Button
                  >
                  <Button :id="`credentiallist-button-remove-${doc.id}`" type="button" :progress="progress" @click.prevent="onRemove(doc.id)">{{
                    t("common.buttons.remove")
                  }}</Button>
                </div>
              </CredentialFull>
              <div v-if="currentActionCredentialId === doc.id && unexpectedError" class="mt-4 text-error-600">{{ t("common.errors.unexpected") }}</div>
            </template>
          </WithCredentialDocument>
        </div>
      </template>
    </div>
  </div>
  <Teleport to="footer">
    <Footer />
  </Teleport>
</template>
