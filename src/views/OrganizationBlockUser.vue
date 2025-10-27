<script setup lang="ts">
import type { BlockedIdentityType, IdentityForAdmin, OrganizationBlockRequest } from "@/types"

import { onBeforeUnmount, ref, watch } from "vue"
import { useI18n } from "vue-i18n"
import { useRouter } from "vue-router"

import { postJSON } from "@/api"
import Button from "@/components/Button.vue"
import RadioButton from "@/components/RadioButton.vue"
import TextArea from "@/components/TextArea.vue"
import WithDocument from "@/components/WithDocument.vue"
import Footer from "@/partials/Footer.vue"
import IdentityPublic from "@/partials/IdentityPublic.vue"
import NavBar from "@/partials/NavBar.vue"
import OrganizationListItem from "@/partials/OrganizationListItem.vue"
import { injectProgress } from "@/progress"

const props = defineProps<{
  id: string
  identityId: string
}>()

const { t } = useI18n({ useScope: "global" })
const router = useRouter()
const progress = injectProgress()

const abortController = new AbortController()
const blockType = ref<BlockedIdentityType>("onlyIdentity")
const organizationNote = ref("")
const userNote = ref("")
const unexpectedError = ref("")
const success = ref(false)

function resetOnInteraction() {
  // We reset flags and errors on interaction.
  unexpectedError.value = ""
  success.value = false
}

watch([blockType, organizationNote, userNote], resetOnInteraction)

onBeforeUnmount(() => {
  abortController.abort()
})

async function onSubmit() {
  if (abortController.signal.aborted) {
    return
  }

  resetOnInteraction()

  progress.value += 1
  try {
    const payload: OrganizationBlockRequest = {
      type: blockType.value,
      organizationNote: organizationNote.value,
      userNote: userNote.value,
    }
    const url = router.apiResolve({
      name: "OrganizationBlockUser",
      params: {
        id: props.id,
        identityId: props.identityId,
      },
    }).href

    await postJSON(url, payload, abortController.signal, progress)
    if (abortController.signal.aborted) {
      return
    }

    success.value = true
  } catch (error) {
    if (abortController.signal.aborted) {
      return
    }
    console.error("OrganizationBlockUser.onSubmit", error)
    unexpectedError.value = `${error}`
  } finally {
    progress.value -= 1
  }
}

const WithIdentityForAdminDocument = WithDocument<IdentityForAdmin>
</script>

<template>
  <Teleport to="header">
    <NavBar></NavBar>
  </Teleport>
  <div class="mt-12 flex w-full flex-col items-center border-t border-transparent sm:mt-[4.5rem]">
    <div class="m-1 grid auto-rows-auto grid-cols-[minmax(0,_65ch)] gap-1 sm:m-4 sm:gap-4">
      <div class="w-full rounded-xs border border-gray-200 bg-white p-4 shadow-sm">
        <div class="flex flex-col gap-4">
          <h1 class="text-2xl font-bold">{{ t("views.OrganizationBlockUser.blockUser") }}</h1>
          <div>
            <OrganizationListItem :item="{ id }" />
          </div>
        </div>
      </div>
      <div class="w-full rounded-xs border border-gray-200 bg-white p-4 shadow-sm">
        <WithIdentityForAdminDocument :params="{ id, identityId }" name="OrganizationIdentity">
          <template #default="{ doc, metadata, url }">
            <IdentityPublic :identity="doc" :url="url" :is-current="metadata.is_current" :can-update="metadata.can_update" />
          </template>
        </WithIdentityForAdminDocument>
      </div>
      <div v-if="success" class="w-full rounded-xs border border-gray-200 bg-white p-4 shadow-sm">
        <div class="text-success-600">{{ t("views.OrganizationBlockUser.blockingSuccess") }}</div>
      </div>
      <div v-else class="w-full rounded-xs border border-gray-200 bg-white p-4 shadow-sm">
        <form class="flex flex-col" novalidate @submit.prevent="onSubmit">
          <p>{{ t("views.OrganizationBlockUser.blockConfirmation") }}</p>
          <fieldset class="mt-4">
            <legend class="mb-1">{{ t("views.OrganizationBlockUser.blockType") }}</legend>
            <div class="flex flex-col gap-1">
              <div>
                <RadioButton id="blockType-onlyIdentity" v-model="blockType" value="onlyIdentity" :progress="progress" class="mx-2" />
                <label for="blockType-onlyIdentity" :class="progress > 0 ? 'cursor-not-allowed text-gray-600' : 'cursor-pointer'">{{
                  t("views.OrganizationBlockUser.blockOnlyIdentity")
                }}</label>
              </div>
              <div>
                <RadioButton id="blockType-identityAndAccounts" v-model="blockType" value="identityAndAccounts" :progress="progress" class="mx-2" />
                <label for="blockType-identityAndAccounts" :class="progress > 0 ? 'cursor-not-allowed text-gray-600' : 'cursor-pointer'">{{
                  t("views.OrganizationBlockUser.blockIdentityAndAccounts")
                }}</label>
              </div>
            </div>
          </fieldset>
          <label for="organizationNote" class="mt-4 mb-1"
            >{{ t("views.OrganizationBlockUser.organizationNote") }} <span class="text-sm text-neutral-500 italic">{{ t("common.labels.optional") }}</span></label
          >
          <TextArea id="organizationNote" v-model="organizationNote" class="min-w-0 flex-auto grow" :progress="progress" />
          <label for="userNote" class="mt-4 mb-1"
            >{{ t("views.OrganizationBlockUser.userNote") }} <span class="text-sm text-neutral-500 italic">{{ t("common.labels.optional") }}</span></label
          >
          <TextArea id="userNote" v-model="userNote" class="min-w-0 flex-auto grow" :progress="progress" />
          <div v-if="unexpectedError" class="mt-4 text-error-600">{{ t("common.errors.unexpected") }}</div>
          <div class="mt-4 flex flex-row justify-end">
            <!--
              Button is on purpose not disabled on unexpectedError so that user can retry.
            -->
            <Button type="submit" primary :progress="progress">{{ t("common.buttons.block") }}</Button>
          </div>
        </form>
      </div>
    </div>
  </div>
  <Teleport to="footer">
    <Footer />
  </Teleport>
</template>
