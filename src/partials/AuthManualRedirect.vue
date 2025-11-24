<script setup lang="ts">
import type { ComponentExposed } from "vue-component-type-helpers"

import type { Flow, OrganizationApplicationPublic } from "@/types"

import { getCurrentInstance, onBeforeUnmount, onMounted, ref } from "vue"
import { useI18n } from "vue-i18n"
import { useRouter } from "vue-router"

import { redirectThirdPartyProvider } from "@/api"
import Button from "@/components/Button.vue"
import WithDocument from "@/components/WithDocument.vue"
import { injectProgress } from "@/progress"
import { getHomepage, redirectServerSide } from "@/utils"

const props = defineProps<{
  flow: Flow
}>()

const { t } = useI18n({ useScope: "global" })
const router = useRouter()
const progress = injectProgress()

const abortController = new AbortController()
const unexpectedError = ref("")

function resetOnInteraction() {
  // We reset the error on interaction.
  unexpectedError.value = ""
}

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

onBeforeUnmount(onBeforeLeave)

function onAfterEnter() {
  document.getElementById("redirect")?.focus()
}

function onBeforeLeave() {
  abortController.abort()
}

async function onRedirect() {
  if (abortController.signal.aborted) {
    return
  }

  resetOnInteraction()

  if (props.flow.getCompleted().includes("failed")) {
    await doRedirectThirdPartyProvider()
  } else if (props.flow.getCompleted().includes("finished")) {
    // When flow is already finished, we can redirect just to the home page
    // because the original third party provider flow has already been completed.
    doRedirectHomepage()
  } else {
    // Should not happen as defined in processCompleted.
    throw new Error(`unexpected completed: ${props.flow.getCompleted().join(", ")}`)
  }
}

async function doRedirectThirdPartyProvider() {
  try {
    await redirectThirdPartyProvider(router, props.flow, abortController, progress)
  } catch (error) {
    if (abortController.signal.aborted) {
      return
    }
    console.error("AuthManualRedirect.doRedirectThirdPartyProvider", error)
    // eslint-disable-next-line @typescript-eslint/restrict-template-expressions
    unexpectedError.value = `${error}`
  }
}

function doRedirectHomepage() {
  // eslint-disable-next-line @typescript-eslint/no-unnecessary-type-assertion
  redirectServerSide(getHomepage(withOrganizationApplicationDocument.value!.doc!), true, progress)
}

const WithOrganizationApplicationDocument = WithDocument<OrganizationApplicationPublic>
const withOrganizationApplicationDocument = ref<ComponentExposed<typeof WithOrganizationApplicationDocument> | null>(null)
</script>

<template>
  <div class="flex w-full flex-col rounded-sm border border-gray-200 bg-white p-4 shadow-sm">
    <WithOrganizationApplicationDocument
      ref="withOrganizationApplicationDocument"
      :params="{ id: flow.getOrganizationId(), appId: flow.getAppId() }"
      name="OrganizationApp"
    >
      <template #default="{ doc }">
        <template v-if="flow.getCompleted().includes('failed')">
          <div class="mb-4 text-error-600">
            <i18n-t keypath="partials.AuthManualRedirect.failed" scope="global">
              <template #strongSorry
                ><strong>{{ t("common.messages.sorry") }}</strong></template
              >
            </i18n-t>
          </div>
          <div class="mb-4">{{ t("partials.AuthManualRedirect.tryAgain", { appName: doc.applicationTemplate.name }) }}</div>
        </template>
        <div v-else-if="flow.getCompleted().includes('finished')" class="mb-4">{{ t("partials.AuthManualRedirect.completed", { appName: doc.applicationTemplate.name }) }}</div>
        <div v-if="unexpectedError" class="mb-4 text-error-600">{{ t("common.errors.unexpected") }}</div>
        <div class="flex flex-row justify-end gap-4">
          <Button id="redirect" primary type="button" tabindex="1" :progress="progress" @click.prevent="onRedirect">{{
            flow.getCompleted().includes("finished") ? t("partials.AuthManualRedirect.homepage") : t("partials.AuthManualRedirect.return")
          }}</Button>
        </div>
      </template>
    </WithOrganizationApplicationDocument>
  </div>
</template>
