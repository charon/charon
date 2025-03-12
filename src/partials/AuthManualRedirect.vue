<script setup lang="ts">
import type { Flow, OrganizationApplicationPublic } from "@/types"
import type { ComponentExposed } from "vue-component-type-helpers"

import { ref, onBeforeUnmount, onMounted, getCurrentInstance } from "vue"
import { useRouter } from "vue-router"
import WithDocument from "@/components/WithDocument.vue"
import Button from "@/components/Button.vue"
import { injectProgress } from "@/progress"
import { getHomepage, redirectServerSide } from "@/utils"
import { redirectOIDC } from "@/api"

const props = defineProps<{
  flow: Flow
}>()

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
    await doRedirectOIDC()
  } else if (props.flow.getCompleted().includes("finished")) {
    // When flow is already finished, we can redirect just to the home page
    // because the original OIDC flow has already been completed.
    await doRedirectHomepage()
  } else {
    // Should not happen as defined in processCompleted.
    throw new Error(`unexpected completed: ${props.flow.getCompleted()}`)
  }
}

async function doRedirectOIDC() {
  try {
    await redirectOIDC(router, props.flow, abortController, progress)
  } catch (error) {
    if (abortController.signal.aborted) {
      return
    }
    console.error("AuthManualRedirect.doRedirectOIDC", error)
    unexpectedError.value = `${error}`
  }
}

async function doRedirectHomepage() {
  redirectServerSide(getHomepage(withOrganizationApplicationDocument.value!.doc!), true, progress)
}

const WithOrganizationApplicationDocument = WithDocument<OrganizationApplicationPublic>
const withOrganizationApplicationDocument = ref<ComponentExposed<typeof WithOrganizationApplicationDocument> | null>(null)
</script>

<template>
  <div class="flex flex-col rounded border bg-white p-4 shadow w-full">
    <WithOrganizationApplicationDocument
      ref="withOrganizationApplicationDocument"
      :params="{ id: flow.getOrganizationId(), appId: flow.getAppId() }"
      name="OrganizationAppGet"
    >
      <template #default="{ doc }">
        <template v-if="flow.getCompleted().includes('failed')">
          <div class="text-error-600 mb-4"><strong>Sorry.</strong> Signing in or signing up failed.</div>
          <div class="mb-4">You can return to {{ doc.applicationTemplate.name }} and try again.</div>
        </template>
        <div v-else-if="flow.getCompleted().includes('finished')" class="mb-4">
          You have already been redirected to {{ doc.applicationTemplate.name }} and completed the flow. You can now instead go to its homepage.
        </div>
        <div v-if="unexpectedError" class="mb-4 text-error-600">Unexpected error. Please try again.</div>
        <div class="flex flex-row justify-end gap-4">
          <Button id="redirect" primary type="button" tabindex="1" :progress="progress" @click.prevent="onRedirect">{{
            flow.getCompleted().includes("finished") ? "Homepage" : "Return"
          }}</Button>
        </div>
      </template>
    </WithOrganizationApplicationDocument>
  </div>
</template>
