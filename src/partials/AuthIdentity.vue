<script setup lang="ts">
import type { Ref } from "vue"
import type { AuthFlowChooseIdentityRequest, AuthFlowResponse, Flow, Identities, IdentityRef } from "@/types"

import { ref, onBeforeUnmount, onMounted, getCurrentInstance } from "vue"
import { useRouter } from "vue-router"
import Button from "@/components/Button.vue"
import IdentityListItem from "@/partials/IdentityListItem.vue"
import IdentityCreate from "@/partials/IdentityCreate.vue"
import { injectProgress } from "@/progress"
import { getURL, postJSON, restartAuth } from "@/api"
import { encodeQuery } from "@/utils"
import { processResponse } from "@/flow"

const props = defineProps<{
  flow: Flow
}>()

const router = useRouter()

const progress = injectProgress()

const abortController = new AbortController()
const usedIdentitiesLoading = ref(true)
const usedIdentitiesLoadingError = ref("")
const usedIdentities = ref<Identities>([])
const otherIdentitiesLoading = ref(true)
const otherIdentitiesLoadingError = ref("")
const otherIdentities = ref<Identities>([])
const createShown = ref(false)

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
  // TODO: Make this work. This is too early because data is not yet loaded so there is nothing to focus.
  document.getElementById("first-identity")?.focus()

  getIdentities(props.flow.getOrganizationId(), false, usedIdentitiesLoading, usedIdentitiesLoadingError, usedIdentities)
  getIdentities(props.flow.getOrganizationId(), true, otherIdentitiesLoading, otherIdentitiesLoadingError, otherIdentities)
}

function onBeforeLeave() {
  abortController.abort()
}

async function getIdentities(organizationId: string, not: boolean, loading: Ref<boolean>, loadingError: Ref<string>, identities: Ref<Identities>) {
  if (abortController.signal.aborted) {
    return false
  }

  progress.value += 1
  try {
    const q: { flow: string; active: string; notorg?: string; org?: string } = {
      flow: props.flow.getId(),
      active: "true",
    }
    if (not) {
      q["notorg"] = organizationId
    } else {
      q["org"] = organizationId
    }
    const url = router.apiResolve({
      name: "IdentityList",
      query: encodeQuery(q),
    }).href

    const response = await getURL<Identities>(url, null, abortController.signal, progress)
    if (abortController.signal.aborted) {
      return
    }

    identities.value = response.doc
  } catch (error) {
    if (abortController.signal.aborted) {
      return
    }
    console.error("IdentityList.getIdentities", error)
    loadingError.value = `${error}`
  } finally {
    loading.value = false
    progress.value -= 1
  }
}

async function onSelect(id: string) {
  if (abortController.signal.aborted) {
    return
  }

  resetOnInteraction()

  progress.value += 1
  try {
    const url = router.apiResolve({
      name: "AuthFlowChooseIdentity",
      params: {
        id: props.flow.getId(),
      },
    }).href

    const response = await postJSON<AuthFlowResponse>(
      url,
      {
        identity: {
          id,
        },
      } as AuthFlowChooseIdentityRequest,
      abortController.signal,
      progress,
    )
    if (abortController.signal.aborted) {
      return
    }
    // processResponse should move the flow to the next step.
    if (processResponse(router, response, props.flow, progress, abortController)) {
      return
    }
    throw new Error("unexpected response")
  } catch (error) {
    if (abortController.signal.aborted) {
      return
    }
    console.error("AuthIdentity.onNext", error)
    unexpectedError.value = `${error}`
  } finally {
    progress.value -= 1
  }
}

async function onBack() {
  if (abortController.signal.aborted) {
    return
  }

  resetOnInteraction()

  progress.value += 1
  try {
    // restartAuth calls abortController.abort so we do not have to do it here.
    await restartAuth(router, props.flow, abortController, progress)
  } catch (error) {
    if (abortController.signal.aborted) {
      return
    }
    console.error("AuthIdentity.onBack", error)
    unexpectedError.value = `${error}`
  } finally {
    progress.value -= 1
  }
}

async function onDecline() {
  if (abortController.signal.aborted) {
    return
  }

  resetOnInteraction()

  progress.value += 1
  try {
    const url = router.apiResolve({
      name: "AuthFlowDecline",
      params: {
        id: props.flow.getId(),
      },
    }).href

    const response = await postJSON<AuthFlowResponse>(url, {}, abortController.signal, progress)
    if (abortController.signal.aborted) {
      return
    }
    // processResponse should move the flow to the next step.
    if (processResponse(router, response, props.flow, progress, abortController)) {
      return
    }
    throw new Error("unexpected response")
  } catch (error) {
    if (abortController.signal.aborted) {
      return
    }
    console.error("AuthIdentity.onDecline", error)
    unexpectedError.value = `${error}`
  } finally {
    progress.value -= 1
  }
}

function onCreateShow() {
  createShown.value = true
}

function onIdentityCreated(identity: IdentityRef) {
  createShown.value = false
  getIdentities(props.flow.getOrganizationId(), true, otherIdentitiesLoading, otherIdentitiesLoadingError, otherIdentities)

  // TODO: Focus "select" button for the new identity.
}
</script>

<template>
  <div class="flex flex-col rounded border bg-white p-4 shadow w-full">
    <div class="flex flex-col">
      <div v-if="flow.getCompleted().includes('signin')" class="mb-4"><strong>Congratulations.</strong> You successfully signed in into Charon.</div>
      <div v-else-if="flow.getCompleted().includes('signup')" class="mb-4"><strong>Congratulations.</strong> You successfully signed up into Charon.</div>
      <div class="mb-4">
        Select the identity you want to continue with. Its information will be provided to the application and the organization. You can also create a new identity or
        decline to proceed.
      </div>
      <h3 class="text-l font-bold mb-4">Previously used identities</h3>
      <div v-if="usedIdentitiesLoading" class="mb-4">Loading...</div>
      <div v-else-if="usedIdentitiesLoadingError" class="mb-4 text-error-600">Unexpected error. Please try again.</div>
      <template v-else>
        <div v-if="!usedIdentities.length" class="italic mb-4">You have not yet used any (active) identity with this organization.</div>
        <template v-for="(identity, i) of usedIdentities" :key="identity.id">
          <div class="grid grid-cols-1 gap-4 mb-4">
            <IdentityListItem :item="identity" :organization-id="flow.getOrganizationId()" :flow-id="flow.getId()">
              <div class="flex flex-col items-start">
                <Button :id="i === 0 ? 'first-identity' : null" primary type="button" tabindex="1" :progress="progress" @click.prevent="onSelect(identity.id)"
                  >Select</Button
                >
              </div>
            </IdentityListItem>
          </div>
        </template>
      </template>
      <h3 class="text-l font-bold mb-4">Other available identities</h3>
      <div v-if="otherIdentitiesLoading" class="mb-4">Loading...</div>
      <div v-else-if="otherIdentitiesLoadingError" class="mb-4 text-error-600">Unexpected error. Please try again.</div>
      <template v-else>
        <div v-if="usedIdentities.length + otherIdentities.length === 0" class="italic mb-4">There are no (active) identities. Create the first one.</div>
        <div v-else-if="otherIdentities.length === 0" class="italic mb-4">There are no other (active) identities. Create one.</div>
        <template v-for="(identity, i) of otherIdentities" :key="identity.id">
          <div class="grid grid-cols-1 gap-4 mb-4">
            <IdentityListItem :item="identity" :flow-id="flow.getId()">
              <div class="flex flex-col items-start">
                <Button
                  :id="usedIdentities.length + i === 0 ? 'first-identity' : null"
                  primary
                  type="button"
                  tabindex="2"
                  :progress="progress"
                  @click.prevent="onSelect(identity.id)"
                  >Select</Button
                >
              </div>
            </IdentityListItem>
          </div>
        </template>
      </template>
      <div v-if="!createShown" class="flex flex-row justify-start gap-4 mb-4">
        <Button type="button" tabindex="3" :progress="progress" @click.prevent="onCreateShow">Create new identity</Button>
      </div>
      <template v-if="createShown">
        <h3 class="text-l font-bold mb-4">Create new identity</h3>
        <IdentityCreate class="mb-4" :flow-id="flow.getId()" @created="onIdentityCreated" />
      </template>
      <div v-if="unexpectedError" class="mb-4 text-error-600">Unexpected error. Please try again.</div>
      <div class="flex flex-row justify-between gap-4">
        <Button type="button" tabindex="5" @click.prevent="onBack">Back</Button>
        <Button type="button" tabindex="4" :progress="progress" @click.prevent="onDecline">Decline</Button>
      </div>
    </div>
  </div>
</template>
