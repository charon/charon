<script setup lang="ts">
import type { Ref } from "vue"
import type { AuthFlowChooseIdentityRequest, AuthFlowResponse, Completed, Identities } from "@/types"

import { ref, onBeforeUnmount, onMounted, getCurrentInstance, inject } from "vue"
import { useRouter } from "vue-router"
import Button from "@/components/Button.vue"
import IdentityListItem from "@/partials/IdentityListItem.vue"
import { injectProgress } from "@/progress"
import { getURL, postJSON, restartAuth } from "@/api"
import { flowKey } from "@/flow"
import { encodeQuery, processCompletedAndLocationRedirect } from "@/utils"

const props = defineProps<{
  id: string
  name: string
  completed: Completed
  organizationId: string
}>()

const router = useRouter()

const flow = inject(flowKey)
const progress = injectProgress()

const abortController = new AbortController()
const usedIdentitiesLoading = ref(true)
const usedIdentitiesLoadingError = ref("")
const usedIdentities = ref<Identities>([])
const otherIdentitiesLoading = ref(true)
const otherIdentitiesLoadingError = ref("")
const otherIdentities = ref<Identities>([])

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
  document.getElementById("first-identity")?.focus()

  getIdentities(props.organizationId, false, usedIdentitiesLoading, usedIdentitiesLoadingError, usedIdentities)
  getIdentities(props.organizationId, true, otherIdentitiesLoading, otherIdentitiesLoadingError, otherIdentities)
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
    const q: { notorg?: string, org?: string } = {}
    if (not) {
      q['notorg'] = organizationId
    } else {
      q['org'] = organizationId
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
        id: props.id,
      },
    }).href

    const response = await postJSON<AuthFlowResponse>(url, {
      identity: {
        id,
      },
    } as AuthFlowChooseIdentityRequest, abortController.signal, progress)
    if (abortController.signal.aborted) {
      return
    }
    if (processCompletedAndLocationRedirect(response, flow, progress, abortController)) {
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
    await restartAuth(router, props.id, flow!, abortController, progress)
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
        id: props.id,
      },
    }).href

    const response = await postJSON<AuthFlowResponse>(url, {}, abortController.signal, progress)
    if (abortController.signal.aborted) {
      return
    }
    if (processCompletedAndLocationRedirect(response, flow, progress, abortController)) {
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
</script>

<template>
  <div class="flex flex-col rounded border bg-white p-4 shadow w-full">
    <div class="flex flex-col">
      <div v-if="completed === 'signin'" class="mb-4"><strong>Congratulations.</strong> You successfully signed in into Charon.</div>
      <div v-else-if="completed === 'signup'" class="mb-4"><strong>Congratulations.</strong> You successfully signed up into Charon.</div>
      <div class="mb-4">
        Select the identity you want to continue with. Its information will be provided to the application and the organization. You can also create a new identity or
        decline to proceed.
      </div>
      <h3 class="text-l font-bold mb-4">Previously used identities</h3>
      <div v-if="usedIdentitiesLoading" class="mb-4">Loading...</div>
      <div v-else-if="usedIdentitiesLoadingError" class="mb-4 text-error-600">Unexpected error. Please try again.</div>
      <template v-else>
        <div v-if="!usedIdentities.length" class="italic mb-4">You have not yet used any identity with this organization.</div>
        <template v-for="identity of usedIdentities" :key="identity.id">
          <div class="grid grid-cols-1 gap-4 mb-4">
            <IdentityListItem :item="identity" :organization-id="organizationId">
              <div class="flex flex-col items-start">
                <Button id="first-identity" primary type="button" tabindex="1" :progress="progress" @click.prevent="onSelect(identity.id)">Select</Button>
              </div>
            </IdentityListItem>
          </div>
        </template>
      </template>
      <h3 class="text-l font-bold mb-4">Available identities</h3>
      <div v-if="otherIdentitiesLoading" class="mb-4">Loading...</div>
      <div v-else-if="otherIdentitiesLoadingError" class="mb-4 text-error-600">Unexpected error. Please try again.</div>
      <template v-else>
        <div v-if="!otherIdentities.length" class="italic mb-4">There are no identities. {{ usedIdentities.length + otherIdentities.length === 0 ? "Create the first one." : "Create another one." }}</div>
        <template v-for="identity of otherIdentities" :key="identity.id">
          <div class="grid grid-cols-1 gap-4 mb-4">
            <IdentityListItem :item="identity">
              <div class="flex flex-col items-start">
                <Button id="first-identity" primary type="button" tabindex="1" :progress="progress" @click.prevent="onSelect(identity.id)">Select</Button>
              </div>
            </IdentityListItem>
          </div>
        </template>
      </template>
      <div v-if="unexpectedError" class="mb-4 text-error-600">Unexpected error. Please try again.</div>
      <div class="flex flex-row justify-between gap-4">
        <Button type="button" tabindex="4" @click.prevent="onBack">Back</Button>
        <div class="flex flex-row gap-4">
          <Button type="button" tabindex="2" :progress="progress" @click.prevent="onDecline">Decline</Button>
          <Button type="button" tabindex="3" :progress="progress" @click.prevent="onDecline">Create</Button>
        </div>
      </div>
    </div>
  </div>
</template>
