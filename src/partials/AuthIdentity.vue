<script setup lang="ts">
import type { DeepReadonly } from "vue"
import type { AllIdentity, AuthFlowChooseIdentityRequest, AuthFlowResponse, Flow, Identities, Identity, IdentityRef } from "@/types"

import { ref, onBeforeUnmount, onMounted, getCurrentInstance, computed } from "vue"
import { useI18n } from "vue-i18n"
import { useRouter } from "vue-router"
import Button from "@/components/Button.vue"
import IdentityPublic from "@/partials/IdentityPublic.vue"
import IdentityCreate from "@/partials/IdentityCreate.vue"
import { injectProgress } from "@/progress"
import { getURL, postJSON, restartAuth } from "@/api"
import { clone, encodeQuery, getOrganization } from "@/utils"
import { processResponse } from "@/flow"

const { t } = useI18n({ useScope: "global" })

const props = defineProps<{
  flow: Flow
}>()

const router = useRouter()

const progress = injectProgress()

const abortController = new AbortController()
const allIdentitiesLoading = ref(true)
const allIdentitiesLoadingError = ref("")
const allIdentities = ref<AllIdentity[]>([])
const createShown = ref(false)

const unexpectedError = ref("")

const usedIdentities = computed(() => {
  const identities: AllIdentity[] = []
  for (const allIdentity of allIdentities.value) {
    const identityOrganization = getOrganization(allIdentity.identity, props.flow.getOrganizationId())
    if (identityOrganization !== null && identityOrganization.active && identityOrganization.applications.find((a) => a.id === props.flow.getAppId())) {
      identities.push(allIdentity)
    }
  }
  return identities
})
const addedIdentities = computed(() => {
  const identities: AllIdentity[] = []
  for (const allIdentity of allIdentities.value) {
    const identityOrganization = getOrganization(allIdentity.identity, props.flow.getOrganizationId())
    // If identity is not already in the organization using the app,
    // then admin access is required to be able to add the app first.
    if (
      identityOrganization !== null &&
      identityOrganization.active &&
      !identityOrganization.applications.find((a) => a.id === props.flow.getAppId()) &&
      allIdentity.canUpdate
    ) {
      identities.push(allIdentity)
    }
  }
  return identities
})
const otherIdentities = computed(() => {
  const identities: AllIdentity[] = []
  for (const allIdentity of allIdentities.value) {
    const identityOrganization = getOrganization(allIdentity.identity, props.flow.getOrganizationId())
    // If identity is not already in the organization, then admin access is
    // required to be able to join the organization first.
    if (identityOrganization === null && allIdentity.canUpdate) {
      identities.push(allIdentity)
    }
  }
  return identities
})
const disabledIdentities = computed(() => {
  const identities: AllIdentity[] = []
  for (const allIdentity of allIdentities.value) {
    const identityOrganization = getOrganization(allIdentity.identity, props.flow.getOrganizationId())
    // If identity is not active in the organization, then admin access is
    // required to be able to enable it in the organization first.
    if (identityOrganization !== null && !identityOrganization.active && allIdentity.canUpdate) {
      identities.push(allIdentity)
    }
  }
  return identities
})

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

async function onAfterEnter() {
  await getIdentities()

  document.getElementById("first-identity")?.focus()
}

function onBeforeLeave() {
  abortController.abort()
}

async function getIdentities() {
  if (abortController.signal.aborted) {
    return false
  }

  progress.value += 1
  try {
    const updatedAllIdentities: AllIdentity[] = []

    const url = router.apiResolve({
      name: "IdentityList",
      query: encodeQuery({
        flow: props.flow.getId(),
      }),
    }).href

    const resp = await getURL<Identities>(url, null, abortController.signal, progress)
    if (abortController.signal.aborted) {
      return
    }

    for (const identity of resp.doc) {
      const identityURL = router.apiResolve({
        name: "IdentityGet",
        params: {
          id: identity.id,
        },
        query: encodeQuery({
          flow: props.flow.getId(),
        }),
      }).href

      const resp = await getURL<Identity>(identityURL, null, abortController.signal, progress)
      if (abortController.signal.aborted) {
        return
      }

      updatedAllIdentities.push({
        identity: resp.doc,
        url: identityURL,
        isCurrent: !!resp.metadata.is_current,
        canUpdate: !!resp.metadata.can_update,
      })
    }

    allIdentities.value = updatedAllIdentities
  } catch (error) {
    if (abortController.signal.aborted) {
      return
    }
    console.error("IdentityList.getIdentities", error)
    allIdentitiesLoadingError.value = `${error}`
  } finally {
    // We toggle allIdentitiesLoading only the first time.
    allIdentitiesLoading.value = false
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

async function onIdentityCreated(identity: IdentityRef) {
  createShown.value = false

  // TODO: Fetch only the new identity instead of re-fetching all.
  await getIdentities()

  // TODO: Focus "select" button for the new identity.
}

async function onEnable(identity: Identity | DeepReadonly<Identity>) {
  if (abortController.signal.aborted) {
    return
  }

  resetOnInteraction()

  progress.value += 1
  try {
    const payload = clone(identity)

    const identityOrganization = getOrganization(payload, props.flow.getOrganizationId())
    if (identityOrganization) {
      identityOrganization.active = true

      const url = router.apiResolve({
        name: "IdentityUpdate",
        params: {
          id: payload.id,
        },
        query: encodeQuery({
          flow: props.flow.getId(),
        }),
      }).href

      await postJSON<Identity>(url, payload, abortController.signal, progress)
      if (abortController.signal.aborted) {
        return
      }
    }

    // TODO: Fetch only the updated identity instead of re-fetching all.
    await getIdentities()

    // TODO: Focus "select" button for the enabled identity.
  } catch (error) {
    if (abortController.signal.aborted) {
      return
    }
    console.error("AuthIdentity.onEnable", error)
    unexpectedError.value = `${error}`
  } finally {
    progress.value -= 1
  }
}
</script>

<template>
  <div class="flex flex-col rounded border bg-white p-4 shadow w-full">
    <div class="flex flex-col">
      <div v-if="flow.getCompleted().includes('signin')" class="mb-4">
        <i18n-t keypath="partials.AuthIdentity.signinSuccess" scope="global">
          <template #strongCongratulations
            ><strong>{{ t("common.messages.congratulations") }}</strong></template
          >
        </i18n-t>
      </div>
      <div v-else-if="flow.getCompleted().includes('signup')" class="mb-4">
        <i18n-t keypath="partials.AuthIdentity.signupSuccess" scope="global">
          <template #strongCongratulations
            ><strong>{{ t("common.messages.congratulations") }}</strong></template
          >
        </i18n-t>
      </div>
      <div class="mb-4">
        {{ t("partials.AuthIdentity.selectInstructions") }}
      </div>
      <div v-if="allIdentitiesLoading" class="mb-4">{{ t("common.data.dataLoading") }}</div>
      <div v-else-if="allIdentitiesLoadingError" class="mb-4 text-error-600">{{ t("common.errors.unexpected") }}</div>
      <template v-else>
        <h3 class="text-l font-bold mb-4">{{ t("partials.AuthIdentity.previouslyUsedIdentities") }}</h3>
        <div v-if="usedIdentities.length + addedIdentities.length + disabledIdentities.length === 0" class="italic mb-4">
          {{ t("partials.AuthIdentity.noIdentityUsed") }}
        </div>
        <div v-else-if="usedIdentities.length + disabledIdentities.length === 0" class="italic mb-4">
          {{ t("partials.AuthIdentity.noIdentityUsedWithApp") }}
        </div>
        <div v-else-if="usedIdentities.length + addedIdentities.length === 0" class="italic mb-4">
          {{ t("partials.AuthIdentity.allPreviousDisabled") }}
        </div>
        <div v-else-if="usedIdentities.length === 0" class="italic mb-4">{{ t("partials.AuthIdentity.previouslyUsedDisabled") }}</div>
        <ul v-else>
          <li v-for="(identity, i) of usedIdentities" :key="identity.identity.id" class="mb-4">
            <IdentityPublic :identity="identity.identity" :url="identity.url" :is-current="identity.isCurrent" :can-update="identity.canUpdate">
              <div class="flex flex-col items-start">
                <Button :id="i === 0 ? 'first-identity' : null" primary type="button" tabindex="1" :progress="progress" @click.prevent="onSelect(identity.identity.id)">{{
                  t("common.buttons.select")
                }}</Button>
              </div>
            </IdentityPublic>
          </li>
        </ul>
        <template v-if="addedIdentities.length">
          <h3 class="text-l font-bold mb-4">{{ t("partials.AuthIdentity.identitiesUsedWithOrg") }}</h3>
          <ul>
            <li v-for="(identity, i) of addedIdentities" :key="identity.identity.id" class="mb-4">
              <IdentityPublic :identity="identity.identity" :url="identity.url" :is-current="identity.isCurrent" :can-update="identity.canUpdate">
                <div class="flex flex-col items-start">
                  <Button
                    :id="usedIdentities.length + i === 0 ? 'first-identity' : null"
                    primary
                    type="button"
                    tabindex="1"
                    :progress="progress"
                    @click.prevent="onSelect(identity.identity.id)"
                    >{{ t("common.buttons.select") }}</Button
                  >
                </div>
              </IdentityPublic>
            </li>
          </ul>
        </template>
        <h3 class="text-l font-bold mb-4">{{ t("partials.AuthIdentity.otherAvailableIdentities") }}</h3>
        <div v-if="usedIdentities.length + addedIdentities.length + otherIdentities.length + disabledIdentities.length === 0" class="italic mb-4">
          {{ t("partials.AuthIdentity.noIdentitiesCreateFirst") }}
        </div>
        <div v-else-if="otherIdentities.length === 0" class="italic mb-4">{{ t("partials.AuthIdentity.noOtherIdentitiesCreateOne") }}</div>
        <ul v-else>
          <li v-for="(identity, i) of otherIdentities" :key="identity.identity.id" class="mb-4">
            <IdentityPublic :identity="identity.identity" :url="identity.url" :is-current="identity.isCurrent" :can-update="identity.canUpdate">
              <div class="flex flex-col items-start">
                <Button
                  :id="usedIdentities.length + addedIdentities.length + i === 0 ? 'first-identity' : null"
                  primary
                  type="button"
                  tabindex="2"
                  :progress="progress"
                  @click.prevent="onSelect(identity.identity.id)"
                  >{{ t("common.buttons.select") }}</Button
                >
              </div>
            </IdentityPublic>
          </li>
        </ul>
        <template v-if="disabledIdentities.length">
          <h3 class="text-l font-bold mb-4">{{ t("partials.AuthIdentity.disabledIdentities") }}</h3>
          <ul>
            <li v-for="identity of disabledIdentities" :key="identity.identity.id" class="mb-4">
              <IdentityPublic
                :identity="identity.identity"
                :url="identity.url"
                :is-current="identity.isCurrent"
                :can-update="identity.canUpdate"
                :labels="[t('common.labels.disabled')]"
              >
                <div class="flex flex-col items-start">
                  <Button primary type="button" tabindex="3" :progress="progress" @click.prevent="onEnable(identity.identity)">{{ t("common.buttons.enable") }}</Button>
                </div>
              </IdentityPublic>
            </li>
          </ul>
        </template>
      </template>
      <div v-if="!createShown" class="flex flex-row justify-start gap-4 mb-4">
        <Button type="button" tabindex="3" :progress="progress" @click.prevent="onCreateShow">{{ t("partials.AuthIdentity.newIdentityButton") }}</Button>
      </div>
      <template v-if="createShown">
        <h3 class="text-l font-bold mb-4">{{ t("partials.AuthIdentity.createNewIdentity") }}</h3>
        <IdentityCreate class="mb-4" :flow-id="flow.getId()" @created="onIdentityCreated" />
      </template>
      <div v-if="unexpectedError" class="mb-4 text-error-600">{{ t("common.errors.unexpected") }}</div>
      <div class="flex flex-row justify-between gap-4">
        <Button type="button" tabindex="5" @click.prevent="onBack">{{ t("common.buttons.back") }}</Button>
        <Button type="button" tabindex="4" :progress="progress" @click.prevent="onDecline">{{ t("common.buttons.decline") }}</Button>
      </div>
    </div>
  </div>
</template>
