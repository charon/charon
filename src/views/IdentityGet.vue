<script setup lang="ts">
import type { Ref } from "vue"
import type { Identity, IdentityOrganization, Metadata, OrganizationRef, Organizations } from "@/types"

import { computed, nextTick, onBeforeMount, onBeforeUnmount, ref, watch } from "vue"
import { useRouter } from "vue-router"
import InputText from "@/components/InputText.vue"
import TextArea from "@/components/TextArea.vue"
import Button from "@/components/Button.vue"
import OrganizationListItem from "@/partials/OrganizationListItem.vue"
import NavBar from "@/partials/NavBar.vue"
import Footer from "@/partials/Footer.vue"
import { getURL, postJSON } from "@/api"
import { injectProgress } from "@/progress"
import { clone, equals } from "@/utils"

const props = defineProps<{
  id: string
}>()

const router = useRouter()

const progress = injectProgress()

const abortController = new AbortController()
const dataLoading = ref(true)
const dataLoadingError = ref("")
const identity = ref<Identity | null>(null)
const metadata = ref<Metadata>({})
const organizations = ref<Organizations>([])

const basicUnexpectedError = ref("")
const basicUpdated = ref(false)
const username = ref("")
const email = ref("")
const givenName = ref("")
const fullName = ref("")
const pictureUrl = ref("")
const description = ref("")

const identityOrganizationsUnexpectedError = ref("")
const identityOrganizationsUpdated = ref(false)
const identityOrganizations = ref<IdentityOrganization[]>([])

const availableOrganizations = computed(() => {
  return organizations.value.filter((organization) => !isOrganizationAdded(organization))
})

function isOrganizationAdded(organization: OrganizationRef): boolean {
  for (const identityOrganization of identityOrganizations.value) {
    if (identityOrganization.organization.id === organization.id) {
      return true
    }
  }
  return false
}

function resetOnInteraction() {
  // We reset flags and errors on interaction.
  basicUnexpectedError.value = ""
  basicUpdated.value = false
  identityOrganizationsUnexpectedError.value = ""
  identityOrganizationsUpdated.value = false
  // dataLoading and dataLoadingError are not listed here on
  // purpose because they are used only on mount.
}

let watchInteractionStop: (() => void) | null = null
function initWatchInteraction() {
  if (abortController.signal.aborted) {
    return
  }

  const stop = watch([username, email, givenName, fullName, pictureUrl, description, identityOrganizations], resetOnInteraction, { deep: true })
  if (watchInteractionStop !== null) {
    throw new Error("watchInteractionStop already set")
  }
  watchInteractionStop = () => {
    watchInteractionStop = null
    stop()
  }
}
initWatchInteraction()

onBeforeUnmount(() => {
  abortController.abort()
})

async function loadData(update: "init" | "basic" | "organizations" | null, dataError: Ref<string> | null) {
  if (abortController.signal.aborted) {
    return
  }

  watchInteractionStop!()
  progress.value += 1
  try {
    const identityURL = router.apiResolve({
      name: "IdentityGet",
      params: {
        id: props.id,
      },
    }).href

    const response = await getURL<Identity>(identityURL, null, abortController.signal, progress)
    if (abortController.signal.aborted) {
      return
    }

    identity.value = response.doc
    metadata.value = response.metadata

    // We have to make copies so that we break reactivity link with data.doc.
    if (update === "init" || update === "basic") {
      username.value = response.doc.username || ""
      email.value = response.doc.email || ""
      givenName.value = response.doc.givenName || ""
      fullName.value = response.doc.fullName || ""
      pictureUrl.value = response.doc.pictureUrl || ""
      description.value = response.doc.description || ""
    }
    if (update == "init" || update === "organizations") {
      identityOrganizations.value = clone(response.doc.organizations || [])
    }

    if (update === "init") {
      const organizationsURL = router.apiResolve({
        name: "OrganizationList",
      }).href

      const resp = await getURL<Organizations>(organizationsURL, null, abortController.signal, progress)
      if (abortController.signal.aborted) {
        return
      }

      organizations.value = resp.doc
    }
  } catch (error) {
    if (abortController.signal.aborted) {
      return
    }
    // TODO: 404 should be shown differently, but probably in the same way for all 404.
    console.error("IdentityGet.loadData", error)
    if (dataError) {
      dataError.value = `${error}`
    }
  } finally {
    dataLoading.value = false
    progress.value -= 1
    initWatchInteraction()
  }
}

onBeforeMount(async () => {
  await loadData("init", dataLoadingError)
})

async function onSubmit(payload: Identity, update: "basic" | "organizations", updated: Ref<boolean>, unexpectedError: Ref<string>) {
  if (abortController.signal.aborted) {
    return
  }

  resetOnInteraction()

  progress.value += 1
  try {
    try {
      const url = router.apiResolve({
        name: "IdentityUpdate",
        params: {
          id: props.id,
        },
      }).href

      await postJSON(url, payload, abortController.signal, progress)
      if (abortController.signal.aborted) {
        return
      }

      updated.value = true
    } catch (error) {
      if (abortController.signal.aborted) {
        return
      }
      console.error("IdentityGet.onSubmit", error)
      unexpectedError.value = `${error}`
    } finally {
      // We update identity state even on errors,
      // but do not update individual fields on errors.
      // If there is already an error, we ignore any data loading error.
      await loadData(unexpectedError.value ? null : update, unexpectedError.value ? null : unexpectedError)
    }
  } finally {
    progress.value -= 1
  }
}

function canBasicSubmit(): boolean {
  // At least something is required.
  if (!username.value && !email.value && !givenName.value && !fullName.value && !pictureUrl.value) {
    return false
  }

  // Anything changed?
  if ((identity.value!.username || "") !== username.value) {
    return true
  }
  if ((identity.value!.email || "") !== email.value) {
    return true
  }
  if ((identity.value!.givenName || "") !== givenName.value) {
    return true
  }
  if ((identity.value!.fullName || "") !== fullName.value) {
    return true
  }
  if ((identity.value!.username || "") !== username.value) {
    return true
  }
  if ((identity.value!.email || "") !== email.value) {
    return true
  }
  if ((identity.value!.description || "") !== description.value) {
    return true
  }

  return false
}

async function onBasicSubmit() {
  const payload: Identity = {
    // We update only basic fields.
    id: props.id,
    username: username.value,
    email: email.value,
    givenName: givenName.value,
    fullName: fullName.value,
    pictureUrl: pictureUrl.value,
    description: description.value,
    admins: [],
    organizations: identity.value!.organizations,
  }
  await onSubmit(payload, "basic", basicUpdated, basicUnexpectedError)
}

function canOrganizationsSubmit(): boolean {
  // Anything changed?
  if (!equals(identity.value!.organizations, identityOrganizations.value)) {
    return true
  }

  return false
}

async function onOrganizationsSubmit() {
  const payload: Identity = {
    // We update only organizations.
    id: props.id,
    username: identity.value!.username,
    email: identity.value!.email,
    givenName: identity.value!.givenName,
    fullName: identity.value!.fullName,
    pictureUrl: identity.value!.pictureUrl,
    description: identity.value!.description,
    admins: [],
    organizations: identityOrganizations.value,
  }
  await onSubmit(payload, "organizations", identityOrganizationsUpdated, identityOrganizationsUnexpectedError)
}

async function onAddOrganization(organization: OrganizationRef) {
  if (abortController.signal.aborted) {
    return
  }

  identityOrganizations.value.push({
    active: false,
    // We manually construct OrganizationRef in a case we got passed whole Organization.
    organization: { id: organization.id },
  })

  nextTick(() => {
    document.getElementById("organizations-update")?.focus()
  })
}
</script>

<template>
  <Teleport to="header">
    <NavBar></NavBar>
  </Teleport>
  <div class="w-full flex flex-col items-center mt-12 sm:mt-[4.5rem] border-t border-transparent">
    <div class="grid auto-rows-auto grid-cols-[minmax(0,_65ch)] m-1 sm:m-4 gap-1 sm:gap-4">
      <div class="w-full rounded border bg-white p-4 shadow flex flex-col gap-4">
        <div class="flex flex-row items-center">
          <h1 class="text-2xl font-bold">Identity</h1>
        </div>
        <div v-if="dataLoading">Loading...</div>
        <div v-else-if="dataLoadingError" class="text-error-600">Unexpected error. Please try again.</div>
        <template v-else>
          <form class="flex flex-col" novalidate @submit.prevent="onBasicSubmit">
            <label for="username" class="mb-1">Username<span v-if="metadata.can_update" class="text-neutral-500 italic text-sm"> (optional)</span></label>
            <InputText id="username" v-model="username" class="flex-grow flex-auto min-w-0" :readonly="!metadata.can_update" :progress="progress" />
            <label for="email" class="mb-1 mt-4">E-mail<span v-if="metadata.can_update" class="text-neutral-500 italic text-sm"> (optional)</span></label>
            <InputText id="email" v-model="email" class="flex-grow flex-auto min-w-0" :readonly="!metadata.can_update" :progress="progress" />
            <label for="givenName" class="mb-1 mt-4">Given name<span v-if="metadata.can_update" class="text-neutral-500 italic text-sm"> (optional)</span></label>
            <InputText id="givenName" v-model="givenName" class="flex-grow flex-auto min-w-0" :readonly="!metadata.can_update" :progress="progress" />
            <label for="fullName" class="mb-1 mt-4">Full name<span v-if="metadata.can_update" class="text-neutral-500 italic text-sm"> (optional)</span></label>
            <InputText id="fullName" v-model="fullName" class="flex-grow flex-auto min-w-0" :readonly="!metadata.can_update" :progress="progress" />
            <label for="pictureUrl" class="mb-1 mt-4">Picture URL<span v-if="metadata.can_update" class="text-neutral-500 italic text-sm"> (optional)</span></label>
            <InputText id="pictureUrl" v-model="pictureUrl" class="flex-grow flex-auto min-w-0" :readonly="!metadata.can_update" :progress="progress" />
            <label for="description" class="mb-1 mt-4">Description<span v-if="metadata.can_update" class="text-neutral-500 italic text-sm"> (optional)</span></label>
            <TextArea id="description" v-model="description" class="flex-grow flex-auto min-w-0" :readonly="!metadata.can_update" :progress="progress" />
            <div v-if="basicUnexpectedError" class="mt-4 text-error-600">Unexpected error. Please try again.</div>
            <div v-else-if="basicUpdated" class="mt-4 text-success-600">Identity updated successfully.</div>
            <div v-if="metadata.can_update" class="mt-4 flex flex-row justify-end">
              <!--
                Button is on purpose not disabled on unexpectedError so that user can retry.
              -->
              <Button type="submit" primary :disabled="!canBasicSubmit()" :progress="progress">Update</Button>
            </div>
          </form>
          <template v-if="identityOrganizations.length || canOrganizationsSubmit()">
            <h2 class="text-xl font-bold">Added organizations</h2>
            <div v-if="identityOrganizationsUnexpectedError" class="text-error-600">Unexpected error. Please try again.</div>
            <div v-else-if="identityOrganizationsUpdated" class="text-success-600">Added organizations updated successfully.</div>
            <form class="flex flex-col" novalidate @submit.prevent="onOrganizationsSubmit">
              <ul>
                <li v-for="(identityOrganization, i) in identityOrganizations" :key="identityOrganization.id || i" class="flex flex-col mb-4">
                  <OrganizationListItem :item="identityOrganization.organization" h3 />
                  <div class="ml-4 mt-4 flex flew-row gap-4 justify-between items-start">
                    <div class="grid auto-rows-auto grid-cols-[max-content,auto] gap-x-1">
                      <div>ID:</div>
                      <div v-if="identityOrganization.id">
                        <code>{{ identityOrganization.id }}</code>
                      </div>
                      <div v-else><span class="italic">confirm update to allocate</span></div>
                      <div>Status:</div>
                      <div><strong>{{ identityOrganization.active ? 'active' : 'disabled' }}</strong></div>
                    </div>
                    <div v-if="identityOrganization.active" class="flex flew-row gap-4">
                      <Button type="button" :progress="progress" @click.prevent="identityOrganization.active = false">Disable</Button>
                      <Button type="button" :progress="progress" @click.prevent="identityOrganizations.splice(i, 1)">Remove</Button>
                    </div>
                    <div v-else class="flex flew-row gap-4">
                      <Button type="button" :progress="progress" @click.prevent="identityOrganization.active = true">Activate</Button>
                      <Button type="button" :progress="progress" @click.prevent="identityOrganizations.splice(i, 1)">Remove</Button>
                    </div>
                  </div>
                </li>
              </ul>
              <div class="flex flex-row justify-end">
                <!--
                  Button is on purpose not disabled on unexpectedError so that user can retry.
                -->
                <Button id="organizations-update" type="submit" primary :disabled="!canOrganizationsSubmit()" :progress="progress">Update</Button>
              </div>
            </form>
          </template>
          <template v-if="metadata.can_update && availableOrganizations.length">
            <h2 class="text-xl font-bold">Available organizations</h2>
            <ul class="flex flex-col gap-4">
              <li v-for="organization in availableOrganizations" :key="organization.id">
                <OrganizationListItem :item="organization" h3>
                  <div class="flex flex-col items-start">
                    <Button type="button" :progress="progress" primary @click.prevent="onAddOrganization(organization)">Add</Button>
                  </div>
                </OrganizationListItem>
              </li>
            </ul>
          </template>
        </template>
      </div>
    </div>
  </div>
  <Teleport to="footer">
    <Footer />
  </Teleport>
</template>
