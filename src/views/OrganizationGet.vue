<script setup lang="ts">
import type { DeepReadonly, Ref } from "vue"
import type {
  Organization,
  Metadata,
  ApplicationTemplates,
  ApplicationTemplate,
  OrganizationApplication,
  ApplicationTemplateRef,
  Identities,
  IdentityRef,
  OrganizationIdentity,
  Identity,
  AllIdentity,
} from "@/types"

import { computed, nextTick, onBeforeMount, onBeforeUnmount, ref, watch } from "vue"
import { useI18n } from "vue-i18n"
import { useRouter } from "vue-router"
import { Identifier } from "@tozd/identifier"
import InputText from "@/components/InputText.vue"
import TextArea from "@/components/TextArea.vue"
import Button from "@/components/Button.vue"
import ButtonLink from "@/components/ButtonLink.vue"
import NavBar from "@/partials/NavBar.vue"
import Footer from "@/partials/Footer.vue"
import ApplicationTemplateListItem from "@/partials/ApplicationTemplateListItem.vue"
import IdentityFull from "@/partials/IdentityFull.vue"
import WithIdentityPublicDocument from "@/partials/WithIdentityPublicDocument.vue"
import IdentityOrganization from "@/partials/IdentityOrganization.vue"
import { getURL, postJSON } from "@/api"
import { setupArgon2id } from "@/argon2id"
import { clone, equals, getIdentityOrganization, getOrganization } from "@/utils"
import { injectProgress } from "@/progress"
import siteContext from "@/context"
import { isSignedIn } from "@/auth"

const { t } = useI18n()

const props = defineProps<{
  id: string
}>()

const router = useRouter()

// We could be using separate progress for the organization and identities, because those
// are really two separate forms (and documents) visually combined into one form, but we are
// using only one progress to further drive the illusion of only one form.
const progress = injectProgress()

const abortController = new AbortController()
const dataLoading = ref(true)
const dataLoadingError = ref("")
const organization = ref<Organization | null>(null)
const metadata = ref<Metadata>({})
const applicationTemplates = ref<ApplicationTemplates>([])
const generatedSecrets = ref(new Map<string, string>())

const basicUnexpectedError = ref("")
const basicUpdated = ref(false)
const name = ref("")
const description = ref("")

const applicationsUnexpectedError = ref("")
const applicationsUpdated = ref(false)
const applications = ref<OrganizationApplication[]>([])

const adminsUnexpectedError = ref("")
const adminsUpdated = ref(false)
const admins = ref<IdentityRef[]>([])

const organizationIdentitiesUnexpectedError = ref("")
const organizationIdentitiesUpdated = ref(false)
let organizationIdentitiesInitial: OrganizationIdentity[] = []
const organizationIdentities = ref<OrganizationIdentity[]>([])

const allIdentities = ref<AllIdentity[]>([])
const availableIdentities = computed(() => {
  const identities: AllIdentity[] = []
  for (const allIdentity of allIdentities.value) {
    // If identity is not already added, then admin access is
    // required to be able to join the organization first.
    if (!isIdentityAdded(allIdentity.identity) && allIdentity.canUpdate) {
      identities.push(allIdentity)
    }
  }
  return identities
})

function isApplicationAdded(applicationTemplate: ApplicationTemplateRef): boolean {
  for (const application of applications.value) {
    if (application.applicationTemplate.id === applicationTemplate.id) {
      return true
    }
  }
  return false
}

function isIdentityAdded(identity: IdentityRef): boolean {
  for (const organizationIdentity of organizationIdentities.value) {
    if (organizationIdentity.identity.id === identity.id) {
      return true
    }
  }
  return false
}

function getInitialOrganizationIdentity(identity: IdentityRef): OrganizationIdentity | null {
  for (const organizationIdentity of organizationIdentitiesInitial) {
    if (organizationIdentity.identity.id === identity.id) {
      return organizationIdentity
    }
  }
  return null
}

function resetOnInteraction() {
  // We reset flags and errors on interaction.
  basicUnexpectedError.value = ""
  basicUpdated.value = false
  applicationsUnexpectedError.value = ""
  applicationsUpdated.value = false
  adminsUnexpectedError.value = ""
  adminsUpdated.value = false
  organizationIdentitiesUnexpectedError.value = ""
  organizationIdentitiesUpdated.value = false
  // dataLoading and dataLoadingError are not listed here on
  // purpose because they are used only on mount.
}

let watchInteractionStop: (() => void) | null = null
function initWatchInteraction() {
  if (abortController.signal.aborted) {
    return
  }

  const stop = watch([name, description, applications, admins, organizationIdentities], resetOnInteraction, { deep: true })
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

async function loadData(update: "init" | "basic" | "applications" | "admins" | "identities" | null, dataError: Ref<string> | null) {
  if (abortController.signal.aborted) {
    return
  }

  watchInteractionStop!()
  progress.value += 1
  try {
    // A special case, we do not need to load the organization if we are loading identities.
    if (update !== "identities") {
      const organizationURL = router.apiResolve({
        name: "OrganizationGet",
        params: {
          id: props.id,
        },
      }).href

      const response = await getURL<Organization>(organizationURL, null, abortController.signal, progress)
      if (abortController.signal.aborted) {
        return
      }

      organization.value = response.doc
      metadata.value = response.metadata

      // We have to make copies so that we break reactivity link with data.doc.
      if (update === "init" || update === "basic") {
        name.value = response.doc.name
        description.value = response.doc.description
      }
      if (update === "init" || update === "applications") {
        applications.value = clone(response.doc.applications || [])
      }
      if (update === "init" || update === "admins") {
        admins.value = clone(response.doc.admins || [])
      }
    }

    if (update === "init") {
      const applicationsURL = router.apiResolve({
        name: "ApplicationTemplateList",
      }).href

      const resp = await getURL<ApplicationTemplates>(applicationsURL, null, abortController.signal, progress)
      if (abortController.signal.aborted) {
        return
      }

      applicationTemplates.value = resp.doc
    }

    if (update === "init" || update === "identities") {
      const updatedOrganizationIdentities: OrganizationIdentity[] = []
      const updatedAllIdentities: AllIdentity[] = []

      if (isSignedIn()) {
        const identitiesURL = router.apiResolve({
          name: "IdentityList",
        }).href

        const resp = await getURL<Identities>(identitiesURL, null, abortController.signal, progress)
        if (abortController.signal.aborted) {
          return
        }

        for (const identity of resp.doc) {
          const identityURL = router.apiResolve({
            name: "IdentityGet",
            params: {
              id: identity.id,
            },
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

          for (const identityOrganization of resp.doc.organizations) {
            if (identityOrganization.organization.id === props.id) {
              updatedOrganizationIdentities.push({
                id: identityOrganization.id,
                active: identityOrganization.active,
                // We clone so that object is not shared with updatedAllIdentities.
                // Just in case we modify any of them.
                identity: clone(resp.doc),
                url: identityURL,
                applications: identityOrganization.applications,
                isCurrent: !!resp.metadata.is_current,
                canUpdate: !!resp.metadata.can_update,
              })
              break
            }
          }
        }
      }

      organizationIdentitiesInitial = clone(updatedOrganizationIdentities)
      organizationIdentities.value = updatedOrganizationIdentities
      allIdentities.value = updatedAllIdentities
    }
  } catch (error) {
    if (abortController.signal.aborted) {
      return
    }
    // TODO: 404 should be shown differently, but probably in the same way for all 404.
    console.error("OrganizationGet.loadData", error)
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

async function onSubmit(payload: Organization, update: "basic" | "applications" | "admins", updated: Ref<boolean>, unexpectedError: Ref<string>) {
  if (abortController.signal.aborted) {
    return
  }

  resetOnInteraction()

  progress.value += 1
  try {
    try {
      const url = router.apiResolve({
        name: "OrganizationUpdate",
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
      console.error("OrganizationGet.onSubmit", error)
      unexpectedError.value = `${error}`
    } finally {
      // We update organization state even on errors,
      // but do not update individual fields on errors.
      // If there is already an error, we ignore any data loading error.
      await loadData(unexpectedError.value ? null : update, unexpectedError.value ? null : unexpectedError)
    }
  } finally {
    progress.value -= 1
  }
}

function canBasicSubmit(): boolean {
  // Required fields.
  if (!name.value) {
    return false
  }

  // Anything changed?
  if (organization.value!.name !== name.value) {
    return true
  }
  if (organization.value!.description !== description.value) {
    return true
  }

  return false
}

async function onBasicSubmit() {
  const payload: Organization = {
    // We update only basic fields.
    id: props.id,
    name: name.value,
    description: description.value,
    admins: organization.value!.admins,
    applications: organization.value!.applications,
  }
  await onSubmit(payload, "basic", basicUpdated, basicUnexpectedError)
}

function canApplicationsSubmit(): boolean {
  // Required fields.
  for (const application of applications.value) {
    for (const value of application.values) {
      if (!value.value) {
        return false
      }
    }
  }

  // Anything changed?
  if (!equals(organization.value!.applications || [], applications.value)) {
    return true
  }

  return false
}

async function onApplicationsSubmit() {
  const payload: Organization = {
    // We update only applications.
    id: props.id,
    name: organization.value!.name,
    description: organization.value!.description,
    admins: organization.value!.admins,
    applications: applications.value,
  }
  await onSubmit(payload, "applications", applicationsUpdated, applicationsUnexpectedError)
}

async function onAddApplicationTemplate(applicationTemplate: DeepReadonly<ApplicationTemplate>) {
  if (abortController.signal.aborted) {
    return
  }

  // applicationTemplate can contain an "admins" field (if user is an admin of the application template)
  // but organization applications do not have this field, so we have to delete it.
  if ("admins" in applicationTemplate) {
    // We have to copy because input is read-only.
    const ap = clone(applicationTemplate)
    delete ap.admins
    applicationTemplate = ap
  }

  applications.value.push({
    active: false,
    applicationTemplate: applicationTemplate,
    values: applicationTemplate.variables.map((variable) => ({
      name: variable.name,
      value: "",
    })),
    clientsPublic: applicationTemplate.clientsPublic.map((client) => ({
      client: { id: client.id! },
    })),
    clientsBackend: await Promise.all(
      applicationTemplate.clientsBackend.map(async (client) => ({
        client: { id: client.id! },
        secret: await getSecret(client.id!),
      })),
    ),
    clientsService: await Promise.all(
      applicationTemplate.clientsService.map(async (client) => ({
        client: { id: client.id! },
        secret: await getSecret(client.id!),
      })),
    ),
  })

  nextTick(() => {
    const el = document.getElementById(`application-${applications.value.length - 1}-values-0`)
    if (el) {
      el.focus()
    } else {
      document.getElementById("applications-update")?.focus()
    }
  })
}

async function getSecret(id: string): Promise<string> {
  const secret = Identifier.new().toString()
  // We setup argon2id every time so that memory used by it
  // can be reclaimed when it is not used anymore.
  // See: https://github.com/openpgpjs/argon2id/issues/4
  const argon2id = await setupArgon2id()
  const hash = argon2id(new TextEncoder().encode(secret))
  // We use a prefix to aid secret scanners.
  generatedSecrets.value.set(id, `chc-${secret}`)
  return hash
}

function getValueDescription(application: OrganizationApplication, valueName: string): string {
  for (const variable of application.applicationTemplate.variables) {
    if (variable.name === valueName) {
      return variable.description
    }
  }
  return ""
}

function getPublicClientDescription(application: OrganizationApplication, clientId: string): string {
  for (const client of application.applicationTemplate.clientsPublic) {
    if (client.id === clientId) {
      return client.description
    }
  }
  return ""
}

function getBackendClientDescription(application: OrganizationApplication, clientId: string): string {
  for (const client of application.applicationTemplate.clientsBackend) {
    if (client.id === clientId) {
      return client.description
    }
  }
  return ""
}

function getServiceClientDescription(application: OrganizationApplication, clientId: string): string {
  for (const client of application.applicationTemplate.clientsService) {
    if (client.id === clientId) {
      return client.description
    }
  }
  return ""
}

function canAdminsSubmit(): boolean {
  // Anything changed?
  if (!equals(organization.value!.admins || [], admins.value)) {
    return true
  }

  return false
}

async function onAdminsSubmit() {
  const payload: Organization = {
    // We update only admins.
    id: props.id,
    name: organization.value!.name,
    description: organization.value!.description,
    admins: admins.value,
    applications: organization.value!.applications,
  }
  await onSubmit(payload, "admins", adminsUpdated, adminsUnexpectedError)
}

function onAddAdmin() {
  if (abortController.signal.aborted) {
    return
  }

  // No need to call resetOnInteraction here because we modify variables
  // which we watch to call resetOnInteraction.

  admins.value.push({
    id: "",
  })

  nextTick(() => {
    document.getElementById(`admin-${admins.value.length - 1}-id`)?.focus()
  })
}

function canIdentitiesSubmit(): boolean {
  // Anything changed?
  if (!equals(organizationIdentitiesInitial, organizationIdentities.value)) {
    return true
  }

  return false
}

async function onAddIdentity(identity: Identity | DeepReadonly<Identity>) {
  if (abortController.signal.aborted) {
    return
  }

  organizationIdentities.value.push({
    active: false,
    identity,
    applications: [],
    url: undefined,
    isCurrent: false,
    canUpdate: true,
  })
  // Because list of all identities is sorted by ID, organizationIdentities itself is also sorted by identity ID. We do not want
  // that after updating the list and retrieving the result from the backend, the list changes with identities changing the
  // order. So we prefer to sort the list before sending it to the backend, in the same way the backend does. Ideally, we
  // would have the order in which identities were added to the organization, but we do not have that information.
  organizationIdentities.value.sort((a, b) => a.identity.id.localeCompare(b.identity.id))

  nextTick(() => {
    document.getElementById("identities-update")?.focus()
  })
}

async function onIdentitiesSubmit() {
  if (abortController.signal.aborted) {
    return
  }

  resetOnInteraction()

  progress.value += 1
  try {
    try {
      for (const organizationIdentity of organizationIdentities.value) {
        // Anything changed?
        const initialOrganizationIdentity = getInitialOrganizationIdentity(organizationIdentity.identity)
        if (initialOrganizationIdentity !== null && equals(initialOrganizationIdentity, organizationIdentity)) {
          continue
        }

        const payload = clone(organizationIdentity.identity)
        // Does there exist an entry with this ID? ID might be undefined which is fine.
        let identityOrganization = getIdentityOrganization(payload, organizationIdentity.id)
        if (identityOrganization === null) {
          // Is there any other entry for this organization?
          identityOrganization = getOrganization(payload, props.id)
          if (identityOrganization === null) {
            payload.organizations.push({
              // ID can be undefined and this is OK, the backend will assign it.
              id: organizationIdentity.id,
              active: organizationIdentity.active,
              organization: { id: props.id },
              applications: [],
            })
          } else {
            // We could not find it by ID but we found it by organization's ID,
            // which probably means the ID was reset to undefined.
            identityOrganization.id = organizationIdentity.id
            identityOrganization.active = organizationIdentity.active
          }
        } else {
          identityOrganization.active = organizationIdentity.active
        }

        const url = router.apiResolve({
          name: "IdentityUpdate",
          params: {
            id: payload.id,
          },
        }).href

        await postJSON(url, payload, abortController.signal, progress)
        if (abortController.signal.aborted) {
          return
        }
      }

      // Some identities might have been removed.
      for (const organizationIdentity of organizationIdentitiesInitial) {
        if (isIdentityAdded(organizationIdentity.identity)) {
          // Not removed.
          continue
        }

        const payload = clone(organizationIdentity.identity)
        payload.organizations = payload.organizations.filter((idOrg) => idOrg.organization.id !== props.id)

        const url = router.apiResolve({
          name: "IdentityUpdate",
          params: {
            id: payload.id,
          },
        }).href

        await postJSON(url, payload, abortController.signal, progress)
        if (abortController.signal.aborted) {
          return
        }
      }

      organizationIdentitiesUpdated.value = true
    } catch (error) {
      if (abortController.signal.aborted) {
        return
      }
      console.error("OrganizationGet.onIdentitiesSubmit", error)
      organizationIdentitiesUnexpectedError.value = `${error}`
    } finally {
      // We always update identities state, even on errors,
      // because it might have been partially successful.
      // If there is already an error, we ignore any data loading error.
      await loadData("identities", organizationIdentitiesUnexpectedError.value ? null : organizationIdentitiesUnexpectedError)
    }
  } finally {
    progress.value -= 1
  }
}

// TODO: Remember previous client ID and secrets and reuse them if an add application is removed and then added back without calling update in-between.
// TODO: Remember previous organization-scoped identity IDs and reuse them if an identity is removed and then added back without calling update in-between.
// TODO: Provide explicit buttons to rotate each secret.
</script>

<template>
  <Teleport to="header">
    <NavBar></NavBar>
  </Teleport>
  <div class="w-full flex flex-col items-center mt-12 sm:mt-[4.5rem] border-t border-transparent">
    <div class="grid auto-rows-auto grid-cols-[minmax(0,_65ch)] m-1 sm:m-4 gap-1 sm:gap-4">
      <div class="w-full rounded border bg-white p-4 shadow flex flex-col gap-4">
        <div class="flex flex-row items-center">
          <h1 class="text-2xl font-bold">{{ t("titles.organization") }}</h1>
        </div>
        <div v-if="dataLoading">{{ t("loading.dataLoading") }}</div>
        <div v-else-if="dataLoadingError" class="text-error-600">{{ t("common.errors.unexpected") }}</div>
        <template v-else>
          <form class="flex flex-col" novalidate @submit.prevent="onBasicSubmit">
            <label for="name" class="mb-1">{{ t("labels.organizationName") }}</label>
            <InputText id="name" v-model="name" class="flex-grow flex-auto min-w-0" :readonly="!metadata.can_update" :progress="progress" required />
            <label for="description" class="mb-1 mt-4"
              >{{ t("labels.description") }}<span v-if="metadata.can_update" class="text-neutral-500 italic text-sm"> {{ t("labels.optional") }}</span></label
            >
            <TextArea id="description" v-model="description" class="flex-grow flex-auto min-w-0" :readonly="!metadata.can_update" :progress="progress" />
            <div v-if="basicUnexpectedError" class="mt-4 text-error-600">{{ t("common.errors.unexpected") }}</div>
            <div v-else-if="basicUpdated" class="mt-4 text-success-600">{{ t("messages.success.organizationUpdated") }}</div>
            <div v-if="metadata.can_update" class="mt-4 flex flex-row justify-end">
              <!--
                Button is on purpose not disabled on basicUnexpectedError so that user can retry.
              -->
              <Button type="submit" primary :disabled="!canBasicSubmit()" :progress="progress">{{ t("common.buttons.update") }}</Button>
            </div>
          </form>
          <template v-if="metadata.can_update">
            <h2 class="text-xl font-bold">Users</h2>
            <div>
              <ButtonLink :to="{ name: 'OrganizationUsers', params: { id } }" primary>Manage</ButtonLink>
            </div>
          </template>
          <template v-if="(metadata.can_update && (applications.length || canApplicationsSubmit())) || applicationsUnexpectedError || applicationsUpdated">
            <h2 class="text-xl font-bold">Added applications</h2>
            <div v-if="applicationsUnexpectedError" class="text-error-600">{{ t("common.errors.unexpected") }}</div>
            <div v-else-if="applicationsUpdated" class="text-success-600">Added applications updated successfully.</div>
            <form v-if="metadata.can_update && (applications.length || canApplicationsSubmit())" class="flex flex-col" novalidate @submit.prevent="onApplicationsSubmit">
              <ul>
                <li v-for="(application, i) in applications" :key="application.id || i" class="flex flex-col mb-4">
                  <ApplicationTemplateListItem :item="{ id: application.applicationTemplate.id }" :public-doc="application.applicationTemplate" h3 />
                  <div class="ml-4">
                    <fieldset v-if="application.values.length" class="mt-4">
                      <legend class="font-bold">Configuration</legend>
                      <ol>
                        <li v-for="(value, j) in application.values" :key="value.name" class="flex flex-col mt-4">
                          <code>{{ value.name }}</code>
                          <div v-if="getValueDescription(application, value.name)" class="ml-4">{{ getValueDescription(application, value.name) }}</div>
                          <InputText
                            :id="`application-${i}-values-${j}`"
                            v-model="value.value"
                            class="flex-grow flex-auto min-w-0 ml-4 mt-1"
                            :progress="progress"
                            required
                          />
                        </li>
                      </ol>
                    </fieldset>
                    <h4 v-if="application.clientsPublic?.length" class="font-bold mt-4">Public clients</h4>
                    <ol v-if="application.clientsPublic?.length">
                      <li v-for="(client, j) in application.clientsPublic" :key="j" class="grid auto-rows-auto grid-cols-[min-content,auto] gap-x-4 mt-4">
                        <div>{{ j + 1 }}.</div>
                        <div class="flex flex-col gap-4">
                          <div v-if="getPublicClientDescription(application, client.client.id)">{{ getPublicClientDescription(application, client.client.id) }}</div>
                          <div class="grid auto-rows-auto grid-cols-[max-content,auto] gap-x-1">
                            <div>Client ID:</div>
                            <div v-if="client.id">
                              <code>{{ client.id }}</code>
                            </div>
                            <div v-else><span class="italic">confirm update to allocate</span></div>
                          </div>
                        </div>
                      </li>
                    </ol>
                    <h4 v-if="application.clientsBackend?.length" class="font-bold mt-4">Backend clients</h4>
                    <ol v-if="application.clientsBackend?.length">
                      <li v-for="(client, j) in application.clientsBackend" :key="j" class="grid auto-rows-auto grid-cols-[min-content,auto] gap-x-4 mt-4">
                        <div>{{ j + 1 }}.</div>
                        <div class="flex flex-col gap-4">
                          <div v-if="getBackendClientDescription(application, client.client.id)">{{ getBackendClientDescription(application, client.client.id) }}</div>
                          <div class="grid auto-rows-auto grid-cols-[max-content,auto] gap-x-1">
                            <div>Client ID:</div>
                            <div v-if="client.id">
                              <code>{{ client.id }}</code>
                            </div>
                            <div v-else><span class="italic">confirm update to allocate</span></div>
                            <template v-if="client.id && generatedSecrets.has(client.client.id)">
                              <div>Client secret:</div>
                              <div>
                                <code>{{ generatedSecrets.get(client.client.id) }}</code>
                              </div>
                            </template>
                          </div>
                        </div>
                      </li>
                    </ol>
                    <h4 v-if="application.clientsService?.length" class="font-bold mt-4">Service clients</h4>
                    <ol v-if="application.clientsService?.length">
                      <li v-for="(client, j) in application.clientsService" :key="j" class="grid auto-rows-auto grid-cols-[min-content,auto] gap-x-4 mt-4">
                        <div>{{ j + 1 }}.</div>
                        <div class="flex flex-col gap-4">
                          <div v-if="getServiceClientDescription(application, client.client.id)">{{ getServiceClientDescription(application, client.client.id) }}</div>
                          <div class="grid auto-rows-auto grid-cols-[max-content,auto] gap-x-1">
                            <div>Client ID:</div>
                            <div v-if="client.id">
                              <code>{{ client.id }}</code>
                            </div>
                            <div v-else><span class="italic">confirm update to allocate</span></div>
                            <template v-if="client.id && generatedSecrets.has(client.client.id)">
                              <div>Client secret:</div>
                              <div>
                                <code>{{ generatedSecrets.get(client.client.id) }}</code>
                              </div>
                            </template>
                          </div>
                        </div>
                      </li>
                    </ol>
                    <div v-if="application.active" class="flex flew-row justify-between items-center gap-4 mt-4">
                      <div>Status: <strong>active</strong></div>
                      <div class="flex flex-row gap-4">
                        <Button type="button" :progress="progress" @click.prevent="application.active = false">Disable</Button>
                        <Button type="button" :progress="progress" @click.prevent="applications.splice(i, 1)">Remove</Button>
                      </div>
                    </div>
                    <div v-else class="flex flew-row justify-between items-center gap-4 mt-4">
                      <div>Status: <strong>disabled</strong></div>
                      <div class="flex flex-row gap-4">
                        <Button type="button" :progress="progress" @click.prevent="application.active = true">Activate</Button>
                        <Button type="button" :progress="progress" @click.prevent="applications.splice(i, 1)">Remove</Button>
                      </div>
                    </div>
                  </div>
                </li>
              </ul>
              <div class="flex flex-row justify-end">
                <!--
                  Button is on purpose not disabled on applicationsUnexpectedError so that user can retry.
                -->
                <Button id="applications-update" type="submit" primary :disabled="!canApplicationsSubmit()" :progress="progress">{{ t("common.buttons.update") }}</Button>
              </div>
            </form>
          </template>
          <template v-if="metadata.can_update && applicationTemplates.length">
            <h2 class="text-xl font-bold">Available applications</h2>
            <ul class="flex flex-col gap-4">
              <li v-for="applicationTemplate in applicationTemplates" :key="applicationTemplate.id">
                <ApplicationTemplateListItem :item="applicationTemplate" :labels="isApplicationAdded(applicationTemplate) ? ['added'] : []" h3>
                  <template #default="{ doc }">
                    <div v-if="doc" class="flex flex-col items-start">
                      <Button type="button" :progress="progress" primary @click.prevent="onAddApplicationTemplate(doc)">Add</Button>
                    </div>
                  </template>
                </ApplicationTemplateListItem>
              </li>
            </ul>
          </template>
          <template v-if="metadata.can_update || adminsUnexpectedError || adminsUpdated">
            <h2 class="text-xl font-bold">Admins</h2>
            <div v-if="adminsUnexpectedError" class="text-error-600">{{ t("common.errors.unexpected") }}</div>
            <div v-else-if="adminsUpdated" class="text-success-600">{{ t("messages.success.adminsUpdated") }}</div>
            <form v-if="metadata.can_update" class="flex flex-col" novalidate @submit.prevent="onAdminsSubmit">
              <ol class="flex flex-col gap-y-4">
                <li v-for="(admin, i) of admins" :key="i" class="grid auto-rows-auto grid-cols-[min-content,auto] gap-x-4">
                  <div>{{ i + 1 }}.</div>
                  <div class="flex flex-col">
                    <WithIdentityPublicDocument v-if="organization?.admins?.find((a) => a.id === admin.id)" :item="admin" :organization-id="siteContext.organizationId">
                      <div class="flex flex-col items-start">
                        <Button type="button" @click.prevent="admins.splice(i, 1)">Remove</Button>
                      </div>
                    </WithIdentityPublicDocument>
                    <div v-else class="flex flex-row gap-4">
                      <InputText :id="`admin-${i}-id`" v-model="admins[i].id" class="flex-grow flex-auto min-w-0" :progress="progress" required />
                      <Button type="button" @click.prevent="admins.splice(i, 1)">Remove</Button>
                    </div>
                  </div>
                </li>
              </ol>
              <div class="flex flex-row justify-between gap-4" :class="admins.length ? 'mt-4' : ''">
                <Button type="button" @click.prevent="onAddAdmin">Add admin</Button>
                <!--
                  Button is on purpose not disabled on adminsUnexpectedError so that user can retry.
                -->
                <Button type="submit" primary :disabled="!canAdminsSubmit()" :progress="progress">{{ t("common.buttons.update") }}</Button>
              </div>
            </form>
          </template>
          <template v-if="organizationIdentities.length || canIdentitiesSubmit() || organizationIdentitiesUnexpectedError || organizationIdentitiesUpdated">
            <h2 class="text-xl font-bold">Added identities</h2>
            <div v-if="organizationIdentitiesUnexpectedError" class="text-error-600">{{ t("common.errors.unexpected") }}</div>
            <div v-else-if="organizationIdentitiesUpdated" class="text-success-600">{{ t("messages.success.identitiesUpdated") }}</div>
            <form v-if="organizationIdentities.length || canIdentitiesSubmit()" class="flex flex-col" novalidate @submit.prevent="onIdentitiesSubmit">
              <ul class="flex flex-col gap-y-4">
                <li v-for="(organizationIdentity, i) in organizationIdentities" :key="organizationIdentity.id || i" class="flex flex-col">
                  <IdentityFull
                    :identity="organizationIdentity.identity"
                    :url="organizationIdentity.url"
                    :is-current="organizationIdentity.isCurrent"
                    :can-update="organizationIdentity.canUpdate"
                    :labels="organizationIdentity.active ? [] : ['disabled']"
                  />
                  <IdentityOrganization
                    :identity-organization="{
                      id: organizationIdentity.id,
                      active: organizationIdentity.active,
                      organization: { id },
                      applications: organizationIdentity.applications,
                    }"
                  >
                    <div v-if="organizationIdentity.canUpdate && organizationIdentity.active" class="flex flex-row gap-4">
                      <Button type="button" :progress="progress" @click.prevent="organizationIdentity.active = false">Disable</Button>
                      <Button type="button" :progress="progress" @click.prevent="organizationIdentities.splice(i, 1)">Remove</Button>
                    </div>
                    <div v-else-if="organizationIdentity.canUpdate" class="flex flex-row gap-4">
                      <Button type="button" :progress="progress" @click.prevent="organizationIdentity.active = true">Activate</Button>
                      <Button type="button" :progress="progress" @click.prevent="organizationIdentities.splice(i, 1)">Remove</Button>
                    </div>
                  </IdentityOrganization>
                </li>
              </ul>
              <div
                v-if="organizationIdentities.filter((oi) => oi.canUpdate).length || canIdentitiesSubmit()"
                class="flex flex-row justify-end"
                :class="organizationIdentities.length ? 'mt-4' : ''"
              >
                <!--
                  Button is on purpose not disabled on organizationIdentitiesUnexpectedError so that user can retry.
                -->
                <Button id="identities-update" type="submit" primary :disabled="!canIdentitiesSubmit()" :progress="progress">{{ t("common.buttons.update") }}</Button>
              </div>
            </form>
          </template>
          <template v-if="availableIdentities.length">
            <h2 class="text-xl font-bold">Available identities</h2>
            <ul class="flex flex-col gap-4">
              <li v-for="identity in availableIdentities" :key="identity.identity.id">
                <IdentityFull :identity="identity.identity" :url="identity.url" :is-current="identity.isCurrent" :can-update="identity.canUpdate">
                  <div class="flex flex-col items-start">
                    <Button type="button" :progress="progress" primary @click.prevent="onAddIdentity(identity.identity)">Add</Button>
                  </div>
                </IdentityFull>
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
