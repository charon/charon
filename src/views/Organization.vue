<script setup lang="ts">
import type { DeepReadonly, Ref } from "vue"
import type { Organization, Metadata, ApplicationTemplateList, ApplicationTemplate, OrganizationApplication, ApplicationTemplateRef } from "@/types"

import { computed, nextTick, onBeforeMount, onUnmounted, ref, watch, inject } from "vue"
import { useRouter } from "vue-router"
import { Identifier } from "@tozd/identifier"
import InputText from "@/components/InputText.vue"
import TextArea from "@/components/TextArea.vue"
import Button from "@/components/Button.vue"
import WithDocument from "@/components/WithDocument.vue"
import NavBar from "@/components/NavBar.vue"
import Footer from "@/components/Footer.vue"
import { getURL, postURL } from "@/api"
import { setupArgon2id } from "@/argon2id"
import { clone, equals } from "@/utils"
import { progressKey } from "@/progress"

const props = defineProps<{
  id: string
}>()

const router = useRouter()

const mainProgress = inject(progressKey, ref(0))

const abortController = new AbortController()
const dataLoading = ref(true)
const dataLoadingError = ref("")
const organization = ref<Organization | null>(null)
const metadata = ref<Metadata>({})
const applicationTemplates = ref<ApplicationTemplateList>([])
const generatedSecrets = ref(new Map<string, string>())

const basicUnexpectedError = ref("")
const basicUpdated = ref(false)
const name = ref("")
const description = ref("")

const applicationsUnexpectedError = ref("")
const applicationsUpdated = ref(false)
const applications = ref<OrganizationApplication[]>([])

function isApplicationEnabled(applicationTemplate: ApplicationTemplateRef): boolean {
  for (const application of applications.value) {
    if (application.applicationTemplate.id === applicationTemplate.id) {
      return true
    }
  }
  return false
}

const availableApplicationTemplates = computed(() => {
  const apps = []
  for (const applicationTemplate of applicationTemplates.value) {
    if (!isApplicationEnabled(applicationTemplate)) {
      apps.push(applicationTemplate)
    }
  }
  return apps
})

function resetOnInteraction() {
  // We reset flags and errors on interaction.
  basicUnexpectedError.value = ""
  basicUpdated.value = false
  applicationsUnexpectedError.value = ""
  applicationsUpdated.value = false
  // dataLoading and dataLoadingError are not listed here on
  // purpose because they are used only on mount.
}

let watchInteractionStop: (() => void) | null = null
function initWatchInteraction() {
  if (abortController.signal.aborted) {
    return
  }

  const stop = watch([name, description, applications], resetOnInteraction, { deep: true })
  if (watchInteractionStop !== null) {
    throw new Error("watchInteractionStop already set")
  }
  watchInteractionStop = () => {
    watchInteractionStop = null
    stop()
  }
}
initWatchInteraction()

onUnmounted(() => {
  abortController.abort()
})

async function loadData(update: "init" | "basic" | "applications" | null) {
  if (abortController.signal.aborted) {
    return
  }

  watchInteractionStop!()
  mainProgress.value += 1
  try {
    const organizationURL = router.apiResolve({
      name: "Organization",
      params: {
        id: props.id,
      },
    }).href

    const response = await getURL<Organization>(organizationURL, null, abortController.signal, mainProgress)
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

    if (update === "init") {
      const applicationsURL = router.apiResolve({
        name: "ApplicationTemplateList",
      }).href

      const resp = await getURL<ApplicationTemplateList>(applicationsURL, null, abortController.signal, mainProgress)
      if (abortController.signal.aborted) {
        return
      }

      applicationTemplates.value = resp.doc
    }
  } catch (error) {
    if (abortController.signal.aborted) {
      return
    }
    // TODO: 404 should be shown differently, but probably in the same way for all 404.
    console.error(error)
    dataLoadingError.value = `${error}`
  } finally {
    dataLoading.value = false
    mainProgress.value -= 1
    initWatchInteraction()
  }
}

onBeforeMount(async () => {
  await loadData("init")
})

async function onSubmit(payload: Organization, update: "basic" | "applications", updated: Ref<boolean>, unexpectedError: Ref<string>) {
  if (abortController.signal.aborted) {
    return
  }

  resetOnInteraction()

  mainProgress.value += 1
  try {
    try {
      const url = router.apiResolve({
        name: "OrganizationUpdate",
        params: {
          id: props.id,
        },
      }).href

      await postURL(url, payload, abortController.signal, mainProgress)
      if (abortController.signal.aborted) {
        return
      }

      updated.value = true
    } catch (error) {
      if (abortController.signal.aborted) {
        return
      }
      console.error(error)
      unexpectedError.value = `${error}`
    } finally {
      // We update organization state even on errors,
      // but do not update individual fields on errors.
      await loadData(unexpectedError.value ? null : update)
    }
  } finally {
    mainProgress.value -= 1
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
  if (!equals(organization.value!.applications, applications.value)) {
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
    applications: applications.value,
  }
  await onSubmit(payload, "applications", applicationsUpdated, applicationsUnexpectedError)
}

async function onEnableApplicationTemplate(applicationTemplate: DeepReadonly<ApplicationTemplate>) {
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

// TODO: Remember previous secrets and reuse them if an add application is removed and then added back.
// TODO: Provide explicit buttons to rotate each secret.

const WithApplicationTemplateDocument = WithDocument<ApplicationTemplate>
</script>

<template>
  <Teleport to="header">
    <NavBar></NavBar>
  </Teleport>
  <div class="w-full flex flex-col items-center mt-12 sm:mt-[4.5rem] border-t border-transparent">
    <div class="grid auto-rows-auto grid-cols-[minmax(0,_65ch)] m-1 sm:m-4 gap-1 sm:gap-4">
      <div class="w-full rounded border bg-white p-4 shadow flex flex-col gap-4">
        <div class="flex flex-row items-center">
          <h1 class="text-2xl font-bold">Organization</h1>
        </div>
        <div v-if="dataLoading">Loading...</div>
        <div v-else-if="dataLoadingError" class="text-error-600">Unexpected error. Please try again.</div>
        <template v-else>
          <form class="flex flex-col" novalidate @submit.prevent="onBasicSubmit">
            <label for="name" class="mb-1">Organization name</label>
            <InputText id="name" v-model="name" class="flex-grow flex-auto min-w-0" :readonly="mainProgress > 0 || !metadata.can_update" required />
            <label for="description" class="mb-1 mt-4">Description<span v-if="metadata.can_update" class="text-neutral-500 italic text-sm"> (optional)</span></label>
            <TextArea id="description" v-model="description" class="flex-grow flex-auto min-w-0" :readonly="mainProgress > 0 || !metadata.can_update" />
            <div v-if="basicUnexpectedError" class="mt-4 text-error-600">Unexpected error. Please try again.</div>
            <div v-else-if="basicUpdated" class="mt-4 text-success-600">Organization updated successfully.</div>
            <div v-if="metadata.can_update" class="mt-4 flex flex-row justify-end">
              <!--
                Button is on purpose not disabled on unexpectedError so that user can retry.
              -->
              <Button type="submit" primary :disabled="!canBasicSubmit() || mainProgress > 0">Update</Button>
            </div>
          </form>
          <h2 v-if="applications.length" class="text-xl font-bold">Added applications</h2>
          <div v-if="applicationsUnexpectedError" class="text-error-600">Unexpected error. Please try again.</div>
          <div v-else-if="applicationsUpdated" class="text-success-600">Added applications updated successfully.</div>
          <form v-if="applications.length" class="flex flex-col" novalidate @submit.prevent="onApplicationsSubmit">
            <ul>
              <li v-for="(application, i) in applications" :key="application.id || i" class="flex flex-col mb-4">
                <!--
                  Embedded application template does not contain list of admins so we have fetch
                  the current list. But we can just check the metadata.
                -->
                <WithApplicationTemplateDocument :id="application.applicationTemplate.id" name="ApplicationTemplate">
                  <template #default="{ metadata: meta, url }">
                    <h3 class="text-lg flex flex-row items-center gap-1">
                      <router-link :to="{ name: 'ApplicationTemplate', params: { id: application.applicationTemplate.id } }" :data-url="url" class="link">{{
                        application.applicationTemplate.name
                      }}</router-link>
                      <span v-if="meta.can_update" class="rounded-sm bg-slate-100 py-0.5 px-1.5 text-gray-600 shadow-sm text-sm leading-none">admin</span>
                    </h3>
                  </template>
                </WithApplicationTemplateDocument>
                <div class="ml-6">
                  <div v-if="application.applicationTemplate.description" class="mt-4">{{ application.applicationTemplate.description }}</div>
                  <fieldset v-if="application.values.length" class="mt-4">
                    <legend class="font-bold">Configuration</legend>
                    <ol>
                      <li v-for="(value, j) in application.values" :key="value.name" class="flex flex-col mt-4">
                        <code>{{ value.name }}</code>
                        <div v-if="getValueDescription(application, value.name)" class="ml-6">{{ getValueDescription(application, value.name) }}</div>
                        <InputText
                          :id="`application-${i}-values-${j}`"
                          v-model="value.value"
                          class="flex-grow flex-auto min-w-0 ml-6 mt-1"
                          :readonly="mainProgress > 0 || !metadata.can_update"
                          required
                        />
                      </li>
                    </ol>
                  </fieldset>
                  <h4 v-if="application.clientsPublic.length" class="font-bold mt-4">Public clients</h4>
                  <ol v-if="application.clientsPublic.length">
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
                  <h4 v-if="application.clientsBackend.length" class="font-bold mt-4">Backend clients</h4>
                  <ol v-if="application.clientsBackend.length">
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
                  <h4 v-if="application.clientsService.length" class="font-bold mt-4">Service clients</h4>
                  <ol v-if="application.clientsService.length">
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
                    <div v-if="metadata.can_update" class="flex flex-row gap-4">
                      <Button type="button" :disabled="mainProgress > 0" @click.prevent="application.active = false">Disable</Button>
                      <Button type="button" :disabled="mainProgress > 0" @click.prevent="applications.splice(i, 1)">Remove</Button>
                    </div>
                  </div>
                  <div v-else class="flex flew-row justify-between items-center gap-4 mt-4">
                    <div>Status: <strong>disabled</strong></div>
                    <div v-if="metadata.can_update" class="flex flex-row gap-4">
                      <Button type="button" :disabled="mainProgress > 0" @click.prevent="application.active = true">Activate</Button>
                      <Button type="button" :disabled="mainProgress > 0" @click.prevent="applications.splice(i, 1)">Remove</Button>
                    </div>
                  </div>
                </div>
              </li>
            </ul>
            <div v-if="metadata.can_update" class="flex flex-row justify-end">
              <!--
                Button is on purpose not disabled on unexpectedError so that user can retry.
              -->
              <Button id="applications-update" type="submit" primary :disabled="!canApplicationsSubmit() || mainProgress > 0">Update</Button>
            </div>
          </form>
          <h2 v-if="metadata.can_update" class="text-xl font-bold">Available applications</h2>
          <ul v-if="metadata.can_update" class="flex flex-col gap-4">
            <li v-for="applicationTemplate in availableApplicationTemplates" :key="applicationTemplate.id" class="flex flex-col gap-4">
              <WithApplicationTemplateDocument :id="applicationTemplate.id" name="ApplicationTemplate">
                <template #default="{ doc, metadata: meta, url }">
                  <div class="flex flex-row justify-between items-center gap-4">
                    <h3 class="text-lg flex flex-row items-center gap-1">
                      <router-link :to="{ name: 'ApplicationTemplate', params: { id: applicationTemplate.id } }" :data-url="url" class="link">{{ doc.name }}</router-link>
                      <span v-if="meta.can_update" class="rounded-sm bg-slate-100 py-0.5 px-1.5 text-gray-600 shadow-sm text-sm leading-none">admin</span>
                    </h3>
                    <Button type="button" :disabled="mainProgress > 0" primary @click.prevent="onEnableApplicationTemplate(doc)">Add</Button>
                  </div>
                  <div v-if="doc.description" class="ml-4">{{ doc.description }}</div>
                </template>
              </WithApplicationTemplateDocument>
            </li>
          </ul>
        </template>
      </div>
    </div>
  </div>
  <Teleport to="footer">
    <Footer />
  </Teleport>
</template>
