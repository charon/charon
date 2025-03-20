<script setup lang="ts">
import type { Ref } from "vue"
import type {
  ApplicationTemplate,
  ApplicationTemplateClientBackend,
  ApplicationTemplateClientPublic,
  ApplicationTemplateClientService,
  Metadata,
  Variable,
} from "@/types"

import { nextTick, onBeforeMount, onBeforeUnmount, ref, watch } from "vue"
import { useRouter } from "vue-router"
import InputText from "@/components/InputText.vue"
import TextArea from "@/components/TextArea.vue"
import Button from "@/components/Button.vue"
import RadioButton from "@/components/RadioButton.vue"
import NavBar from "@/partials/NavBar.vue"
import Footer from "@/partials/Footer.vue"
import { getURL, postJSON } from "@/api"
import { clone, equals } from "@/utils"
import { injectProgress } from "@/progress"

const props = defineProps<{
  id: string
}>()

const router = useRouter()

const progress = injectProgress()

const abortController = new AbortController()
const dataLoading = ref(true)
const dataLoadingError = ref("")
const applicationTemplate = ref<ApplicationTemplate | null>(null)
const metadata = ref<Metadata>({})

const basicUnexpectedError = ref("")
const basicUpdated = ref(false)
const name = ref("")
const description = ref("")
const homepageTemplate = ref("")
const idScopes = ref<string[]>([])

const variablesUnexpectedError = ref("")
const variablesUpdated = ref(false)
const variables = ref<Variable[]>([])

const clientsPublicUnexpectedError = ref("")
const clientsPublicUpdated = ref(false)
const clientsPublic = ref<ApplicationTemplateClientPublic[]>([])

const clientsBackendUnexpectedError = ref("")
const clientsBackendUpdated = ref(false)
const clientsBackend = ref<ApplicationTemplateClientBackend[]>([])

const clientsServiceUnexpectedError = ref("")
const clientsServiceUpdated = ref(false)
const clientsService = ref<ApplicationTemplateClientService[]>([])

function resetOnInteraction() {
  // We reset flags and errors on interaction.
  basicUnexpectedError.value = ""
  basicUpdated.value = false
  variablesUnexpectedError.value = ""
  variablesUpdated.value = false
  clientsPublicUnexpectedError.value = ""
  clientsPublicUpdated.value = false
  clientsBackendUnexpectedError.value = ""
  clientsBackendUpdated.value = false
  clientsServiceUnexpectedError.value = ""
  clientsServiceUpdated.value = false
  // dataLoading and dataLoadingError are not listed here on
  // purpose because they are used only on mount.
}

let watchInteractionStop: (() => void) | null = null
function initWatchInteraction() {
  if (abortController.signal.aborted) {
    return
  }

  const stop = watch([name, description, homepageTemplate, idScopes, variables, clientsPublic, clientsBackend, clientsService], resetOnInteraction, { deep: true })
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

async function loadData(update: "init" | "basic" | "variables" | "clientsPublic" | "clientsBackend" | "clientsService" | null, dataError: Ref<string> | null) {
  if (abortController.signal.aborted) {
    return
  }

  watchInteractionStop!()
  progress.value += 1
  try {
    const url = router.apiResolve({
      name: "ApplicationTemplateGet",
      params: {
        id: props.id,
      },
    }).href

    const response = await getURL<ApplicationTemplate>(url, null, abortController.signal, progress)
    if (abortController.signal.aborted) {
      return
    }

    applicationTemplate.value = response.doc
    metadata.value = response.metadata

    // We have to make copies so that we break reactivity link with data.doc.
    if (update === "init" || update === "basic") {
      name.value = response.doc.name
      description.value = response.doc.description
      homepageTemplate.value = response.doc.homepageTemplate
      idScopes.value = clone(response.doc.idScopes)
    }
    if (update === "init" || update === "variables") {
      variables.value = clone(response.doc.variables)
    }
    if (update === "init" || update === "clientsPublic") {
      clientsPublic.value = clone(response.doc.clientsPublic)
    }
    if (update === "init" || update === "clientsBackend") {
      clientsBackend.value = clone(response.doc.clientsBackend)
    }
    if (update === "init" || update === "clientsService") {
      clientsService.value = clone(response.doc.clientsService)
    }
  } catch (error) {
    if (abortController.signal.aborted) {
      return
    }
    // TODO: 404 should be shown differently, but probably in the same way for all 404.
    console.error("ApplicationTemplateGet.loadData", error)
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

async function onSubmit(
  payload: ApplicationTemplate,
  update: "basic" | "variables" | "clientsPublic" | "clientsBackend" | "clientsService",
  updated: Ref<boolean>,
  unexpectedError: Ref<string>,
) {
  if (abortController.signal.aborted) {
    return
  }

  resetOnInteraction()

  progress.value += 1
  try {
    try {
      const url = router.apiResolve({
        name: "ApplicationTemplateUpdate",
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
      console.error("ApplicationTemplateGet.onSubmit", error)
      unexpectedError.value = `${error}`
    } finally {
      // We update applicationTemplate state even on errors,
      // but do not update individual fields on errors.
      // If there is already an error, we ignore any data loading error.
      await loadData(unexpectedError.value ? null : update, unexpectedError.value ? null : unexpectedError)
    }
  } finally {
    progress.value -= 1
  }
}

function splitSpace(str: string): string[] {
  const out = str.split(" ")
  if (out.length === 1 && out[0] === "") {
    return []
  }
  return out
}

function addRedirectUriTemplate(client: { redirectUriTemplates: string[] }, idPrefix: string) {
  client.redirectUriTemplates.push("")

  nextTick(() => {
    document.getElementById(`${idPrefix}${client.redirectUriTemplates.length - 1}`)?.focus()
  })
}

function canBasicSubmit(): boolean {
  // Required fields.
  if (!name.value) {
    return false
  }

  // Anything changed?
  if (applicationTemplate.value!.name !== name.value) {
    return true
  }
  if (applicationTemplate.value!.description !== description.value) {
    return true
  }
  if (applicationTemplate.value!.homepageTemplate !== homepageTemplate.value) {
    return true
  }
  if (!equals(applicationTemplate.value!.idScopes, idScopes.value)) {
    return true
  }

  return false
}

async function onBasicSubmit() {
  const payload: ApplicationTemplate = {
    // We update only basic fields.
    id: props.id,
    name: name.value,
    description: description.value,
    homepageTemplate: homepageTemplate.value,
    idScopes: idScopes.value,
    variables: applicationTemplate.value!.variables,
    clientsPublic: applicationTemplate.value!.clientsPublic,
    clientsBackend: applicationTemplate.value!.clientsBackend,
    clientsService: applicationTemplate.value!.clientsService,
  }
  await onSubmit(payload, "basic", basicUpdated, basicUnexpectedError)
}

function canVariablesSubmit(): boolean {
  // Required fields.
  for (const variable of variables.value) {
    if (!variable.name) {
      return false
    }
  }

  // Anything changed?
  if (!equals(applicationTemplate.value!.variables, variables.value)) {
    return true
  }

  return false
}

async function onVariablesSubmit() {
  const payload: ApplicationTemplate = {
    // We update only variables.
    id: props.id,
    name: applicationTemplate.value!.name,
    description: applicationTemplate.value!.description,
    homepageTemplate: applicationTemplate.value!.homepageTemplate,
    idScopes: applicationTemplate.value!.idScopes,
    variables: variables.value,
    clientsPublic: applicationTemplate.value!.clientsPublic,
    clientsBackend: applicationTemplate.value!.clientsBackend,
    clientsService: applicationTemplate.value!.clientsService,
  }
  await onSubmit(payload, "variables", variablesUpdated, variablesUnexpectedError)
}

function onAddVariable() {
  if (abortController.signal.aborted) {
    return
  }

  // No need to call resetOnInteraction here because we modify variables
  // which we watch to call resetOnInteraction.

  variables.value.push({
    name: "",
    type: "uriPrefix",
    description: "",
  })

  nextTick(() => {
    document.getElementById(`variable-${variables.value.length - 1}-name`)?.focus()
  })
}

function canClientsPublicSubmit(): boolean {
  // Required fields.
  for (const client of clientsPublic.value) {
    if (!client.redirectUriTemplates.length) {
      return false
    }
    for (const template of client.redirectUriTemplates) {
      if (!template) {
        return false
      }
    }
  }

  // Anything changed?
  if (!equals(applicationTemplate.value!.clientsPublic, clientsPublic.value)) {
    return true
  }

  return false
}

async function onClientsPublicSubmit() {
  const payload: ApplicationTemplate = {
    // We update only clientsPublic.
    id: props.id,
    name: applicationTemplate.value!.name,
    description: applicationTemplate.value!.description,
    homepageTemplate: applicationTemplate.value!.homepageTemplate,
    idScopes: applicationTemplate.value!.idScopes,
    variables: applicationTemplate.value!.variables,
    clientsPublic: clientsPublic.value,
    clientsBackend: applicationTemplate.value!.clientsBackend,
    clientsService: applicationTemplate.value!.clientsService,
  }
  await onSubmit(payload, "clientsPublic", clientsPublicUpdated, clientsPublicUnexpectedError)
}

function onAddClientPublic() {
  if (abortController.signal.aborted) {
    return
  }

  // No need to call resetOnInteraction here because we modify variables
  // which we watch to call resetOnInteraction.

  // If there is standard uriBase variable, we populate with example redirect.
  for (const variable of variables.value) {
    if (variable.name === "uriBase") {
      clientsPublic.value.push({
        description: "",
        additionalScopes: [],
        redirectUriTemplates: ["{uriBase}/oidc/redirect"],
      })

      nextTick(() => {
        document.getElementById(`client-public-${clientsPublic.value.length - 1}-redirectUriTemplates-0`)?.focus()
      })

      return
    }
  }

  clientsPublic.value.push({
    description: "",
    additionalScopes: [],
    redirectUriTemplates: [],
  })

  nextTick(() => {
    document.getElementById(`client-public-${clientsPublic.value.length - 1}-addTemplate`)?.focus()
  })
}

function canClientsBackendSubmit(): boolean {
  // Required fields.
  for (const client of clientsBackend.value) {
    if (!client.redirectUriTemplates.length) {
      return false
    }
    for (const template of client.redirectUriTemplates) {
      if (!template) {
        return false
      }
    }
  }

  // Anything changed?
  if (!equals(applicationTemplate.value!.clientsBackend, clientsBackend.value)) {
    return true
  }

  return false
}

async function onClientsBackendSubmit() {
  const payload: ApplicationTemplate = {
    // We update only clientsBackend.
    id: props.id,
    name: applicationTemplate.value!.name,
    description: applicationTemplate.value!.description,
    homepageTemplate: applicationTemplate.value!.homepageTemplate,
    idScopes: applicationTemplate.value!.idScopes,
    variables: applicationTemplate.value!.variables,
    clientsPublic: applicationTemplate.value!.clientsPublic,
    clientsBackend: clientsBackend.value,
    clientsService: applicationTemplate.value!.clientsService,
  }
  await onSubmit(payload, "clientsBackend", clientsBackendUpdated, clientsBackendUnexpectedError)
}

function onAddClientBackend() {
  if (abortController.signal.aborted) {
    return
  }

  // No need to call resetOnInteraction here because we modify variables
  // which we watch to call resetOnInteraction.

  // If there is standard uriBase variable, we populate with example redirect.
  for (const variable of variables.value) {
    if (variable.name === "uriBase") {
      clientsBackend.value.push({
        description: "",
        additionalScopes: [],
        tokenEndpointAuthMethod: "client_secret_post",
        redirectUriTemplates: ["{uriBase}/oidc/redirect"],
      })

      nextTick(() => {
        document.getElementById(`client-backend-${clientsBackend.value.length - 1}-redirectUriTemplates-0`)?.focus()
      })

      return
    }
  }

  clientsBackend.value.push({
    description: "",
    additionalScopes: [],
    tokenEndpointAuthMethod: "client_secret_post",
    redirectUriTemplates: [],
  })

  nextTick(() => {
    document.getElementById(`client-backend-${clientsBackend.value.length - 1}-addTemplate`)?.focus()
  })
}

function canClientsServiceSubmit(): boolean {
  // Anything changed?
  if (!equals(applicationTemplate.value!.clientsService, clientsService.value)) {
    return true
  }

  return false
}

async function onClientsServiceSubmit() {
  const payload: ApplicationTemplate = {
    // We update only clientsService.
    id: props.id,
    name: applicationTemplate.value!.name,
    description: applicationTemplate.value!.description,
    homepageTemplate: applicationTemplate.value!.homepageTemplate,
    idScopes: applicationTemplate.value!.idScopes,
    variables: applicationTemplate.value!.variables,
    clientsPublic: applicationTemplate.value!.clientsPublic,
    clientsBackend: applicationTemplate.value!.clientsBackend,
    clientsService: clientsService.value,
  }
  await onSubmit(payload, "clientsService", clientsServiceUpdated, clientsServiceUnexpectedError)
}

function onAddClientService() {
  if (abortController.signal.aborted) {
    return
  }

  // No need to call resetOnInteraction here because we modify variables
  // which we watch to call resetOnInteraction.

  clientsService.value.push({
    description: "",
    additionalScopes: [],
    tokenEndpointAuthMethod: "client_secret_post",
  })

  nextTick(() => {
    document.getElementById(`client-service-${clientsService.value.length - 1}-tokenEndpointAuthMethod-client_secret_post`)?.focus()
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
          <h1 class="text-2xl font-bold">Application template</h1>
        </div>
        <div v-if="dataLoading">Loading...</div>
        <div v-else-if="dataLoadingError" class="text-error-600">Unexpected error. Please try again.</div>
        <template v-else>
          <form class="flex flex-col" novalidate @submit.prevent="onBasicSubmit">
            <label for="name" class="mb-1">Application template name</label>
            <InputText id="name" v-model="name" class="flex-grow flex-auto min-w-0" :readonly="!metadata.can_update" :progress="progress" required />
            <label for="description" class="mb-1 mt-4">Description<span v-if="metadata.can_update" class="text-neutral-500 italic text-sm"> (optional)</span></label>
            <TextArea id="description" v-model="description" class="flex-grow flex-auto min-w-0" :readonly="!metadata.can_update" :progress="progress" />
            <label for="homepageTemplate" class="mb-1 mt-4">Homepage template</label>
            <InputText
              id="homepageTemplate"
              v-model="homepageTemplate"
              class="flex-grow flex-auto min-w-0"
              :readonly="!metadata.can_update"
              :progress="progress"
              required
            />
            <label for="idScopes" class="mb-1 mt-4"
              >Space-separated OpenID scopes the application might request<span v-if="metadata.can_update" class="text-neutral-500 italic text-sm">
                (optional)</span
              ></label
            >
            <TextArea
              id="idScopes"
              :model-value="idScopes.join(' ')"
              class="flex-grow flex-auto min-w-0"
              :readonly="!metadata.can_update"
              :progress="progress"
              @update:model-value="(v) => (idScopes = splitSpace(v))"
            />
            <div v-if="basicUnexpectedError" class="mt-4 text-error-600">Unexpected error. Please try again.</div>
            <div v-else-if="basicUpdated" class="mt-4 text-success-600">Application template updated successfully.</div>
            <div v-if="metadata.can_update" class="mt-4 flex flex-row justify-end">
              <!--
                Button is on purpose not disabled on unexpectedError so that user can retry.
              -->
              <Button type="submit" primary :disabled="!canBasicSubmit()" :progress="progress">Update</Button>
            </div>
          </form>
          <h2 class="text-xl font-bold">Variables</h2>
          <div v-if="variablesUnexpectedError" class="text-error-600">Unexpected error. Please try again.</div>
          <div v-else-if="variablesUpdated" class="text-success-600">Variables updated successfully.</div>
          <form class="flex flex-col" novalidate @submit.prevent="onVariablesSubmit">
            <ol>
              <li v-for="(variable, i) in variables" :key="i" class="grid auto-rows-auto grid-cols-[min-content,auto] gap-x-4 mb-4">
                <div>{{ i + 1 }}.</div>
                <div class="flex flex-col">
                  <label :for="`variable-${i}-name`" class="mb-1">Name</label>
                  <InputText
                    :id="`variable-${i}-name`"
                    v-model="variable.name"
                    class="flex-grow flex-auto min-w-0"
                    :readonly="!metadata.can_update"
                    :progress="progress"
                    required
                  />
                  <label :for="`variable-${i}-description`" class="mb-1 mt-4"
                    >Description<span v-if="metadata.can_update" class="text-neutral-500 italic text-sm"> (optional)</span></label
                  >
                  <TextArea
                    :id="`variable-${i}-description`"
                    v-model="variable.description"
                    class="flex-grow flex-auto min-w-0"
                    :readonly="!metadata.can_update"
                    :progress="progress"
                  />
                  <div v-if="metadata.can_update" class="mt-4 flex flex-row justify-end">
                    <Button type="button" :progress="progress" @click.prevent="variables.splice(i, 1)">Remove</Button>
                  </div>
                </div>
              </li>
            </ol>
            <div v-if="metadata.can_update" class="flex flex-row justify-between gap-4">
              <Button type="button" @click.prevent="onAddVariable">Add variable</Button>
              <!--
                Button is on purpose not disabled on unexpectedError so that user can retry.
              -->
              <Button type="submit" primary :disabled="!canVariablesSubmit()" :progress="progress">Update</Button>
            </div>
          </form>
          <h2 class="text-xl font-bold">Public clients</h2>
          <div v-if="clientsPublicUnexpectedError" class="text-error-600">Unexpected error. Please try again.</div>
          <div v-else-if="clientsPublicUpdated" class="text-success-600">Public clients updated successfully.</div>
          <form class="flex flex-col" novalidate @submit.prevent="onClientsPublicSubmit">
            <ol>
              <li v-for="(client, i) in clientsPublic" :key="i" class="grid auto-rows-auto grid-cols-[min-content,auto] gap-x-4 mb-4">
                <div>{{ i + 1 }}.</div>
                <div class="flex flex-col">
                  <fieldset>
                    <legend>OIDC redirect URI templates</legend>
                    <ol>
                      <li v-for="(_, j) in client.redirectUriTemplates" :key="j" class="grid auto-rows-auto grid-cols-[min-content,auto] gap-x-4 mt-4">
                        <div>{{ j + 1 }}.</div>
                        <div class="flex flex-row gap-4">
                          <InputText
                            :id="`client-public-${i}-redirectUriTemplates-${j}`"
                            v-model="client.redirectUriTemplates[j]"
                            class="flex-grow flex-auto min-w-0"
                            :readonly="!metadata.can_update"
                            :progress="progress"
                            required
                          />
                          <Button v-if="metadata.can_update" type="button" :progress="progress" @click.prevent="client.redirectUriTemplates.splice(j, 1)">Remove</Button>
                        </div>
                      </li>
                    </ol>
                  </fieldset>
                  <div v-if="metadata.can_update" class="mt-4 flex flex-row justify-start">
                    <Button
                      :id="`client-public-${i}-addTemplate`"
                      type="button"
                      :progress="progress"
                      @click.prevent="addRedirectUriTemplate(client, `client-public-${i}-redirectUriTemplates-`)"
                      >Add redirect URI</Button
                    >
                  </div>
                  <label :for="`client-public-${i}-description`" class="mb-1 mt-4"
                    >Description<span v-if="metadata.can_update" class="text-neutral-500 italic text-sm"> (optional)</span></label
                  >
                  <TextArea
                    :id="`client-public-${i}-description`"
                    v-model="client.description"
                    class="flex-grow flex-auto min-w-0"
                    :readonly="!metadata.can_update"
                    :progress="progress"
                  />
                  <label :for="`client-public-${i}-additionalScopes`" class="mb-1 mt-4"
                    >Space-separated additional scopes the client might request<span v-if="metadata.can_update" class="text-neutral-500 italic text-sm">
                      (optional)</span
                    ></label
                  >
                  <TextArea
                    :id="`client-public-${i}-additionalScopes`"
                    :model-value="client.additionalScopes.join(' ')"
                    class="flex-grow flex-auto min-w-0"
                    :readonly="!metadata.can_update"
                    :progress="progress"
                    @update:model-value="(v) => (client.additionalScopes = splitSpace(v))"
                  />
                  <div v-if="metadata.can_update" class="mt-4 flex flex-row justify-end">
                    <Button type="button" :progress="progress" @click.prevent="clientsPublic.splice(i, 1)">Remove</Button>
                  </div>
                </div>
              </li>
            </ol>
            <div v-if="metadata.can_update" class="flex flex-row justify-between gap-4">
              <Button type="button" @click.prevent="onAddClientPublic">Add client</Button>
              <!--
                Button is on purpose not disabled on unexpectedError so that user can retry.
              -->
              <Button type="submit" primary :disabled="!canClientsPublicSubmit()" :progress="progress">Update</Button>
            </div>
          </form>
          <h2 class="text-xl font-bold">Backend clients</h2>
          <div v-if="clientsBackendUnexpectedError" class="text-error-600">Unexpected error. Please try again.</div>
          <div v-else-if="clientsBackendUpdated" class="text-success-600">Backend clients updated successfully.</div>
          <form class="flex flex-col" novalidate @submit.prevent="onClientsBackendSubmit">
            <ol>
              <li v-for="(client, i) in clientsBackend" :key="i" class="grid auto-rows-auto grid-cols-[min-content,auto] gap-x-4 mb-4">
                <div>{{ i + 1 }}.</div>
                <div class="flex flex-col">
                  <fieldset>
                    <legend>OIDC redirect URI templates</legend>
                    <ol>
                      <li v-for="(_, j) in client.redirectUriTemplates" :key="j" class="grid auto-rows-auto grid-cols-[min-content,auto] gap-x-4 mt-4">
                        <div>{{ j + 1 }}.</div>
                        <div class="flex flex-row gap-4">
                          <InputText
                            :id="`client-backend-${i}-redirectUriTemplates-${j}`"
                            v-model="client.redirectUriTemplates[j]"
                            class="flex-grow flex-auto min-w-0"
                            :readonly="!metadata.can_update"
                            :progress="progress"
                            required
                          />
                          <Button v-if="metadata.can_update" type="button" :progress="progress" @click.prevent="client.redirectUriTemplates.splice(j, 1)">Remove</Button>
                        </div>
                      </li>
                    </ol>
                  </fieldset>
                  <div v-if="metadata.can_update" class="mt-4 flex flex-row justify-start">
                    <Button
                      :id="`client-backend-${i}-addTemplate`"
                      type="button"
                      :progress="progress"
                      @click.prevent="addRedirectUriTemplate(client, `client-backend-${i}-redirectUriTemplates-`)"
                      >Add redirect URI</Button
                    >
                  </div>
                  <fieldset class="mt-4">
                    <legend class="mb-1">Token endpoint authentication method</legend>
                    <div class="flex flex-col gap-1">
                      <div>
                        <RadioButton
                          :id="`client-backend-${i}-tokenEndpointAuthMethod-client_secret_post`"
                          v-model="client.tokenEndpointAuthMethod"
                          value="client_secret_post"
                          :disabled="!metadata.can_update"
                          :progress="progress"
                          class="mx-2"
                        />
                        <label
                          :for="`client-backend-${i}-tokenEndpointAuthMethod-client_secret_post`"
                          :class="progress > 0 || !metadata.can_update ? 'cursor-not-allowed text-gray-600' : 'cursor-pointer'"
                          ><code>client_secret_post</code></label
                        >
                      </div>
                      <div>
                        <RadioButton
                          :id="`client-backend-${i}-tokenEndpointAuthMethod-client_secret_basic`"
                          v-model="client.tokenEndpointAuthMethod"
                          value="client_secret_basic"
                          :disabled="!metadata.can_update"
                          :progress="progress"
                          class="mx-2"
                        />
                        <label
                          :for="`client-backend-${i}-tokenEndpointAuthMethod-client_secret_basic`"
                          :class="progress > 0 || !metadata.can_update ? 'cursor-not-allowed text-gray-600' : 'cursor-pointer'"
                          ><code>client_secret_basic</code></label
                        >
                      </div>
                    </div>
                  </fieldset>
                  <label :for="`client-backend-${i}-description`" class="mb-1 mt-4"
                    >Description<span v-if="metadata.can_update" class="text-neutral-500 italic text-sm"> (optional)</span></label
                  >
                  <TextArea
                    :id="`client-backend-${i}-description`"
                    v-model="client.description"
                    class="flex-grow flex-auto min-w-0"
                    :readonly="!metadata.can_update"
                    :progress="progress"
                  />
                  <label :for="`client-backend-${i}-additionalScopes`" class="mb-1 mt-4"
                    >Space-separated additional scopes the client might request<span v-if="metadata.can_update" class="text-neutral-500 italic text-sm">
                      (optional)</span
                    ></label
                  >
                  <TextArea
                    :id="`client-backend-${i}-additionalScopes`"
                    :model-value="client.additionalScopes.join(' ')"
                    class="flex-grow flex-auto min-w-0"
                    :readonly="!metadata.can_update"
                    :progress="progress"
                    @update:model-value="(v) => (client.additionalScopes = splitSpace(v))"
                  />
                  <div v-if="metadata.can_update" class="mt-4 flex flex-row justify-end">
                    <Button type="button" :progress="progress" @click.prevent="clientsBackend.splice(i, 1)">Remove</Button>
                  </div>
                </div>
              </li>
            </ol>
            <div v-if="metadata.can_update" class="flex flex-row justify-between gap-4">
              <Button type="button" @click.prevent="onAddClientBackend">Add client</Button>
              <!--
                Button is on purpose not disabled on unexpectedError so that user can retry.
              -->
              <Button type="submit" primary :disabled="!canClientsBackendSubmit()" :progress="progress">Update</Button>
            </div>
          </form>
          <h2 class="text-xl font-bold">Service clients</h2>
          <div v-if="clientsServiceUnexpectedError" class="text-error-600">Unexpected error. Please try again.</div>
          <div v-else-if="clientsServiceUpdated" class="text-success-600">Service clients updated successfully.</div>
          <form class="flex flex-col" novalidate @submit.prevent="onClientsServiceSubmit">
            <ol>
              <li v-for="(client, i) in clientsService" :key="i" class="grid auto-rows-auto grid-cols-[min-content,auto] gap-x-4 mb-4">
                <div>{{ i + 1 }}.</div>
                <div class="flex flex-col">
                  <fieldset>
                    <legend class="mb-1">Token endpoint authentication method</legend>
                    <div class="flex flex-col gap-1">
                      <div>
                        <RadioButton
                          :id="`client-service-${i}-tokenEndpointAuthMethod-client_secret_post`"
                          v-model="client.tokenEndpointAuthMethod"
                          value="client_secret_post"
                          :disabled="!metadata.can_update"
                          :progress="progress"
                          class="mx-2"
                        />
                        <label
                          :for="`client-service-${i}-tokenEndpointAuthMethod-client_secret_post`"
                          :class="progress > 0 || !metadata.can_update ? 'cursor-not-allowed text-gray-600' : 'cursor-pointer'"
                          ><code>client_secret_post</code></label
                        >
                      </div>
                      <div>
                        <RadioButton
                          :id="`client-service-${i}-tokenEndpointAuthMethod-client_secret_basic`"
                          v-model="client.tokenEndpointAuthMethod"
                          value="client_secret_basic"
                          :disabled="!metadata.can_update"
                          :progress="progress"
                          class="mx-2"
                        />
                        <label
                          :for="`client-service-${i}-tokenEndpointAuthMethod-client_secret_basic`"
                          :class="progress > 0 || !metadata.can_update ? 'cursor-not-allowed text-gray-600' : 'cursor-pointer'"
                          ><code>client_secret_basic</code></label
                        >
                      </div>
                    </div>
                  </fieldset>
                  <label :for="`client-service-${i}-description`" class="mb-1 mt-4"
                    >Description<span v-if="metadata.can_update" class="text-neutral-500 italic text-sm"> (optional)</span></label
                  >
                  <TextArea
                    :id="`client-service-${i}-description`"
                    v-model="client.description"
                    class="flex-grow flex-auto min-w-0"
                    :readonly="!metadata.can_update"
                    :progress="progress"
                  />
                  <label :for="`client-service-${i}-additionalScopes`" class="mb-1 mt-4"
                    >Space-separated additional scopes the client might request<span v-if="metadata.can_update" class="text-neutral-500 italic text-sm">
                      (optional)</span
                    ></label
                  >
                  <TextArea
                    :id="`client-service-${i}-additionalScopes`"
                    :model-value="client.additionalScopes.join(' ')"
                    class="flex-grow flex-auto min-w-0"
                    :readonly="!metadata.can_update"
                    :progress="progress"
                    @update:model-value="(v) => (client.additionalScopes = splitSpace(v))"
                  />
                  <div v-if="metadata.can_update" class="mt-4 flex flex-row justify-end">
                    <Button type="button" :progress="progress" @click.prevent="clientsService.splice(i, 1)">Remove</Button>
                  </div>
                </div>
              </li>
            </ol>
            <div v-if="metadata.can_update" class="flex flex-row justify-between gap-4">
              <Button type="button" @click.prevent="onAddClientService">Add client</Button>
              <!--
                Button is on purpose not disabled on unexpectedError so that user can retry.
              -->
              <Button type="submit" primary :disabled="!canClientsServiceSubmit()" :progress="progress">Update</Button>
            </div>
          </form>
        </template>
      </div>
    </div>
  </div>
  <Teleport to="footer">
    <Footer />
  </Teleport>
</template>
