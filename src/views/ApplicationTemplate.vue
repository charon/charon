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

import { onBeforeMount, onUnmounted, ref, watch } from "vue"
import { useRouter } from "vue-router"
import InputText from "@/components/InputText.vue"
import TextArea from "@/components/TextArea.vue"
import Button from "@/components/Button.vue"
import RadioButton from "@/components/RadioButton.vue"
import NavBar from "@/components/NavBar.vue"
import Footer from "@/components/Footer.vue"
import { getURL, postURL } from "@/api"
import { clone, equals } from "@/utils"

const props = defineProps<{
  id: string
}>()

const router = useRouter()

const mainProgress = ref(0)
const abortController = new AbortController()
const dataLoading = ref(true)
const dataLoadingError = ref("")
const applicationTemplate = ref<ApplicationTemplate | null>(null)
const metadata = ref<Metadata>({})

const basicUnexpectedError = ref("")
const basicUpdated = ref(false)
const name = ref("")
const description = ref("")
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

watch([name, description, idScopes, variables, clientsPublic, clientsBackend, clientsService], resetOnInteraction, { deep: true })

onUnmounted(() => {
  abortController.abort()
})

async function loadData(init: boolean) {
  mainProgress.value += 1
  try {
    const url = router.apiResolve({
      name: "ApplicationTemplate",
      params: {
        id: props.id,
      },
    }).href
    const data = await getURL<ApplicationTemplate>(url, null, abortController.signal, mainProgress)
    applicationTemplate.value = data.doc
    metadata.value = data.metadata

    if (init) {
      name.value = data.doc.name
      description.value = data.doc.description
      // We have to make copies so that we break reactivity link with data.doc.
      idScopes.value = clone(data.doc.idScopes)
      variables.value = clone(data.doc.variables)
      clientsPublic.value = clone(data.doc.clientsPublic)
      clientsBackend.value = clone(data.doc.clientsBackend)
      clientsService.value = clone(data.doc.clientsService)
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
  }
}

onBeforeMount(async () => {
  await loadData(true)
})

async function onSubmit(payload: ApplicationTemplate, updated: Ref<boolean>, unexpectedError: Ref<string>) {
  resetOnInteraction()

  mainProgress.value += 1
  try {
    try {
      const url = router.apiResolve({
        name: "ApplicationTemplateUpdate",
        params: {
          id: props.id,
        },
      }).href

      await postURL(url, payload, abortController.signal, mainProgress)

      updated.value = true
    } catch (error) {
      if (abortController.signal.aborted) {
        return
      }
      console.error(error)
      unexpectedError.value = `${error}`
    } finally {
      // We update state even on errors.
      await loadData(false)
    }
  } finally {
    mainProgress.value -= 1
  }
}

function splitSpace(str: string): string[] {
  const out = str.split(" ")
  if (out.length === 1 && out[0] === "") {
    return []
  }
  return out
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
    idScopes: idScopes.value,
    variables: applicationTemplate.value!.variables,
    clientsPublic: applicationTemplate.value!.clientsPublic,
    clientsBackend: applicationTemplate.value!.clientsBackend,
    clientsService: applicationTemplate.value!.clientsService,
  }
  await onSubmit(payload, basicUpdated, basicUnexpectedError)
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
    idScopes: applicationTemplate.value!.idScopes,
    variables: variables.value,
    clientsPublic: applicationTemplate.value!.clientsPublic,
    clientsBackend: applicationTemplate.value!.clientsBackend,
    clientsService: applicationTemplate.value!.clientsService,
  }
  await onSubmit(payload, variablesUpdated, variablesUnexpectedError)
}

function onAddVariable() {
  // No need to call resetOnInteraction here because we modify variables
  // which we watch to call resetOnInteraction.

  variables.value.push({
    name: "",
    type: "uriPrefix",
    description: "",
  })
}

function canClientsPublicSubmit(): boolean {
  // Required fields.
  for (const client of clientsPublic.value) {
    if (!client.redirectUriTemplates.length) {
      return false
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
    idScopes: applicationTemplate.value!.idScopes,
    variables: applicationTemplate.value!.variables,
    clientsPublic: clientsPublic.value,
    clientsBackend: applicationTemplate.value!.clientsBackend,
    clientsService: applicationTemplate.value!.clientsService,
  }
  await onSubmit(payload, variablesUpdated, variablesUnexpectedError)
}

function onAddClientPublic() {
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
      return
    }
  }

  clientsPublic.value.push({
    description: "",
    additionalScopes: [],
    redirectUriTemplates: [],
  })
}

function canClientsBackendSubmit(): boolean {
  // Required fields.
  for (const client of clientsBackend.value) {
    if (!client.redirectUriTemplates.length) {
      return false
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
    idScopes: applicationTemplate.value!.idScopes,
    variables: applicationTemplate.value!.variables,
    clientsPublic: applicationTemplate.value!.clientsPublic,
    clientsBackend: clientsBackend.value,
    clientsService: applicationTemplate.value!.clientsService,
  }
  await onSubmit(payload, variablesUpdated, variablesUnexpectedError)
}

function onAddClientBackend() {
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
      return
    }
  }

  clientsBackend.value.push({
    description: "",
    additionalScopes: [],
    tokenEndpointAuthMethod: "client_secret_post",
    redirectUriTemplates: [],
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
    idScopes: applicationTemplate.value!.idScopes,
    variables: applicationTemplate.value!.variables,
    clientsPublic: applicationTemplate.value!.clientsPublic,
    clientsBackend: applicationTemplate.value!.clientsBackend,
    clientsService: clientsService.value,
  }
  await onSubmit(payload, variablesUpdated, variablesUnexpectedError)
}

function onAddClientService() {
  // No need to call resetOnInteraction here because we modify variables
  // which we watch to call resetOnInteraction.

  // If there is standard uriBase variable, we populate with example redirect.
  for (const variable of variables.value) {
    if (variable.name === "uriBase") {
      clientsService.value.push({
        description: "",
        additionalScopes: [],
        tokenEndpointAuthMethod: "client_secret_post",
      })
      return
    }
  }

  clientsService.value.push({
    description: "",
    additionalScopes: [],
    tokenEndpointAuthMethod: "client_secret_post",
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
            <InputText id="name" v-model="name" class="flex-grow flex-auto min-w-0" :readonly="mainProgress > 0 || !metadata.can_update" required />
            <label for="description" class="mb-1 mt-4">Description<span v-if="metadata.can_update" class="text-neutral-500 italic text-sm"> (optional)</span></label>
            <TextArea id="description" v-model="description" class="flex-grow flex-auto min-w-0" :readonly="mainProgress > 0 || !metadata.can_update" />
            <label for="idScopes" class="mb-1 mt-4"
              >Space-separated Charon ID scopes the application might request<span v-if="metadata.can_update" class="text-neutral-500 italic text-sm">
                (optional)</span
              ></label
            >
            <TextArea
              id="idScopes"
              :model-value="idScopes.join(' ')"
              class="flex-grow flex-auto min-w-0"
              :readonly="mainProgress > 0 || !metadata.can_update"
              @update:model-value="(v) => (idScopes = splitSpace(v))"
            />
            <div v-if="basicUnexpectedError" class="mt-4 text-error-600">Unexpected error. Please try again.</div>
            <div v-else-if="basicUpdated" class="mt-4 text-success-600">Application template updated successfully.</div>
            <div v-if="metadata.can_update" class="mt-4 flex flex-row justify-end">
              <!--
              Button is on purpose not disabled on unexpectedError so that user can retry.
            -->
              <Button type="submit" primary :disabled="!canBasicSubmit() || mainProgress > 0">Update</Button>
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
                    :readonly="mainProgress > 0 || !metadata.can_update"
                    required
                  />
                  <label :for="`variable-${i}-description`" class="mb-1 mt-4"
                    >Description<span v-if="metadata.can_update" class="text-neutral-500 italic text-sm"> (optional)</span></label
                  >
                  <TextArea
                    :id="`variable-${i}-description`"
                    v-model="variable.description"
                    class="flex-grow flex-auto min-w-0"
                    :readonly="mainProgress > 0 || !metadata.can_update"
                  />
                  <div v-if="metadata.can_update" class="mt-4 flex flex-row justify-end">
                    <Button type="button" :disabled="mainProgress > 0" @click.prevent="variables.splice(i, 1)">Remove</Button>
                  </div>
                </div>
              </li>
            </ol>
            <div v-if="metadata.can_update" class="flex flex-row justify-between gap-4">
              <Button type="button" @click.prevent="onAddVariable">Add variable</Button>
              <!--
                Button is on purpose not disabled on unexpectedError so that user can retry.
              -->
              <Button type="submit" primary :disabled="!canVariablesSubmit() || mainProgress > 0">Update</Button>
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
                            v-model="client.redirectUriTemplates[j]"
                            class="flex-grow flex-auto min-w-0"
                            :readonly="mainProgress > 0 || !metadata.can_update"
                            required
                          />
                          <Button v-if="metadata.can_update" type="button" :disabled="mainProgress > 0" @click.prevent="client.redirectUriTemplates.splice(j, 1)"
                            >Remove</Button
                          >
                        </div>
                      </li>
                    </ol>
                  </fieldset>
                  <div v-if="metadata.can_update" class="mt-4 flex flex-row justify-start">
                    <Button type="button" :disabled="mainProgress > 0" @click.prevent="client.redirectUriTemplates.push('')">Add template</Button>
                  </div>
                  <label :for="`client-public-${i}-description`" class="mb-1 mt-4"
                    >Description<span v-if="metadata.can_update" class="text-neutral-500 italic text-sm"> (optional)</span></label
                  >
                  <TextArea
                    :id="`client-public-${i}-description`"
                    v-model="client.description"
                    class="flex-grow flex-auto min-w-0"
                    :readonly="mainProgress > 0 || !metadata.can_update"
                  />
                  <label :for="`client-public-${i}-additionalScopes`" class="mb-1 mt-4"
                    >Space-separated additional scopes the application might request<span v-if="metadata.can_update" class="text-neutral-500 italic text-sm">
                      (optional)</span
                    ></label
                  >
                  <TextArea
                    id="client-public-${i}-additionalScopes"
                    :model-value="client.additionalScopes.join(' ')"
                    class="flex-grow flex-auto min-w-0"
                    :readonly="mainProgress > 0 || !metadata.can_update"
                    @update:model-value="(v) => (client.additionalScopes = splitSpace(v))"
                  />
                  <div v-if="metadata.can_update" class="mt-4 flex flex-row justify-end">
                    <Button type="button" :disabled="mainProgress > 0" @click.prevent="clientsPublic.splice(i, 1)">Remove</Button>
                  </div>
                </div>
              </li>
            </ol>
            <div v-if="metadata.can_update" class="flex flex-row justify-between gap-4">
              <Button type="button" @click.prevent="onAddClientPublic">Add client</Button>
              <!--
                Button is on purpose not disabled on unexpectedError so that user can retry.
              -->
              <Button type="submit" primary :disabled="!canClientsPublicSubmit() || mainProgress > 0">Update</Button>
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
                            v-model="client.redirectUriTemplates[j]"
                            class="flex-grow flex-auto min-w-0"
                            :readonly="mainProgress > 0 || !metadata.can_update"
                            required
                          />
                          <Button v-if="metadata.can_update" type="button" :disabled="mainProgress > 0" @click.prevent="client.redirectUriTemplates.splice(j, 1)"
                            >Remove</Button
                          >
                        </div>
                      </li>
                    </ol>
                  </fieldset>
                  <div v-if="metadata.can_update" class="mt-4 flex flex-row justify-start">
                    <Button type="button" :disabled="mainProgress > 0" @click.prevent="client.redirectUriTemplates.push('')">Add template</Button>
                  </div>
                  <fieldset class="mt-4">
                    <legend class="mb-1">Token endpoint authentication method</legend>
                    <div class="flex flex-col gap-1">
                      <div>
                        <RadioButton
                          :id="`client-backend-${i}-tokenEndpointAuthMethod-client_secret_post`"
                          v-model="client.tokenEndpointAuthMethod"
                          value="client_secret_post"
                          class="mx-2"
                        />
                        <label :for="`client-backend-${i}-tokenEndpointAuthMethod-client_secret_post`"><code>client_secret_post</code></label>
                      </div>
                      <div>
                        <RadioButton
                          :id="`client-backend-${i}-tokenEndpointAuthMethod-client_secret_basic`"
                          v-model="client.tokenEndpointAuthMethod"
                          value="client_secret_basic"
                          class="mx-2"
                        />
                        <label :for="`client-backend-${i}-tokenEndpointAuthMethod-client_secret_basic`"><code>client_secret_basic</code></label>
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
                    :readonly="mainProgress > 0 || !metadata.can_update"
                  />
                  <label :for="`client-backend-${i}-additionalScopes`" class="mb-1 mt-4"
                    >Space-separated additional scopes the application might request<span v-if="metadata.can_update" class="text-neutral-500 italic text-sm">
                      (optional)</span
                    ></label
                  >
                  <TextArea
                    id="client-backend-${i}-additionalScopes"
                    :model-value="client.additionalScopes.join(' ')"
                    class="flex-grow flex-auto min-w-0"
                    :readonly="mainProgress > 0 || !metadata.can_update"
                    @update:model-value="(v) => (client.additionalScopes = splitSpace(v))"
                  />
                  <div v-if="metadata.can_update" class="mt-4 flex flex-row justify-end">
                    <Button type="button" :disabled="mainProgress > 0" @click.prevent="clientsBackend.splice(i, 1)">Remove</Button>
                  </div>
                </div>
              </li>
            </ol>
            <div v-if="metadata.can_update" class="flex flex-row justify-between gap-4">
              <Button type="button" @click.prevent="onAddClientBackend">Add client</Button>
              <!--
                Button is on purpose not disabled on unexpectedError so that user can retry.
              -->
              <Button type="submit" primary :disabled="!canClientsBackendSubmit() || mainProgress > 0">Update</Button>
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
                          class="mx-2"
                        />
                        <label :for="`client-service-${i}-tokenEndpointAuthMethod-client_secret_post`"><code>client_secret_post</code></label>
                      </div>
                      <div>
                        <RadioButton
                          :id="`client-service-${i}-tokenEndpointAuthMethod-client_secret_basic`"
                          v-model="client.tokenEndpointAuthMethod"
                          value="client_secret_basic"
                          class="mx-2"
                        />
                        <label :for="`client-service-${i}-tokenEndpointAuthMethod-client_secret_basic`"><code>client_secret_basic</code></label>
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
                    :readonly="mainProgress > 0 || !metadata.can_update"
                  />
                  <label :for="`client-service-${i}-additionalScopes`" class="mb-1 mt-4"
                    >Space-separated additional scopes the application might request<span v-if="metadata.can_update" class="text-neutral-500 italic text-sm">
                      (optional)</span
                    ></label
                  >
                  <TextArea
                    id="client-service-${i}-additionalScopes"
                    :model-value="client.additionalScopes.join(' ')"
                    class="flex-grow flex-auto min-w-0"
                    :readonly="mainProgress > 0 || !metadata.can_update"
                    @update:model-value="(v) => (client.additionalScopes = splitSpace(v))"
                  />
                  <div v-if="metadata.can_update" class="mt-4 flex flex-row justify-end">
                    <Button type="button" :disabled="mainProgress > 0" @click.prevent="clientsService.splice(i, 1)">Remove</Button>
                  </div>
                </div>
              </li>
            </ol>
            <div v-if="metadata.can_update" class="flex flex-row justify-between gap-4">
              <Button type="button" @click.prevent="onAddClientService">Add client</Button>
              <!--
                Button is on purpose not disabled on unexpectedError so that user can retry.
              -->
              <Button type="submit" primary :disabled="!canClientsServiceSubmit() || mainProgress > 0">Update</Button>
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
