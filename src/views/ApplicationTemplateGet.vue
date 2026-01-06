<script setup lang="ts">
import type { Ref } from "vue"

import type {
  ApplicationTemplate,
  ApplicationTemplateClientBackend,
  ApplicationTemplateClientPublic,
  ApplicationTemplateClientService,
  IdentityRef,
  Metadata,
  Variable,
} from "@/types"

import { nextTick, onBeforeMount, onBeforeUnmount, ref, watch } from "vue"
import { useI18n } from "vue-i18n"
import { useRouter } from "vue-router"

import { getURL, postJSON } from "@/api"
import Button from "@/components/Button.vue"
import InputText from "@/components/InputText.vue"
import RadioButton from "@/components/RadioButton.vue"
import TextArea from "@/components/TextArea.vue"
import siteContext from "@/context"
import Footer from "@/partials/Footer.vue"
import NavBar from "@/partials/NavBar.vue"
import WithIdentityPublicDocument from "@/partials/WithIdentityPublicDocument.vue"
import { useProgress } from "@/progress"
import { clone, equals } from "@/utils"

const props = defineProps<{
  id: string
}>()

const { t } = useI18n({ useScope: "global" })
const router = useRouter()
const progress = useProgress()

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

const adminsUnexpectedError = ref("")
const adminsUpdated = ref(false)
const admins = ref<IdentityRef[]>([])

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
  adminsUnexpectedError.value = ""
  adminsUpdated.value = false
  // dataLoading and dataLoadingError are not listed here on
  // purpose because they are used only on mount.
}

let watchInteractionStop: (() => void) | null = null
function initWatchInteraction() {
  if (abortController.signal.aborted) {
    return
  }

  const stop = watch([name, description, homepageTemplate, idScopes, variables, clientsPublic, clientsBackend, clientsService, admins], resetOnInteraction, {
    deep: true,
  })
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

async function loadData(update: "init" | "basic" | "variables" | "clientsPublic" | "clientsBackend" | "clientsService" | "admins" | null, dataError: Ref<string> | null) {
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

    for (const clientType of ["clientsPublic", "clientsBackend", "clientsService"] as const) {
      for (const client of response.doc[clientType]) {
        if (!client.accessTokenLifespan) {
          client.accessTokenLifespan = ""
        }
        if (!client.idTokenLifespan) {
          client.idTokenLifespan = ""
        }
        if (!client.refreshTokenLifespan) {
          client.refreshTokenLifespan = ""
        }
      }
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
    if (update === "init" || update === "admins") {
      admins.value = clone(response.doc.admins || [])
    }
  } catch (error) {
    if (abortController.signal.aborted) {
      return
    }
    // TODO: 404 should be shown differently, but probably in the same way for all 404.
    console.error("ApplicationTemplateGet.loadData", error)
    if (dataError) {
      // eslint-disable-next-line @typescript-eslint/restrict-template-expressions
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
  update: "basic" | "variables" | "clientsPublic" | "clientsBackend" | "clientsService" | "admins",
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
      // eslint-disable-next-line @typescript-eslint/restrict-template-expressions
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

async function addRedirectUriTemplate(client: { redirectUriTemplates: string[] }, idPrefix: string) {
  client.redirectUriTemplates.push("")

  await nextTick(() => {
    document.getElementById(`${idPrefix}${client.redirectUriTemplates.length - 1}`)?.focus()
  })
}

function canBasicSubmit(): boolean {
  // Submission is on purpose not disabled on basicUnexpectedError so that user can retry.

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
    admins: applicationTemplate.value!.admins,
  }
  await onSubmit(payload, "basic", basicUpdated, basicUnexpectedError)
}

function canVariablesSubmit(): boolean {
  // Submission is on purpose not disabled on variablesUnexpectedError so that user can retry.

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
    admins: applicationTemplate.value!.admins,
  }
  await onSubmit(payload, "variables", variablesUpdated, variablesUnexpectedError)
}

async function onAddVariable() {
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

  await nextTick(() => {
    document.getElementById(`applicationtemplateget-field-${variables.value.length - 1}-name`)?.focus()
  })
}

function canClientsPublicSubmit(): boolean {
  // Submission is on purpose not disabled on clientsPublicUnexpectedError so that user can retry.

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
    if (!client.accessTokenLifespan) {
      return false
    }
    if (!client.idTokenLifespan) {
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
  const c = clone(clientsPublic.value)
  for (const client of c) {
    if (!client.refreshTokenLifespan) {
      delete client.refreshTokenLifespan
    }
  }

  const payload: ApplicationTemplate = {
    // We update only clientsPublic.
    id: props.id,
    name: applicationTemplate.value!.name,
    description: applicationTemplate.value!.description,
    homepageTemplate: applicationTemplate.value!.homepageTemplate,
    idScopes: applicationTemplate.value!.idScopes,
    variables: applicationTemplate.value!.variables,
    clientsPublic: c,
    clientsBackend: applicationTemplate.value!.clientsBackend,
    clientsService: applicationTemplate.value!.clientsService,
    admins: applicationTemplate.value!.admins,
  }
  await onSubmit(payload, "clientsPublic", clientsPublicUpdated, clientsPublicUnexpectedError)
}

async function onAddClientPublic() {
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
        accessTokenType: "hmac",
        redirectUriTemplates: ["{uriBase}/oidc/redirect"],
        accessTokenLifespan: "1h0m0s",
        idTokenLifespan: "1h0m0s",
        refreshTokenLifespan: 24 * 30 + "h0m0s",
      })

      await nextTick(() => {
        document.getElementById(`client-public-${clientsPublic.value.length - 1}-redirectUriTemplates-0`)?.focus()
      })

      return
    }
  }

  clientsPublic.value.push({
    description: "",
    additionalScopes: [],
    accessTokenType: "hmac",
    redirectUriTemplates: [],
    accessTokenLifespan: "1h0m0s",
    idTokenLifespan: "1h0m0s",
    refreshTokenLifespan: 24 * 30 + "h0m0s",
  })

  await nextTick(() => {
    document.getElementById(`client-public-${clientsPublic.value.length - 1}-addTemplate`)?.focus()
  })
}

function canClientsBackendSubmit(): boolean {
  // Submission is on purpose not disabled on clientsBackendUnexpectedError so that user can retry.

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

    if (!client.accessTokenLifespan) {
      return false
    }
    if (!client.idTokenLifespan) {
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
  const c = clone(clientsBackend.value)
  for (const client of c) {
    if (!client.refreshTokenLifespan) {
      delete client.refreshTokenLifespan
    }
  }

  const payload: ApplicationTemplate = {
    // We update only clientsBackend.
    id: props.id,
    name: applicationTemplate.value!.name,
    description: applicationTemplate.value!.description,
    homepageTemplate: applicationTemplate.value!.homepageTemplate,
    idScopes: applicationTemplate.value!.idScopes,
    variables: applicationTemplate.value!.variables,
    clientsPublic: applicationTemplate.value!.clientsPublic,
    clientsBackend: c,
    clientsService: applicationTemplate.value!.clientsService,
    admins: applicationTemplate.value!.admins,
  }
  await onSubmit(payload, "clientsBackend", clientsBackendUpdated, clientsBackendUnexpectedError)
}

async function onAddClientBackend() {
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
        accessTokenType: "hmac",
        tokenEndpointAuthMethod: "client_secret_post",
        redirectUriTemplates: ["{uriBase}/oidc/redirect"],
        accessTokenLifespan: "1h0m0s",
        idTokenLifespan: "1h0m0s",
        refreshTokenLifespan: 24 * 30 + "h0m0s",
      })

      await nextTick(() => {
        document.getElementById(`client-backend-${clientsBackend.value.length - 1}-redirectUriTemplates-0`)?.focus()
      })

      return
    }
  }

  clientsBackend.value.push({
    description: "",
    additionalScopes: [],
    accessTokenType: "hmac",
    tokenEndpointAuthMethod: "client_secret_post",
    redirectUriTemplates: [],
    accessTokenLifespan: "1h0m0s",
    idTokenLifespan: "1h0m0s",
    refreshTokenLifespan: 24 * 30 + "h0m0s",
  })

  await nextTick(() => {
    document.getElementById(`client-backend-${clientsBackend.value.length - 1}-addTemplate`)?.focus()
  })
}

function canClientsServiceSubmit(): boolean {
  // Submission is on purpose not disabled on clientsServiceUnexpectedError so that user can retry.

  // Required fields.
  for (const client of clientsService.value) {
    if (!client.accessTokenLifespan) {
      return false
    }
    if (!client.idTokenLifespan) {
      return false
    }
  }

  // Anything changed?
  if (!equals(applicationTemplate.value!.clientsService, clientsService.value)) {
    return true
  }

  return false
}

async function onClientsServiceSubmit() {
  const c = clone(clientsService.value)
  for (const client of c) {
    if (!client.refreshTokenLifespan) {
      delete client.refreshTokenLifespan
    }
  }

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
    clientsService: c,
    admins: applicationTemplate.value!.admins,
  }
  await onSubmit(payload, "clientsService", clientsServiceUpdated, clientsServiceUnexpectedError)
}

async function onAddClientService() {
  if (abortController.signal.aborted) {
    return
  }

  // No need to call resetOnInteraction here because we modify variables
  // which we watch to call resetOnInteraction.

  clientsService.value.push({
    description: "",
    additionalScopes: [],
    accessTokenType: "hmac",
    tokenEndpointAuthMethod: "client_secret_post",
    accessTokenLifespan: "1h0m0s",
    idTokenLifespan: "1h0m0s",
    refreshTokenLifespan: 24 * 30 + "h0m0s",
  })

  await nextTick(() => {
    document.getElementById(`client-service-${clientsService.value.length - 1}-description`)?.focus()
  })
}

function canAdminsSubmit(): boolean {
  // Button is on purpose not disabled on adminsUnexpectedError so that user can retry.

  // Anything changed?
  if (!equals(applicationTemplate.value!.admins || [], admins.value)) {
    return true
  }

  return false
}

async function onAdminsSubmit() {
  const payload: ApplicationTemplate = {
    // We update only admins.
    id: props.id,
    name: applicationTemplate.value!.name,
    description: applicationTemplate.value!.description,
    homepageTemplate: applicationTemplate.value!.homepageTemplate,
    idScopes: applicationTemplate.value!.idScopes,
    variables: applicationTemplate.value!.variables,
    clientsPublic: applicationTemplate.value!.clientsPublic,
    clientsBackend: applicationTemplate.value!.clientsBackend,
    clientsService: applicationTemplate.value!.clientsService,
    admins: admins.value,
  }
  await onSubmit(payload, "admins", adminsUpdated, adminsUnexpectedError)
}

async function onAddAdmin() {
  if (abortController.signal.aborted) {
    return
  }

  // No need to call resetOnInteraction here because we modify variables
  // which we watch to call resetOnInteraction.

  admins.value.push({
    id: "",
  })

  await nextTick(() => {
    document.getElementById(`admin-${admins.value.length - 1}-id`)?.focus()
  })
}
</script>

<template>
  <Teleport to="header">
    <NavBar></NavBar>
  </Teleport>
  <div class="mt-12 flex w-full flex-col items-center border-t border-transparent sm:mt-[4.5rem]">
    <div class="m-1 grid auto-rows-auto grid-cols-[minmax(0,65ch)] gap-1 sm:m-4 sm:gap-4">
      <div class="flex w-full flex-col gap-4 rounded-sm border border-gray-200 bg-white p-4 shadow-sm">
        <div class="flex flex-row items-center">
          <h1 class="text-2xl font-bold">{{ t("common.entities.applicationTemplates") }}</h1>
        </div>
        <div v-if="dataLoading">{{ t("common.data.dataLoading") }}</div>
        <div v-else-if="dataLoadingError" class="text-error-600">{{ t("common.errors.unexpected") }}</div>
        <template v-else>
          <!--
            We set novalidate because we do not want UA to show hints.
            We show them ourselves when we want them.
          -->
          <form class="flex flex-col" novalidate @submit.prevent="onBasicSubmit">
            <label for="name" class="mb-1">{{ t("views.ApplicationTemplateGet.applicationTemplateName") }}</label>
            <InputText id="name" v-model="name" class="min-w-0 flex-auto grow" :readonly="!metadata.can_update" :progress="progress" required />
            <label for="description" class="mt-4 mb-1"
              >{{ t("common.fields.description") }}
              <span v-if="metadata.can_update" class="text-sm text-neutral-500 italic">{{ t("common.labels.optional") }}</span></label
            >
            <TextArea id="description" v-model="description" class="min-w-0 flex-auto grow" :readonly="!metadata.can_update" :progress="progress" />
            <label for="homepageTemplate" class="mt-4 mb-1">{{ t("views.ApplicationTemplateGet.homepageTemplate") }}</label>
            <InputText id="homepageTemplate" v-model="homepageTemplate" class="min-w-0 flex-auto grow" :readonly="!metadata.can_update" :progress="progress" required />
            <label for="applicationtemplateget-input-idscopes" class="mt-4 mb-1"
              >{{ t("views.ApplicationTemplateGet.spaceSeparatedScopes") }}
              <span v-if="metadata.can_update" class="text-sm text-neutral-500 italic">{{ t("common.labels.optional") }}</span></label
            >
            <TextArea
              id="applicationtemplateget-input-idscopes"
              :model-value="idScopes.join(' ')"
              class="min-w-0 flex-auto grow"
              :readonly="!metadata.can_update"
              :progress="progress"
              @update:model-value="(v) => (idScopes = splitSpace(v))"
            />
            <div v-if="basicUnexpectedError" class="mt-4 text-error-600">{{ t("common.errors.unexpected") }}</div>
            <div v-else-if="basicUpdated" class="mt-4 text-success-600">{{ t("views.ApplicationTemplateGet.applicationsUpdated") }}</div>
            <div v-if="metadata.can_update" class="mt-4 flex flex-row justify-end">
              <Button id="applicatiomtemplateget-update-button" type="submit" primary :disabled="!canBasicSubmit()"
                      :progress="progress">{{
                  t("common.buttons.update") }}</Button>
            </div>
          </form>
          <template v-if="metadata.can_update || variables.length || canVariablesSubmit() || variablesUnexpectedError || variablesUpdated">
            <h2 class="text-xl font-bold">{{ t("views.ApplicationTemplateGet.variables") }}</h2>
            <div v-if="variablesUnexpectedError" class="text-error-600">{{ t("common.errors.unexpected") }}</div>
            <div v-else-if="variablesUpdated" class="text-success-600">{{ t("views.ApplicationTemplateGet.variablesUpdated") }}</div>
            <!--
              We set novalidate because we do not want UA to show hints.
              We show them ourselves when we want them.
            -->
            <form v-if="metadata.can_update || variables.length || canVariablesSubmit()" class="flex flex-col" novalidate @submit.prevent="onVariablesSubmit">
              <ol>
                <li v-for="(variable, i) in variables" :key="i" class="mb-4 grid auto-rows-auto grid-cols-[min-content_auto] gap-x-4">
                  <div>{{ i + 1 }}.</div>
                  <div class="flex flex-col">
                    <label :for="`applicationtemplateget-field-${i}-name`" class="mb-1">{{ t("views.ApplicationTemplateGet.name") }}</label>
                    <InputText
                      :id="`applicationtemplateget-field-${i}-name`"
                      v-model="variable.name"
                      class="min-w-0 flex-auto grow"
                      :readonly="!metadata.can_update"
                      :progress="progress"
                      required
                    />
                    <label :for="`applicationtemplateget-field-${i}-description`" class="mt-4 mb-1"
                      >{{ t("common.fields.description") }}
                      <span v-if="metadata.can_update" class="text-sm text-neutral-500 italic">{{ t("common.labels.optional") }}</span></label
                    >
                    <TextArea
                      :id="`applicationtemplateget-field-${i}-description`"
                      v-model="variable.description"
                      class="min-w-0 flex-auto grow"
                      :readonly="!metadata.can_update"
                      :progress="progress"
                    />
                    <div v-if="metadata.can_update" class="mt-4 flex flex-row justify-end">
                      <Button type="button" :progress="progress" @click.prevent="variables.splice(i, 1)">{{ t("common.buttons.remove") }}</Button>
                    </div>
                  </div>
                </li>
              </ol>
              <div v-if="metadata.can_update" class="flex flex-row justify-between gap-4">
                <Button type="button" @click.prevent="onAddVariable">{{ t("views.ApplicationTemplateGet.addVariable") }}</Button>
                <Button type="submit" primary :disabled="!canVariablesSubmit()" :progress="progress">{{ t("common.buttons.update") }}</Button>
              </div>
            </form>
          </template>
          <template v-if="metadata.can_update || clientsPublic.length || canClientsPublicSubmit() || clientsPublicUnexpectedError || clientsPublicUpdated">
            <h2 class="text-xl font-bold">{{ t("views.ApplicationTemplateGet.publicClients") }}</h2>
            <div v-if="clientsPublicUnexpectedError" class="text-error-600">{{ t("common.errors.unexpected") }}</div>
            <div v-else-if="clientsPublicUpdated" class="text-success-600">{{ t("views.ApplicationTemplateGet.publicClientsUpdated") }}</div>
            <!--
              We set novalidate because we do not want UA to show hints.
              We show them ourselves when we want them.
            -->
            <form v-if="metadata.can_update || clientsPublic.length || canClientsPublicSubmit()" class="flex flex-col" novalidate @submit.prevent="onClientsPublicSubmit">
              <ol>
                <li v-for="(client, i) in clientsPublic" :key="i" class="mb-4 grid auto-rows-auto grid-cols-[min-content_auto] gap-x-4">
                  <div>{{ i + 1 }}.</div>
                  <div class="flex flex-col">
                    <fieldset>
                      <legend>{{ t("views.ApplicationTemplateGet.oidcRedirectUriTemplates") }}</legend>
                      <ol>
                        <li v-for="(_, j) in client.redirectUriTemplates" :key="j" class="mt-4 grid auto-rows-auto grid-cols-[min-content_auto] gap-x-4">
                          <div>{{ j + 1 }}.</div>
                          <div class="flex flex-row gap-4">
                            <InputText
                              :id="`client-public-${i}-redirectUriTemplates-${j}`"
                              v-model="client.redirectUriTemplates[j]"
                              class="min-w-0 flex-auto grow"
                              :readonly="!metadata.can_update"
                              :progress="progress"
                              required
                            />
                            <Button v-if="metadata.can_update" type="button" :progress="progress" @click.prevent="client.redirectUriTemplates.splice(j, 1)">{{
                              t("common.buttons.remove")
                            }}</Button>
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
                        >{{ t("views.ApplicationTemplateGet.addRedirectUri") }}</Button
                      >
                    </div>
                    <label :for="`client-public-${i}-description`" class="mt-4 mb-1"
                      >{{ t("common.fields.description") }}
                      <span v-if="metadata.can_update" class="text-sm text-neutral-500 italic">{{ t("common.labels.optional") }}</span></label
                    >
                    <TextArea
                      :id="`client-public-${i}-description`"
                      v-model="client.description"
                      class="min-w-0 flex-auto grow"
                      :readonly="!metadata.can_update"
                      :progress="progress"
                    />
                    <label :for="`client-public-${i}-additionalScopes`" class="mt-4 mb-1"
                      >{{ t("views.ApplicationTemplateGet.spaceSeparatedAdditionalScopes") }}
                      <span v-if="metadata.can_update" class="text-sm text-neutral-500 italic">{{ t("common.labels.optional") }}</span></label
                    >
                    <TextArea
                      :id="`client-public-${i}-additionalScopes`"
                      :model-value="client.additionalScopes.join(' ')"
                      class="min-w-0 flex-auto grow"
                      :readonly="!metadata.can_update"
                      :progress="progress"
                      @update:model-value="(v) => (client.additionalScopes = splitSpace(v))"
                    />
                    <fieldset class="mt-4">
                      <legend class="mb-1">{{ t("views.ApplicationTemplateGet.accessTokenType") }}</legend>
                      <div class="grid auto-rows-auto grid-cols-[max-content_auto] gap-x-1">
                        <RadioButton
                          :id="`client-public-${i}-accessTokenType-hmac`"
                          v-model="client.accessTokenType"
                          value="hmac"
                          :disabled="!metadata.can_update"
                          :progress="progress"
                          class="mx-2"
                        />
                        <label
                          :for="`client-public-${i}-accessTokenType-hmac`"
                          :class="progress > 0 || !metadata.can_update ? 'cursor-not-allowed text-gray-600' : 'cursor-pointer'"
                          >{{ t("views.ApplicationTemplateGet.hmac") }}</label
                        >
                        <RadioButton
                          :id="`client-public-${i}-accessTokenType-jwt`"
                          v-model="client.accessTokenType"
                          value="jwt"
                          :disabled="!metadata.can_update"
                          :progress="progress"
                          class="mx-2"
                        />
                        <label
                          :for="`client-public-${i}-accessTokenType-jwt`"
                          :class="progress > 0 || !metadata.can_update ? 'cursor-not-allowed text-gray-600' : 'cursor-pointer'"
                          >{{ t("views.ApplicationTemplateGet.jwt") }}</label
                        >
                      </div>
                    </fieldset>
                    <label :for="`client-public-${i}-accessTokenLifespan`" class="mt-4 mb-1">{{ t("views.ApplicationTemplateGet.accessTokenLifespan") }}</label>
                    <TextArea
                      :id="`client-public-${i}-accessTokenLifespan`"
                      v-model="client.accessTokenLifespan"
                      class="min-w-0 flex-auto grow"
                      :readonly="!metadata.can_update"
                      :progress="progress"
                    />
                    <label :for="`client-public-${i}-idTokenLifespan`" class="mt-4 mb-1">{{ t("views.ApplicationTemplateGet.idTokenLifespan") }}</label>
                    <TextArea
                      :id="`client-public-${i}-idTokenLifespan`"
                      v-model="client.idTokenLifespan"
                      class="min-w-0 flex-auto grow"
                      :readonly="!metadata.can_update"
                      :progress="progress"
                    />
                    <label :for="`client-public-${i}-refreshTokenLifespan`" class="mt-4 mb-1"
                      >{{ t("views.ApplicationTemplateGet.refreshTokenLifespan") }}
                      <span v-if="metadata.can_update" class="text-sm text-neutral-500 italic">{{ t("common.labels.optional") }}</span></label
                    >
                    <TextArea
                      :id="`client-public-${i}-refreshTokenLifespan`"
                      v-model="client.refreshTokenLifespan"
                      class="min-w-0 flex-auto grow"
                      :readonly="!metadata.can_update"
                      :progress="progress"
                    />
                    <div v-if="metadata.can_update" class="mt-4 flex flex-row justify-end">
                      <Button type="button" :progress="progress" @click.prevent="clientsPublic.splice(i, 1)">{{ t("common.buttons.remove") }}</Button>
                    </div>
                  </div>
                </li>
              </ol>
              <div v-if="metadata.can_update" class="flex flex-row justify-between gap-4">
                <Button id="applicationtemplateget-button-addpublicclient" type="button"
                        @click.prevent="onAddClientPublic">{{
                    t("views.ApplicationTemplateGet.addClient") }}</Button>
                <Button id="applicationtemplateget-button-updatepublicclient" type="submit" primary
                        :disabled="!canClientsPublicSubmit()" :progress="progress">{{
                    t("common.buttons.update") }}</Button>
              </div>
            </form>
          </template>
          <template v-if="metadata.can_update || clientsBackend.length || canClientsBackendSubmit() || clientsBackendUnexpectedError || clientsBackendUpdated">
            <h2 class="text-xl font-bold">{{ t("views.ApplicationTemplateGet.backendClients") }}</h2>
            <div v-if="clientsBackendUnexpectedError" class="text-error-600">{{ t("common.errors.unexpected") }}</div>
            <div v-else-if="clientsBackendUpdated" class="text-success-600">{{ t("views.ApplicationTemplateGet.backendClientsUpdated") }}</div>
            <!--
              We set novalidate because we do not want UA to show hints.
              We show them ourselves when we want them.
            -->
            <form
              v-if="metadata.can_update || clientsBackend.length || canClientsBackendSubmit()"
              class="flex flex-col"
              novalidate
              @submit.prevent="onClientsBackendSubmit"
            >
              <ol>
                <li v-for="(client, i) in clientsBackend" :key="i" class="mb-4 grid auto-rows-auto grid-cols-[min-content_auto] gap-x-4">
                  <div>{{ i + 1 }}.</div>
                  <div class="flex flex-col">
                    <fieldset>
                      <legend>{{ t("views.ApplicationTemplateGet.oidcRedirectUriTemplates") }}</legend>
                      <ol>
                        <li v-for="(_, j) in client.redirectUriTemplates" :key="j" class="mt-4 grid auto-rows-auto grid-cols-[min-content_auto] gap-x-4">
                          <div>{{ j + 1 }}.</div>
                          <div class="flex flex-row gap-4">
                            <InputText
                              :id="`client-backend-${i}-redirectUriTemplates-${j}`"
                              v-model="client.redirectUriTemplates[j]"
                              class="min-w-0 flex-auto grow"
                              :readonly="!metadata.can_update"
                              :progress="progress"
                              required
                            />
                            <Button v-if="metadata.can_update" type="button" :progress="progress" @click.prevent="client.redirectUriTemplates.splice(j, 1)">{{
                              t("common.buttons.remove")
                            }}</Button>
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
                        >{{ t("views.ApplicationTemplateGet.addRedirectUri") }}</Button
                      >
                    </div>
                    <label :for="`client-backend-${i}-description`" class="mt-4 mb-1"
                      >{{ t("common.fields.description") }}
                      <span v-if="metadata.can_update" class="text-sm text-neutral-500 italic">{{ t("common.labels.optional") }}</span></label
                    >
                    <TextArea
                      :id="`client-backend-${i}-description`"
                      v-model="client.description"
                      class="min-w-0 flex-auto grow"
                      :readonly="!metadata.can_update"
                      :progress="progress"
                    />
                    <label :for="`client-backend-${i}-additionalScopes`" class="mt-4 mb-1"
                      >{{ t("views.ApplicationTemplateGet.spaceSeparatedAdditionalScopes") }}
                      <span v-if="metadata.can_update" class="text-sm text-neutral-500 italic">{{ t("common.labels.optional") }}</span></label
                    >
                    <TextArea
                      :id="`client-backend-${i}-additionalScopes`"
                      :model-value="client.additionalScopes.join(' ')"
                      class="min-w-0 flex-auto grow"
                      :readonly="!metadata.can_update"
                      :progress="progress"
                      @update:model-value="(v) => (client.additionalScopes = splitSpace(v))"
                    />
                    <fieldset class="mt-4">
                      <legend class="mb-1">{{ t("views.ApplicationTemplateGet.accessTokenType") }}</legend>
                      <div class="grid auto-rows-auto grid-cols-[max-content_auto] gap-x-1">
                        <RadioButton
                          :id="`client-backend-${i}-accessTokenType-hmac`"
                          v-model="client.accessTokenType"
                          value="hmac"
                          :disabled="!metadata.can_update"
                          :progress="progress"
                          class="mx-2"
                        />
                        <label
                          :for="`client-backend-${i}-accessTokenType-hmac`"
                          :class="progress > 0 || !metadata.can_update ? 'cursor-not-allowed text-gray-600' : 'cursor-pointer'"
                          >{{ t("views.ApplicationTemplateGet.hmac") }}</label
                        >
                        <RadioButton
                          :id="`client-backend-${i}-accessTokenType-jwt`"
                          v-model="client.accessTokenType"
                          value="jwt"
                          :disabled="!metadata.can_update"
                          :progress="progress"
                          class="mx-2"
                        />
                        <label
                          :for="`client-backend-${i}-accessTokenType-jwt`"
                          :class="progress > 0 || !metadata.can_update ? 'cursor-not-allowed text-gray-600' : 'cursor-pointer'"
                          >{{ t("views.ApplicationTemplateGet.jwt") }}</label
                        >
                      </div>
                    </fieldset>
                    <fieldset class="mt-4">
                      <legend class="mb-1">{{ t("views.ApplicationTemplateGet.tokenEndpointAuthMethod") }}</legend>
                      <div class="grid auto-rows-auto grid-cols-[max-content_auto] gap-x-1">
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
                    </fieldset>
                    <label :for="`client-backend-${i}-accessTokenLifespan`" class="mt-4 mb-1">{{ t("views.ApplicationTemplateGet.accessTokenLifespan") }}</label>
                    <TextArea
                      :id="`client-backend-${i}-accessTokenLifespan`"
                      v-model="client.accessTokenLifespan"
                      class="min-w-0 flex-auto grow"
                      :readonly="!metadata.can_update"
                      :progress="progress"
                    />
                    <label :for="`client-backend-${i}-idTokenLifespan`" class="mt-4 mb-1">{{ t("views.ApplicationTemplateGet.idTokenLifespan") }}</label>
                    <TextArea
                      :id="`client-backend-${i}-idTokenLifespan`"
                      v-model="client.idTokenLifespan"
                      class="min-w-0 flex-auto grow"
                      :readonly="!metadata.can_update"
                      :progress="progress"
                    />
                    <label :for="`client-backend-${i}-refreshTokenLifespan`" class="mt-4 mb-1"
                      >{{ t("views.ApplicationTemplateGet.refreshTokenLifespan") }}
                      <span v-if="metadata.can_update" class="text-sm text-neutral-500 italic">{{ t("common.labels.optional") }}</span></label
                    >
                    <TextArea
                      :id="`client-backend-${i}-refreshTokenLifespan`"
                      v-model="client.refreshTokenLifespan"
                      class="min-w-0 flex-auto grow"
                      :readonly="!metadata.can_update"
                      :progress="progress"
                    />
                    <div v-if="metadata.can_update" class="mt-4 flex flex-row justify-end">
                      <Button type="button" :progress="progress" @click.prevent="clientsBackend.splice(i, 1)">{{ t("common.buttons.remove") }}</Button>
                    </div>
                  </div>
                </li>
              </ol>
              <div v-if="metadata.can_update" class="flex flex-row justify-between gap-4">
                <Button type="button" @click.prevent="onAddClientBackend">{{ t("views.ApplicationTemplateGet.addClient") }}</Button>
                <Button type="submit" primary :disabled="!canClientsBackendSubmit()" :progress="progress">{{ t("common.buttons.update") }}</Button>
              </div>
            </form>
          </template>
          <template v-if="metadata.can_update || clientsService.length || canClientsServiceSubmit() || clientsServiceUnexpectedError || clientsServiceUpdated">
            <h2 class="text-xl font-bold">{{ t("views.ApplicationTemplateGet.serviceClients") }}</h2>
            <div v-if="clientsServiceUnexpectedError" class="text-error-600">{{ t("common.errors.unexpected") }}</div>
            <div v-else-if="clientsServiceUpdated" class="text-success-600">{{ t("views.ApplicationTemplateGet.serviceClientsUpdated") }}</div>
            <!--
              We set novalidate because we do not want UA to show hints.
              We show them ourselves when we want them.
            -->
            <form
              v-if="metadata.can_update || clientsService.length || canClientsServiceSubmit()"
              class="flex flex-col"
              novalidate
              @submit.prevent="onClientsServiceSubmit"
            >
              <ol>
                <li v-for="(client, i) in clientsService" :key="i" class="mb-4 grid auto-rows-auto grid-cols-[min-content_auto] gap-x-4">
                  <div>{{ i + 1 }}.</div>
                  <div class="flex flex-col">
                    <label :for="`client-service-${i}-description`" class="mb-1"
                      >{{ t("common.fields.description") }}
                      <span v-if="metadata.can_update" class="text-sm text-neutral-500 italic">{{ t("common.labels.optional") }}</span></label
                    >
                    <TextArea
                      :id="`client-service-${i}-description`"
                      v-model="client.description"
                      class="min-w-0 flex-auto grow"
                      :readonly="!metadata.can_update"
                      :progress="progress"
                    />
                    <label :for="`client-service-${i}-additionalScopes`" class="mt-4 mb-1"
                      >{{ t("views.ApplicationTemplateGet.spaceSeparatedAdditionalScopes") }}
                      <span v-if="metadata.can_update" class="text-sm text-neutral-500 italic">{{ t("common.labels.optional") }}</span></label
                    >
                    <TextArea
                      :id="`client-service-${i}-additionalScopes`"
                      :model-value="client.additionalScopes.join(' ')"
                      class="min-w-0 flex-auto grow"
                      :readonly="!metadata.can_update"
                      :progress="progress"
                      @update:model-value="(v) => (client.additionalScopes = splitSpace(v))"
                    />
                    <fieldset class="mt-4">
                      <legend class="mb-1">{{ t("views.ApplicationTemplateGet.accessTokenType") }}</legend>
                      <div class="grid auto-rows-auto grid-cols-[max-content_auto] gap-x-1">
                        <RadioButton
                          :id="`client-service-${i}-accessTokenType-hmac`"
                          v-model="client.accessTokenType"
                          value="hmac"
                          :disabled="!metadata.can_update"
                          :progress="progress"
                          class="mx-2"
                        />
                        <label
                          :for="`client-service-${i}-accessTokenType-hmac`"
                          :class="progress > 0 || !metadata.can_update ? 'cursor-not-allowed text-gray-600' : 'cursor-pointer'"
                          >{{ t("views.ApplicationTemplateGet.hmac") }}</label
                        >
                        <RadioButton
                          :id="`client-service-${i}-accessTokenType-jwt`"
                          v-model="client.accessTokenType"
                          value="jwt"
                          :disabled="!metadata.can_update"
                          :progress="progress"
                          class="mx-2"
                        />
                        <label
                          :for="`client-service-${i}-accessTokenType-jwt`"
                          :class="progress > 0 || !metadata.can_update ? 'cursor-not-allowed text-gray-600' : 'cursor-pointer'"
                          >{{ t("views.ApplicationTemplateGet.jwt") }}</label
                        >
                      </div>
                    </fieldset>
                    <fieldset class="mt-4">
                      <legend class="mb-1">{{ t("views.ApplicationTemplateGet.tokenEndpointAuthMethod") }}</legend>
                      <div class="grid auto-rows-auto grid-cols-[max-content_auto] gap-x-1">
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
                    </fieldset>
                    <label :for="`client-service-${i}-accessTokenLifespan`" class="mt-4 mb-1">{{ t("views.ApplicationTemplateGet.accessTokenLifespan") }}</label>
                    <TextArea
                      :id="`client-service-${i}-accessTokenLifespan`"
                      v-model="client.accessTokenLifespan"
                      class="min-w-0 flex-auto grow"
                      :readonly="!metadata.can_update"
                      :progress="progress"
                    />
                    <label :for="`client-service-${i}-idTokenLifespan`" class="mt-4 mb-1">{{ t("views.ApplicationTemplateGet.idTokenLifespan") }}</label>
                    <TextArea
                      :id="`client-service-${i}-idTokenLifespan`"
                      v-model="client.idTokenLifespan"
                      class="min-w-0 flex-auto grow"
                      :readonly="!metadata.can_update"
                      :progress="progress"
                    />
                    <label :for="`client-service-${i}-refreshTokenLifespan`" class="mt-4 mb-1"
                      >{{ t("views.ApplicationTemplateGet.refreshTokenLifespan") }}
                      <span v-if="metadata.can_update" class="text-sm text-neutral-500 italic">{{ t("common.labels.optional") }}</span></label
                    >
                    <TextArea
                      :id="`client-service-${i}-refreshTokenLifespan`"
                      v-model="client.refreshTokenLifespan"
                      class="min-w-0 flex-auto grow"
                      :readonly="!metadata.can_update"
                      :progress="progress"
                    />
                    <div v-if="metadata.can_update" class="mt-4 flex flex-row justify-end">
                      <Button type="button" :progress="progress" @click.prevent="clientsService.splice(i, 1)">{{ t("common.buttons.remove") }}</Button>
                    </div>
                  </div>
                </li>
              </ol>
              <div v-if="metadata.can_update" class="flex flex-row justify-between gap-4">
                <Button type="button" @click.prevent="onAddClientService">{{ t("views.ApplicationTemplateGet.addClient") }}</Button>
                <Button type="submit" primary :disabled="!canClientsServiceSubmit()" :progress="progress">{{ t("common.buttons.update") }}</Button>
              </div>
            </form>
          </template>
          <template v-if="metadata.can_update || adminsUnexpectedError || adminsUpdated">
            <h2 class="text-xl font-bold">{{ t("common.entities.admins") }}</h2>
            <div v-if="adminsUnexpectedError" class="text-error-600">{{ t("common.errors.unexpected") }}</div>
            <div v-else-if="adminsUpdated" class="text-success-600">{{ t("common.data.adminsUpdated") }}</div>
            <!--
              We set novalidate because we do not want UA to show hints.
              We show them ourselves when we want them.
            -->
            <form v-if="metadata.can_update" class="flex flex-col" novalidate @submit.prevent="onAdminsSubmit">
              <ol class="flex flex-col gap-y-4">
                <li v-for="(admin, i) in admins" :key="i" class="grid auto-rows-auto grid-cols-[min-content_auto] gap-x-4">
                  <div>{{ i + 1 }}.</div>
                  <div class="flex flex-col">
                    <WithIdentityPublicDocument
                      v-if="applicationTemplate?.admins?.find((a) => a.id === admin.id)"
                      :item="admin"
                      :organization-id="siteContext.organizationId"
                    >
                      <div class="flex flex-col items-start">
                        <Button type="button" @click.prevent="admins.splice(i, 1)">{{ t("common.buttons.remove") }}</Button>
                      </div>
                    </WithIdentityPublicDocument>
                    <div v-else class="flex flex-row gap-4">
                      <InputText :id="`admin-${i}-id`" v-model="admins[i].id" class="min-w-0 flex-auto grow" :progress="progress" required />
                      <Button type="button" @click.prevent="admins.splice(i, 1)">{{ t("common.buttons.remove") }}</Button>
                    </div>
                  </div>
                </li>
              </ol>
              <div class="flex flex-row justify-between gap-4" :class="admins.length ? 'mt-4' : ''">
                <Button type="button" @click.prevent="onAddAdmin">{{ t("common.buttons.addAdmin") }}</Button>
                <Button type="submit" primary :disabled="!canAdminsSubmit()" :progress="progress">{{ t("common.buttons.update") }}</Button>
              </div>
            </form>
          </template>
        </template>
      </div>
    </div>
  </div>
  <Teleport to="footer">
    <Footer />
  </Teleport>
</template>
