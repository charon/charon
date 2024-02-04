<script setup lang="ts">
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
const idScopes = ref("")

const variablesUnexpectedError = ref("")
const variablesUpdated = ref(false)
const variables = ref<Variable[]>([])

const clientsPublic = ref<ApplicationTemplateClientPublic[]>([])

const clientsBackend = ref<ApplicationTemplateClientBackend[]>([])

const clientsService = ref<ApplicationTemplateClientService[]>([])

function resetOnInteraction() {
  // We reset flags and errors on interaction.
  basicUnexpectedError.value = ""
  basicUpdated.value = false
  variablesUnexpectedError.value = ""
  variablesUpdated.value = false
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
      idScopes.value = data.doc.idScopes.join(" ")
      // We have to make copies so that we break reactivity link with data.doc.
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
  if (applicationTemplate.value!.idScopes.join(" ") !== idScopes.value) {
    return true
  }

  return false
}

async function onBasicSubmit() {
  resetOnInteraction()

  mainProgress.value += 1
  try {
    try {
      const payload: ApplicationTemplate = {
        // We update only basic fields.
        id: props.id,
        name: name.value,
        description: description.value,
        idScopes: idScopes.value.split(" "),
        variables: applicationTemplate.value!.variables,
        clientsPublic: applicationTemplate.value!.clientsPublic,
        clientsBackend: applicationTemplate.value!.clientsBackend,
        clientsService: applicationTemplate.value!.clientsService,
      }
      const url = router.apiResolve({
        name: "ApplicationTemplateUpdate",
        params: {
          id: props.id,
        },
      }).href

      await postURL(url, payload, abortController.signal, mainProgress)

      basicUpdated.value = true
    } catch (error) {
      if (abortController.signal.aborted) {
        return
      }
      console.error(error)
      basicUnexpectedError.value = `${error}`
    } finally {
      // We update state even on errors.
      await loadData(false)
    }
  } finally {
    mainProgress.value -= 1
  }
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
  resetOnInteraction()

  mainProgress.value += 1
  try {
    try {
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
      const url = router.apiResolve({
        name: "ApplicationTemplateUpdate",
        params: {
          id: props.id,
        },
      }).href

      await postURL(url, payload, abortController.signal, mainProgress)

      variablesUpdated.value = true
    } catch (error) {
      if (abortController.signal.aborted) {
        return
      }
      console.error(error)
      variablesUnexpectedError.value = `${error}`
    } finally {
      // We update state even on errors.
      await loadData(false)
    }
  } finally {
    mainProgress.value -= 1
  }
}

async function onRemoveVariable(i: number) {
  // No need to call resetOnInteraction here because we modify variables
  // which we watch to call resetOnInteraction.

  variables.value.splice(i, 1)
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
            <TextArea id="idScopes" v-model="idScopes" class="flex-grow flex-auto min-w-0" :readonly="mainProgress > 0 || !metadata.can_update" />
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
              <li v-for="(variable, i) in variables" :key="i" class="grid auto-rows-auto grid-cols-[min-content,auto] gap-x-4">
                <div>{{ i + 1 }}.</div>
                <div class="flex flex-col">
                  <label for="variable-1-name" class="mb-1">Name</label>
                  <InputText
                    id="variable-1-name"
                    v-model="variable.name"
                    class="flex-grow flex-auto min-w-0"
                    :readonly="mainProgress > 0 || !metadata.can_update"
                    required
                  />
                  <label for="variable-1-description" class="mb-1 mt-4"
                    >Description<span v-if="metadata.can_update" class="text-neutral-500 italic text-sm"> (optional)</span></label
                  >
                  <TextArea
                    id="variable-1-description"
                    v-model="variable.description"
                    class="flex-grow flex-auto min-w-0"
                    :readonly="mainProgress > 0 || !metadata.can_update"
                  />
                  <div v-if="metadata.can_update" class="mt-4 flex flex-row justify-end">
                    <Button type="button" :disabled="mainProgress > 0" @click.prevent="onRemoveVariable(i)">Remove</Button>
                  </div>
                </div>
              </li>
            </ol>
            <div v-if="metadata.can_update" class="mt-4 flex flex-row justify-between gap-4">
              <Button type="button" @click.prevent="onAddVariable">Add variable</Button>
              <!--
                Button is on purpose not disabled on unexpectedError so that user can retry.
              -->
              <Button type="submit" primary :disabled="!canVariablesSubmit() || mainProgress > 0">Update</Button>
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
