<script setup lang="ts">
import type { Organization, Metadata, Applications, Application, OrganizationApplication } from "@/types"

import { onBeforeMount, onUnmounted, ref, watch } from "vue"
import { useRouter } from "vue-router"
import { ArrowTopRightOnSquareIcon } from "@heroicons/vue/20/solid"
import InputText from "@/components/InputText.vue"
import Button from "@/components/Button.vue"
import WithDocument from "@/components/WithDocument.vue"
import Footer from "@/components/Footer.vue"
import { getURL, postURL } from "@/api"
import { setupArgon2id } from "@/argon2id"

const props = defineProps<{
  id: string
}>()

const router = useRouter()

const mainProgress = ref(0)
const abortController = new AbortController()
const dataLoading = ref(true)
const dataLoadingError = ref("")
const unexpectedError = ref("")
const updated = ref(false)
const applicationsUnexpectedError = ref("")
const applicationsUpdated = ref(false)
const organization = ref<Organization | null>(null)
const metadata = ref<Metadata>({})
const name = ref("")
const organizationApplications = ref<OrganizationApplication[]>([])
const applications = ref<Applications>([])
const generatedSecrets = ref(new Map<string, string>())

function resetOnInteraction() {
  // We reset flags and errors on interaction.
  updated.value = false
  applicationsUpdated.value = false
  unexpectedError.value = ""
  applicationsUnexpectedError.value = ""
  // dataLoading and dataLoadingError are not listed here on
  // purpose because they are used only on mount.
}

watch([name, organizationApplications], resetOnInteraction)

onUnmounted(() => {
  abortController.abort()
})

async function loadData(init: boolean) {
  mainProgress.value += 1
  try {
    const organizationURL = router.apiResolve({
      name: "Organization",
      params: {
        id: props.id,
      },
    }).href
    const data = await getURL<Organization>(organizationURL, null, abortController.signal, mainProgress)
    organization.value = data.doc
    metadata.value = data.metadata

    if (init) {
      name.value = data.doc.name
      organizationApplications.value = data.doc.applications || []

      const applicationsURL = router.apiResolve({
        name: "Applications",
      }).href
      applications.value = (await getURL<Applications>(applicationsURL, null, abortController.signal, mainProgress)).doc
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

function isEnabled(id: string): boolean {
  for (const orgApp of organizationApplications.value) {
    if (orgApp.application === id) {
      return true
    }
  }
  return false
}

function getOrganizationApplicationID(id: string): string {
  for (const orgApp of organizationApplications.value) {
    if (orgApp.application === id) {
      if (orgApp.id) {
        return orgApp.id
      }
      break
    }
  }
  for (const orgApp of organization.value?.applications || []) {
    if (orgApp.application === id) {
      if (orgApp.id) {
        return orgApp.id
      }
      break
    }
  }
  return ""
}

async function onSubmit() {
  resetOnInteraction()

  mainProgress.value += 1
  try {
    try {
      const payload: Organization = {
        id: props.id,
        name: name.value,
        // We update only name.
        applications: organization.value!.applications,
      }
      const url = router.apiResolve({
        name: "OrganizationUpdate",
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

async function getSecret(id: string): Promise<string> {
  // TODO: Generate a random identifier instead.
  const secret = Array.from(crypto.getRandomValues(new Uint8Array(22))).reduce((s, b) => s + (b % 35).toString(36)[(b % 2) - 1 ? "toLowerCase" : "toUpperCase"](), "")
  // We setup argon2id every time so that memory used by it
  // can be reclaimed when it is not used anymore.
  // See: https://github.com/openpgpjs/argon2id/issues/4
  const argon2id = await setupArgon2id()
  const hash = argon2id(new TextEncoder().encode(secret))
  generatedSecrets.value.set(id, secret)
  return hash
}

// TODO: Remember previous secrets and reuse them if an enabled application is disabled and then enabled back.
// TODO: Provide explicit buttons to rotate the secret, remove (and not just disable) the app (with all the data).
async function onChange(event: Event, id: string) {
  resetOnInteraction()

  if ((event.target as HTMLInputElement).checked) {
    if (!isEnabled(id)) {
      organizationApplications.value.push({
        application: id,
        secret: await getSecret(id),
      })
    }
  } else {
    organizationApplications.value = organizationApplications.value.filter((x) => x.application !== id)
    generatedSecrets.value.delete(id)
  }

  mainProgress.value += 1
  try {
    try {
      const payload: Organization = {
        id: props.id,
        // We update only applications.
        name: organization.value!.name,
        applications: organizationApplications.value,
      }
      const url = router.apiResolve({
        name: "OrganizationUpdate",
        params: {
          id: props.id,
        },
      }).href

      await postURL(url, payload, abortController.signal, mainProgress)

      applicationsUpdated.value = true
    } catch (error) {
      if (abortController.signal.aborted) {
        return
      }
      console.error(error)
      applicationsUnexpectedError.value = `${error}`
    } finally {
      // We update state even on errors.
      await loadData(false)
    }
  } finally {
    mainProgress.value -= 1
  }
}

const WithApplicationDocument = WithDocument<Application>
</script>

<template>
  <div class="w-full flex flex-col items-center">
    <div class="grid auto-rows-auto grid-cols-[minmax(0,_65ch)] m-1 sm:m-4 gap-1 sm:gap-4">
      <div class="w-full rounded border bg-white p-4 shadow flex flex-col gap-4">
        <div class="flex flex-row items-center">
          <h1 class="text-2xl font-bold">Organization</h1>
        </div>
        <div v-if="dataLoading">Loading...</div>
        <div v-else-if="dataLoadingError" class="text-error-600">Unexpected error. Please try again.</div>
        <template v-else>
          <form class="flex flex-col" novalidate @submit.prevent="onSubmit">
            <label for="name" class="mb-1">Organization name</label>
            <InputText id="name" v-model="name" class="flex-grow flex-auto min-w-0" :readonly="mainProgress > 0 || !metadata.can_update" required />
            <div v-if="unexpectedError" class="mt-4 text-error-600">Unexpected error. Please try again.</div>
            <div v-else-if="updated" class="mt-4 text-success-600">Organization updated successfully.</div>
            <div v-if="metadata.can_update" class="mt-4 flex flex-row justify-end">
              <!--
                Button is on purpose not disabled on unexpectedError so that user can retry.
              -->
              <Button type="submit" primary :disabled="name.length === 0 || organization!.name === name || mainProgress > 0">Update</Button>
            </div>
          </form>
          <h2 class="text-xl font-bold">Enabled applications</h2>
          <div v-if="applicationsUnexpectedError" class="text-error-600">Unexpected error. Please try again.</div>
          <div v-else-if="applicationsUpdated" class="text-success-600">Applications updated successfully.</div>
          <ul>
            <li v-for="application of applications" :key="application.id" class="flex flex-row items-baseline gap-x-1">
              <input
                :id="'app/' + application.id"
                :disabled="mainProgress > 0"
                :checked="isEnabled(application.id)"
                :class="
                  mainProgress > 0 ? 'cursor-not-allowed bg-gray-100 text-primary-300 focus:ring-primary-300' : 'cursor-pointer text-primary-600 focus:ring-primary-500'
                "
                type="checkbox"
                class="my-1 rounded"
                @change="onChange($event, application.id)"
              />
              <div class="lex flex-col">
                <div class="flex flex-row items-baseline gap-x-1">
                  <WithApplicationDocument :id="application.id" name="Application">
                    <template #default="{ doc, url }">
                      <label
                        :for="'app/' + application.id"
                        class="my-1 leading-none"
                        :class="mainProgress > 0 ? 'cursor-not-allowed text-gray-600' : 'cursor-pointer'"
                        :data-url="url"
                        >{{ doc.name }}</label
                      >
                    </template>
                  </WithApplicationDocument>
                  <label :for="'app/' + application.id" class="my-1 leading-none" :class="mainProgress > 0 ? 'cursor-not-allowed text-gray-600' : 'cursor-pointer'"
                    >xxx</label
                  >
                  <router-link :to="{ name: 'Application', params: { id: application.id } }" class="link"
                    ><ArrowTopRightOnSquareIcon alt="Link" class="inline h-5 w-5 align-text-top"
                  /></router-link>
                </div>
                <div v-if="getOrganizationApplicationID(application.id)">Client ID: {{ getOrganizationApplicationID(application.id) }}</div>
                <div v-if="generatedSecrets.has(application.id)">Client secret: {{ generatedSecrets.get(application.id) }}</div>
              </div>
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
