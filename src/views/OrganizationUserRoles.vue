<script setup lang="ts">
import type {IdentityForAdmin, Metadata, Organization, Role} from "@/types"

import { onBeforeMount, onBeforeUnmount, ref, watch } from "vue"
import { useI18n } from "vue-i18n"
import { useRouter } from "vue-router"

import { getURL, postJSON } from "@/api"
import Button from "@/components/Button.vue"
import CheckBox from "@/components/CheckBox.vue"
import Footer from "@/partials/Footer.vue"
import IdentityPublic from "@/partials/IdentityPublic.vue"
import NavBar from "@/partials/NavBar.vue"
import OrganizationListItem from "@/partials/OrganizationListItem.vue"
import { useProgress } from "@/progress"

const props = defineProps<{
  id: string
  identityId: string
}>()

const { t } = useI18n({ useScope: "global" })
const router = useRouter()
const progress = useProgress()

const abortController = new AbortController()
const dataLoading = ref(true)
const dataLoadingError = ref("")

const identity = ref<IdentityForAdmin | null>(null)
const metadata = ref<Metadata>({})
const organization = ref<Organization | null>(null)
const availableRoles = ref<Role[]>([])
const selectedRoleKeys = ref<string[]>([])
const updateError = ref("")
const updateSuccess = ref(false)

function resetOnInteraction() {
  // We reset flags and errors on interaction.
  updateError.value = ""
  updateSuccess.value = false
  // dataLoading and dataLoadingError are not listed here on
  // purpose because they are used only on mount.
}

watch([selectedRoleKeys], resetOnInteraction)

onBeforeUnmount(() => {
  abortController.abort()
})

onBeforeMount(async () => {
  progress.value += 1
  try {
    const identityURL = router.apiResolve({
      name: "OrganizationIdentity",
      params: {
        id: props.id,
        identityId: props.identityId,
      },
    }).href

    const response = await getURL<IdentityForAdmin>(identityURL, null, abortController.signal, progress)
    if (abortController.signal.aborted) {
      return
    }

    identity.value = response.doc
    metadata.value = response.metadata

    const identityOrganization = identity.value.organizations.find((o) => o.organization.id === props.id)
    if (identityOrganization?.roles) {
      selectedRoleKeys.value = [...identityOrganization.roles]
    }

    const organizationURL = router.apiResolve({
      name: "OrganizationGet",
      params: {
        id: props.id,
      },
    }).href

    const resp = await getURL<Organization>(organizationURL, null, abortController.signal, progress)
    if (abortController.signal.aborted) {
      return
    }
    organization.value = resp.doc

    availableRoles.value = computeAvailableRoles(organization.value)
  } catch (error) {
    if (abortController.signal.aborted) {
      return
    }
    console.error("OrganizationUserRoles.onBeforeMount", error)
    // eslint-disable-next-line @typescript-eslint/restrict-template-expressions
    dataLoadingError.value = `${error}`
  } finally {
    dataLoading.value = false
    progress.value -= 1
  }
})

function computeAvailableRoles(organization: Organization | null): Role[] {
  const roles = organization?.applications?.filter((app) => app.active)?.flatMap((app) => app.applicationTemplate.roles) ?? []

  const rolesMap = new Map(roles.map((role) => [role.key, role]))
  return Array.from(rolesMap.values()).sort((a, b) => a.key.localeCompare(b.key))
}

async function onSubmit() {
  if (abortController.signal.aborted || !identity.value) {
    return
  }

  resetOnInteraction()

  progress.value += 1
  try {
    const payload = {
      roles: selectedRoleKeys.value,
    }
    const url = router.apiResolve({
      name: "OrganizationUserRoles",
      params: {
        id: props.id,
        identityId: props.identityId,
      },
    }).href

    await postJSON(url, payload, abortController.signal, progress)
    if (abortController.signal.aborted) {
      return
    }

    updateSuccess.value = true
  } catch (error) {
    if (abortController.signal.aborted) {
      return
    }
    console.error("OrganizationUserRoles.onUpdate", error)
    // eslint-disable-next-line @typescript-eslint/restrict-template-expressions
    updateError.value = `${error}`
  } finally {
    progress.value -= 1
  }
}
</script>

<template>
  <Teleport to="header">
    <NavBar></NavBar>
  </Teleport>
  <div class="mt-12 flex w-full flex-col items-center border-t border-transparent sm:mt-[4.5rem]">
    <div class="m-1 grid auto-rows-auto grid-cols-[minmax(0,65ch)] gap-1 sm:m-4 sm:gap-4">
      <div class="flex w-full flex-col gap-4 rounded-sm border border-gray-200 bg-white p-4 shadow-sm">
        <div class="flex flex-col gap-4">
          <h1 class="text-2xl font-bold">{{ t("views.OrganizationUserRoles.userRolesInOrganization") }}</h1>
          <div>
            <OrganizationListItem :item="{ id }" />
          </div>
        </div>
      </div>
      <div v-if="dataLoading" class="w-full rounded-sm border border-gray-200 bg-white p-4 shadow-sm">{{ t("common.data.dataLoading") }}</div>
      <div v-else-if="dataLoadingError" class="w-full rounded-sm border border-gray-200 bg-white p-4 text-error-600 shadow-sm">{{ t("common.errors.unexpected") }}</div>
      <template v-else-if="identity">
        <div class="w-full rounded-sm border border-gray-200 bg-white p-4 shadow-sm">
          <IdentityPublic :identity="identity" :is-current="!metadata.is_current" :can-update="true" />
        </div>
      </template>
      <div class="w-full rounded-sm border border-gray-200 bg-white p-4 shadow-sm">
        <div v-if="updateError" class="mb-4 text-error-600">{{ t("common.errors.unexpected") }}</div>
        <div v-if="updateSuccess" class="mb-4 text-success-600">{{ t("views.OrganizationUserRoles.rolesUpdatedSuccessfully") }}</div>
        <div v-if="!availableRoles.length" class="mb-4 text-gray-500 italic"> {{ t("views.OrganizationUserRoles.noRoles") }} </div>
        <form v-else class="flex flex-col" novalidate @submit.prevent="onSubmit">
          <fieldset class="mb-4">
            <legend class="mb-1">{{ t("views.OrganizationUserRoles.availableRoles") }}</legend>
            <div class="grid auto-rows-auto grid-cols-[max-content_auto] gap-x-1">
              <template v-for="role in availableRoles" :key="role.key">
                <CheckBox :id="`organizationuserroles-checkbox-${role.key}`" v-model="selectedRoleKeys" :value="role.key" :progress="progress" class="mx-2" />
                <div class="flex flex-col">
                  <label :for="`organizationuserroles-checkbox-${role.key}`">{{ role.key }}</label>
                  <label :for="`organizationuserroles-checkbox-${role.key}`">{{ role.description }}</label>
                </div>
              </template>
            </div>
          </fieldset>
          <div class="flex justify-end">
            <Button type="submit" primary :disabled="false" :progress="progress">
              {{ t("common.buttons.update") }}
            </Button>
          </div>
        </form>
      </div>
    </div>
  </div>
  <Teleport to="footer">
    <Footer />
  </Teleport>
</template>
