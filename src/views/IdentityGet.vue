<script setup lang="ts">
import type { Ref } from "vue"
import type { Identity, IdentityOrganization as IdentityOrganizationType, IdentityRef, Metadata, OrganizationRef, Organizations } from "@/types"

import { computed, nextTick, onBeforeMount, onBeforeUnmount, ref, watch } from "vue"
import { useI18n } from "vue-i18n"
import { useRouter } from "vue-router"
import InputText from "@/components/InputText.vue"
import TextArea from "@/components/TextArea.vue"
import Button from "@/components/Button.vue"
import OrganizationListItem from "@/partials/OrganizationListItem.vue"
import NavBar from "@/partials/NavBar.vue"
import Footer from "@/partials/Footer.vue"
import WithIdentityPublicDocument from "@/partials/WithIdentityPublicDocument.vue"
import IdentityOrganization from "@/partials/IdentityOrganization.vue"
import { getURL, postJSON } from "@/api"
import { injectProgress } from "@/progress"
import { clone, equals } from "@/utils"
import siteContext from "@/context"

const { t } = useI18n({ useScope: "global" })

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

const usersUnexpectedError = ref("")
const usersUpdated = ref(false)
const users = ref<IdentityRef[]>([])

const adminsUnexpectedError = ref("")
const adminsUpdated = ref(false)
const admins = ref<IdentityRef[]>([])

const identityOrganizationsUnexpectedError = ref("")
const identityOrganizationsUpdated = ref(false)
const identityOrganizations = ref<IdentityOrganizationType[]>([])

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
  usersUnexpectedError.value = ""
  usersUpdated.value = false
  adminsUnexpectedError.value = ""
  adminsUpdated.value = false
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

  const stop = watch([username, email, givenName, fullName, pictureUrl, description, identityOrganizations, users, admins], resetOnInteraction, { deep: true })
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

async function loadData(update: "init" | "basic" | "users" | "admins" | "organizations" | null, dataError: Ref<string> | null) {
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
    if (update === "init" || update === "users") {
      users.value = clone(response.doc.users || [])
    }
    if (update === "init" || update === "admins") {
      admins.value = clone(response.doc.admins || [])
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

async function onSubmit(payload: Identity, update: "basic" | "users" | "admins" | "organizations", updated: Ref<boolean>, unexpectedError: Ref<string>) {
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
  if ((identity.value!.pictureUrl || "") !== pictureUrl.value) {
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
    users: identity.value!.users,
    admins: identity.value!.admins,
    organizations: identity.value!.organizations,
  }
  await onSubmit(payload, "basic", basicUpdated, basicUnexpectedError)
}

function canUsersSubmit(): boolean {
  // Anything changed?
  if (!equals(identity.value!.users || [], users.value)) {
    return true
  }

  return false
}

async function onUsersSubmit() {
  const payload: Identity = {
    // We update only users.
    id: props.id,
    username: identity.value!.username,
    email: identity.value!.email,
    givenName: identity.value!.givenName,
    fullName: identity.value!.fullName,
    pictureUrl: identity.value!.pictureUrl,
    description: identity.value!.description,
    users: users.value,
    admins: identity.value!.admins,
    organizations: identity.value!.organizations,
  }
  await onSubmit(payload, "users", usersUpdated, usersUnexpectedError)
}

function onAddUser() {
  if (abortController.signal.aborted) {
    return
  }

  // No need to call resetOnInteraction here because we modify variables
  // which we watch to call resetOnInteraction.

  users.value.push({
    id: "",
  })

  nextTick(() => {
    document.getElementById(`user-${users.value.length - 1}-id`)?.focus()
  })
}

function canAdminsSubmit(): boolean {
  // Anything changed?
  if (!equals(identity.value!.admins || [], admins.value)) {
    return true
  }

  return false
}

async function onAdminsSubmit() {
  const payload: Identity = {
    // We update only admins.
    id: props.id,
    username: identity.value!.username,
    email: identity.value!.email,
    givenName: identity.value!.givenName,
    fullName: identity.value!.fullName,
    pictureUrl: identity.value!.pictureUrl,
    description: identity.value!.description,
    users: identity.value!.users,
    admins: admins.value,
    organizations: identity.value!.organizations,
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

function canOrganizationsSubmit(): boolean {
  // Anything changed?
  if (!equals(identity.value!.organizations || [], identityOrganizations.value)) {
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
    users: identity.value!.users,
    admins: identity.value!.admins,
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
    applications: [],
  })

  nextTick(() => {
    document.getElementById("organizations-update")?.focus()
  })
}

// TODO: Remember previous organization-scoped identity IDs and reuse them if an organization is removed and then added back without calling update in-between.
</script>

<template>
  <Teleport to="header">
    <NavBar></NavBar>
  </Teleport>
  <div class="w-full flex flex-col items-center mt-12 sm:mt-[4.5rem] border-t border-transparent">
    <div class="grid auto-rows-auto grid-cols-[minmax(0,_65ch)] m-1 sm:m-4 gap-1 sm:gap-4">
      <div class="w-full rounded border bg-white p-4 shadow flex flex-col gap-4">
        <div class="flex flex-row items-center">
          <h1 class="text-2xl font-bold">{{ t("common.entities.identity") }}</h1>
        </div>
        <div v-if="dataLoading">{{ t("common.data.dataLoading") }}</div>
        <div v-else-if="dataLoadingError" class="text-error-600">{{ t("common.errors.unexpected") }}</div>
        <template v-else>
          <form class="flex flex-col" novalidate @submit.prevent="onBasicSubmit">
            <label for="username" class="mb-1"
              >{{ t("common.fields.username") }}<span v-if="metadata.can_update" class="text-neutral-500 italic text-sm"> {{ t("common.labels.optional") }}</span></label
            >
            <InputText id="username" v-model="username" class="flex-grow flex-auto min-w-0" :readonly="!metadata.can_update" :progress="progress" />
            <label for="email" class="mb-1 mt-4"
              >{{ t("common.fields.email") }}<span v-if="metadata.can_update" class="text-neutral-500 italic text-sm"> {{ t("common.labels.optional") }}</span></label
            >
            <InputText id="email" v-model="email" class="flex-grow flex-auto min-w-0" :readonly="!metadata.can_update" :progress="progress" />
            <label for="givenName" class="mb-1 mt-4"
              >{{ t("common.fields.givenName") }}<span v-if="metadata.can_update" class="text-neutral-500 italic text-sm"> {{ t("common.labels.optional") }}</span></label
            >
            <InputText id="givenName" v-model="givenName" class="flex-grow flex-auto min-w-0" :readonly="!metadata.can_update" :progress="progress" />
            <label for="fullName" class="mb-1 mt-4"
              >{{ t("common.fields.fullName") }}<span v-if="metadata.can_update" class="text-neutral-500 italic text-sm"> {{ t("common.labels.optional") }}</span></label
            >
            <InputText id="fullName" v-model="fullName" class="flex-grow flex-auto min-w-0" :readonly="!metadata.can_update" :progress="progress" />
            <label for="pictureUrl" class="mb-1 mt-4"
              >{{ t("common.fields.pictureUrl")
              }}<span v-if="metadata.can_update" class="text-neutral-500 italic text-sm"> {{ t("common.labels.optional") }}</span></label
            >
            <InputText id="pictureUrl" v-model="pictureUrl" class="flex-grow flex-auto min-w-0" :readonly="!metadata.can_update" :progress="progress" />
            <label for="description" class="mb-1 mt-4"
              >{{ t("common.fields.description")
              }}<span v-if="metadata.can_update" class="text-neutral-500 italic text-sm"> {{ t("common.labels.optional") }}</span></label
            >
            <TextArea id="description" v-model="description" class="flex-grow flex-auto min-w-0" :readonly="!metadata.can_update" :progress="progress" />
            <div v-if="basicUnexpectedError" class="mt-4 text-error-600">{{ t("common.errors.unexpected") }}</div>
            <div v-else-if="basicUpdated" class="mt-4 text-success-600">{{ t("views.IdentityGet.identityUpdated") }}</div>
            <div v-if="metadata.can_update" class="mt-4 flex flex-row justify-end">
              <!--
                Button is on purpose not disabled on basicUnexpectedError so that user can retry.
              -->
              <Button type="submit" primary :disabled="!canBasicSubmit()" :progress="progress">{{ t("common.buttons.update") }}</Button>
            </div>
          </form>
          <h2 class="text-xl font-bold">{{ t("common.entities.users") }}</h2>
          <div v-if="usersUnexpectedError" class="text-error-600">{{ t("common.errors.unexpected") }}</div>
          <div v-else-if="usersUpdated" class="text-success-600">{{ t("views.IdentityGet.usersUpdated") }}</div>
          <form class="flex flex-col" novalidate @submit.prevent="onUsersSubmit">
            <ol class="flex flex-col gap-y-4">
              <li v-for="(user, i) of users" :key="i" class="grid auto-rows-auto grid-cols-[min-content,auto] gap-x-4">
                <div>{{ i + 1 }}.</div>
                <div class="flex flex-col">
                  <WithIdentityPublicDocument
                    v-if="identity?.users?.find((a) => a.id === user.id)"
                    :item="user"
                    :organization-id="siteContext.organizationId"
                    :labels="identity?.id === user.id ? [t('common.labels.creator')] : []"
                  >
                    <div v-if="metadata.can_update" class="flex flex-col items-start">
                      <Button type="button" @click.prevent="users.splice(i, 1)">{{ t("common.buttons.remove") }}</Button>
                    </div>
                  </WithIdentityPublicDocument>
                  <div v-else-if="metadata.can_update" class="flex flex-row gap-4">
                    <InputText :id="`user-${i}-id`" v-model="users[i].id" class="flex-grow flex-auto min-w-0" :progress="progress" required />
                    <Button type="button" @click.prevent="users.splice(i, 1)">{{ t("common.buttons.remove") }}</Button>
                  </div>
                </div>
              </li>
            </ol>
            <div v-if="metadata.can_update" class="flex flex-row justify-between gap-4" :class="users.length ? 'mt-4' : ''">
              <Button type="button" @click.prevent="onAddUser">{{ t("common.buttons.addUser") }}</Button>
              <!--
                Button is on purpose not disabled on usersUnexpectedError so that user can retry.
              -->
              <Button type="submit" primary :disabled="!canUsersSubmit()" :progress="progress">{{ t("common.buttons.update") }}</Button>
            </div>
          </form>
          <h2 class="text-xl font-bold">{{ t("common.entities.admins") }}</h2>
          <div v-if="adminsUnexpectedError" class="text-error-600">{{ t("common.errors.unexpected") }}</div>
          <div v-else-if="adminsUpdated" class="text-success-600">{{ t("common.data.adminsUpdated") }}</div>
          <form class="flex flex-col" novalidate @submit.prevent="onAdminsSubmit">
            <ol class="flex flex-col gap-y-4">
              <li v-for="(admin, i) of admins" :key="i" class="grid auto-rows-auto grid-cols-[min-content,auto] gap-x-4">
                <div>{{ i + 1 }}.</div>
                <div class="flex flex-col">
                  <WithIdentityPublicDocument
                    v-if="identity?.admins?.find((a) => a.id === admin.id)"
                    :item="admin"
                    :organization-id="siteContext.organizationId"
                    :labels="identity?.id === admin.id ? [t('common.labels.creator')] : []"
                  >
                    <div v-if="metadata.can_update" class="flex flex-col items-start">
                      <Button type="button" @click.prevent="admins.splice(i, 1)">{{ t("common.buttons.remove") }}</Button>
                    </div>
                  </WithIdentityPublicDocument>
                  <div v-else-if="metadata.can_update" class="flex flex-row gap-4">
                    <InputText :id="`admin-${i}-id`" v-model="admins[i].id" class="flex-grow flex-auto min-w-0" :progress="progress" required />
                    <Button type="button" @click.prevent="admins.splice(i, 1)">{{ t("common.buttons.remove") }}</Button>
                  </div>
                </div>
              </li>
            </ol>
            <div v-if="metadata.can_update" class="flex flex-row justify-between gap-4" :class="admins.length ? 'mt-4' : ''">
              <Button type="button" @click.prevent="onAddAdmin">{{ t("common.buttons.addAdmin") }}</Button>
              <!--
                Button is on purpose not disabled on adminsUnexpectedError so that user can retry.
              -->
              <Button type="submit" primary :disabled="!canAdminsSubmit()" :progress="progress">{{ t("common.buttons.update") }}</Button>
            </div>
          </form>
          <template v-if="identityOrganizations.length || canOrganizationsSubmit() || identityOrganizationsUnexpectedError || identityOrganizationsUpdated">
            <h2 class="text-xl font-bold">{{ t("views.IdentityGet.addedOrganizations") }}</h2>
            <div v-if="identityOrganizationsUnexpectedError" class="text-error-600">{{ t("common.errors.unexpected") }}</div>
            <div v-else-if="identityOrganizationsUpdated" class="text-success-600">{{ t("views.IdentityGet.organizationsUpdated") }}</div>
            <form v-if="identityOrganizations.length || canOrganizationsSubmit()" class="flex flex-col" novalidate @submit.prevent="onOrganizationsSubmit">
              <ul>
                <li v-for="(identityOrganization, i) in identityOrganizations" :key="identityOrganization.id || i" class="flex flex-col mb-4">
                  <OrganizationListItem :item="identityOrganization.organization" h3 />
                  <IdentityOrganization :identity-organization="identityOrganization">
                    <div v-if="metadata.can_update" class="flex flew-row gap-4">
                      <Button type="button" :progress="progress" @click.prevent="identityOrganization.active = !identityOrganization.active">
                        {{ identityOrganization.active ? t("common.buttons.disable") : t("common.buttons.activate") }}
                      </Button>
                      <Button type="button" :progress="progress" @click.prevent="identityOrganizations.splice(i, 1)">{{ t("common.buttons.remove") }}</Button>
                    </div>
                  </IdentityOrganization>
                </li>
              </ul>
              <div v-if="metadata.can_update" class="flex flex-row justify-end">
                <!--
                  Button is on purpose not disabled on identityOrganizationsUnexpectedError so that user can retry.
                -->
                <Button id="organizations-update" type="submit" primary :disabled="!canOrganizationsSubmit()" :progress="progress">{{
                  t("common.buttons.update")
                }}</Button>
              </div>
            </form>
          </template>
          <template v-if="metadata.can_update && availableOrganizations.length">
            <h2 class="text-xl font-bold">{{ t("views.IdentityGet.availableOrganizations") }}</h2>
            <ul class="flex flex-col gap-4">
              <li v-for="organization in availableOrganizations" :key="organization.id">
                <OrganizationListItem :item="organization" h3>
                  <template #default="{ doc }">
                    <div v-if="doc" class="flex flex-col items-start">
                      <Button type="button" :progress="progress" primary @click.prevent="onAddOrganization(organization)">{{ t("common.buttons.add") }}</Button>
                    </div>
                  </template>
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
