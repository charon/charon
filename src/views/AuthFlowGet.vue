<!--
For flow step components:

Define transition hooks to be called by the parent component through onMounted
and defineExpose. Use onBeforeLeave to abort the abort controller. Call
onBeforeLeave as both the transition hook and onBeforeUnmount.

Use abort controller for async operations. After every await check if it is aborted.
At the beginning of every event handler check if it is aborted. This allows us to
quickly abort all async operations if step (and thus its component) changes.
It also effectively disables the component once it starts being transitioned out.

We do not want to visually disable the component once it starts being transitioned out
(unless it is already disabled) to avoid flicker. AutoFlow component disables for
elements and links but that should not change how components look.
-->

<script setup lang="ts">
import type { AuthFlowResponse, AuthFlowStep, Completed, DeriveOptions, EncryptOptions, Flow, Organization, OrganizationApplicationPublic, SiteProvider } from "@/types"

import { onBeforeMount, onBeforeUnmount, onMounted, ref, watch } from "vue"
import { useI18n } from "vue-i18n"
import { useRouter } from "vue-router"

import { getURL, restartAuth } from "@/api"
import Stepper from "@/components/Stepper.vue"
import WithDocument from "@/components/WithDocument.vue"
// Importing "@/flow" also fetches siteContext which we have to fetch because
// the server sends the preload header for it. Generally this is already cached.
import { processFirstResponse, updateSteps } from "@/flow"
import AuthAutoRedirect from "@/partials/AuthAutoRedirect.vue"
import AuthCode from "@/partials/AuthCode.vue"
import AuthIdentity from "@/partials/AuthIdentity.vue"
import AuthManualRedirect from "@/partials/AuthManualRedirect.vue"
import AuthPasskeySignin from "@/partials/AuthPasskeySignin.vue"
import AuthPasskeySignup from "@/partials/AuthPasskeySignup.vue"
import AuthPassword from "@/partials/AuthPassword.vue"
import AuthStart from "@/partials/AuthStart.vue"
import AuthThirdPartyProvider from "@/partials/AuthThirdPartyProvider.vue"
import Footer from "@/partials/Footer.vue"
import { injectProgress } from "@/progress"
import { getHomepage } from "@/utils"

const props = defineProps<{
  id: string
}>()

const { t } = useI18n({ useScope: "global" })
const router = useRouter()
const progress = injectProgress()

const abortController = new AbortController()
const dataLoading = ref(true)
const unexpectedError = ref("")
const steps = ref<AuthFlowStep[]>([])
const currentStep = ref("start")
const direction = ref<"forward" | "backward">("forward")

const completed = ref<Completed[]>([])
const organizationId = ref("")
const appId = ref("")
const thirdPartyProvider = ref<SiteProvider | null>(null)
const emailOrUsername = ref("")
const publicKey = ref<Uint8Array<ArrayBuffer>>()
const deriveOptions = ref<DeriveOptions>()
const encryptOptions = ref<EncryptOptions>()

onBeforeUnmount(() => {
  abortController.abort()
})

const flow: Flow = {
  getId(): string {
    return props.id
  },

  forward(to: string) {
    updateSteps(flow, to)
    direction.value = "forward"
    currentStep.value = to
  },
  backward(to: string) {
    direction.value = "backward"
    currentStep.value = to
  },
  getSteps(): AuthFlowStep[] {
    return steps.value
  },
  setSteps(value: AuthFlowStep[]) {
    steps.value = value
  },

  getCompleted(): Completed[] {
    return completed.value
  },
  setCompleted(value: Completed[]) {
    completed.value = value
  },
  getOrganizationId(): string {
    return organizationId.value
  },
  setOrganizationId(value: string) {
    organizationId.value = value
  },
  getAppId(): string {
    return appId.value
  },
  setAppId(value: string) {
    appId.value = value
  },
  getThirdPartyProvider(): SiteProvider | null {
    return thirdPartyProvider.value
  },
  setThirdPartyProvider(value: SiteProvider | null) {
    thirdPartyProvider.value = value
  },
  getEmailOrUsername(): string {
    return emailOrUsername.value
  },
  setEmailOrUsername(value: string) {
    emailOrUsername.value = value
  },

  getPublicKey: function (): Uint8Array<ArrayBuffer> | undefined {
    return publicKey.value
  },
  setPublicKey(value?: Uint8Array<ArrayBuffer>) {
    publicKey.value = value
  },
  getDeriveOptions: function (): DeriveOptions | undefined {
    return deriveOptions.value
  },
  setDeriveOptions(value?: DeriveOptions) {
    deriveOptions.value = value
  },
  getEncryptOptions: function (): EncryptOptions | undefined {
    return encryptOptions.value
  },
  setEncryptOptions(value?: EncryptOptions) {
    encryptOptions.value = value
  },
}

onBeforeMount(async () => {
  try {
    const url = router.apiResolve({
      name: "AuthFlowGet",
      params: {
        id: props.id,
      },
    }).href

    const response = await getURL<AuthFlowResponse>(url, null, abortController.signal, progress)
    if (abortController.signal.aborted) {
      return
    }
    processFirstResponse(router, response.doc, flow, progress)
  } catch (error) {
    if (abortController.signal.aborted) {
      return
    }
    console.error("AuthFLowGet.onBeforeMount", error)
    unexpectedError.value = `${error}`
  } finally {
    dataLoading.value = false
  }
})

async function onPreviousStep(step: string) {
  if (abortController.signal.aborted) {
    return
  }

  if (completed.value.length > 0 && step === "start") {
    // Going back to start (after completed auth step) means restarting authentication.
    // TODO: What to do if unexpected error happens?
    // Here we do not pass abortController, but just its signal because we do not want to abort
    // the view-level controller, which is what restartAuth does if it receives the abort controller.
    await restartAuth(router, flow, abortController.signal, progress)
  } else if (completed.value.length > 0 && step === "identity") {
    // Going back to identity step means removing steps after the completed identity step.
    const completed = flow.getCompleted()
    flow.setCompleted(completed.filter((c) => c !== "identity" && c !== "finishReady" && c !== "declined"))
    flow.backward(step)
  } else {
    flow.backward(step)
  }
}

const component = ref()

// Call transition hooks on child components.
// See: https://github.com/vuejs/rfcs/discussions/613
function callHook(el: Element, hook: string) {
  if ("__vue_exposed" in el) {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const exposed = el.__vue_exposed as Record<string, any> | null
    if (exposed && hook in exposed) {
      exposed[hook]()
    }
  }
}

function onAfterEnter(el: Element) {
  callHook(el, "onAfterEnter")
}

function onEnterCancelled(el: Element) {
  callHook(el, "onEnterCancelled")
}

function onBeforeLeave(el: Element) {
  callHook(el, "onBeforeLeave")

  // We make all form elements be disabled.
  // Event handlers should be disabled by components themselves which is
  // generally done by having an abortController which gets aborted in
  // onBeforeLeave hook and which is checked in event handlers.
  for (const e of el.querySelectorAll("button, input, select, textarea")) {
    ;(e as HTMLInputElement).disabled = true
  }
  // We make all links be disabled.
  // Links with existing event handlers should be disabled by components themselves
  // which is generally done by having an abortController which gets aborted in
  // onBeforeLeave hook and which is checked in event handlers.
  for (const l of el.querySelectorAll("a")) {
    l.onclick = function () {
      return false
    }
  }
}

function onLeave(el: Element) {
  callHook(el, "onLeave")
}

function onAfterLeave(el: Element) {
  callHook(el, "onAfterLeave")
}

function onLeaveCancelled(el: Element) {
  callHook(el, "onLeaveCancelled")
}

onMounted(() => {
  // We wait for the component to be set for the first time.
  const unwatch = watch(
    component,
    (c) => {
      if (!c) {
        // Not yet set.
        return
      }
      // Set, stop watching.
      unwatch()
      // Call a hook if it is defined on the component.
      if ("onAfterEnter" in c) {
        c.onAfterEnter()
      }
    },
    { immediate: true },
  )
})

onBeforeUnmount(() => {
  if (component.value && "onBeforeLeave" in component.value) {
    component.value.onBeforeLeave()
  }
})

const WithOrganizationDocument = WithDocument<Organization>
const WithOrganizationApplicationDocument = WithDocument<OrganizationApplicationPublic>
</script>

<template>
  <!-- TODO: Show data loading placeholder. -->
  <!-- TODO: Contents should recenter after height change using a transition which runs at the same time transition between steps does. -->
  <!--
    We use overflow-x-hidden so that during transition we do not get scrollbars while elements are moved in and out.
    We could potentially add overflow-x-hidden only during transition, but for now it does not seem to be a problem to have it always.

    Use of v-if="!dataLoading" is critical here, because otherwise onAfterEnter on step components can be called twice.
    Also transitions break because it can happen that first start step is rendered and then it is updated to another one after data loads.
  -->
  <div v-if="!dataLoading" class="flex w-full flex-col items-center justify-center self-stretch overflow-x-hidden">
    <!--
      We use grid here to have contents of maximum 65ch and grow to 65ch even if contents are narrower,
      but allow contents to shrink if necessary to fit into the smaller window width.
    -->
    <div class="m-1 grid auto-rows-auto grid-cols-[minmax(0,65ch)] gap-1 sm:m-4 sm:gap-4">
      <div v-if="unexpectedError" class="w-full rounded-sm border border-gray-200 bg-white p-4 text-error-600 shadow-sm">{{ t("common.errors.unexpected") }}</div>
      <template v-else>
        <div class="w-full rounded-sm border border-gray-200 bg-white p-4 shadow-sm">
          <h2 class="mx-4 mb-4 text-center text-xl font-bold uppercase">{{ t("common.buttons.signIn") }}</h2>
          <div class="mb-4">
            <i18n-t keypath="views.AuthFlowGet.instructionsMessage" scope="global">
              <template #appLink>
                <WithOrganizationApplicationDocument :params="{ id: flow.getOrganizationId(), appId: flow.getAppId() }" name="OrganizationApp">
                  <template #default="{ doc, url }">
                    <a :href="getHomepage(doc)" :data-url="url" class="link"
                      ><strong>{{ doc.applicationTemplate.name }}</strong></a
                    >
                  </template>
                </WithOrganizationApplicationDocument>
              </template>
              <template #orgLink>
                <WithOrganizationDocument :params="{ id: flow.getOrganizationId() }" name="OrganizationGet">
                  <template #default="{ doc, url }">
                    <router-link :to="{ name: 'OrganizationGet', params: { id: flow.getOrganizationId() } }" :data-url="url" class="link"
                      ><strong>{{ doc.name }}</strong></router-link
                    >
                  </template>
                </WithOrganizationDocument>
              </template>
            </i18n-t>
          </div>
          <Stepper v-if="steps.length" v-slot="{ step, active, beforeActive }" :steps="steps" :current-step="currentStep">
            <!--
              TODO: Text wrapping can change as text changes between regular and bold.
                    Find a way to prevent that (maybe always use wrapping of a bold version, it is not a problem that
                    characters move inside the line but they should not move between lines and rewrapping should not happen).
            -->
            <li class="text-center text-balance">
              <strong v-if="active">{{ step.name }}</strong>
              <a
                v-else-if="
                  beforeActive &&
                  !flow.getCompleted().includes('failed') &&
                  (flow.getCompleted().length === 0 ||
                    // After authentication has completed, but not the whole flow has finished
                    // allow returning to any step which is not an intermediary authentication step
                    // (we want to force full authentication restart to the first authentication step
                    // if a user wants to redo authentication).
                    (!flow.getCompleted().includes('finished') &&
                      step.key != 'password' &&
                      step.key != 'thirdPartyProvider' &&
                      step.key != 'passkeySignin' &&
                      step.key != 'passkeySignup' &&
                      step.key != 'code'))
                "
                href=""
                class="link"
                @click.prevent="onPreviousStep(step.key)"
                >{{ step.name }}</a
              >
              <template v-else>{{ step.name }}</template>
            </li>
          </Stepper>
        </div>
        <div class="relative w-full">
          <Transition
            :name="direction"
            @after-enter="onAfterEnter"
            @enter-cancelled="onEnterCancelled"
            @before-leave="onBeforeLeave"
            @leave="onLeave"
            @after-leave="onAfterLeave"
            @leave-cancelled="onLeaveCancelled"
          >
            <AuthStart v-if="currentStep === 'start'" ref="component" :flow="flow" />
            <AuthThirdPartyProvider v-else-if="currentStep === 'thirdPartyProvider'" ref="component" :flow="flow" />
            <AuthPasskeySignin v-else-if="currentStep === 'passkeySignin'" ref="component" :flow="flow" />
            <AuthPasskeySignup v-else-if="currentStep === 'passkeySignup'" ref="component" :flow="flow" />
            <AuthPassword v-else-if="currentStep === 'password'" ref="component" :flow="flow" />
            <AuthCode v-else-if="currentStep === 'code'" ref="component" :flow="flow" />
            <AuthIdentity v-else-if="currentStep === 'identity'" ref="component" :flow="flow" />
            <AuthAutoRedirect v-else-if="currentStep === 'autoRedirect'" ref="component" :flow="flow" />
            <AuthManualRedirect v-else-if="currentStep === 'manualRedirect'" ref="component" :flow="flow" />
          </Transition>
        </div>
      </template>
    </div>
  </div>
  <Teleport to="footer">
    <Footer />
  </Teleport>
</template>
