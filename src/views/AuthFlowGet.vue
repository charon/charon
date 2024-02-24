<!--
For flow step components:

Define transition hooks to be called by the parent component through onMounted
and defineExpose. Use onBeforeLeave to abort the abort controller. Call
onBeforeLeave as both the transition hook and onUnmounted.

Use abort controller for async operations. After every await check if it is aborted.
At the beginning of every event handler check if it is aborted. This allows us to
quickly abort all async operations if step (and thus its component) changes.
It also effectively disables the component once it starts being transitioned out.

We do not want to visually disable the component once it starts being transitioned out
(unless it is already disabled) to avoid flicker. AutoFlow component disables for
elements and links but that should not change how components look.
-->

<script setup lang="ts">
import type { AuthFlowResponse, AuthFlowStep, Completed, DeriveOptions, EncryptOptions, LocationResponse, Organization } from "@/types"

import { inject, onBeforeMount, onBeforeUnmount, onMounted, onUnmounted, provide, ref, watch } from "vue"
import { useRouter } from "vue-router"
import WithDocument from "@/components/WithDocument.vue"
import Footer from "@/components/Footer.vue"
import Stepper from "@/components/Stepper.vue"
import AuthStart from "@/components/AuthStart.vue"
import AuthOIDCProvider from "@/components/AuthOIDCProvider.vue"
import AuthPassword from "@/components/AuthPassword.vue"
import AuthPasskeySignin from "@/components/AuthPasskeySignin.vue"
import AuthPasskeySignup from "@/components/AuthPasskeySignup.vue"
import AuthCode from "@/components/AuthCode.vue"
import AuthIdentity from "@/components/AuthIdentity.vue"
import AuthAutoRedirect from "@/components/AuthAutoRedirect.vue"
import AuthManualRedirect from "@/components/AuthManualRedirect.vue"
import { getURL, restartAuth } from "@/api"
// Importing "@/flow" also fetches siteContext which we have to fetch because
// the server sends the preload header for it. Generally this is already cached.
import { getProvider, updateSteps, flowKey, updateStepsNoCode } from "@/flow"
import { processCompleted } from "@/utils"
import { progressKey } from "@/progress"

const props = defineProps<{
  id: string
}>()

const router = useRouter()

const mainProgress = inject(progressKey, ref(0))

const abortController = new AbortController()

const dataLoading = ref(true)
const unexpectedError = ref("")
const steps = ref<AuthFlowStep[]>([])
const currentStep = ref("start")
const direction = ref<"forward" | "backward">("forward")
const emailOrUsername = ref("")
const publicKey = ref<Uint8Array>()
const deriveOptions = ref<DeriveOptions>()
const encryptOptions = ref<EncryptOptions>()
const provider = ref("")
const location = ref<LocationResponse>({ url: "", replace: false })
const target = ref<"session" | "oidc">("session")
const name = ref("")
const homepage = ref("")
const organizationId = ref("")
const completed = ref<Completed>("")

onUnmounted(() => {
  abortController.abort()
})

const flow = {
  forward(to: string) {
    updateSteps(flow, to)
    direction.value = "forward"
    currentStep.value = to
  },
  backward(to: string) {
    direction.value = "backward"
    currentStep.value = to
  },
  getEmailOrUsername(): string {
    return emailOrUsername.value
  },
  updateEmailOrUsername(value: string) {
    emailOrUsername.value = value
  },
  updatePublicKey(value?: Uint8Array) {
    publicKey.value = value
  },
  updateDeriveOptions(value?: DeriveOptions) {
    deriveOptions.value = value
  },
  updateEncryptOptions(value?: EncryptOptions) {
    encryptOptions.value = value
  },
  getProvider(): string {
    return provider.value
  },
  updateProvider(value: string) {
    provider.value = value
  },
  getTarget(): "session" | "oidc" {
    return target.value
  },
  updateTarget(value: "session" | "oidc") {
    target.value = value
  },
  updateLocation(value: LocationResponse) {
    location.value = value
  },
  getName(): string {
    return name.value
  },
  updateName(value: string) {
    name.value = value
  },
  updateHomepage(value: string) {
    homepage.value = value
  },
  updateOrganizationId(value: string) {
    organizationId.value = value
  },
  getSteps(): AuthFlowStep[] {
    return steps.value
  },
  updateSteps(value: AuthFlowStep[]) {
    steps.value = value
  },
  getCompleted(): Completed {
    return completed.value
  },
  updateCompleted(value: Completed) {
    completed.value = value
  },
}
provide(flowKey, flow)

onBeforeMount(async () => {
  try {
    const url = router.apiResolve({
      name: "AuthFlowGet",
      params: {
        id: props.id,
      },
    }).href

    const response = await getURL<AuthFlowResponse>(url, null, abortController.signal, null)
    if (abortController.signal.aborted) {
      return
    }

    const flowResponse = response.doc
    target.value = flowResponse.target
    if (flowResponse.name) {
      name.value = flowResponse.name
    }
    if ("homepage" in flowResponse) {
      homepage.value = flowResponse.homepage
    }
    if ("organizationId" in flowResponse) {
      organizationId.value = flowResponse.organizationId
    }
    if (flowResponse.emailOrUsername) {
      emailOrUsername.value = flowResponse.emailOrUsername
    }
    if (flowResponse.provider) {
      if (flowResponse.provider === "code" || flowResponse.provider === "password") {
        updateSteps(flow, flowResponse.provider)
        currentStep.value = flowResponse.provider
      } else if (flowResponse.provider === "passkey") {
        updateSteps(flow, "passkeySignin")
        currentStep.value = "passkeySignin"
      } else if (getProvider(flowResponse.provider)) {
        provider.value = flowResponse.provider
        // We call updateSteps but the flow is probably completed so
        // we will set currentStep to "autoRedirect" (or "manualRedirect") below.
        // Still, we want steps to be updated for the "oidcProvider" first.
        updateSteps(flow, "oidcProvider")
        currentStep.value = "oidcProvider"
      } else {
        throw new Error(`unknown provider "${flowResponse.provider}"`)
      }
    } else {
      updateSteps(flow, "start", true)
    }
    if ("location" in flowResponse && "completed" in flowResponse) {
      if (flowResponse.provider === "password") {
        updateStepsNoCode(flow)
      }
      // "location" and "completed" are provided together only for session target,
      // so there is no organization ID.
      processCompleted(flow, flowResponse.target, flowResponse.location, flowResponse.name, "", "", flowResponse.completed)
    } else if ("completed" in flowResponse) {
      if (flowResponse.provider === "password") {
        updateStepsNoCode(flow)
      }
      // If "completed" is provided, but "location" is not, we are in OIDC target,
      // so we pass an empty location response as it is not really used.
      processCompleted(
        flow,
        flowResponse.target,
        { url: "", replace: false },
        flowResponse.name,
        flowResponse.homepage,
        flowResponse.organizationId,
        flowResponse.completed,
      )
    }
    if ("error" in flowResponse && flowResponse.error) {
      throw new Error(`unexpected error "${flowResponse.error}"`)
    }
  } catch (error) {
    if (abortController.signal.aborted) {
      return
    }
    console.error(error)
    unexpectedError.value = `${error}`
  } finally {
    dataLoading.value = false
  }
})

async function onPreviousStep(step: string) {
  if (abortController.signal.aborted) {
    return
  }

  if (completed.value !== "" && step === "start") {
    // TODO: What to do if unexpected error happens?
    await restartAuth(router, props.id, flow, abortController.signal, mainProgress)
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
  <div v-if="!dataLoading" class="w-full self-stretch overflow-x-hidden flex flex-col items-center justify-center">
    <!--
      We use grid here to have contents of maximum 65ch and grow to 65ch even if contents are narrower,
      but allow contents to shrink if necessary to fit into the smaller window width.
    -->
    <div class="grid auto-rows-auto grid-cols-[minmax(0,_65ch)] m-1 sm:m-4 gap-1 sm:gap-4">
      <div v-if="unexpectedError" class="w-full rounded border bg-white p-4 shadow text-error-600">Unexpected error. Please try again.</div>
      <template v-else>
        <div class="w-full rounded border bg-white p-4 shadow">
          <h2 class="text-center mx-4 mb-4 text-xl font-bold uppercase">Sign-in or sign-up</h2>
          <div v-if="target === 'session'" class="mb-4">
            <strong>{{ name }}</strong> is asking you to sign-in or sign-up. Please follow the steps below to do so.
          </div>
          <div v-else class="mb-4">
            <a :href="homepage" class="link"
              ><strong>{{ name }}</strong></a
            >
            from organization
            <WithOrganizationDocument :id="organizationId" name="OrganizationGet">
              <template #default="{ doc, url }">
                <router-link :to="{ name: 'OrganizationGet', params: { id: organizationId } }" :data-url="url" class="link"
                  ><strong>{{ doc.name }}</strong></router-link
                >
              </template>
            </WithOrganizationDocument>
            is using Charon to ask you to sign-in or sign-up. Please follow the steps below to do so, or to decline.
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
                  completed !== 'failed' &&
                  (completed === '' ||
                    (target === 'oidc' &&
                      completed !== 'redirect' &&
                      step.key != 'password' &&
                      step.key != 'oidcProvider' &&
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
        <div class="w-full relative">
          <Transition
            :name="direction"
            @after-enter="onAfterEnter"
            @enter-cancelled="onEnterCancelled"
            @before-leave="onBeforeLeave"
            @leave="onLeave"
            @after-leave="onAfterLeave"
            @leave-cancelled="onLeaveCancelled"
          >
            <AuthStart v-if="currentStep === 'start'" :id="id" ref="component" :email-or-username="emailOrUsername" />
            <AuthOIDCProvider v-else-if="currentStep === 'oidcProvider'" :id="id" ref="component" :provider="provider" />
            <AuthPasskeySignin v-else-if="currentStep === 'passkeySignin'" :id="id" ref="component" />
            <AuthPasskeySignup v-else-if="currentStep === 'passkeySignup'" :id="id" ref="component" />
            <AuthPassword
              v-else-if="currentStep === 'password'"
              :id="id"
              ref="component"
              :email-or-username="emailOrUsername"
              :public-key="publicKey"
              :derive-options="deriveOptions"
              :encrypt-options="encryptOptions"
            />
            <AuthCode v-else-if="currentStep === 'code'" :id="id" ref="component" :name="name" :email-or-username="emailOrUsername" />
            <AuthIdentity v-else-if="currentStep === 'identity'" :id="id" ref="component" :name="name" :completed="completed" :organization-id="organizationId" />
            <AuthAutoRedirect
              v-else-if="currentStep === 'autoRedirect'"
              :id="id"
              ref="component"
              :name="name"
              :completed="completed"
              :location="location"
              :target="target"
            />
            <AuthManualRedirect
              v-else-if="currentStep === 'manualRedirect'"
              :id="id"
              ref="component"
              :name="name"
              :completed="completed"
              :location="location"
              :target="target"
              :homepage="homepage"
            />
          </Transition>
        </div>
      </template>
    </div>
  </div>
  <Teleport to="footer">
    <Footer />
  </Teleport>
</template>
