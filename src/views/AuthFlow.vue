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
import { onBeforeMount, onBeforeUnmount, onMounted, provide, ref, watch } from "vue"
import Footer from "@/components/Footer.vue"
import Stepper from "@/components/Stepper.vue"
import AuthStart from "@/components/AuthStart.vue"
import AuthOIDCProvider from "@/components/AuthOIDCProvider.vue"
import AuthPassword from "@/components/AuthPassword.vue"
import AuthPasskeySignin from "@/components/AuthPasskeySignin.vue"
import AuthPasskeySignup from "@/components/AuthPasskeySignup.vue"
import AuthCode from "@/components/AuthCode.vue"
import AuthComplete from "@/components/AuthComplete.vue"
import { flowKey, getProvider, updateSteps } from "@/utils"
import { AuthFlowResponse, AuthFlowStep, DeriveOptions, EncryptOptions, LocationResponse } from "@/types"
import { useRouter } from "vue-router"
import { FetchError } from "@/api"

const props = defineProps<{
  id: string
}>()

const router = useRouter()

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
const name = ref("")

const flow = {
  forward(to: string) {
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
  updateLocation(value: LocationResponse) {
    location.value = value
  },
  getName(): string {
    return name.value
  },
  updateName(value: string) {
    name.value = value
  },
  updateSteps(value: AuthFlowStep[]) {
    steps.value = value
  },
}
provide(flowKey, flow)

onBeforeMount(async () => {
  try {
    const url = router.apiResolve({
      name: "AuthFlow",
      params: {
        id: props.id,
      },
    }).href
    const response = await fetch(url, {
      method: "GET",
      // Mode and credentials match crossorigin=anonymous in link preload header.
      mode: "cors",
      credentials: "same-origin",
      referrer: document.location.href,
      referrerPolicy: "strict-origin-when-cross-origin",
    })
    const contentType = response.headers.get("Content-Type")
    if (!contentType || !contentType.includes("application/json")) {
      const body = await response.text()
      throw new FetchError(`fetch POST error ${response.status}: ${body}`, {
        status: response.status,
        body,
        url,
        requestID: response.headers.get("Request-ID"),
      })
    }
    const flowResponse = (await response.json()) as AuthFlowResponse
    if ("name" in flowResponse && flowResponse.name) {
      name.value = flowResponse.name
      steps.value = [
        {
          key: "start",
          name: "Charon sign-in or sign-up",
        },
        { key: "complete", name: `Redirect to ${flowResponse.name}` },
      ]
    }
    if ("emailOrUsername" in flowResponse && flowResponse.emailOrUsername) {
      emailOrUsername.value = flowResponse.emailOrUsername
    }
    if ("provider" in flowResponse && flowResponse.provider) {
      if (flowResponse.provider === "code" || flowResponse.provider === "password") {
        updateSteps(flow, flowResponse.provider)
        currentStep.value = flowResponse.provider
      } else if (flowResponse.provider === "passkey") {
        updateSteps(flow, "passkeySignin")
        currentStep.value = "passkeySignin"
      } else if (getProvider(flowResponse.provider)) {
        provider.value = flowResponse.provider
        // We call updateSteps but the flow is probably completed so
        // we will set currentStep to "complete" below. Still, we
        // want steps to be updated for the "oidcProvider" first.
        updateSteps(flow, "oidcProvider")
        currentStep.value = "oidcProvider"
      } else {
        throw new Error(`unknown provider "${flowResponse.provider}"`)
      }
    }
    if ("location" in flowResponse && flowResponse.completed) {
      location.value = flowResponse.location
      // updateSteps currently does not do anything for "complete"
      // target step and just leaves previously set steps.
      updateSteps(flow, "complete")
      currentStep.value = "complete"
    }
    if ("error" in flowResponse && flowResponse.error) {
      throw new Error(`unexpected error "${flowResponse.error}"`)
    }
  } catch (error) {
    console.error(error)
    unexpectedError.value = `${error}`
  } finally {
    dataLoading.value = false
  }
})

async function onPreviousStep(step: string) {
  flow.backward(step)
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
  // Event handlers should be disabled by components themselves.
  for (const e of el.querySelectorAll("button, input, select, textarea")) {
    ;(e as HTMLInputElement).disabled = true
  }
  // We make all links be disabled.
  // Links with existing event handlers should be disabled by components themselves.
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
  const unwatch = watch(component, (c) => {
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
  })
})

onBeforeUnmount(() => {
  if (component.value && "onBeforeLeave" in component.value) {
    component.value.onBeforeLeave()
  }
})
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
          <div class="mb-4">
            <strong>{{ name }}</strong> is asking you to sign-in or sign-up. Please follow the steps below to do so.
          </div>
          <Stepper v-if="steps.length" v-slot="{ step, active, beforeActive }" :steps="steps" :current-step="currentStep">
            <!-- TODO: Use text-balance instead of style here once TailwindCSS releases a new version. -->
            <!--
              TODO: Text wrapping can change as text changes between regular and bold.
                    Find a way to prevent that (maybe always use wrapping of a bold version, it is not a problem that
                    characters move inside the line but they should not move between lines and rewrapping should not happen).
            -->
            <li class="text-center" style="text-wrap: balance">
              <strong v-if="active">{{ step.name }}</strong>
              <a v-else-if="beforeActive && currentStep !== 'complete'" href="" class="link" @click.prevent="onPreviousStep(step.key)">{{ step.name }}</a>
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
            <AuthCode v-else-if="currentStep === 'code'" :id="id" ref="component" :email-or-username="emailOrUsername" />
            <AuthComplete v-else-if="currentStep === 'complete'" ref="component" :name="name" :location="location" />
          </Transition>
        </div>
      </template>
    </div>
  </div>
  <Teleport to="footer">
    <Footer />
  </Teleport>
</template>
