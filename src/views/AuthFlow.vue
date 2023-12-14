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
import { onBeforeMount, onMounted, onUnmounted, provide, ref } from "vue"
import Footer from "@/components/Footer.vue"
import AuthStart from "@/components/AuthStart.vue"
import AuthOIDCProvider from "@/components/AuthOIDCProvider.vue"
import AuthPassword from "@/components/AuthPassword.vue"
import AuthPasskeySignin from "@/components/AuthPasskeySignin.vue"
import AuthPasskeySignup from "@/components/AuthPasskeySignup.vue"
import AuthCode from "@/components/AuthCode.vue"
import AuthComplete from "@/components/AuthComplete.vue"
import { flowKey } from "@/utils"
// We fetch siteContext in view because the server sends preload header
// so we have to fetch it always, even if particular step does not need it.
// Generally this is already cached.
import siteContext from "@/context"
import { AuthFlowResponse, DeriveOptions, EncryptOptions, LocationResponse } from "@/types"
import { useRouter } from "vue-router"
import { FetchError } from "@/api"

const props = defineProps<{
  id: string
}>()

const router = useRouter()

const dataLoading = ref(true)
const state = ref("start")
const direction = ref<"forward" | "backward">("forward")
const emailOrUsername = ref("")
const publicKey = ref(new Uint8Array())
const deriveOptions = ref<DeriveOptions>({ name: "", namedCurve: "" })
const encryptOptions = ref<EncryptOptions>({ name: "", iv: new Uint8Array(), tagLength: 0, length: 0 })
const provider = ref("")
const location = ref<LocationResponse>({ url: "", replace: false })
const name = ref("")

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
    }
    if ("code" in flowResponse) {
      state.value = "code"
      emailOrUsername.value = flowResponse.code.emailOrUsername
    } else if ("location" in flowResponse && flowResponse.completed) {
      state.value = "complete"
      location.value = flowResponse.location
    }
    // TODO: Handle error.
  } finally {
    dataLoading.value = false
  }
})

const component = ref()

provide(flowKey, {
  forward(to: string) {
    direction.value = "forward"
    state.value = to
  },
  backward(to: string) {
    direction.value = "backward"
    state.value = to
  },
  updateEmailOrUsername(value: string) {
    emailOrUsername.value = value
  },
  updatePublicKey(value: Uint8Array) {
    publicKey.value = value
  },
  updateDeriveOptions(value: DeriveOptions) {
    deriveOptions.value = value
  },
  updateEncryptOptions(value: EncryptOptions) {
    encryptOptions.value = value
  },
  updateProvider(value: string) {
    provider.value = value
  },
  updateLocation(value: LocationResponse) {
    location.value = value
  },
  updateName(value: string) {
    name.value = value
  },
})

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
  if (component.value && "onAfterEnter" in component.value) {
    component.value.onAfterEnter()
  }
})

onUnmounted(() => {
  if (component.value && "onBeforeLeave" in component.value) {
    component.value.onBeforeLeave()
  }
})
</script>

<template>
  <!-- TODO: Show data loading placeholder. -->
  <div v-if="!dataLoading" class="w-full self-start overflow-hidden flex flex-col items-center">
    <div class="w-[65ch] m-1 mb-0 sm:mb-0 sm:m-4 rounded border bg-white p-4 shadow">
      <strong>{{ name }}</strong> is asking you to sign-in or sign-up. Please follow the steps below to do so.
    </div>
    <div class="w-[65ch] m-1 sm:m-4">
      <Transition
        :name="direction"
        @after-enter="onAfterEnter"
        @enter-cancelled="onEnterCancelled"
        @before-leave="onBeforeLeave"
        @leave="onLeave"
        @after-leave="onAfterLeave"
        @leave-cancelled="onLeaveCancelled"
      >
        <AuthStart
          v-if="state === 'start'"
          :id="id"
          ref="component"
          :email-or-username="emailOrUsername"
          :public-key="publicKey"
          :derive-options="deriveOptions"
          :encrypt-options="encryptOptions"
          :provider="provider"
          :providers="siteContext.providers"
        />
        <AuthOIDCProvider v-else-if="state === 'oidcProvider'" :id="id" ref="component" :providers="siteContext.providers" :provider="provider" />
        <AuthPasskeySignin v-else-if="state === 'passkeySignin'" :id="id" ref="component" />
        <AuthPasskeySignup v-else-if="state === 'passkeySignup'" :id="id" ref="component" />
        <AuthPassword
          v-else-if="state === 'password'"
          :id="id"
          ref="component"
          :email-or-username="emailOrUsername"
          :public-key="publicKey"
          :derive-options="deriveOptions"
          :encrypt-options="encryptOptions"
        />
        <AuthCode v-else-if="state === 'code'" :id="id" ref="component" :email-or-username="emailOrUsername" />
        <AuthComplete v-else-if="state === 'complete'" ref="component" :location="location" :name="name" />
      </Transition>
    </div>
  </div>
  <Teleport to="footer">
    <Footer />
  </Teleport>
</template>
