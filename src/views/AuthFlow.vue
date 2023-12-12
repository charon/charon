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
import { onMounted, onUnmounted, ref } from "vue"
import Footer from "@/components/Footer.vue"
import AuthStart from "@/components/AuthStart.vue"
import AuthPassword from "@/components/AuthPassword.vue"
import AuthPasskeySignin from "@/components/AuthPasskeySignin.vue"
import AuthPasskeySignup from "@/components/AuthPasskeySignup.vue"
import AuthCode from "@/components/AuthCode.vue"
import siteContext from "@/context"

defineProps<{
  id: string
}>()

const state = ref("start")
const direction = ref<"forward" | "backward">("forward")
const emailOrUsername = ref("")
const publicKey = ref(new Uint8Array())
const deriveOptions = ref({ name: "", namedCurve: "" })
const encryptOptions = ref({ name: "", iv: new Uint8Array(), tagLength: 0, length: 0 })

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
  <div class="w-full self-start overflow-hidden flex flex-row justify-center">
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
          v-model:state="state"
          v-model:direction="direction"
          v-model:emailOrUsername="emailOrUsername"
          v-model:publicKey="publicKey"
          v-model:deriveOptions="deriveOptions"
          v-model:encryptOptions="encryptOptions"
          :providers="siteContext.providers"
        />
        <AuthPasskeySignin v-else-if="state === 'passkeySignin'" :id="id" ref="component" v-model:state="state" v-model:direction="direction" />
        <AuthPasskeySignup v-else-if="state === 'passkeySignup'" :id="id" ref="component" v-model:state="state" v-model:direction="direction" />
        <AuthPassword
          v-else-if="state === 'password'"
          :id="id"
          ref="component"
          v-model:state="state"
          v-model:direction="direction"
          :email-or-username="emailOrUsername"
          :public-key="publicKey"
          :derive-options="deriveOptions"
          :encrypt-options="encryptOptions"
        />
        <AuthCode v-else-if="state === 'code'" :id="id" ref="component" v-model:state="state" v-model:direction="direction" :email-or-username="emailOrUsername" />
      </Transition>
    </div>
  </div>
  <Teleport to="footer">
    <Footer />
  </Teleport>
</template>
