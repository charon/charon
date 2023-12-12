<script setup lang="ts">
import { onMounted, onUnmounted, ref } from "vue"
import Footer from "@/components/Footer.vue"
import AuthStart from "@/components/AuthStart.vue"
import AuthPassword from "@/components/AuthPassword.vue"
import AuthPasskeySignin from "@/components/AuthPasskeySignin.vue"
import AuthPasskeySignup from "@/components/AuthPasskeySignup.vue"
import AuthCode from "@/components/AuthCode.vue"

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
