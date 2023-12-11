<script setup lang="ts">
import { ref, nextTick } from "vue"
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

async function onTransitionend(el: Element) {
  await nextTick()
  el.querySelector<HTMLElement>("input.autofocus")?.focus()
}
</script>

<template>
  <div class="w-[65ch] m-1 sm:m-4 self-start overflow-hidden">
    <Transition :name="direction" @after-enter="onTransitionend">
      <AuthStart
        v-if="state === 'start'"
        :id="id"
        v-model:state="state"
        v-model:direction="direction"
        v-model:emailOrUsername="emailOrUsername"
        v-model:publicKey="publicKey"
        v-model:deriveOptions="deriveOptions"
        v-model:encryptOptions="encryptOptions"
      />
      <AuthPasskeySignin v-else-if="state === 'passkeySignin'" :id="id" v-model:state="state" v-model:direction="direction" />
      <AuthPasskeySignup v-else-if="state === 'passkeySignup'" :id="id" v-model:state="state" v-model:direction="direction" />
      <AuthPassword
        v-else-if="state === 'password'"
        :id="id"
        v-model:state="state"
        v-model:direction="direction"
        :email-or-username="emailOrUsername"
        :public-key="publicKey"
        :derive-options="deriveOptions"
        :encrypt-options="encryptOptions"
      />
      <AuthCode v-else-if="state === 'code'" :id="id" v-model:state="state" v-model:direction="direction" :email-or-username="emailOrUsername" />
    </Transition>
  </div>
</template>
