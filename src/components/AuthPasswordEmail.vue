<script setup lang="ts">
import { ref, onMounted, nextTick } from "vue"
import Button from "@/components/Button.vue"
import InputText from "@/components/InputText.vue"

defineProps<{
  modelValue: string
  id: string
  email: string
}>()

const emit = defineEmits<{
  "update:modelValue": [value: string]
}>()

const password = ref("")
const progress = ref(0)

onMounted(async () => {
  await nextTick()
  document.getElementById("password")?.focus()
})

async function onBack() {
  emit("update:modelValue", "start")
  await nextTick()
  document.getElementById("email-or-username")?.focus()
}

async function onNext() {}
</script>

<template>
  <button
    type="button"
    class="flex-grow appearance-none rounded border-0 border-gray-500 bg-white px-3 py-2 text-left text-base shadow outline-none ring-2 ring-neutral-300 hover:ring-neutral-400 focus:border-blue-600 focus:ring-2 focus:ring-primary-500"
    @click.prevent="onBack"
  >
    {{ email }}
  </button>
  <div class="flex flex-col mt-4">
    <label for="password" class="mb-1">Password or passphrase</label>
    <form class="flex flex-row" @submit.prevent="onNext">
      <InputText id="password" v-model="password" type="password" tabindex="1" class="flex-grow flex-auto min-w-0" :readonly="progress > 0" />
      <Button type="submit" class="ml-4" tabindex="2" :disabled="password.trim().length == 0 || progress > 0">Next</Button>
    </form>
  </div>
  <div class="mt-4">
    If you do not yet have an account, it will be created for you. If you enter invalid password or passphrase, recovery will be done automatically for you by sending you
    a code to your e-mail address. You can also skip entering password or passphrase and directly request the code.
  </div>
  <div class="mt-4 flex flex-row justify-between gap-4">
    <Button type="button" tabindex="4" @click.prevent="onBack">Back</Button>
    <Button type="button" tabindex="3">Send code</Button>
  </div>
</template>
