<script setup lang="ts">
import { ref } from "vue"
import InputText from "@/components/InputText.vue"
import Button from "@/components/Button.vue"

defineProps<{
  modelValue: string
  id: string
  disabled: boolean
}>()

defineEmits<{
  "update:modelValue": [value: string]
}>()

const emailOrUsername = ref("")

async function onNext() {}
</script>

<template>
  <div class="flex flex-col">
    <label for="email-address" class="mb-1">Enter your Charon username or your e-mail address</label>
    <form class="flex flex-row" @submit.prevent="onNext">
      <InputText id="email-address" v-model="emailOrUsername" class="flex-grow flex-auto min-w-0" :readonly="disabled" />
      <Button type="submit" class="ml-4" :disabled="emailOrUsername.length == 0 || disabled">Next</Button>
    </form>
  </div>
</template>
