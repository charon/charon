<script setup lang="ts">
defineProps<{
  modelValue: string
  id: string
  username: string
}>()

defineEmits<{
  "update:modelValue": [value: string]
}>()
</script>

<template>
  <div>Username: {{ username }}</div>
</template>
