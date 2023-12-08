<script setup lang="ts">
withDefaults(
  defineProps<{
    progress?: number
    modelValue?: string
    type?: string
    invalid?: boolean
  }>(),
  {
    progress: 0,
    modelValue: "",
    type: "text",
    invalid: false,
  },
)

defineEmits<{
  "update:modelValue": [value: string]
}>()
</script>

<template>
  <input
    :readonly="progress > 0"
    :type="type"
    class="rounded border-0 bg-white shadow ring-2 ring-neutral-300 read-only:bg-gray-100 read-only:text-gray-800 hover:ring-neutral-400 read-only:hover:ring-neutral-300 focus:ring-2 focus:ring-primary-500 read-only:focus:border-primary-300 read-only:focus:ring-2 read-only:focus:ring-primary-300"
    :class="{ 'cursor-not-allowed': progress > 0, 'bg-error-50': invalid }"
    :value="modelValue"
    @input="$emit('update:modelValue', ($event.target as HTMLInputElement).value)"
  />
</template>
