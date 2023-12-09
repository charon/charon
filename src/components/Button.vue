<script setup lang="ts">
withDefaults(
  defineProps<{
    progress?: number
    disabled?: boolean
    primary?: boolean
  }>(),
  {
    progress: 0,
    disabled: false,
    primary: false,
  },
)
</script>

<template>
  <button
    :disabled="progress > 0 || disabled"
    class="relative select-none rounded px-6 py-2.5 font-medium uppercase leading-tight shadow outline-none focus:ring-2 focus:ring-offset-1"
    :class="{
      'cursor-not-allowed': progress > 0 || disabled,
      'bg-primary-300 text-gray-100': primary && (progress > 0 || disabled),
      'bg-primary-600 text-white hover:bg-primary-700 focus:ring-primary-500 active:bg-primary-500': primary && progress === 0 && !disabled,
      'border-neutral-300 border-2 bg-gray-100 text-gray-800 shadow-none': !primary && (progress > 0 || disabled),
      'border-primary-600 border-2 text-primary-600 hover:bg-primary-50 hover:border-primary-700 hover:text-primary-700 focus:ring-primary-500 active:border-primary-500 active:text-primary-500 active:bg-primary-100':
        !primary && progress === 0 && !disabled,
    }"
  >
    <slot></slot>
  </button>
</template>
