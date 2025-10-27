<!--
We do not use :read-only or :disabled pseudo classes to style the component because
we want component to retain how it visually looks even if DOM element's read-only or
disabled attributes are set, unless they are set through component's props.
This is used during transitions/animations to disable the component by directly setting
its DOM attributes without flickering how the component looks.

This component uses @tailwindcss/forms style for input text field and applies it to
a button. Then we add our own site style InputText.vue on top to make the button
look the same as InputText.vue.
-->

<script setup lang="ts">
withDefaults(
  defineProps<{
    disabled?: boolean
  }>(),
  {
    disabled: false,
  },
)
</script>

<template>
  <button
    :disabled="disabled"
    type="button"
    class="appearance-none border-gray-500 px-3 py-2 text-base focus:border-blue-600"
    :class="{
      'text-left outline-none': true, // Override default @tailwindcss/forms style.
      'rounded-sm border-0 shadow-sm ring-2 ring-neutral-300 focus:ring-2': true, // InputText.vue style.
      'cursor-not-allowed': disabled, // InputText.vue readonly style.
      'bg-gray-100 text-gray-800 hover:ring-neutral-300 focus:border-primary-300 focus:ring-primary-300': disabled, // InputText.vue readonly style.
      'bg-white hover:ring-neutral-400 focus:ring-primary-500': !disabled, // InputText.vue non-readonly style.
    }"
  >
    <slot />
  </button>
</template>
