<script setup lang="ts">
import type { RouteLocationRaw } from "vue-router"

import { computed } from "vue"
import { useLink } from "vue-router"

const props = withDefaults(
  defineProps<{
    to: RouteLocationRaw
    replace?: boolean
    progress?: number
    disabled?: boolean
    primary?: boolean
  }>(),
  {
    replace: false,
    progress: 0,
    disabled: false,
    primary: false,
  },
)

// We use fake "/" when disabled. The link is not really active then, so that is OK.
// We have to make both be computed to retain reactivity.
//
// eslint-disable-next-line @typescript-eslint/unbound-method
const { navigate, href } = useLink({
  to: computed(() => (props.disabled ? "/" : props.to)),
  replace: computed(() => props.replace),
})
</script>

<template>
  <!--
    We on purpose keep the structure of class attribute the same and have checks for
    progress and disabled in there to make it easier to compare with the <Button> component.
  -->
  <div
    v-if="progress > 0 || disabled"
    class="relative rounded-sm text-center leading-tight font-medium uppercase shadow-sm outline-none select-none focus:ring-2 focus:ring-offset-1"
    :class="{
      'cursor-not-allowed': progress > 0 || disabled,
      'px-6 py-2.5': primary,
      'px-[calc(1.5rem-2px)] py-[calc(0.625rem-2px)]': !primary,
      'bg-primary-300 text-gray-100': primary && (progress > 0 || disabled),
      'bg-primary-600 text-white hover:bg-primary-700 focus:ring-primary-500 active:bg-primary-500': primary && progress === 0 && !disabled,
      'border-2 border-neutral-300 bg-gray-100 text-gray-800 shadow-none': !primary && (progress > 0 || disabled),
      'border-2 border-primary-600 text-primary-600 hover:border-primary-700 hover:bg-primary-50 hover:text-primary-700 focus:ring-primary-500 active:border-primary-500 active:bg-primary-100 active:text-primary-500':
        !primary && progress === 0 && !disabled,
    }"
  >
    <slot />
  </div>
  <a
    v-else
    :href="href"
    class="relative rounded-sm text-center leading-tight font-medium uppercase shadow-sm outline-none select-none focus:ring-2 focus:ring-offset-1"
    :class="{
      'cursor-not-allowed': progress > 0 || disabled,
      'px-6 py-2.5': primary,
      'px-[calc(1.5rem-2px)] py-[calc(0.625rem-2px)]': !primary,
      'bg-primary-300 text-gray-100': primary && (progress > 0 || disabled),
      'bg-primary-600 text-white hover:bg-primary-700 focus:ring-primary-500 active:bg-primary-500': primary && progress === 0 && !disabled,
      'border-2 border-neutral-300 bg-gray-100 text-gray-800 shadow-none': !primary && (progress > 0 || disabled),
      'border-2 border-primary-600 text-primary-600 hover:border-primary-700 hover:bg-primary-50 hover:text-primary-700 focus:ring-primary-500 active:border-primary-500 active:bg-primary-100 active:text-primary-500':
        !primary && progress === 0 && !disabled,
    }"
    @click="navigate"
  >
    <slot />
  </a>
</template>
