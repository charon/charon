<script setup lang="ts">
import { onMounted, ref } from "vue"

import InputText from "@/components/InputText.vue"

defineProps<{
  codeLength: number
}>()

const el = ref()
const scrollLeft = ref(0)

// Chromium does not yet support CSS sign function and is also currently buggy.
// Without CSS sign support background repeats from the right when it is moved
// to the left when text is longer than the input field and position X is negative.
// See: https://bugs.chromium.org/p/chromium/issues/detail?id=1407476
const supportsSign = CSS.supports("width: calc(1px * sign(1)")

onMounted(() => {
  updateBackgroundPosition()
})

function updateBackgroundPosition() {
  if (!el.value?.$el) {
    return
  }

  scrollLeft.value = el.value?.$el.scrollLeft
}
</script>

<template>
  <InputText
    ref="el"
    class="input-code-gradient bg-repeat-x bg-origin-padding font-mono tracking-[2ch]"
    :style="{
      backgroundImage: Array(codeLength).fill('var(--input-code-gradient)').join(','),
      backgroundPositionX: Array.from({ length: codeLength }, (v, i) => `calc(${2 + 3 * i}ch + 0.75rem - 1px - ${scrollLeft}px)`).join(','),
      backgroundPositionY:
        Array(codeLength - 1)
          .fill('0.25rem')
          .join(',') + ',0',
      backgroundSize:
        Array.from({ length: codeLength - 1 }, (v, i) =>
          supportsSign ? `calc(max(sign(${2 + 3 * i}ch + 0.75rem - 1px - ${scrollLeft}px), 0) * 100%) calc(100% - 0.5rem)` : `100% calc(100% - 0.5rem)`,
        ).join(',') + (supportsSign ? `,calc(max(sign(${2 + 3 * (codeLength - 1)}ch + 0.75rem - 1px - ${scrollLeft}px), 0) * 100%) 100%` : `,100% 100%`),
    }"
    autocomplete="one-time-code"
    autocorrect="off"
    autocapitalize="none"
    spellcheck="false"
    :minlength="codeLength"
    @scroll="updateBackgroundPosition"
  />
</template>
