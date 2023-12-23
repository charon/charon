<script setup lang="ts">
import InputText from "@/components/InputText.vue"

const props = defineProps<{
  codeLength: number
}>()
</script>

<template>
  <InputText
    class="font-mono tracking-[2ch] bg-repeat-x bg-origin-padding input-code-gradient"
    :style="{
      backgroundImage: Array(props.codeLength).fill('var(--input-code-gradient)').join(','),
      backgroundPositionX: Array.from({ length: props.codeLength }, (v, i) => `calc(${2 + 3 * i}ch + 0.75rem - 1px)`).join(','),
      backgroundPositionY:
        Array(props.codeLength - 1)
          .fill('0.25rem')
          .join(',') + ',0',
      backgroundSize:
        Array(props.codeLength - 1)
          .fill('100% calc(100% - 0.5rem)')
          .join(',') + ',100% 100%',
    }"
    autocomplete="one-time-code"
    autocorrect="off"
    autocapitalize="none"
    spellcheck="false"
    :minlength="codeLength"
  />
</template>
