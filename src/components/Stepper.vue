<script setup lang="ts">
const props = defineProps<{
  steps: { key: string; name: string }[]
  currentStep: string
}>()

function progressBarWidth() {
  for (let i = 0; i < props.steps.length; i++) {
    if (props.steps[i].key === props.currentStep) {
      return `${(i / (props.steps.length - 1)) * 100}%`
    }
  }
  return "0%"
}

function beforeActive(step: string): boolean {
  for (const s of props.steps) {
    if (s.key === props.currentStep) {
      return false
    }
    if (s.key === step) {
      return true
    }
  }
  return false
}
</script>

<template>
  <div class="py-1">
    <div
      class="relative h-1 rounded-full bg-slate-200"
      :style="{
        marginLeft: `calc(((1 / (2 * ${props.steps.length})) * (100% + 0.5rem)) - 0.25rem)`,
        marginRight: `calc(((1 / (2 * ${props.steps.length})) * (100% + 0.5rem)) - 0.25rem)`,
      }"
    >
      <div
        class="absolute inset-y-0 left-0 rounded-l-full bg-secondary-400 after:float-right after:-mt-1 after:-mr-1.5 after:h-3 after:w-3 after:rounded-full after:bg-inherit motion-safe:transition-[width] motion-safe:duration-700 motion-safe:will-change-[width]"
        :style="{ width: progressBarWidth() }"
      ></div>
    </div>
  </div>
  <ul class="mt-2 grid w-full auto-cols-fr grid-flow-col gap-x-2">
    <slot v-for="step in steps" :key="step.key" :active="step.key === currentStep" :step="step" :before-active="beforeActive(step.key)">
      <li class="text-center">
        <strong v-if="step.key === currentStep">{{ step.name }}</strong>
        <template v-else>{{ step.name }}</template>
      </li>
    </slot>
  </ul>
</template>
