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
      class="bg-slate-200 rounded-full h-1 relative"
      :style="{
        marginLeft: `calc(((1 / (2 * ${props.steps.length})) * (100% + 0.5rem)) - 0.25rem)`,
        marginRight: `calc(((1 / (2 * ${props.steps.length})) * (100% + 0.5rem)) - 0.25rem)`,
      }"
    >
      <div
        class="bg-secondary-400 rounded-l-full transition-[width] will-change-[width] duration-700 absolute inset-y-0 left-0 after:float-right after:h-3 after:w-3 after:-mt-1 after:-mr-1.5 after:bg-inherit after:rounded-full"
        :style="{ width: progressBarWidth() }"
      ></div>
    </div>
  </div>
  <ul class="grid grid-flow-col auto-cols-fr w-full gap-x-2 mt-2">
    <slot v-for="step in steps" :key="step.key" :active="step.key === currentStep" :step="step" :before-active="beforeActive(step.key)">
      <li class="text-center">
        <strong v-if="step.key === currentStep">{{ step.name }}</strong>
        <template v-else>{{ step.name }}</template>
      </li>
    </slot>
  </ul>
</template>
