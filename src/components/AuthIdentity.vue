<script setup lang="ts">
import { ref, onUnmounted, onMounted, getCurrentInstance, inject } from "vue"
import Button from "@/components/Button.vue"
import { progressKey } from "@/progress"

defineProps<{
  name: string
  organizationId: string
}>()

const mainProgress = inject(progressKey, ref(0))

const abortController = new AbortController()

// Define transition hooks to be called by the parent component.
// See: https://github.com/vuejs/rfcs/discussions/613
onMounted(() => {
  const vm = getCurrentInstance()!
  vm.vnode.el!.__vue_exposed = vm.exposeProxy
})

defineExpose({
  onAfterEnter,
  onBeforeLeave,
})

onUnmounted(onBeforeLeave)

function onAfterEnter() {
  document.getElementById("redirect")?.focus()
}

function onBeforeLeave() {
  abortController.abort()
}
</script>

<template>
  <div class="flex flex-col rounded border bg-white p-4 shadow w-full">
    <div>Identity.</div>
  </div>
</template>
