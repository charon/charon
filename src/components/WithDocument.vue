<script setup lang="ts" generic="T">
import { ref, watch, readonly, onMounted, onUpdated, onUnmounted, getCurrentInstance, Ref, DeepReadonly } from "vue"
import { useRouter } from "vue-router"
import { getURL } from "@/api"

const props = defineProps<{
  id: string
  name: string
}>()

const router = useRouter()

const _doc = ref<T | null>(null) as Ref<T | null>
const _error = ref<string | null>(null)
const _url = ref<string | null>(null)
const doc = (import.meta.env.DEV ? readonly(_doc) : _doc) as DeepReadonly<Ref<T | null>>
const error = import.meta.env.DEV ? readonly(_error) : _error
const url = import.meta.env.DEV ? readonly(_url) : _url

const el = ref<HTMLElement | null>(null)

onMounted(() => {
  el.value = getCurrentInstance()?.proxy?.$el
})

onUnmounted(() => {
  el.value = null
})

onUpdated(() => {
  const el = getCurrentInstance()?.proxy?.$el
  if (el !== el.value) {
    el.value = el
  }
})

watch(
  () => ({ id: props.id, name: props.name }),
  async (params, oldParams, onCleanup) => {
    const abortController = new AbortController()
    onCleanup(() => abortController.abort())

    const newURL = router.apiResolve({
      name: params.name,
      params: {
        id: params.id,
      },
    }).href
    _url.value = newURL

    // We want to eagerly remove any old doc and show loading again.
    _doc.value = null
    // We want to eagerly remove any error.
    _error.value = null

    try {
      _doc.value = (await getURL<T>(newURL, el, abortController.signal, null)).doc
    } catch (error) {
      if (abortController.signal.aborted) {
        return
      }
      console.error(error)
      _error.value = `${error}`
      return
    }
  },
  {
    immediate: true,
  },
)

defineExpose({
  doc,
  error,
  url,
})

defineSlots<{
  default(props: { doc: DeepReadonly<T>; url: string }): unknown
  error(props: { error: string; url: string | null }): unknown
  loading(props: { url: string | null }): unknown
}>()
</script>

<template>
  <slot v-if="doc" :doc="doc" :url="url!"></slot>
  <slot v-else-if="error" name="error" :error="error" :url="url">
    <i class="text-error-600" :data-url="url">loading data failed</i>
  </slot>
  <slot v-else name="loading" :url="url"></slot>
</template>
