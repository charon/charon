<script setup lang="ts" generic="T">
import type { Metadata, QueryValues } from "@/types"

import { ref, watch, readonly, onMounted, onUpdated, onUnmounted, getCurrentInstance, Ref, DeepReadonly } from "vue"
import { useI18n } from "vue-i18n"
import { useRouter } from "vue-router"
import { getURL } from "@/api"
import { injectMainProgress } from "@/progress"
import { encodeQuery } from "@/utils"

const { t } = useI18n({ useScope: 'global' })

const props = withDefaults(
  defineProps<{
    name: string
    params: QueryValues
    query?: QueryValues
  }>(),
  {
    query: () => {
      return {}
    },
  },
)

const router = useRouter()

const mainProgress = injectMainProgress()

const _doc = ref<T | null>(null) as Ref<T | null>
const _metadata = ref<Metadata>({})
const _error = ref<string | null>(null)
const _url = ref<string | null>(null)
const doc = (import.meta.env.DEV ? readonly(_doc) : _doc) as DeepReadonly<Ref<T | null>>
const metadata = (import.meta.env.DEV ? readonly(_metadata) : _metadata) as DeepReadonly<Ref<Metadata>>
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
  // We use JSON.stringify so that watch reruns really only when params and query objects change meaningfully and is not that only their
  // objects are recreated (with same values), for example. JSON.stringify orders JSON fields in the object iteration order which means
  // that JSON serialization could change (and watch callback would rerun) while objects did not really change meaningfully (for params
  // and query we do not care about order of fields). In practice, this should not really happen because generally objects passed to
  // props are created every time in the same way in templates.
  // See: https://github.com/vuejs/vue/issues/13242
  [() => JSON.stringify(props.params), () => props.name, () => JSON.stringify(props.query)],
  async ([paramsJSON, name, queryJSON], [oldParamsJSON, oldName, oldQueryJSON], onCleanup) => {
    const params = JSON.parse(paramsJSON)
    const query = JSON.parse(queryJSON)

    const abortController = new AbortController()
    onCleanup(() => abortController.abort())

    const newURL = router.apiResolve({
      name,
      params,
      query: encodeQuery(query),
    }).href
    _url.value = newURL

    // We want to eagerly remove any old doc and show loading again.
    _doc.value = null
    _metadata.value = {}
    // We want to eagerly remove any error.
    _error.value = null

    try {
      const response = await getURL<T>(newURL, el, abortController.signal, mainProgress)
      if (abortController.signal.aborted) {
        return
      }

      _doc.value = response.doc
      _metadata.value = response.metadata
    } catch (error) {
      if (abortController.signal.aborted) {
        return
      }
      console.error("WithDocument", error)
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
  metadata,
  error,
  url,
})

defineSlots<{
  default(props: { doc: DeepReadonly<T>; metadata: DeepReadonly<Metadata>; url: string }): unknown
  error(props: { error: string; url: string | null }): unknown
  loading(props: { url: string | null }): unknown
}>()
</script>

<template>
  <slot v-if="doc" :doc="doc" :metadata="metadata" :url="url!"></slot>
  <slot v-else-if="error" name="error" :error="error" :url="url">
    <i class="text-error-600" :data-url="url">{{ t("loading.loadingDataFailed") }}</i>
  </slot>
  <slot v-else name="loading" :url="url"></slot>
</template>
