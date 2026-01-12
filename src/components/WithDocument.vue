<script setup lang="ts" generic="T">
import type { DeepReadonly } from "vue"

import type { Metadata, QueryValues } from "@/types"

import { getCurrentInstance, onMounted, onUnmounted, onUpdated, readonly, ref, Ref, watch } from "vue"
import { useI18n } from "vue-i18n"
import { useRouter } from "vue-router"

import { getURL } from "@/api"
import { getRootProgress } from "@/progress"
import { encodeQuery } from "@/utils"

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

const { t } = useI18n({ useScope: "global" })
const router = useRouter()

// We use root progress for loading data.
const rootProgress = getRootProgress()

const _doc = ref<T | null>(null)
const _metadata = ref<Metadata>({})
const _error = ref<string | null>(null)
const _url = ref<string | null>(null)
const doc = (import.meta.env.DEV ? readonly(_doc) : (_doc as DeepReadonly<Ref<T | null>>))
const metadata = (import.meta.env.DEV ? readonly(_metadata) : (_metadata as DeepReadonly<Ref<Metadata>>))
const error = import.meta.env.DEV ? readonly(_error) : _error
const url = import.meta.env.DEV ? readonly(_url) : _url

const el = ref<HTMLElement | null>(null)

onMounted(() => {
  // TODO: Make sure $el is really a HTMLElement and not for example a text node.
  //       We can search for the first sibling element? Or element with data-url attribute.
  el.value = getCurrentInstance()?.proxy?.$el as HTMLElement
})

onUnmounted(() => {
  el.value = null
})

onUpdated(() => {
  // TODO: Make sure $el is really a HTMLElement and not for example a text node.
  //       We can search for the first sibling element? Or element with data-url attribute.
  const e = getCurrentInstance()?.proxy?.$el as HTMLElement
  if (e !== el.value) {
    el.value = e
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
    const params = JSON.parse(paramsJSON) as QueryValues
    const query = JSON.parse(queryJSON) as QueryValues

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
      const response = await getURL<T>(newURL, el, abortController.signal, rootProgress)
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
      // eslint-disable-next-line @typescript-eslint/restrict-template-expressions
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
  <slot v-if="doc" :doc="doc as DeepReadonly<T>" :metadata="metadata" :url="url!"></slot>
  <slot v-else-if="error" name="error" :error="error" :url="url">
    <i class="text-error-600" :data-url="url">{{ t("common.data.loadingDataFailed") }}</i>
  </slot>
  <slot v-else name="loading" :url="url"></slot>
</template>
