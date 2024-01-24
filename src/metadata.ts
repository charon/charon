import type { Item } from "structured-field-values"
import type { Metadata, ItemTypes } from "./types"

import { decodeDict } from "structured-field-values"

const metadataHeaderPrefix = ""
const metadataHeader = metadataHeaderPrefix + "Metadata"

function convertItem(item: Item): ItemTypes {
  if (item.params !== null) {
    throw new Error("params not supported")
  }

  if (Array.isArray(item.value)) {
    return item.value.map((i) => convertItem(i))
  }

  return item.value
}

export function decodeMetadata(headers: Headers): Metadata {
  const header = headers.get(metadataHeader) || ""
  const result: Metadata = {}
  for (const [key, item] of decodeDict(header)) {
    result[key] = convertItem(item)
  }
  return result
}
