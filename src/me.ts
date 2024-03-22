import { getURL } from "@/api"

// We have a hard-coded URL here instead of resolving it from the router to simplify imports order.
const response = await getURL("/api/me", null, null, null)
export default { success: "success" in (response.doc as { success: true } | { error: "unauthorized" }) }
