import type { Router as VueRouter, RouteLocationRaw, RouteLocationNormalizedLoaded, RouteLocation } from "vue-router"

export type Router = VueRouter & {
  apiResolve(
    to: RouteLocationRaw,
    currentLocation?: RouteLocationNormalizedLoaded,
  ): RouteLocation & {
    href: string
  }
}
