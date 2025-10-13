import { createApp, ref } from "vue"
import { createRouter, createWebHistory } from "vue-router"

import { routes } from "@/../routes.json"
import "@/app.css"
import App from "@/App.vue"
import { processOIDCRedirect } from "@/auth"
import i18n from "@/i18n"
import { progressKey } from "@/progress"
import { replaceLocationHash } from "@/utils"

// Facebook Login returns adds a hash on its callback. Here we remove it before
// we create Vue router so that Vue router gets clean route (it might matter if
// we used createWebHashHistory). In any case it is faster than waiting for router
// to initialize and then removing the hash using the Vue router.
if (window.location.hash === "#_=_") {
  replaceLocationHash("")
}

// Process OIDC redirect if it is present.
await processOIDCRedirect()

const router = createRouter({
  history: createWebHistory(),
  routes: routes
    .filter((route) => route.get)
    .map((route) => ({
      path: route.path,
      name: route.name,
      component: () => import(`./views/${route.name}.vue`),
      props: true,
      strict: true,
    })),
})

const apiRouter = createRouter({
  history: createWebHistory(),
  routes: routes
    .filter((route) => route.api)
    .map((route) => ({
      path: route.path === "/" ? "/api" : `/api${route.path}`,
      name: route.name,
      component: () => null,
      props: true,
      strict: true,
    })),
})

router.apiResolve = apiRouter.resolve.bind(apiRouter)

createApp(App).use(router).use(i18n).provide(progressKey, ref(0)).mount("main")
