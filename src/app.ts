import { createApp, ref } from "vue"
import { createRouter, createWebHistory } from "vue-router"

import "@/app.css"
import App from "@/App.vue"
import { processOIDCRedirect } from "@/auth"
import siteContext from "@/context"
import i18n from "@/i18n"
import { progressKey, rootProgressKey } from "@/progress"
import routes from "@/routes"
import { replaceLocationHash } from "@/utils"

// During development when requests are proxied to Vite, placeholders
// in HTML files are not rendered. So we set them here as well.
if (siteContext.title) {
  document.title = siteContext.title
}

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
  routes: Object.entries(routes)
    .filter(([, route]) => route.handlers)
    .map(([name, route]) => ({
      path: route.path,
      name,
      component: () => import(`./views/${name}.vue`),
      props: true,
      strict: true,
    })),
})

const apiRouter = createRouter({
  history: createWebHistory(),
  routes: Object.entries(routes)
    .filter(([, route]) => route.api)
    .map(([name, route]) => ({
      path: route.path === "/" ? "/api" : `/api${route.path}`,
      name,
      component: () => null,
      props: true,
      strict: true,
    })),
})

router.apiResolve = apiRouter.resolve.bind(apiRouter)

const rootProgress = ref(0)
createApp(App).use(router).use(i18n).provide(progressKey, rootProgress).provide(rootProgressKey, rootProgress).mount("main")
