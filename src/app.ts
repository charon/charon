import type { Router } from "@/types"

import { createApp } from "vue"
import { createRouter, createWebHistory } from "vue-router"
import App from "@/App.vue"
import { routes } from "@/../routes.json"
import "./app.css"

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
}) as Router

const apiRouter = createRouter({
  history: createWebHistory(),
  routes: routes
    .filter((route) => route.api)
    .map((route) => ({
      path: route.path == "/" ? "/api" : `/api${route.path}`,
      name: route.name,
      component: () => null,
      props: true,
      strict: true,
    })),
})

router.apiResolve = apiRouter.resolve.bind(apiRouter)

createApp(App).use(router).mount("main")
