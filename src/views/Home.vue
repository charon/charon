<script setup lang="ts">
import Button from "@/components/Button.vue"
import { useRouter } from "vue-router"

const router = useRouter()
</script>

<template>
  <div>Hello world.</div>
  <form :action="router.apiResolve({ name: 'AuthSignout' }).href" method="post">
    <Button type="submit">Sign-out</Button>
  </form>
</template>
