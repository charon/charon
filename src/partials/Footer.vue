<template>
  <div class="flex justify-between gap-x-2 p-2 leading-none sm:gap-x-4 sm:p-4">
    <ul class="flex gap-x-2 sm:gap-x-4">
      <!-- <li><router-link :to="{ name: 'Home' }" class="link">About</router-link></li>
      <li><router-link :to="{ name: 'Home' }" class="link">Help</router-link></li>
      <li><router-link :to="{ name: 'Home' }" class="link">Privacy</router-link></li>
      <li><router-link :to="{ name: 'Home' }" class="link">Terms</router-link></li> -->
    </ul>
    <ul class="flex gap-x-2 sm:gap-x-4">
      <li class="text-neutral-500">
        <i18n-t keypath="footer.poweredBy">
          <template #name>
            <a href="https://gitlab.com/charon/charon" class="link">Charon</a>
          </template>
        </i18n-t>
      </li>
    </ul>
  </div>
</template>
