import type { Ref } from "vue"

import { ref } from "vue"
import * as client from "openid-client"
// It is OK that we fetch siteContext here because the server sends preload header
// so we have to fetch it always anyway. Generally this is already cached.
import siteContext from "@/context"
import { currentAbsoluteURL, redirectServerSide, replaceLocationSearch } from "./utils"

const config = await client.discovery(new URL(document.location.origin), siteContext.clientId)

type State = {
  redirect: string
  codeVerifier: string
  nonce: string
}

export const accessToken = ref("")

export async function signIn(progress: Ref<number>) {
  const codeVerifier = client.randomPKCECodeVerifier()
  const codeChallenge = await client.calculatePKCECodeChallenge(codeVerifier)
  const stateId = client.randomState()
  const nonce = client.randomNonce()

  const redirectTo = client
    .buildAuthorizationUrl(config, {
      redirect_uri: siteContext.redirectUri,
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
      scope: "openid profile email",
      state: stateId,
      nonce: nonce,
    })
    .toString()

  const state: State = {
    redirect: currentAbsoluteURL(),
    codeVerifier: codeVerifier,
    nonce,
  }

  localStorage.setItem(stateId, JSON.stringify(state))

  redirectServerSide(redirectTo, false, progress)
}

export async function processOIDCRedirect() {
  const stateId = new URLSearchParams(window.location.search).get("state")
  if (!stateId) {
    return
  }
  const url = new URL(window.location.href)
  replaceLocationSearch("")

  const stateJSON = localStorage.getItem(stateId)
  if (!stateJSON) {
    // TODO: Log some error? Show something to the user?
    return
  }
  localStorage.removeItem(stateId)
  const state = JSON.parse(stateJSON) as State

  const tokens = await client.authorizationCodeGrant(config, url, {
    pkceCodeVerifier: state.codeVerifier,
    expectedState: stateId,
    expectedNonce: state.nonce,
  })

  accessToken.value = tokens.access_token
}

export function isSignedIn(): boolean {
  // TODO: Use introspection endpoint to check if the user is signed in.
  //       Cache until the known expiration. Make sure this is checked only
  //       once even if multiple calls to this function are done in parallel.
  return accessToken.value !== ""
}
