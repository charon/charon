import type { PublicKeyCredentialCreationOptionsJSON, PublicKeyCredentialRequestOptionsJSON } from "@simplewebauthn/typescript-types"

export type AuthResponse = {
  location: string
}

export type AuthPasskeySigninResponse = {
  options: { publicKey: PublicKeyCredentialRequestOptionsJSON }
}

export type AuthPasskeySignupResponse = {
  options: { publicKey: PublicKeyCredentialCreationOptionsJSON }
}
