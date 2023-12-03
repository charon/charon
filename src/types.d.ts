import type { PublicKeyCredentialCreationOptionsJSON, PublicKeyCredentialRequestOptionsJSON } from "@simplewebauthn/typescript-types"

export type AuthFlowResponse = {
  replaceLocation?: string
  pushLocation?: string
  passkey?: {
    createOptions?: { publicKey: PublicKeyCredentialCreationOptionsJSON },
    getOptions?: { publicKey: PublicKeyCredentialRequestOptionsJSON },
  }
}
