import type { PublicKeyCredentialCreationOptionsJSON, PublicKeyCredentialRequestOptionsJSON } from "@simplewebauthn/typescript-types"

export type AuthFlowResponse = {
  location?: {
    url: string,
    replace: boolean,
  }
  passkey?: {
    createOptions?: { publicKey: PublicKeyCredentialCreationOptionsJSON },
    getOptions?: { publicKey: PublicKeyCredentialRequestOptionsJSON },
  }
}
