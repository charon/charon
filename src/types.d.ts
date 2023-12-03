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

export type SiteContext = {
  domain: string,
  build?: {
    version?: string,
    buildTimestamp?: string,
    revision?: string,
  },
  providers: {
    key: string,
    name: string,
    type: string,
  }[]
}
