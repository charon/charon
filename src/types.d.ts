import type { PublicKeyCredentialCreationOptionsJSON, PublicKeyCredentialRequestOptionsJSON } from "@simplewebauthn/typescript-types"

export type AuthFlowResponse = {
  location?: {
    url: string
    replace: boolean
  }
  passkey?: {
    createOptions?: { publicKey: PublicKeyCredentialCreationOptionsJSON }
    getOptions?: { publicKey: PublicKeyCredentialRequestOptionsJSON }
  }
  password?: {
    publicKey: string
    deriveOptions: object
    encryptOptions: object & {
      nonceSize: number
    }
    secretSize: number
  }
  code?: boolean
}

export type SiteContext = {
  domain: string
  build?: {
    version?: string
    buildTimestamp?: string
    revision?: string
  }
  providers: {
    key: string
    name: string
    type: string
  }[]
}
