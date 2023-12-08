import type { PublicKeyCredentialCreationOptionsJSON, PublicKeyCredentialRequestOptionsJSON, AuthenticationResponseJSON, RegistrationResponseJSON } from "@simplewebauthn/typescript-types"

export type DeriveOptions = {
  name: string
  namedCurve: string
}

export type EncryptOptionsJSON = {
  name: string
  iv: string
  tagLength: number
  length: number
}

export type EncryptOptions = {
  name: string
  iv: Uint8Array
  tagLength: number
  length: number
}

export type PasswordResponseJSON = {
  emailOrUsername: string
  publicKey: string
  deriveOptions: DeriveOptions
  encryptOptions: EncryptOptionsJSON
}

export type PasswordResponse = {
  emailOrUsername: string
  publicKey: Uint8Array
  deriveOptions: DeriveOptions
  encryptOptions: EncryptOptions
}

export type AuthFlowResponse = {
  error: "wrongPassword" | "noEmails" | "noAccount" | "invalidCode" | "invalidEmailOrUsername" | "shortEmailOrUsername" | "invalidPassword" | "shortPassword"
} | {
  location: {
    url: string
    replace: boolean
  }
} | {
  passkey: {
    createOptions: { publicKey: PublicKeyCredentialCreationOptionsJSON }
  } | {
    getOptions: { publicKey: PublicKeyCredentialRequestOptionsJSON }
  }
} | {
  password: PasswordResponseJSON
} | {
  code: {
    emailOrUsername: string
  }
}

export type AuthFlowRequest = {
  provider: string
  step: "start"
} | {
  provider: "passkey"
  step: "getStart"
} | {
  provider: "passkey"
  step: "getComplete"
  passkey: {
    getResponse: AuthenticationResponseJSON
  }
} | {
  provider: "passkey"
  step: "createStart"
} | {
  provider: "passkey"
  step: 'createComplete'
  passkey: {
    createResponse: RegistrationResponseJSON
  }
} | {
  provider: "password"
  step: "start"
  password: {
    start: {
      emailOrUsername: string
    }
  }
} | {
  provider: "password"
  step: "complete"
  password: {
    complete: {
      publicKey: string
      password: string
    }
  }
} | {
  provider: "code"
  step: "start"
  code: {
    start: {
      emailOrUsername: string
    }
  }
} | {
  provider: "code"
  step: "complete"
  code: {
    complete: {
      code: string
    }
  }
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
