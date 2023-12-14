import type {
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  AuthenticationResponseJSON,
  RegistrationResponseJSON,
} from "@simplewebauthn/typescript-types"

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

export type LocationResponse = {
  url: string
  replace: boolean
}

export type AuthFlowResponse =
  | {
      name: string
    }
  | {
      error: "wrongPassword" | "noEmails" | "noAccount" | "invalidCode" | "invalidEmailOrUsername" | "shortEmailOrUsername" | "invalidPassword" | "shortPassword"
    }
  | {
      name?: string
      completed?: boolean
      location: LocationResponse
    }
  | {
      passkey:
        | {
            createOptions: { publicKey: PublicKeyCredentialCreationOptionsJSON }
          }
        | {
            getOptions: { publicKey: PublicKeyCredentialRequestOptionsJSON }
          }
    }
  | {
      password: PasswordResponseJSON
    }
  | {
      name?: string
      code: {
        emailOrUsername: string
      }
    }

export type AuthFlowRequest =
  | {
      provider: string
      step: "start"
    }
  | {
      provider: "passkey"
      step: "getStart"
    }
  | {
      provider: "passkey"
      step: "getComplete"
      passkey: {
        getResponse: AuthenticationResponseJSON
      }
    }
  | {
      provider: "passkey"
      step: "createStart"
    }
  | {
      provider: "passkey"
      step: "createComplete"
      passkey: {
        createResponse: RegistrationResponseJSON
      }
    }
  | {
      provider: "password"
      step: "start"
      password: {
        start: {
          emailOrUsername: string
        }
      }
    }
  | {
      provider: "password"
      step: "complete"
      password: {
        complete: {
          publicKey: string
          password: string
        }
      }
    }
  | {
      provider: "code"
      step: "start"
      code: {
        start: {
          emailOrUsername: string
        }
      }
    }
  | {
      provider: "code"
      step: "complete"
      code: {
        complete: {
          code: string
        }
      }
    }

export type Providers = {
  key: string
  name: string
  type: string
}[]

export type SiteContext = {
  domain: string
  build?: {
    version?: string
    buildTimestamp?: string
    revision?: string
  }
  providers: Providers
}

export type Flow = {
  forward(to: string): void
  backward(to: string): void
  updateEmailOrUsername(value: string): void
  updatePublicKey(value: Uint8Array): void
  updateDeriveOptions(value: DeriveOptions): void
  updateEncryptOptions(value: EncryptOptions): void
  updateProvider(value: string): void
  updateLocation(value: LocationResponse): void
  updateName(value: string): void
}
