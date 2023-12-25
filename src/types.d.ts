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
  publicKey: string
  deriveOptions: DeriveOptions
  encryptOptions: EncryptOptionsJSON
}

export type PasswordResponse = {
  publicKey: Uint8Array
  deriveOptions: DeriveOptions
  encryptOptions: EncryptOptions
}

export type LocationResponse = {
  url: string
  replace: boolean
}

export type AuthFlowStep = { key: string; name: string }

export type AuthFlowResponse = {
  name?: string
  provider?: string
  emailOrUsername?: string
} & (
  | {
      error: "wrongPassword" | "noEmails" | "noAccount" | "invalidCode" | "invalidEmailOrUsername" | "shortEmailOrUsername" | "invalidPassword" | "shortPassword"
    }
  | {
      completed?: "signin" | "signup" | "failed"
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
)

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

export type Provider = {
  key: string
  name: string
  type: string
}

export type SiteContext = {
  domain: string
  build?: {
    version?: string
    buildTimestamp?: string
    revision?: string
  }
  providers: Provider[]
}

export type Flow = {
  forward(to: string): void
  backward(to: string): void
  getEmailOrUsername(): string
  updateEmailOrUsername(value: string): void
  updatePublicKey(value?: Uint8Array): void
  updateDeriveOptions(value?: DeriveOptions): void
  updateEncryptOptions(value?: EncryptOptions): void
  getProvider(): string
  updateProvider(value: string): void
  updateLocation(value: LocationResponse): void
  getName(): string
  updateName(value: string): void
  getSteps(): AuthFlowStep[]
  updateSteps(value: AuthFlowStep[]): void
  updateCompleted(value: "signin" | "signup"): void
}
