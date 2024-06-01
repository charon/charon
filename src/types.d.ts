import type {
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  AuthenticationResponseJSON,
  RegistrationResponseJSON,
} from "@simplewebauthn/types"
import type { BareItem, Key } from "structured-field-values"
import type { DeepReadonly } from "vue"

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

// "signinOrSignup" is frontend only addition where we have to move back to choose the identity, but we do not know
// anymore if it was "signin" or "signup". We cannot use "" because that means that the user is not yet authenticated.
export type Completed = "" | "signin" | "signup" | "failed" | "identity" | "declined" | "redirect" | "signinOrSignup"

export type AuthFlowStep = { key: string; name: string }

export type AuthFlowResponse = (
  | {
      target: "session"
      name: string
    }
  | {
      target: "oidc"
      name: string
      homepage: string
      organizationId: string
      completed: Completed
    }
) & {
  provider?: string
  emailOrUsername?: string
} & (
    | {
        error: "wrongPassword" | "noEmails" | "noAccount" | "invalidCode" | "invalidEmailOrUsername" | "shortEmailOrUsername" | "invalidPassword" | "shortPassword"
      }
    | {
        location: LocationResponse
      }
    | {
        completed: Completed
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

export type AuthFlowProviderStartRequest = {
  provider: string
}

export type AuthFlowPasskeyGetCompleteRequest = {
  getResponse: AuthenticationResponseJSON
}

export type AuthFlowPasskeyCreateCompleteRequest = {
  createResponse: RegistrationResponseJSON
}

type AuthFlowPasswordStartRequest = {
  emailOrUsername: string
}

export type AuthFlowPasswordCompleteRequest = {
  publicKey: string
  password: string
}

export type AuthFlowCodeStartRequest = {
  emailOrUsername: string
}

export type AuthFlowCodeCompleteRequest = {
  code: string
}

export type AuthSignoutRequest = {
  location: string
}

export type AuthSignoutResponse = {
  url: string
  replace: boolean
}

export type AuthFlowCreateRequest = {
  location: string
}

export type AuthFlowCreateResponse =
  | {
      id: string
    }
  | {
      error: "alreadyAuthenticated"
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
  getTarget(): "session" | "oidc"
  updateTarget(value: "session" | "oidc"): void
  updateLocation(value: LocationResponse): void
  getName(): string
  updateName(value: string): void
  updateHomepage(value: string): void
  updateOrganizationId(value: string): void
  getSteps(): AuthFlowStep[]
  updateSteps(value: AuthFlowStep[]): void
  getCompleted(): Completed
  updateCompleted(value: Completed): void
}

// Symbol is not generated by the server side, but we can easily support it here.
type ItemTypes = BareItem | ItemTypes[]

export type Metadata = Record<Key, ItemTypes>

export type ApplicationTemplates = ApplicationTemplateRef[]

export type ApplicationTemplateRef = {
  id: string
}

export type VariableType = "uriPrefix"

export type Variable = {
  name: string
  type: VariableType
  description: string
}

export type ApplicationTemplateClientPublic = {
  id?: string
  description: string
  additionalScopes: string[]
  redirectUriTemplates: string[]
}

export type ApplicationTemplateClientBackend = {
  id?: string
  description: string
  additionalScopes: string[]
  tokenEndpointAuthMethod: "client_secret_post" | "client_secret_basic"
  redirectUriTemplates: string[]
}

export type ApplicationTemplateClientService = {
  id?: string
  description: string
  additionalScopes: string[]
  tokenEndpointAuthMethod: "client_secret_post" | "client_secret_basic"
}

export type ApplicationTemplate = ApplicationTemplateCreate & {
  id: string
  description: string
  homepageTemplate: string
  idScopes: string[]
  variables: Variable[]
  clientsPublic: ApplicationTemplateClientPublic[]
  clientsBackend: ApplicationTemplateClientBackend[]
  clientsService: ApplicationTemplateClientService[]
  admins: AccountRef[]
}

export type ApplicationTemplateCreate = {
  name: string
}

export type Organizations = OrganizationRef[]

export type OrganizationRef = {
  id: string
}

export type Value = {
  name: string
  value: string
}

export type ClientRef = {
  id: string
}

export type AccountRef = {
  id: string
}

export type OrganizationApplicationClientPublic = {
  id?: string
  client: ClientRef
}

export type OrganizationApplicationClientBackend = {
  id?: string
  client: ClientRef
  secret: string
}

export type OrganizationApplicationClientService = {
  id?: string
  client: ClientRef
  secret: string
}

export type OrganizationApplication = {
  id?: string
  active: boolean
  applicationTemplate: ApplicationTemplate | DeepReadonly<ApplicationTemplate>
  values: Value[]
  clientsPublic: OrganizationApplicationClientPublic[]
  clientsBackend: OrganizationApplicationClientBackend[]
  clientsService: OrganizationApplicationClientService[]
}

export type Organization = OrganizationCreate & {
  id: string
  description: string
  admins: AccountRef[]
  applications: OrganizationApplication[]
}

export type OrganizationCreate = {
  name: string
}

export type Identity = IdentityCreate & {
  id: string
  users?: AccountRef[]
  admins: AccountRef[]
}

export type IdentityCreate = {
  username: string
  email: string
  givenName: string
  fullName: string
  pictureUrl: string
  description: string
}

export type Identities = IdentityRef[]

export type IdentityRef = {
  id: string
}

// It is recursive.
export type Mutable<T> = {
  -readonly [k in keyof T]: Mutable<T[k]>
}
