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

export type AuthFlowResponsePasswordJSON = {
  publicKey: string
  deriveOptions: DeriveOptions
  encryptOptions: EncryptOptionsJSON
}

export type AuthFlowResponsePassword = {
  publicKey: Uint8Array
  deriveOptions: DeriveOptions
  encryptOptions: EncryptOptions
}

export type AuthFlowResponseOIDCProvider = {
  location: string
}

export type AuthFlowResponsePasskey =
  | {
      createOptions: { publicKey: PublicKeyCredentialCreationOptionsJSON }
    }
  | {
      getOptions: { publicKey: PublicKeyCredentialRequestOptionsJSON }
    }

export type Completed = "" | "signin" | "signup" | "failed" | "identity" | "declined" | "finishReady" | "finished"

export type ErrorCode =
  | "wrongPassword"
  | "noEmails"
  | "noAccount"
  | "invalidCode"
  | "invalidEmailOrUsername"
  | "shortEmailOrUsername"
  | "invalidPassword"
  | "shortPassword"

// AuthFlowResponse can also return none of the fields in the union below. Not sure
// if this is captured by this type definition, but it probably does not matter in practice.
export type AuthFlowResponse = {
  completed: Completed[]
  organizationId: string
  appId: string
  providers?: string[]
  emailOrUsername?: string
} & (
  | {
      error: ErrorCode
    }
  | {
      oidcProvider: AuthFlowResponseOIDCProvider
    }
  | {
      passkey: AuthFlowResponsePasskey
    }
  | {
      password: AuthFlowResponsePasswordJSON
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
  location: string
}

export type AuthFlowChooseIdentityRequest = {
  identity: IdentityRef
}

export type SiteProvider = {
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
  providers: SiteProvider[]
  organizationId: string
  clientId: string
  redirectUri: string
}

export type AuthFlowStep = { key: string; name: string }

export type Flow = {
  getId(): string

  forward(to: string): void
  backward(to: string): void
  getSteps(): AuthFlowStep[]
  setSteps(value: AuthFlowStep[]): void

  getCompleted(): Completed[]
  setCompleted(value: Completed[]): void
  getOrganizationId(): string
  setOrganizationId(value: string): void
  getAppId(): string
  setAppId(value: string): void
  getOIDCProvider(): SiteProvider | null
  setOIDCProvider(value: SiteProvider | null): void
  getEmailOrUsername(): string
  setEmailOrUsername(value: string): void

  getPublicKey(): Uint8Array | undefined
  setPublicKey(value?: Uint8Array): void
  getDeriveOptions(): DeriveOptions | undefined
  setDeriveOptions(value?: DeriveOptions): void
  getEncryptOptions(): EncryptOptions | undefined
  setEncryptOptions(value?: EncryptOptions): void
}

// Symbol is not generated by the server side, but we can easily support it here.
type ItemTypes = BareItem | ItemTypes[]

export type Metadata = Record<Key, ItemTypes>

export type QueryValues = Record<string, string | string[]>

export type QueryValuesWithOptional = Record<string, string | (string | null)[] | undefined | null>

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

export type ApplicationTemplateCreate = {
  name: string
}

export type ApplicationTemplatePublic = ApplicationTemplateCreate & {
  id: string
  description: string
  homepageTemplate: string
  idScopes: string[]
  variables: Variable[]
  clientsPublic: ApplicationTemplateClientPublic[]
  clientsBackend: ApplicationTemplateClientBackend[]
  clientsService: ApplicationTemplateClientService[]
}

export type ApplicationTemplate = ApplicationTemplatePublic & {
  // When user does not have admin permissions, they get in fact only
  // ApplicationTemplatePublic so we have this field as optional.
  admins?: IdentityRef[]
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

export type IdentityRef = {
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

export type OrganizationApplicationPublic = {
  id?: string
  active: boolean
  applicationTemplate: ApplicationTemplatePublic | DeepReadonly<ApplicationTemplatePublic>
  values: Value[]
}

export type OrganizationApplication = OrganizationApplicationPublic & {
  clientsPublic?: OrganizationApplicationClientPublic[]
  clientsBackend?: OrganizationApplicationClientBackend[]
  clientsService?: OrganizationApplicationClientService[]
}

// This is used only on the frontend.
export type OrganizationIdentity = {
  id?: string
  active: boolean
  identity: Identity | DeepReadonly<Identity>
}

export type IdentityOrganization = {
  id?: string
  active: boolean
  organization: OrganizationRef
}

export type OrganizationPublic = OrganizationCreate & {
  id: string
  description: string
}

export type Organization = OrganizationPublic & {
  // When user does not have admin permissions, they get in fact only
  // OrganizationPublic so we have these fields as optional.
  admins?: IdentityRef[]
  applications?: OrganizationApplication[]
}

export type OrganizationCreate = {
  name: string
}

export type Identity = IdentityCreate & IdentityPublic & {
  // Identity is returned from API only when user can access it and can access
  // its full document, including permissions and organizations, so we can be
  // precise which fields are optional.
  users?: IdentityRef[]
  admins: IdentityRef[]
  organizations: IdentityOrganization[]
}

type IdentityAttributes = {
  username?: string
  email?: string
  givenName?: string
  fullName?: string
  pictureUrl?: string
}

export type IdentityPublic = IdentityAttributes & {
  id: string
}

export type IdentityCreate = IdentityAttributes & {
  description?: string
}

export type Identities = IdentityRef[]

// It is recursive.
export type Mutable<T> = {
  -readonly [k in keyof T]: Mutable<T[k]>
}
