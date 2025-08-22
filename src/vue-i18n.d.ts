import en from "@/locales/en.json"

declare module "vue-i18n" {
  export interface DefineLocaleMessage {
    common: {
      buttons: {
        next: string
        back: string
        retry: string
        continue: string
        create: string
        update: string
        select: string
        enable: string
        decline: string
        cancel: string
        add: string
        remove: string
        disable: string
        activate: string
        addUser: string
        addAdmin: string
        signOut: string
        signIn: string
      }
      errors: {
        unexpected: string
        wrongPassword: string
        invalidPassword: string
        shortPassword: string
        invalidCode: string
        noAccount: string
        noEmails: string
        invalidEmailOrUsername: {
          email: string
          username: string
        }
        shortEmailOrUsername: {
          email: string
          username: string
        }
      }
      labels: {
        optional: string
        admin: string
        current: string
        active: string
        disabled: string
        added: string
        creator: string
      }
      loading: {
        dataLoading: string
        loadingDataFailed: string
      }
    }
    partials: {
      AuthAutoRedirect: {
        congratulations: string
        declined: string
        redirectMessage: string
        oneSecond: string
        seconds: string
        paused: string
        resume: string
        pause: string
        redirect: string
        congratulationsFromIdentity: string
        declineSignInOrSignUp: string
      }
      AuthCode: {
        codeSentEmail: string
        codeSentUsername: string
        codeFromHashEmail: string
        codeFromHashUsername: string
        resendButton: string
        sent: string
        sentMultiple: string
        confirmCode: string
        waitForCode: string
        securityWarning: string
        strongDont: string
        troubleEmail: string
        differentMethod: string
      }
      AuthIdentity: {
        selectIdentity: string
        newIdentityButton: string
        signinSuccess: string
        signupSuccess: string
        congratulations: string
        declineSignInOrSignUp: string
        sorry: string
        previouslyUsedDisabled: string
        otherAvailableIdentities: string
        noIdentitiesCreateFirst: string
        noOtherIdentitiesCreateOne: string
        selectInstructions: string
        noIdentityUsed: string
        noIdentityUsedWithApp: string
        allPreviousDisabled: string
        identitiesUsedWithOrg: string
        disabledIdentities: string
        previouslyUsedIdentities: string
        createNewIdentity: string
        sectionTitles: {
          identitiesUsedWithOrg: string
          disabledIdentities: string
        }
        statusMessages: {
          noIdentityUsed: string
          noIdentityUsedWithApp: string
          allPreviousDisabled: string
        }
      }
      AuthManualRedirect: {
        failed: string
        tryAgain: string
        completed: string
        homepage: string
        return: string
      }
      AuthPasskeySignin: {
        signingIn: string
        signupInfo: string
      }
      AuthPasskeySignup: {
        instructions: string
        signingUp: string
        failed: string
        retrySigninButton: string
        passkeySignupButton: string
        retrySignupButton: string
      }
      AuthPasskey: {
        signingIn: string
        signin: {
          signupInfo: string
        }
        signup: {
          instructions: string
          signingUp: string
          failed: string
          retrySigninButton: string
          passkeySignupButton: string
          retrySignupButton: string
        }
      }
      AuthPassword: {
        emailAddressLabel: string
        usernameLabel: string
        passwordLabel: string
        sendCodeButton: string
        emailAccount: string
        usernameAccount: string
        skipPassword: string
        troublePassword: string
        differentSigninMethod: string
      }
      AuthStart: {
        emailOrUsernameLabel: string
        orUse: string
      }
      AuthThirdPartyProvider: {
        redirectMessage: string
        instructions: string
        additionalInfo: string
        redirecting: string
        failed: string
        oneSecond: string
        seconds: string
        paused: string
        resume: string
        pause: string
        redirect: string
      }
      Footer: {
        poweredBy: string
      }
      IdentityCreate: {
        username: string
        email: string
        givenName: string
        fullName: string
        pictureUrl: string
        description: string
      }
      IdentityOrganization: {
        id: string
        confirmUpdateToAllocate: string
        status: string
        apps: string
        none: string
      }
    }
    views: {
      ApplicationTemplateCreate: {
        createApplicationTemplate: string
        applicationTemplateName: string
        chooseApplicationTemplateName: string
      }
      ApplicationTemplateGet: {
        applicationTemplates: string
        applicationTemplateName: string
        description: string
        homepageTemplate: string
        spaceSeparatedScopes: string
        applicationsUpdated: string
        variables: string
        variablesUpdated: string
        name: string
        addVariable: string
        publicClients: string
        publicClientsUpdated: string
        oidcRedirectUriTemplates: string
        addRedirectUri: string
        spaceSeparatedAdditionalScopes: string
        accessTokenType: string
        hmac: string
        jwt: string
        accessTokenLifespan: string
        idTokenLifespan: string
        refreshTokenLifespan: string
        addClient: string
        backendClients: string
        backendClientsUpdated: string
        tokenEndpointAuthMethod: string
        serviceClients: string
        serviceClientsUpdated: string
        admins: string
        adminsUpdated: string
        addAdmin: string
      }
      ApplicationTemplateList: {
        applicationTemplates: string
        noApplicationTemplatesCreate: string
        noApplicationTemplatesSignIn: string
      }
      AuthFlowGet: {
        instructionsMessage: string
      }
      Home: {
        identities: string
        applicationTemplates: string
        organizations: string
      }
      IdentityCreate: {
        createIdentity: string
      }
      IdentityGet: {
        identity: string
        createIdentity: string
        createNewIdentity: string
        addedIdentities: string
        availableIdentities: string
        manage: string
        identityUpdated: string
        usersUpdated: string
        adminsUpdated: string
        organizationsUpdated: string
        noIdentities: string
        noIdentitiesCreate: string
        noIdentitiesSignIn: string
        noOtherIdentities: string
        addedOrganizations: string
        availableOrganizations: string
        description: string
        email: string
        fullName: string
        givenName: string
        pictureUrl: string
        username: string
        users: string
      }
      IdentityList: {
        identities: string
        noIdentitiesCreate: string
        noIdentitiesSignIn: string
      }
      OrganizationCreate: {
        organization: string
        organizationName: string
        chooseOrganizationName: string
      }
      OrganizationGet: {
        organization: string
        usersForOrganization: string
        users: string
        admins: string
        organizationName: string
        description: string
        organizationUpdated: string
        addedApplicationsUpdated: string
        adminsUpdated: string
        identitiesUpdated: string
        addedApplications: string
        availableApplications: string
        addedIdentities: string
        availableIdentities: string
        addAdmin: string
        backendClients: string
        clientId: string
        clientSecret: string
        configuration: string
        confirmUpdateToAllocate: string
        manage: string
        publicClients: string
        serviceClients: string
        status: string
      }
      OrganizationList: {
        organizations: string
        noOrganizationsCreate: string
        noOrganizationsSignIn: string
      }
      OrganizationUsers: {
        usersForOrganization: string
        noUsers: string
      }
    }
  }
}

export type MessageSchema = typeof en