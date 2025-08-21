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
      Footer: {
        poweredBy: string
      }
      AuthStart: {
        emailOrUsernameLabel: string
        orUse: string
      }
      AuthPassword: {
        emailAddressLabel: string
        usernameLabel: string
        passwordLabel: string
        sendCodeButton: string
        instructions: {
          emailAccount: string
          usernameAccount: string
          skipPassword: string
        }
        troublePassword: string
        differentSigninMethod: string
      }
      AuthCode: {
        codeSentEmail: string
        codeSentUsername: string
        codeFromHashEmail: string
        codeFromHashUsername: string
        resendButton: string
        sent: string
        sentMultiple: string
        instructions: {
          confirmCode: string
          waitForCode: string
          securityWarning: string
          strongDont: string
          troubleEmail: string
          differentMethod: string
        }
      }
      AuthPasskey: {
        signingIn: string
        signin: {
          instructions: string
          failed: string
          signupButton: string
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
      AuthThirdParty: {
        redirecting: string
        failed: string
      }
      AuthRedirect: {
        auto: {
          message: string
          manualRedirect: string
          here: string
        }
        manual: {
          message: string
        }
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
        statusMessages: {
          noIdentityUsed: string
          noIdentityUsedWithApp: string
          allPreviousDisabled: string
        }
        sectionTitles: {
          identitiesUsedWithOrg: string
          disabledIdentities: string
        }
      }
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
      }
      AuthThirdPartyRedirect: {
        redirectMessage: string
        instructions: string
        additionalInfo: string
      }
      AuthManualRedirect: {
        failed: string
        tryAgain: string
        completed: string
        homepage: string
        return: string
      }
    }
    views: {
      AuthFlowGet: {
        instructionsMessage: string
      }
      IdentityCreate: {
        applicationTemplateName: string
        organizationName: string
        username: string
        givenName: string
        fullName: string
        pictureUrl: string
        description: string
        email: string
      }
      ApplicationTemplateGet: {
        status: string
        apps: string
        none: string
        clientId: string
        clientSecret: string
        name: string
        id: string
        confirmUpdateToAllocate: string
        addAdmin: string
        addVariable: string
        addClient: string
        addRedirectUri: string
        oidcRedirectUriTemplates: string
        hmac: string
        jwt: string
        spaceSeparatedScopes: string
        spaceSeparatedAdditionalScopes: string
        accessTokenType: string
        accessTokenLifespan: string
        idTokenLifespan: string
        refreshTokenLifespan: string
        tokenEndpointAuthMethod: string
        organizations: string
        createOrganization: string
        createApplicationTemplate: string
        addedOrganizations: string
        availableOrganizations: string
        variables: string
        publicClients: string
        backendClients: string
        serviceClients: string
        addedApplications: string
        availableApplications: string
        configuration: string
        homepageTemplate: string
        applicationsUpdated: string
        variablesUpdated: string
        publicClientsUpdated: string
        backendClientsUpdated: string
        serviceClientsUpdated: string
        adminsUpdated: string
        noApplicationTemplates: string
        noApplicationTemplatesCreate: string
        noApplicationTemplatesSignIn: string
        chooseApplicationTemplateName: string
      }
      Home: {
        identities: string
        applicationTemplates: string
        organizations: string
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
      }
      OrganizationGet: {
        organization: string
        usersForOrganization: string
        users: string
        admins: string
        organizationUpdated: string
        addedApplicationsUpdated: string
        adminsUpdated: string
        identitiesUpdated: string
        noUsers: string
        noOrganizations: string
        noOrganizationsCreate: string
        noOrganizationsSignIn: string
        chooseOrganizationName: string
      }
      AuthIdentity: {
        previouslyUsedIdentities: string
        otherAvailableIdentities: string
        disabledIdentities: string
      }
    }
  }
}

export type MessageSchema = typeof en