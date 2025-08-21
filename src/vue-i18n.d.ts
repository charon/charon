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
    }
    navigation: {
      signOut: string
      signIn: string
      identities: string
      applicationTemplates: string
      organizations: string
    }
    footer: {
      poweredBy: string
    }
    auth: {
      start: {
        emailOrUsernameLabel: string
        orUse: string
      }
      password: {
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
      code: {
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
      passkey: {
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
      thirdParty: {
        redirecting: string
        failed: string
      }
      redirect: {
        auto: {
          message: string
          manualRedirect: string
          here: string
        }
        manual: {
          message: string
        }
      }
      identity: {
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
      }
      autoRedirect: {
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
      thirdPartyRedirect: {
        redirectMessage: string
        instructions: string
        additionalInfo: string
      }
      manualRedirect: {
        failed: string
        tryAgain: string
        completed: string
        homepage: string
        return: string
      }
    }
    loading: {
      dataLoading: string
      loadingDataFailed: string
    }
    labels: {
      optional: string
      applicationTemplateName: string
      organizationName: string
      username: string
      givenName: string
      fullName: string
      pictureUrl: string
      description: string
      email: string
      current: string
      admin: string
      active: string
      disabled: string
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
      spaceSeparatedScopes: string
      spaceSeparatedAdditionalScopes: string
      accessTokenType: string
      accessTokenLifespan: string
      idTokenLifespan: string
      refreshTokenLifespan: string
      tokenEndpointAuthMethod: string
    }
    titles: {
      organizations: string
      identities: string
      applicationTemplates: string
      organization: string
      identity: string
      createOrganization: string
      createApplicationTemplate: string
      createIdentity: string
      createNewIdentity: string
      usersForOrganization: string
      previouslyUsedIdentities: string
      otherAvailableIdentities: string
      disabledIdentities: string
      users: string
      admins: string
      addedOrganizations: string
      availableOrganizations: string
      variables: string
      publicClients: string
      backendClients: string
      serviceClients: string
      addedApplications: string
      availableApplications: string
      addedIdentities: string
      availableIdentities: string
      configuration: string
      homepageTemplate: string
      manage: string
    }
    passkey: {
      signingIn: string
    }
    messages: {
      success: {
        organizationUpdated: string
        applicationsUpdated: string
        adminsUpdated: string
        identitiesUpdated: string
        identityUpdated: string
        usersUpdated: string
        organizationsUpdated: string
        variablesUpdated: string
        publicClientsUpdated: string
        backendClientsUpdated: string
        serviceClientsUpdated: string
        addedApplicationsUpdated: string
        addedApplicationsUpdatedSuccess: string
      }
      empty: {
        noUsers: string
        noIdentities: string
        noIdentitiesCreate: string
        noIdentitiesSignIn: string
        noOrganizations: string
        noOrganizationsCreate: string
        noOrganizationsSignIn: string
        noApplicationTemplates: string
        noApplicationTemplatesCreate: string
        noApplicationTemplatesSignIn: string
        noOtherIdentities: string
      }
      help: {
        chooseApplicationTemplateName: string
        chooseOrganizationName: string
      }
    }
  }
}

export type MessageSchema = typeof en
