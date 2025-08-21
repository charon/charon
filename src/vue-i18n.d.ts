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
      }
    }
  }
}

export type MessageSchema = typeof en
