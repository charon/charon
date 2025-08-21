import en from "@/locales/en.json"

declare module "vue-i18n" {
  export interface DefineLocaleMessage {
    auth: {
      start: {
        emailOrUsernameLabel: string
        nextButton: string
        orUse: string
        passkeyButton: string
        errors: {
          invalidEmailAddress: string
          invalidUsername: string
          shortEmailAddress: string
          shortUsername: string
          unexpected: string
        }
      }
      password: {
        emailAddressLabel: string
        usernameLabel: string
        passwordLabel: string
        nextButton: string
        backButton: string
        sendCodeButton: string
        instructions: {
          emailAccount: string
          usernameAccount: string
          skipPassword: string
        }
        errors: {
          wrongPassword: string
          invalidPassword: string
          shortPassword: string
          noAccount: string
          noEmails: string
          unexpected: string
        }
        troublePassword: string
        differentSigninMethod: string
      }
      code: {
        codeSentEmail: string
        codeSentUsername: string
        codeFromHashEmail: string
        codeFromHashUsername: string
        nextButton: string
        backButton: string
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
        errors: {
          invalidCode: string
          unexpected: string
        }
      }
      passkey: {
        signin: {
          instructions: string
          strongPasskey: string
          failed: string
          retryButton: string
          signupButton: string
          backButton: string
        }
        signup: {
          instructions: string
          strongPasskey: string
          signingUp: string
          failed: string
          retrySigninButton: string
          passkeySignupButton: string
          retrySignupButton: string
        }
        errors: {
          unexpected: string
        }
      }
      thirdParty: {
        redirecting: string
        failed: string
        retryButton: string
        backButton: string
      }
      redirect: {
        auto: {
          message: string
          manualRedirect: string
          here: string
        }
        manual: {
          message: string
          continueButton: string
        }
      }
      identity: {
        selectIdentity: string
        continueButton: string
        backButton: string
        newIdentityButton: string
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
    common: {
      errors: {
        unexpected: string
      }
    }
  }
}

export type MessageSchema = typeof en