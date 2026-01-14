import { signInWithPassword, test } from "../utils"

test.describe.serial("Charon Sign-in Flows", () => {
  test("Successful password sign-in flow", async ({ context }) => {
    const page = await context.newPage()

    await signInWithPassword(page, "tester", "tester123", true, true)

    console.log("Successfully completed sign-in flow: entered credentials, navigated through flow, selected tester identity, and verified Identities link is visible")
  })

  test("Wrong password sign-in flow", async ({ context }) => {
    const page = await context.newPage()

    await signInWithPassword(page, "tester", "tester1234", false, false)

    console.log("Successfully tested wrong password flow: entered wrong password and verified error message appeared")
  })
})
