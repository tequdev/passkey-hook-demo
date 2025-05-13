import { getAuthenticator, setAuthenticationChallenge } from "@/lib/authStore"; // Import from store
import { generateAuthenticationOptions } from "@simplewebauthn/server";
import type { GenerateAuthenticationOptionsOpts } from "@simplewebauthn/server";
import { NextResponse } from "next/server";

const rpID = process.env.RP_ID || "localhost";

export async function POST(request: Request) {
  const { username } = await request.json();

  if (!username) {
    return NextResponse.json(
      { error: "Username is required" },
      { status: 400 },
    );
  }

  const authenticator = getAuthenticator(username);

  if (!authenticator) {
    // Allow generating challenge even if user/authenticator not found
    // This handles "discoverable credentials" (passkeys) where the
    // browser/authenticator identifies the user.
    console.log(
      `No authenticator found for ${username}, generating discoverable credential challenge.`,
    );
  }

  const opts: GenerateAuthenticationOptionsOpts = {
    timeout: 60000,
    allowCredentials: authenticator
      ? [
          {
            id: authenticator.credentialID,
            transports: authenticator.transports,
          },
        ]
      : undefined, // Important: Allow discoverable credentials if no specific one found
    userVerification: "preferred",
    rpID,
  };

  const options = await generateAuthenticationOptions(opts);

  // Use imported function to store challenge
  setAuthenticationChallenge(username, options.challenge);

  console.log("Generated Authentication Options:", options);

  return NextResponse.json(options);
}
