import { getAuthenticator } from "@/lib/authStore";
import type { PublicKeyCredentialRequestOptionsJSON } from "@simplewebauthn/browser";
import { isoBase64URL } from "@simplewebauthn/server/helpers";
import { NextResponse } from "next/server";

const rpID = process.env.RP_ID || "localhost";

export async function POST(request: Request) {
  const { username, challenge } = await request.json();

  if (!username || !challenge) {
    return NextResponse.json(
      { error: "Username and challenge are required" },
      { status: 400 },
    );
  }

  const authenticator = getAuthenticator(username);

  if (!authenticator) {
    return NextResponse.json(
      { error: `Authenticator not found for user ${username}.` },
      { status: 404 },
    );
  }

  // Prepare options for navigator.credentials.get()
  // We only allow the specific credential associated with the logged-in user
  // for this signing operation. Discoverable credentials are not suitable here.
  console.log("challenge", challenge);
  const options: PublicKeyCredentialRequestOptionsJSON = {
    challenge: isoBase64URL.fromBuffer(Buffer.from(challenge, "hex")), // Encode the custom challenge
    rpId: rpID,
    allowCredentials: [
      {
        id: authenticator.credentialID, // Use the stored credential ID (Base64URL string)
        type: "public-key",
        transports: authenticator.transports,
      },
    ],
    timeout: 60000,
    userVerification: "preferred",
  };

  console.log("Generated Signing Options for Custom Challenge:", options);

  // Note: We are NOT storing this challenge like in login/registration.
  // The client will send the challenge back during verification.

  return NextResponse.json(options);
}
