import { getUser, setRegistrationChallenge, setUser } from "@/lib/authStore";
import { generateRegistrationOptions } from "@simplewebauthn/server";
import type {
  GenerateRegistrationOptionsOpts,
  PublicKeyCredentialCreationOptionsJSON,
} from "@simplewebauthn/server";
import { isoBase64URL, isoUint8Array } from "@simplewebauthn/server/helpers";
import { NextResponse } from "next/server";

// Human-readable title for your website
const rpName = "SimpleWebAuthn Example";
// A unique identifier for your website
const rpID = process.env.RP_ID || "localhost";

export async function POST(request: Request) {
  const { username } = await request.json();

  if (!username) {
    return NextResponse.json(
      { error: "Username is required" },
      { status: 400 },
    );
  }

  if (getUser(username)) {
    return NextResponse.json(
      { error: "Username already taken" },
      { status: 409 },
    );
  }

  const userID = isoUint8Array.fromUTF8String(`user_${username}_${Date.now()}`);
  const user = { id: userID, username };

  const opts: GenerateRegistrationOptionsOpts = {
    rpName,
    rpID,
    userID,
    userName: username,
    timeout: 60000,
    attestationType: "none",
    excludeCredentials: [],
    authenticatorSelection: {
      residentKey: "preferred",
      userVerification: "preferred",
    },
  };

  // @ts-ignore - Temporarily ignore potential type issue if it persists
  opts.pubKeyCredParams = [{ alg: -7, type: "public-key" }];

  const options = await generateRegistrationOptions(opts);

  setRegistrationChallenge(username, options.challenge);
  setUser(username, user);

  console.log("Generated Registration Options:", options);

  return NextResponse.json({
    ...(options as PublicKeyCredentialCreationOptionsJSON),
    user: {
      id: isoBase64URL.fromBuffer(userID),
      name: username,
      displayName: username,
    },
  });
}
