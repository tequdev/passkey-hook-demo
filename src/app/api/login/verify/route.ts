import { Buffer } from "node:buffer";
import {
  getAuthenticationChallenge,
  getAuthenticator,
  getUser,
  setAuthenticator, // Need this to update counter
} from "@/lib/authStore";
import type { AuthenticationResponseJSON } from "@simplewebauthn/browser";
import { verifyAuthenticationResponse } from "@simplewebauthn/server";
import type {
  VerifiedAuthenticationResponse,
  VerifyAuthenticationResponseOpts,
} from "@simplewebauthn/server";
import { NextResponse } from "next/server";

const rpID = process.env.RP_ID || "localhost";
const origin = process.env.ORIGIN || `http://${rpID}:3000`;

/**
 * Convert Uint8Array to Hex String
 */
function bufferToHex(buffer: Uint8Array): string {
  return Buffer.from(buffer).toString("hex");
}

/**
 * Decode ASN.1 DER signature to R and S components (Hex)
 * Assumes signature is ECDSA-SHA256
 */
function decodeASSN1Signature(
  signature: Buffer,
): { r: string; s: string } | null {
  try {
    // Basic ASN.1 DER parsing for SEQUENCE (0x30), INTEGER (0x02)
    if (signature[0] !== 0x30 || signature[1] > signature.length - 2) {
      throw new Error("Invalid ASN.1 SEQUENCE header");
    }

    const lengthR = signature[3];
    const offsetR = 4;
    if (signature[2] !== 0x02 || offsetR + lengthR > signature.length) {
      throw new Error("Invalid ASN.1 INTEGER R");
    }
    let r = signature.subarray(offsetR, offsetR + lengthR);

    const offsetS = offsetR + lengthR;
    if (signature[offsetS] !== 0x02 || offsetS + 1 > signature.length) {
      throw new Error("Invalid ASN.1 INTEGER S header");
    }
    const lengthS = signature[offsetS + 1];
    if (offsetS + 2 + lengthS > signature.length) {
      throw new Error("Invalid ASN.1 INTEGER S length");
    }
    let s = signature.subarray(offsetS + 2, offsetS + 2 + lengthS);

    // Remove leading zero byte if present (positive integer representation)
    if (r[0] === 0x00) r = r.subarray(1);
    if (s[0] === 0x00) s = s.subarray(1);

    return {
      r: bufferToHex(r),
      s: bufferToHex(s),
    };
  } catch (error) {
    console.error("Error decoding ASN.1 signature:", error);
    return null;
  }
}

export async function POST(request: Request) {
  const body: {
    username?: string;
    authenticationResponse: AuthenticationResponseJSON;
  } = await request.json();

  let { username, authenticationResponse } = body;

  // Try to get username from userHandle if not provided explicitly (for discoverable credentials)
  if (!username && authenticationResponse.response.userHandle) {
    const userHandle = authenticationResponse.response.userHandle;
    // This lookup assumes userHandle during registration was set to username
    // In a real app, you might query based on the userHandle (which could be userID)
    const potentialUser = getUser(userHandle);
    if (potentialUser) {
      username = potentialUser.username;
      console.log(`Identified user '${username}' via userHandle.`);
    }
  }

  if (!username) {
    return NextResponse.json(
      { error: "Could not identify user for authentication." },
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

  const expectedChallenge = getAuthenticationChallenge(username);
  if (!expectedChallenge) {
    return NextResponse.json(
      { error: "Challenge not found or expired." },
      { status: 400 },
    );
  }

  let verification: VerifiedAuthenticationResponse;
  try {
    const opts: VerifyAuthenticationResponseOpts = {
      response: authenticationResponse,
      expectedChallenge: `${expectedChallenge}`,
      expectedOrigin: origin,
      expectedRPID: rpID,
      credential: {
        id: authenticator.credentialID,
        publicKey: Buffer.from(authenticator.credentialPublicKey, "hex"),
        counter: authenticator.counter,
        transports: authenticator.transports,
      },
      requireUserVerification: false,
    };
    verification = await verifyAuthenticationResponse(opts);
  } catch (error: any) {
    console.error("Authentication verification failed:", error);
    return NextResponse.json({ error: error.message }, { status: 400 });
  }

  const { verified, authenticationInfo } = verification;

  if (verified) {
    // Update the authenticator counter in the store
    const updatedAuthenticator = {
      ...authenticator,
      counter: authenticationInfo.newCounter,
    };
    setAuthenticator(username, updatedAuthenticator);

    // You can now use passkeyData within your application logic
    // For the POC, we just return verification status
    return NextResponse.json({ verified: true, username });
  }
  console.error("Authentication failed verification.");
  return NextResponse.json({ verified: false }, { status: 400 });
}
