import { Buffer } from "node:buffer";
import * as crypto from "node:crypto";
import { getAuthenticator, setAuthenticator } from "@/lib/authStore";
import type { AuthenticationResponseJSON } from "@simplewebauthn/browser";
import { verifyAuthenticationResponse } from "@simplewebauthn/server";
import type {
  VerifiedAuthenticationResponse,
  VerifyAuthenticationResponseOpts,
} from "@simplewebauthn/server";
import { isoBase64URL } from "@simplewebauthn/server/helpers";
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
    username: string;
    challenge: string; // The original challenge string sent by the client
    authenticationResponse: AuthenticationResponseJSON;
  } = await request.json();

  const { username, challenge, authenticationResponse } = body;

  if (!username || !challenge || !authenticationResponse) {
    return NextResponse.json(
      {
        error: "Username, challenge, and authenticationResponse are required",
      },
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

  // IMPORTANT: Encode the *provided* challenge string in the same way the client did
  // This is crucial for the verification to succeed.
  const expectedChallenge = isoBase64URL.fromBuffer(
    Buffer.from(challenge, "utf8"),
  );

  let verification: VerifiedAuthenticationResponse;
  try {
    const opts: VerifyAuthenticationResponseOpts = {
      response: authenticationResponse,
      expectedChallenge: `${expectedChallenge}`, // Use the encoded custom challenge
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
    console.error("Custom challenge verification failed:", error);
    return NextResponse.json(
      { verified: false, error: error.message },
      { status: 400 },
    );
  }

  const { verified, authenticationInfo } = verification;

  if (verified) {
    // Update the authenticator counter in the store
    const updatedAuthenticator = {
      ...authenticator,
      counter: authenticationInfo.newCounter,
    };
    setAuthenticator(username, updatedAuthenticator);

    // Log the details as requested
    const signatureBuffer = Buffer.from(
      authenticationResponse.response.signature,
      "base64",
    );
    const signatureRS = decodeASSN1Signature(signatureBuffer);

    // Construct the signed data (authenticatorData + clientDataHash)
    const authenticatorData = Buffer.from(
      authenticationResponse.response.authenticatorData,
      "base64",
    );
    const clientDataJSON = Buffer.from(
      authenticationResponse.response.clientDataJSON,
      "base64",
    );
    const clientDataHash = crypto
      .createHash("sha256")
      .update(clientDataJSON)
      .digest();
    const signedData = Buffer.concat([authenticatorData, clientDataHash]);

    console.log("--- Custom Challenge Signature Verification --- ");
    console.log("Verified:", verified);
    console.log("Username:", username);
    console.log("Original Challenge:", challenge);
    console.log("Encoded Challenge (Base64URL):", expectedChallenge);
    console.log("clientDataJSON (UTF-8):", clientDataJSON.toString("utf-8"));
    console.log("New Counter:", authenticationInfo.newCounter);
    console.log("Signature (Hex):", signatureBuffer.toString("hex"));
    console.log("Signature R (Hex):", signatureRS?.r);
    console.log("Signature S (Hex):", signatureRS?.s);
    console.log(
      "Authenticator Public Key Coords (Hex):",
      authenticator.publicKeyCoords,
    );
    console.log("\tSigned Data (Hex):", signedData.toString("hex"));
    console.log(
      "\tSigned Data Hash (SHA256 Hex):",
      clientDataHash.toString("hex"),
    ); // This is the hash of clientDataJSON
    console.log("--- End Custom Challenge Verification --- ");

    console.log("authenticator", authenticator);

    return NextResponse.json({
      verified: true,
      username,
      newCounter: authenticationInfo.newCounter,
      // signatureHex: signatureBuffer.toString("hex"),
      signature: {
        r: signatureRS?.r,
        s: signatureRS?.s,
      },
      clientDataJSON: clientDataJSON.toString("utf-8"),
      publicKeyCoords: authenticator.publicKeyCoords,
    });
  }

  console.error("Custom challenge authentication failed verification.");
  return NextResponse.json({ verified: false }, { status: 400 });
}
