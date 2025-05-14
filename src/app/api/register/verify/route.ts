import { Buffer } from "node:buffer";
import {
  getRegistrationChallenge,
  getUser,
  setAuthenticator,
} from "@/lib/authStore";
import type { RegistrationResponseJSON } from "@simplewebauthn/browser"; // Get type from browser package
import { verifyRegistrationResponse } from "@simplewebauthn/server";
import type {
  VerifiedRegistrationResponse,
  VerifyRegistrationResponseOpts,
} from "@simplewebauthn/server";
import { isoBase64URL } from "@simplewebauthn/server/helpers";
import { decode } from "cbor-x"; // Use decode from cbor-x
import { NextResponse } from "next/server";
import { fundWallet, generateWallet, installHook } from "@/app/xahau";

const rpID = process.env.RP_ID || "localhost";
const origin = process.env.ORIGIN || `http://${rpID}:3000`;

/**
 * Convert Uint8Array to Hex String
 */
function bufferToHex(buffer: Uint8Array): string {
  return Buffer.from(buffer).toString("hex");
}

/**
 * Extract P-256 Public Key Coordinates (x, y) from COSE Key
 * Assumes uncompressed point format (0x04 prefix)
 */
function extractPublicKeyCoords(
  publicKey: Uint8Array,
): { x: string; y: string } | null {
  try {
    // Parse the COSE key using cbor-x
    const coseKey = decode(publicKey);

    // Check if the decoded key is an object/map-like structure
    if (typeof coseKey !== "object" || coseKey === null) {
      console.error("Decoded COSE key is not an object:", coseKey);
      return null;
    }

    // Access properties using object indexing
    const kty = coseKey[1]; // kty (key type)
    const alg = coseKey[3]; // alg (algorithm)
    const crv = coseKey[-1]; // crv (curve)
    const xCoord = coseKey[-2]; // x-coordinate
    const yCoord = coseKey[-3]; // y-coordinate

    // Ensure it's an EC2 key (-2), uses ES256 (-7), on P-256 curve (1)
    if (kty !== 2 || alg !== -7 || crv !== 1) {
      console.error("Public key is not P-256 EC2 type. Found:", {
        kty,
        alg,
        crv,
      });
      return null;
    }

    if (!(xCoord instanceof Uint8Array) || !(yCoord instanceof Uint8Array)) {
      console.error("Missing or invalid x/y coordinate in COSE key.", {
        xCoord,
        yCoord,
      });
      return null;
    }

    return {
      x: bufferToHex(xCoord),
      y: bufferToHex(yCoord),
    };
  } catch (error) {
    console.error("Error parsing COSE public key:", error);
    return null;
  }
}

export async function POST(request: Request) {
  const body: {
    username: string;
    registrationResponse: RegistrationResponseJSON;
  } = await request.json();
  const { username, registrationResponse } = body;

  const user = getUser(username);
  if (!user) {
    return NextResponse.json(
      { error: "User not found during registration verification." },
      { status: 400 },
    );
  }

  const expectedChallenge = getRegistrationChallenge(username);

  if (!expectedChallenge) {
    return NextResponse.json(
      { error: "Challenge not found or expired." },
      { status: 400 },
    );
  }

  let verification: VerifiedRegistrationResponse;
  try {
    const opts: VerifyRegistrationResponseOpts = {
      response: registrationResponse,
      expectedChallenge: `${expectedChallenge}`,
      expectedOrigin: origin,
      expectedRPID: rpID,
      requireUserVerification: false,
    };
    verification = await verifyRegistrationResponse(opts);
  } catch (error: any) {
    console.error("Verification failed:", error);
    return NextResponse.json({ error: error.message }, { status: 400 });
  }

  const { verified, registrationInfo } = verification;

  if (verified && registrationInfo) {
    if (registrationInfo.credentialType === "public-key") {
      // Destructure from registrationInfo.credential using actual property names
      const {
        publicKey: credentialPublicKey, // Rename publicKey to credentialPublicKey
        id, // Keep original name 'id' for now
        counter,
        transports,
      } = registrationInfo.credential;

      // Ensure the extracted types are correct before proceeding
      if (
        !(credentialPublicKey instanceof Uint8Array) ||
        typeof id !== "string" || // Check if 'id' is a string
        typeof counter !== "number"
      ) {
        console.error(
          "Invalid types extracted from registrationInfo.credential",
        );
        console.error(registrationInfo.credential);
        return NextResponse.json(
          { error: "Internal server error during registration verification" },
          { status: 500 },
        );
      }

      // Convert the Base64URL ID string to a Uint8Array
      const credentialID = isoBase64URL.toBuffer(id);

      const publicKeyCoords = extractPublicKeyCoords(credentialPublicKey);

      const wallet = await generateWallet()
      await fundWallet(wallet)
      await installHook(wallet)

      const newAuthenticator = {
        credentialID: id, // Store the original Base64URL string ID
        credentialPublicKey: bufferToHex(credentialPublicKey), // Store as Hex
        publicKeyCoords: publicKeyCoords, // Store extracted coords
        counter,
        address: wallet.address,
        transports: transports, // Use transports from credential
      };

      setAuthenticator(username, newAuthenticator);

      console.log("Registration Verified:", verified);
      console.log("Stored Authenticator for user:", user.username);
      console.log(
        "\tCredential ID (Base64URL):",
        id, // Log the original Base64URL string ID
      );
      console.log("\tRaw Public Key (Hex):", bufferToHex(credentialPublicKey));
      console.log("\tPublic Key Coords (Hex):", publicKeyCoords);
      console.log("\tCounter:", counter);

      return NextResponse.json({ verified });
    }
    console.error(
      "Unexpected credential type during registration:",
      registrationInfo.credentialType,
    );
    return NextResponse.json(
      { error: "Unexpected credential type" },
      { status: 400 },
    );
  }

  return NextResponse.json({ verified: false }, { status: 400 });
}
