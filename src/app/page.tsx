"use client";

import {
  startAuthentication,
  startRegistration,
} from "@simplewebauthn/browser";
import type {
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
} from "@simplewebauthn/browser";
import { useState } from "react";
import { encode } from "xahau";

export default function Home() {
  const [address, setAddress] = useState<string>("");
  const [username, setUsername] = useState("");
  const [message, setMessage] = useState("");
  const [loggedInUser, setLoggedInUser] = useState<string | null>(null);
  const [showDebug, setShowDebug] = useState(false);
  const [debugData, setDebugData] = useState<any>(null);
  const [challengeInput, setChallengeInput] =
    useState<string>("Sign this data");
  const [txJson, setTxJson] = useState<string>("");
  const [signResult, setSignResult] = useState<any>(null);

  const handleRegister = async () => {
    if (!username) {
      setMessage("Please enter a username");
      return;
    }
    setMessage("Initiating registration...");
    setDebugData(null);

    try {
      // 1. Get registration options from server
      const regOptsResponse = await fetch("/api/register/challenge", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username }),
      });

      const regOptsJSON: PublicKeyCredentialCreationOptionsJSON & {
        user?: any;
      } = await regOptsResponse.json();

      if (!regOptsResponse.ok) {
        throw new Error(
          `Failed to get registration options: ${(regOptsJSON as any).error || regOptsResponse.statusText}`,
        );
      }

      setMessage(
        "Registration options received. Waiting for Passkey interaction...",
      );
      console.log("Registration Options:", regOptsJSON);

      // 2. Pass options wrapped for linter
      const attResp = await startRegistration({ optionsJSON: regOptsJSON });
      console.log("Registration Response from Browser:", attResp);
      setMessage("Passkey created. Verifying with server...");

      // 3. Send response to server for verification
      const verificationResp = await fetch("/api/register/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        // Pass username explicitly along with the response
        body: JSON.stringify({
          username,
          registrationResponse: attResp,
        }),
      });

      const verificationJSON = await verificationResp.json();

      if (!verificationResp.ok || !verificationJSON.verified) {
        throw new Error(
          `Registration verification failed: ${(verificationJSON as any).error || "Unknown error"}`,
        );
      }

      setMessage(
        `Registration successful for ${username}! You can now log in.`,
      );
      setDebugData({
        registrationOptions: regOptsJSON,
        registrationResponse: attResp,
      });
    } catch (error: any) {
      setMessage(`Registration failed: ${error.message}`);
      console.error("Registration Error:", error);
      setDebugData({ error: error.message, stack: error.stack });
    }
  };

  const handleLogin = async () => {
    if (!username) {
      setMessage("Please enter your username");
      return;
    }
    setMessage("Initiating login...");
    setDebugData(null);

    try {
      // 1. Get authentication options from server
      const authOptsResponse = await fetch("/api/login/challenge", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username }),
      });

      const authOptsJSON: PublicKeyCredentialRequestOptionsJSON =
        await authOptsResponse.json();

      if (!authOptsResponse.ok) {
        throw new Error(
          `Failed to get authentication options: ${(authOptsJSON as any).error || authOptsResponse.statusText}`,
        );
      }

      setMessage(
        "Authentication options received. Waiting for Passkey interaction...",
      );
      console.log("Authentication Options:", authOptsJSON);

      // 2. Pass options wrapped for linter
      const assertResp = await startAuthentication({
        optionsJSON: authOptsJSON,
      });
      console.log("Authentication Response from Browser:", assertResp);
      setMessage("Passkey used. Verifying with server...");

      // 3. Send response to server for verification
      const verificationResp = await fetch("/api/login/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        // Pass username (optional if discoverable handled) and response
        body: JSON.stringify({
          username,
          authenticationResponse: assertResp,
        }),
      });

      const verificationJSON = await verificationResp.json();

      if (!verificationResp.ok || !verificationJSON.verified) {
        throw new Error(
          `Authentication verification failed: ${(verificationJSON as any).error || "Unknown error"}`,
        );
      }

      setMessage(`Login successful! Welcome, ${verificationJSON.username}!`);
      setLoggedInUser(verificationJSON.username);
      setAddress(verificationJSON.address);
      console.log(verificationJSON)
      const tx_json = {
        TransactionType: "AccountSet",
        Account: address,
      }
      console.log('tx_json', tx_json)
      setTxJson(JSON.stringify(tx_json, null, 2))
      const tx_blob = encode(tx_json as any)
      setChallengeInput(tx_blob)
      
      setDebugData({
        authenticationOptions: authOptsJSON,
        authenticationResponse: assertResp,
      });
      setSignResult(null);
    } catch (error: any) {
      setMessage(`Login failed: ${error.message}`);
      console.error("Authentication Error:", error);
      setDebugData({ error: error.message, stack: error.stack });
    }
  };

  const handleLogout = () => {
    setLoggedInUser(null);
    setUsername("");
    setMessage("Logged out.");
    setDebugData(null);
    setSignResult(null);
  };

  const handleSignChallenge = async () => {
    if (!loggedInUser) {
      setMessage("Please log in first.");
      return;
    }
    if (!challengeInput) {
      setMessage("Please enter a challenge string to sign.");
      return;
    }

    setMessage("Requesting signing options...");
    setSignResult(null);
    setDebugData(null);

    try {
      // 1. Get signing options from the new endpoint
      const signOptsResponse = await fetch("/api/sign-challenge", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username: loggedInUser,
          challenge: challengeInput,
        }),
      });

      const signOptsJSON: PublicKeyCredentialRequestOptionsJSON =
        await signOptsResponse.json();

      if (!signOptsResponse.ok) {
        throw new Error(
          `Failed to get signing options: ${(signOptsJSON as any).error || signOptsResponse.statusText}`,
        );
      }

      setMessage(
        "Signing options received. Waiting for Passkey interaction...",
      );
      console.log("Signing Options:", signOptsJSON);

      // 2. Call navigator.credentials.get() with the custom challenge options
      // Note: simplewebauthn's startAuthentication expects optionsJSON property
      const assertResp = await startAuthentication({
        optionsJSON: signOptsJSON,
      });

      console.log("Signing Assertion Response from Browser:", assertResp);
      setMessage("Signature generated. Verifying with server...");

      // 3. Send the assertion response and the original challenge to the verification endpoint
      const verificationResp = await fetch("/api/sign-challenge/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username: loggedInUser,
          challenge: challengeInput,
          authenticationResponse: assertResp,
        }),
      });

      const verificationJSON = await verificationResp.json();

      if (!verificationResp.ok || !verificationJSON.verified) {
        throw new Error(
          `Custom challenge verification failed: ${(verificationJSON as any).error || "Unknown error"}`,
        );
      }

      setMessage(
        `Successfully signed challenge: "${challengeInput}" for ${loggedInUser}!`,
      );
      setSignResult(verificationJSON);
      setDebugData({
        signingOptions: signOptsJSON,
        signingResponse: assertResp,
        verificationResult: verificationJSON,
      });
    } catch (error: any) {
      setMessage(`Signing failed: ${error.message}`);
      console.error("Signing Error:", error);
      setSignResult({ error: error.message });
      setDebugData({ error: error.message, stack: error.stack });
    }
  };

  return (
    <main className="flex min-h-screen flex-col items-center justify-center p-8 bg-gray-50 font-[family-name:var(--font-geist-sans)]">
      <div className="w-full max-w-md p-8 space-y-6 bg-white rounded-lg shadow-md">
        <h1 className="text-2xl font-bold text-center text-gray-800">
          P256 Passkey Demo (SimpleWebAuthn)
        </h1>

        {!loggedInUser ? (
          <div className="space-y-4">
            <div>
              <label
                htmlFor="username"
                className="block text-sm font-medium text-gray-700"
              >
                Username
              </label>
              <input
                id="username"
                name="username"
                type="text"
                autoComplete="username webauthn"
                required
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm text-gray-700"
              />
            </div>
            <div className="flex space-x-4">
              <button
                type="button"
                onClick={handleRegister}
                className="flex-1 justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500"
              >
                Register Passkey
              </button>
              <button
                type="button"
                onClick={handleLogin}
                className="flex-1 justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-green-600 hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-green-500"
              >
                Login with Passkey
              </button>
            </div>
          </div>
        ) : (
          <div className="text-center space-y-4">
            <p className="text-lg font-medium text-green-700">
              Welcome, {loggedInUser}!
            </p>
            <button
              type="button"
              onClick={handleLogout}
              className="w-full justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-red-600 hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500"
            >
              Logout
            </button>
          </div>
        )}

        {loggedInUser && (
          <div className="mt-8 pt-6 border-t border-gray-200 space-y-4">
            <h2 className="text-lg font-semibold text-center text-gray-700">
              Sign Custom Challenge
            </h2>
            <div>
              <label
                htmlFor="challengeInput"
                className="block text-sm font-medium text-gray-700"
              >
                Tx Json
              </label>
              <textarea
                id="txJson"
                name="txJson"
                rows={7}
                value={txJson}
                onChange={(e) => {
                  setTxJson(e.target.value)
                  const tx_blob = encode(JSON.parse(e.target.value))
                  setChallengeInput(tx_blob)
                }
                }
                className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm text-gray-700"
              />
            </div>
            <div>
              <label
                htmlFor="challengeInput"
                className="block text-sm font-medium text-gray-700"
              >
                Challenge Data
              </label>
              <input
                id="challengeInput"
                name="challengeInput"
                type="text"
                value={challengeInput}
                onChange={(e) => setChallengeInput(e.target.value)}
                className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm text-gray-700"
              />
            </div>
            <button
              type="button"
              onClick={handleSignChallenge}
              className="w-full justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
            >
              Sign Challenge with Passkey
            </button>
            {signResult && (
              <div className="mt-4 p-3 bg-gray-50 rounded border border-gray-200">
                <h4 className="text-sm font-semibold text-gray-600">
                  Signing Result:
                </h4>
                <pre className="mt-1 text-xs text-gray-500 break-all whitespace-pre-wrap">
                  {JSON.stringify(signResult, null, 2)}
                </pre>
              </div>
            )}
          </div>
        )}

        {message && (
          <p className="mt-4 text-center text-sm text-gray-600">{message}</p>
        )}

        <div className="mt-6 text-center">
          <button
            type="button"
            onClick={() => setShowDebug(!showDebug)}
            className="text-xs text-indigo-600 hover:text-indigo-800"
          >
            {showDebug ? "Hide" : "Show"} Debug Info
          </button>
        </div>

        {showDebug && debugData && (
          <div className="mt-4 p-4 bg-gray-100 rounded overflow-x-auto">
            <h3 className="text-sm font-semibold text-gray-700">Debug Data:</h3>
            <pre className="text-xs text-gray-600">
              {JSON.stringify(debugData, null, 2)}
            </pre>
          </div>
        )}
      </div>
    </main>
  );
}
