// Simple in-memory stores for POC - Replace with a database in production
// Use globalThis for persistence across module reloads in dev environments
declare global {
  var registrationChallengeStore: { [key: string]: string };
  var authenticationChallengeStore: { [key: string]: string };
  var userStore: { [key: string]: any };
  var authenticatorStore: { [key: string]: any };
}

// Initialize stores on globalThis if they don't exist
globalThis.registrationChallengeStore =
  globalThis.registrationChallengeStore || {};
globalThis.authenticationChallengeStore =
  globalThis.authenticationChallengeStore || {};
globalThis.userStore = globalThis.userStore || {};
globalThis.authenticatorStore = globalThis.authenticatorStore || {};

// Stores challenges temporarily (references global store)
// const registrationChallengeStore = globalThis.registrationChallengeStore;
// const authenticationChallengeStore = globalThis.authenticationChallengeStore;

// // Stores user information (references global store)
// const userStore = globalThis.userStore;

// // Stores authenticator information (references global store)
// const authenticatorStore = globalThis.authenticatorStore;

// --- User Store Functions ---
export function getUser(username: string): any | undefined {
  return userStore[username];
}

export function setUser(username: string, user: any): void {
  userStore[username] = user;
}

// --- Registration Challenge Store Functions ---
export function getRegistrationChallenge(username: string): string | undefined {
  const challenge = registrationChallengeStore[username];
  delete registrationChallengeStore[username]; // Consume challenge
  return challenge;
}

export function setRegistrationChallenge(
  username: string,
  challenge: string,
): void {
  registrationChallengeStore[username] = challenge;
}

// --- Authentication Challenge Store Functions ---
export function getAuthenticationChallenge(
  username: string,
): string | undefined {
  const challenge = authenticationChallengeStore[username];
  delete authenticationChallengeStore[username]; // Consume challenge
  return challenge;
}

export function setAuthenticationChallenge(
  username: string,
  challenge: string,
): void {
  authenticationChallengeStore[username] = challenge;
}

// --- Authenticator Store Functions ---
export function getAuthenticator(username: string): any | undefined {
  console.log("getting authenticator", authenticatorStore, username);
  return authenticatorStore[username];
}

export function setAuthenticator(username: string, authenticator: any): void {
  console.log(
    "setting authenticator",
    authenticatorStore,
    authenticator,
    username,
  );
  authenticatorStore[username] = authenticator;
}
