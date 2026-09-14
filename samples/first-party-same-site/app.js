const authkit = window.AUTHKIT_URL || "https://auth.example.test";
let accessToken = null; // Deliberately memory-only: never localStorage/sessionStorage/IndexedDB.
const output = document.querySelector("#output");
const emailInput = document.querySelector("#email");
const passwordInput = document.querySelector("#password");
const codeInput = document.querySelector("#code");
let fragmentToken = null;
let pendingTotpCredentialId = null;

function csrfCookie() {
  const entry = document.cookie.split("; ").find(value => value.startsWith("XSRF-TOKEN="));
  return entry ? decodeURIComponent(entry.substring("XSRF-TOKEN=".length)) : "";
}

async function request(path, options = {}, render = true) {
  const response = await fetch(authkit + path, {credentials: "include", ...options});
  const body = await response.json().catch(() => ({}));
  if (render) {
    output.textContent = JSON.stringify({status: response.status, requestId: body.requestId,
      code: body.code, data: body.data && "accessToken" in body.data ? {...body.data, accessToken: "[memory-only]"} : body.data}, null, 2);
  }
  if (!response.ok) throw new Error(body.code || `HTTP ${response.status}`);
  return body;
}

function bearer() {
  if (!accessToken) throw new Error("Authenticate first");
  return {Authorization: `Bearer ${accessToken}`, "Content-Type": "application/json"};
}

function base64urlToBytes(value) {
  const base64 = value.replaceAll("-", "+").replaceAll("_", "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  return Uint8Array.from(atob(base64), character => character.charCodeAt(0));
}

function publicKeyOptions(json, kind) {
  const options = JSON.parse(json);
  options.challenge = base64urlToBytes(options.challenge);
  if (kind === "create") options.user.id = base64urlToBytes(options.user.id);
  if (options.excludeCredentials) options.excludeCredentials.forEach(item => { item.id = base64urlToBytes(item.id); });
  if (options.allowCredentials) options.allowCredentials.forEach(item => { item.id = base64urlToBytes(item.id); });
  return options;
}

function credentialJson(credential) {
  // Modern browsers expose PublicKeyCredential.toJSON(), which applies the WebAuthn
  // base64url serialization required by the server-side Yubico parser.
  if (typeof credential.toJSON !== "function") throw new Error("This browser lacks PublicKeyCredential.toJSON()");
  return JSON.stringify(credential.toJSON());
}

document.querySelector("#register").onclick = () => request("/api/v1/auth/register", {method: "POST",
  headers: {"Content-Type": "application/json"}, body: JSON.stringify({email: emailInput.value,
    password: passwordInput.value, termsAccepted: true, privacyPolicyAccepted: true})});
document.querySelector("#resend").onclick = () => request("/api/v1/auth/email-confirmation/resend", {method: "POST",
  headers: {"Content-Type": "application/json"}, body: JSON.stringify({email: emailInput.value})});
document.querySelector("#confirm").onclick = async () => {
  if (!fragmentToken) throw new Error("Open the confirmation link first");
  await request("/api/v1/auth/email-confirmation/confirm", {method: "POST", headers: {"Content-Type": "application/json"},
    body: JSON.stringify({token: fragmentToken})});
  fragmentToken = null;
};

document.querySelector("#login").onclick = async () => {
  const body = await request("/api/v1/auth/login", {method: "POST", headers: {"Content-Type": "application/json"},
    body: JSON.stringify({email: emailInput.value, password: passwordInput.value})});
  accessToken = body.data.accessToken;
  passwordInput.value = "";
};
document.querySelector("#profile").onclick = () => request("/api/v1/users/me", {headers: {Authorization: `Bearer ${accessToken}`}});
document.querySelector("#refresh").onclick = async () => {
  const body = await request("/api/v1/auth/refresh", {method: "POST", headers: {"X-XSRF-TOKEN": csrfCookie()}});
  accessToken = body.data.accessToken;
};
document.querySelector("#logout").onclick = async () => {
  await request("/api/v1/auth/logout", {method: "POST", headers: {"X-XSRF-TOKEN": csrfCookie()}});
  accessToken = null;
};

document.querySelector("#recovery").onclick = () => request("/api/v1/auth/password-recovery/request", {method: "POST",
  headers: {"Content-Type": "application/json"}, body: JSON.stringify({email: emailInput.value})});
document.querySelector("#reset").onclick = async () => {
  if (!fragmentToken) throw new Error("Open the recovery link first");
  await request(`/api/v1/auth/password-recovery/reset?email=${encodeURIComponent(emailInput.value)}`, {method: "POST",
    headers: {"Content-Type": "application/json"}, body: JSON.stringify({token: fragmentToken, newPassword: passwordInput.value})});
  fragmentToken = null;
};

document.querySelector("#totp-enroll").onclick = async () => {
  const body = await request("/api/v1/users/me/mfa/totp/enroll", {method: "POST", headers: bearer(),
    body: JSON.stringify({currentPassword: passwordInput.value})}, false);
  pendingTotpCredentialId = body.data.credentialId;
  output.textContent = JSON.stringify({warning: "One-time TOTP secret: enter it now; do not log or persist this output.",
    ...body.data}, null, 2);
};
document.querySelector("#totp-confirm").onclick = async () => {
  if (!pendingTotpCredentialId) throw new Error("Start TOTP enrollment first");
  const body = await request("/api/v1/users/me/mfa/totp/confirm", {method: "POST", headers: bearer(),
    body: JSON.stringify({credentialId: pendingTotpCredentialId, currentPassword: passwordInput.value, code: codeInput.value})}, false);
  pendingTotpCredentialId = null;
  output.textContent = JSON.stringify({warning: "One-time backup codes: store them securely now; they are not shown again.",
    ...body.data}, null, 2);
};

document.querySelector("#passkey-register").onclick = async () => {
  const start = await request("/api/v1/users/me/passkeys/options", {method: "POST", headers: bearer(),
    body: JSON.stringify({currentPassword: passwordInput.value, mfaCode: codeInput.value || null})});
  const credential = await navigator.credentials.create({publicKey:
    publicKeyOptions(start.data.publicKeyCredentialCreationOptionsJson, "create")});
  await request("/api/v1/users/me/passkeys", {method: "POST", headers: bearer(), body: JSON.stringify({
    challengeId: start.data.challengeId, label: "Browser passkey", credentialJson: credentialJson(credential)})});
};
document.querySelector("#passkey-login").onclick = async () => {
  const start = await request("/api/v1/auth/passkeys/options", {method: "POST", headers: {"Content-Type": "application/json"},
    body: JSON.stringify({email: emailInput.value})});
  const credential = await navigator.credentials.get({publicKey:
    publicKeyOptions(start.data.publicKeyCredentialRequestOptionsJson, "get")});
  const body = await request("/api/v1/auth/passkeys/verify", {method: "POST", headers: {"Content-Type": "application/json"},
    body: JSON.stringify({challengeId: start.data.challengeId, credentialJson: credentialJson(credential)})});
  accessToken = body.data.accessToken;
};

// Authentication email links use fragments. Remove the secret before any
// analytics/error integration can observe the URL, then submit it in JSON.
const fragment = new URLSearchParams(location.hash.substring(1));
if (fragment.has("token")) {
  fragmentToken = fragment.get("token");
  history.replaceState(null, "", location.pathname + location.search);
  output.textContent = "One-time token captured in memory and removed from the URL. Choose Confirm or Reset.";
}
