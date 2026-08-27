const config = Object.freeze({
  issuer: window.AUTHKIT_ISSUER || "https://auth.example.test",
  clientId: window.AUTHKIT_CLIENT_ID || "sample-public-client",
  redirectUri: location.origin + location.pathname,
  resourceUrl: window.RESOURCE_URL || "https://api.example.test/sample/me",
  scope: "openid email profile sample.read"
});
let tokens = null; // Access, ID and OAuth refresh tokens are memory-only.
const output = document.querySelector("#output");
const encode = bytes => btoa(String.fromCharCode(...bytes)).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
const random = size => encode(crypto.getRandomValues(new Uint8Array(size)));
const challenge = async verifier => encode(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))));
const jwtPayload = token => {
  const value = token.split(".")[1].replaceAll("-", "+").replaceAll("_", "/");
  return JSON.parse(decodeURIComponent(Array.from(atob(value.padEnd(Math.ceil(value.length / 4) * 4, "=")),
    character => `%${character.charCodeAt(0).toString(16).padStart(2, "0")}`).join("")));
};

document.querySelector("#authorize").onclick = async () => {
  const ceremony = {state: random(24), nonce: random(24), verifier: random(48), createdAt: Date.now()};
  // Only short-lived redirect ceremony material is persisted. Tokens never are.
  sessionStorage.setItem("authkit.oauth.ceremony", JSON.stringify(ceremony));
  const query = new URLSearchParams({response_type: "code", client_id: config.clientId,
    redirect_uri: config.redirectUri, scope: config.scope, state: ceremony.state,
    nonce: ceremony.nonce, code_challenge: await challenge(ceremony.verifier), code_challenge_method: "S256"});
  location.assign(`${config.issuer}/oauth2/authorize?${query}`);
};

async function tokenRequest(parameters) {
  const response = await fetch(`${config.issuer}/oauth2/token`, {method: "POST",
    headers: {"Content-Type": "application/x-www-form-urlencoded"}, body: new URLSearchParams(parameters)});
  const body = await response.json();
  if (!response.ok) throw new Error(body.error || `HTTP ${response.status}`);
  return body;
}

async function completeCallback() {
  const query = new URLSearchParams(location.search);
  if (!query.has("code") && !query.has("error")) return;
  history.replaceState(null, "", location.pathname); // Remove code/error immediately.
  const raw = sessionStorage.getItem("authkit.oauth.ceremony");
  sessionStorage.removeItem("authkit.oauth.ceremony");
  const ceremony = raw && JSON.parse(raw);
  if (!ceremony || Date.now() - ceremony.createdAt > 300000 || query.get("state") !== ceremony.state)
    throw new Error("OAuth state is missing, expired, or mismatched");
  if (query.has("error")) throw new Error(query.get("error"));
  tokens = await tokenRequest({grant_type: "authorization_code", code: query.get("code"),
    redirect_uri: config.redirectUri, client_id: config.clientId, code_verifier: ceremony.verifier});
  const idClaims = jwtPayload(tokens.id_token);
  if (idClaims.nonce !== ceremony.nonce) { tokens = null; throw new Error("OIDC nonce mismatch"); }
  output.textContent = "Authorization code, PKCE, state and nonce completed; tokens remain memory-only.";
}

document.querySelector("#call").onclick = async () => {
  const response = await fetch(config.resourceUrl, {headers: {Authorization: `Bearer ${tokens?.access_token || ""}`}});
  output.textContent = JSON.stringify(await response.json(), null, 2);
};
document.querySelector("#refresh").onclick = async () => {
  tokens = await tokenRequest({grant_type: "refresh_token", refresh_token: tokens.refresh_token, client_id: config.clientId});
  output.textContent = "OAuth refresh rotated; the previous credential must now fail.";
};
document.querySelector("#logout").onclick = async () => {
  if (tokens?.refresh_token) await fetch(`${config.issuer}/oauth2/revoke`, {method: "POST",
    headers: {"Content-Type": "application/x-www-form-urlencoded"},
    body: new URLSearchParams({token: tokens.refresh_token, token_type_hint: "refresh_token", client_id: config.clientId})});
  tokens = null;
  output.textContent = "Local tokens cleared and OAuth refresh revoked.";
};

completeCallback().catch(error => { tokens = null; output.textContent = error.message; });
