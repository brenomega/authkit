const authkit = window.AUTHKIT_URL || "https://auth.example.test";
let accessToken = null; // Deliberately memory-only: never localStorage/sessionStorage/IndexedDB.
const output = document.querySelector("#output");
const emailInput = document.querySelector("#email");
const passwordInput = document.querySelector("#password");

function csrfCookie() {
  const entry = document.cookie.split("; ").find(value => value.startsWith("XSRF-TOKEN="));
  return entry ? decodeURIComponent(entry.substring("XSRF-TOKEN=".length)) : "";
}

async function request(path, options = {}) {
  const response = await fetch(authkit + path, {credentials: "include", ...options});
  const body = await response.json().catch(() => ({}));
  output.textContent = JSON.stringify({status: response.status, requestId: body.requestId,
    code: body.code, data: body.data && "accessToken" in body.data ? {...body.data, accessToken: "[memory-only]"} : body.data}, null, 2);
  if (!response.ok) throw new Error(body.code || `HTTP ${response.status}`);
  return body;
}

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

// Authentication email links use fragments. Remove the secret before any
// analytics/error integration can observe the URL, then submit it in JSON.
const fragment = new URLSearchParams(location.hash.substring(1));
if (fragment.has("token")) {
  const token = fragment.get("token");
  history.replaceState(null, "", location.pathname + location.search);
  request("/api/v1/auth/email-confirmation/confirm", {method: "POST",
    headers: {"Content-Type": "application/json"}, body: JSON.stringify({token})});
}
