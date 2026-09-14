import http from 'k6/http';
import { check, sleep } from 'k6';

const baseUrl = __ENV.AUTHKIT_BASE_URL || 'http://localhost:8080';
const introspectionUrl = __ENV.AUTHKIT_INTROSPECTION_URL;
const workerToken = __ENV.AUTHKIT_WORKER_TOKEN;
const email = __ENV.AUTHKIT_K6_LOGIN_EMAIL;
const password = __ENV.AUTHKIT_K6_LOGIN_PASSWORD;
const vus = Number(__ENV.K6_VUS || 4);
const targetRps = Number(__ENV.K6_TARGET_RPS || 0.8);
const loginStaggerSeconds = Number(__ENV.K6_LOGIN_STAGGER_SECONDS || 4);
const pacingSeconds = vus / targetRps;

let accessToken;
let refreshToken;
let csrfToken;
let authenticated = false;
let initialLoginAttempted = false;

export const options = {
  vus,
  duration: __ENV.K6_DURATION || '1m',
  thresholds: {
    checks: ['rate>0.99'],
    http_req_failed: ['rate<0.01'],
    'http_req_duration{endpoint:login}': ['p(95)<1200'],
    'http_req_duration{endpoint:refresh}': ['p(95)<300'],
    'http_req_duration{endpoint:introspection}': ['p(95)<300'],
    'http_req_duration{endpoint:sessions}': ['p(95)<400'],
  },
};

function requireConfiguration() {
  if (!email || !password || !introspectionUrl || !workerToken) {
    throw new Error('AUTHKIT_K6_LOGIN_EMAIL, AUTHKIT_K6_LOGIN_PASSWORD, AUTHKIT_INTROSPECTION_URL and AUTHKIT_WORKER_TOKEN are required');
  }
  if (!Number.isFinite(vus) || vus < 1 || !Number.isFinite(targetRps) || targetRps <= 0
      || !Number.isFinite(loginStaggerSeconds) || loginStaggerSeconds < 0) {
    throw new Error('K6_VUS must be >= 1, K6_TARGET_RPS must be > 0, and K6_LOGIN_STAGGER_SECONDS must be >= 0');
  }
}

function login() {
  const response = http.post(`${baseUrl}/api/v1/auth/login`, JSON.stringify({ email, password }), {
    headers: { 'Content-Type': 'application/json' },
    tags: { flow: 'mixed-auth', endpoint: 'login' },
  });
  const responseRefreshCookie = response.cookies['Refresh-Token'] && response.cookies['Refresh-Token'][0];
  const responseCsrfCookie = response.cookies['XSRF-TOKEN'] && response.cookies['XSRF-TOKEN'][0];
  refreshToken = responseRefreshCookie ? responseRefreshCookie.value : undefined;
  csrfToken = responseCsrfCookie ? responseCsrfCookie.value : undefined;
  const passed = check(response, {
    'login status is 200': r => r.status === 200,
    'login returns access token': r => Boolean(r.json('data.accessToken')),
    'login returns refresh cookie': () => Boolean(refreshToken),
    'login returns CSRF cookie': () => Boolean(csrfToken),
  });
  if (!passed) {
    authenticated = false;
    return;
  }
  accessToken = response.json('data.accessToken');
  authenticated = true;
}

function refresh() {
  if (!refreshToken || !csrfToken) {
    authenticated = false;
    check(null, { 'refresh has CSRF cookie': () => false });
    return;
  }
  const response = http.post(`${baseUrl}/api/v1/auth/refresh`, null, {
    headers: {
      'Cookie': `Refresh-Token=${refreshToken}; XSRF-TOKEN=${csrfToken}`,
      'X-XSRF-TOKEN': csrfToken,
    },
    tags: { flow: 'mixed-auth', endpoint: 'refresh' },
  });
  const passed = check(response, {
    'refresh status is 200': r => r.status === 200,
    'refresh returns rotated access token': r => Boolean(r.json('data.accessToken')),
  });
  if (!passed) {
    authenticated = false;
    return;
  }
  accessToken = response.json('data.accessToken');
  const rotatedRefresh = response.cookies['Refresh-Token'] && response.cookies['Refresh-Token'][0];
  const rotatedCsrf = response.cookies['XSRF-TOKEN'] && response.cookies['XSRF-TOKEN'][0];
  if (rotatedRefresh) {
    refreshToken = rotatedRefresh.value;
  }
  if (rotatedCsrf) {
    csrfToken = rotatedCsrf.value;
  }
}

function listSessions() {
  const response = http.get(`${baseUrl}/api/v1/users/me/sessions?limit=20`, {
    headers: { Authorization: `Bearer ${accessToken}` },
    tags: { flow: 'mixed-auth', endpoint: 'sessions' },
  });
  check(response, { 'session listing status is 200': r => r.status === 200 });
}

function introspect() {
  const response = http.post(introspectionUrl, JSON.stringify({ token: accessToken }), {
    headers: {
      'Content-Type': 'application/json',
      'X-Worker-Token': workerToken,
    },
    tags: { flow: 'mixed-auth', endpoint: 'introspection' },
  });
  check(response, {
    'introspection status is 200': r => r.status === 200,
    'introspection reports active token': r => r.json('data.active') === true,
  });
}

function health() {
  const response = http.get(`${baseUrl}/actuator/health`, {
    tags: { flow: 'mixed-auth', endpoint: 'health' },
  });
  check(response, { 'health status is 200': r => r.status === 200 });
}

export default function () {
  requireConfiguration();
  if (!authenticated) {
    if (!initialLoginAttempted) {
      sleep((__VU - 1) * loginStaggerSeconds);
      initialLoginAttempted = true;
    }
    login();
    sleep(pacingSeconds);
    return;
  }

  switch (__ITER % 4) {
    case 0:
      refresh();
      break;
    case 1:
      listSessions();
      break;
    case 2:
      introspect();
      break;
    default:
      health();
  }
  sleep(pacingSeconds);
}
