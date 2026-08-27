import http from 'k6/http';
import { check, sleep } from 'k6';
import { Counter } from 'k6/metrics';

const baseUrl = __ENV.AUTHKIT_BASE_URL || 'http://localhost:8080';
const email = __ENV.AUTHKIT_K6_LOGIN_EMAIL;
const password = __ENV.AUTHKIT_K6_LOGIN_PASSWORD;
const accessToken = __ENV.AUTHKIT_ACCESS_TOKEN;
const loginThrottled = new Counter('auth_login_throttled');

export const options = {
  vus: Number(__ENV.K6_VUS || 3),
  duration: __ENV.K6_DURATION || '1m',
  thresholds: {
    http_req_failed: ['rate<0.03'],
    http_req_duration: ['p(95)<1200'],
  },
};

export default function () {
  const choice = Math.random();
  if (choice < 0.4 && email && password) {
    const login = http.post(`${baseUrl}/api/v1/auth/login`, JSON.stringify({ email, password }), {
      headers: { 'Content-Type': 'application/json' },
      tags: { flow: 'mixed-auth', endpoint: 'login' },
      responseCallback: http.expectedStatuses(200, 403, 429),
    });
    if (login.status === 429) {
      loginThrottled.add(1);
    }
    check(login, { 'login status contractually handled': r => r.status === 200 || r.status === 403 || r.status === 429 });
  } else if (choice < 0.7 && accessToken) {
    const me = http.get(`${baseUrl}/api/v1/users/me`, {
      headers: { Authorization: `Bearer ${accessToken}` },
      tags: { flow: 'mixed-auth', endpoint: 'me' },
    });
    check(me, { 'me status is 200': r => r.status === 200 });
  } else {
    const health = http.get(`${baseUrl}/actuator/health`, {
      tags: { flow: 'mixed-auth', endpoint: 'health' },
    });
    check(health, { 'health status is 200': r => r.status === 200 });
  }
  sleep(1);
}
