import http from 'k6/http';
import { check, sleep } from 'k6';

const baseUrl = __ENV.AUTHKIT_BASE_URL || 'http://localhost:8080';
const email = __ENV.AUTHKIT_K6_LOGIN_EMAIL;
const password = __ENV.AUTHKIT_K6_LOGIN_PASSWORD;

export const options = {
  vus: Number(__ENV.K6_VUS || 2),
  duration: __ENV.K6_DURATION || '30s',
  thresholds: {
    http_req_failed: ['rate<0.02'],
    'http_req_duration{flow:login-refresh}': ['p(95)<1000'],
  },
};

export default function () {
  if (!email || !password) {
    throw new Error('AUTHKIT_K6_LOGIN_EMAIL and AUTHKIT_K6_LOGIN_PASSWORD are required');
  }
  const login = http.post(`${baseUrl}/api/v1/auth/login`, JSON.stringify({ email, password }), {
    headers: { 'Content-Type': 'application/json' },
    tags: { flow: 'login-refresh', endpoint: 'login' },
  });
  check(login, { 'login status is 200 or MFA required': r => r.status === 200 || r.status === 403 });
  sleep(1);
}
