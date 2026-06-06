import http from 'k6/http';
import { check, sleep } from 'k6';

const baseUrl = __ENV.AUTHKIT_BASE_URL || 'http://localhost:8080';
const email = __ENV.AUTHKIT_K6_MFA_EMAIL;
const password = __ENV.AUTHKIT_K6_MFA_PASSWORD;

export const options = {
  vus: Number(__ENV.K6_VUS || 1),
  duration: __ENV.K6_DURATION || '30s',
  thresholds: {
    http_req_failed: ['rate<0.05'],
    'http_req_duration{flow:mfa-login}': ['p(95)<1500'],
  },
};

export default function () {
  if (!email || !password) {
    throw new Error('AUTHKIT_K6_MFA_EMAIL and AUTHKIT_K6_MFA_PASSWORD are required');
  }
  const response = http.post(`${baseUrl}/api/v1/auth/login`, JSON.stringify({ email, password }), {
    headers: { 'Content-Type': 'application/json' },
    tags: { flow: 'mfa-login', endpoint: 'login' },
  });
  check(response, { 'MFA login challenged or completed': r => r.status === 200 || r.status === 403 });
  sleep(1);
}
