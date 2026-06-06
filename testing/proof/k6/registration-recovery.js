import http from 'k6/http';
import { check, sleep } from 'k6';

const baseUrl = __ENV.AUTHKIT_BASE_URL || 'http://localhost:8080';

export const options = {
  vus: Number(__ENV.K6_VUS || 1),
  duration: __ENV.K6_DURATION || '30s',
  thresholds: {
    http_req_failed: ['rate<0.05'],
    'http_req_duration{flow:registration-recovery}': ['p(95)<1500'],
  },
};

function uniqueEmail() {
  return `k6-${Date.now()}-${Math.floor(Math.random() * 1000000)}@example.test`;
}

export default function () {
  const email = uniqueEmail();
  const password = `AuthKit-K6-${Date.now()}!Long`;
  const register = http.post(`${baseUrl}/api/v1/auth/register`, JSON.stringify({
    email,
    password,
    termsAccepted: true,
    privacyPolicyAccepted: true,
  }), {
    headers: { 'Content-Type': 'application/json' },
    tags: { flow: 'registration-recovery', endpoint: 'register' },
  });
  check(register, { 'register accepted or created': r => r.status === 201 || r.status === 202 });

  const recovery = http.post(`${baseUrl}/api/v1/auth/password-recovery/request`, JSON.stringify({ email }), {
    headers: { 'Content-Type': 'application/json' },
    tags: { flow: 'registration-recovery', endpoint: 'recovery-request' },
  });
  check(recovery, { 'recovery request is opaque success': r => r.status === 200 });
  sleep(1);
}
