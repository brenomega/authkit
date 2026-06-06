import http from 'k6/http';
import { check, sleep } from 'k6';

const baseUrl = __ENV.AUTHKIT_BASE_URL || 'http://localhost:8080';
const accessToken = __ENV.AUTHKIT_ACCESS_TOKEN;

export const options = {
  vus: Number(__ENV.K6_VUS || 2),
  duration: __ENV.K6_DURATION || '30s',
  thresholds: {
    http_req_failed: ['rate<0.02'],
    'http_req_duration{flow:session-pagination}': ['p(95)<500'],
  },
};

export default function () {
  if (!accessToken) {
    throw new Error('AUTHKIT_ACCESS_TOKEN is required');
  }
  const response = http.get(`${baseUrl}/api/v1/users/me/sessions?limit=${__ENV.K6_SESSION_LIMIT || 50}`, {
    headers: { Authorization: `Bearer ${accessToken}` },
    tags: { flow: 'session-pagination', endpoint: 'sessions' },
  });
  check(response, { 'session page is 200': r => r.status === 200 });
  sleep(1);
}
