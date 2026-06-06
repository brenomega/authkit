import http from 'k6/http';
import { check, sleep } from 'k6';

const baseUrl = __ENV.AUTHKIT_BASE_URL || 'http://localhost:8080';
const token = __ENV.AUTHKIT_OAUTH_ACCESS_TOKEN;
const clientId = __ENV.AUTHKIT_OAUTH_CLIENT_ID;
const clientSecret = __ENV.AUTHKIT_OAUTH_CLIENT_SECRET || '';

export const options = {
  vus: Number(__ENV.K6_VUS || 2),
  duration: __ENV.K6_DURATION || '30s',
  thresholds: {
    http_req_failed: ['rate<0.02'],
    'http_req_duration{flow:oauth-introspection}': ['p(95)<500'],
  },
};

export default function () {
  if (!token || !clientId) {
    throw new Error('AUTHKIT_OAUTH_ACCESS_TOKEN and AUTHKIT_OAUTH_CLIENT_ID are required');
  }
  const response = http.post(`${baseUrl}/oauth2/introspect`, {
    token,
    token_type_hint: 'access_token',
    client_id: clientId,
    client_secret: clientSecret,
  }, {
    tags: { flow: 'oauth-introspection', endpoint: 'introspect' },
  });
  check(response, { 'introspection succeeds': r => r.status === 200 });
  sleep(1);
}
