const BASE = import.meta.env.VITE_API_URL || 'http://localhost:3001';

let token = localStorage.getItem('nfc_token') || '';

export function setToken(t) {
  token = t;
  localStorage.setItem('nfc_token', t);
}

export function clearToken() {
  token = '';
  localStorage.removeItem('nfc_token');
}

export function hasToken() { return !!token; }

async function req(method, path, body) {
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {})
    },
    body: body ? JSON.stringify(body) : undefined
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Request failed');
  return data;
}

export const api = {
  login: (passphrase) => req('POST', '/api/auth/token', { passphrase }),
  health: () => req('GET', '/api/health'),
  metrics: () => req('GET', '/api/metrics'),
  validUids: () => req('GET', '/api/metrics/valid-uids'),
  scans: (params = {}) => {
    const q = new URLSearchParams(params).toString();
    return req('GET', `/api/scans${q ? '?' + q : ''}`);
  },
  attacks: (params = {}) => {
    const q = new URLSearchParams(params).toString();
    return req('GET', `/api/attacks${q ? '?' + q : ''}`);
  },
};
