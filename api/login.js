// /api/login.js
// POST { email, password }  -> sets bb_auth HttpOnly cookie if allow-listed + password matches

const crypto = require('crypto');

const ORIGIN      = process.env.SITE_ORIGIN || 'https://YOUR-USER.github.io';
const AUTH_SECRET = process.env.AUTH_SECRET;          // required
const ADMIN_PASS  = process.env.ADMIN_PASS;           // required (shared password)
const ADMIN_EMAILS= process.env.ADMIN_EMAILS || '';   // comma-separated list

const COOKIE_NAME = 'bb_auth';
const COOKIE_MAX_AGE = 60 * 60 * 24; // 24h in seconds
const JWT_ISSUER  = 'BugBox-Admin';

function cors(res){
  res.setHeader('Access-Control-Allow-Origin', ORIGIN);
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Headers', 'content-type');
  res.setHeader('Access-Control-Allow-Methods', 'POST,OPTIONS');
}

function b64url(input){
  return Buffer.from(input).toString('base64')
    .replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');
}

function signJWT(payload, secret){
  const header = { alg:'HS256', typ:'JWT' };
  const encHeader = b64url(JSON.stringify(header));
  const encPayload= b64url(JSON.stringify(payload));
  const data = `${encHeader}.${encPayload}`;
  const sig = crypto.createHmac('sha256', secret).update(data).digest('base64')
    .replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');
  return `${data}.${sig}`;
}

function safeEqual(a, b){
  const A = Buffer.from(String(a) || '');
  const B = Buffer.from(String(b) || '');
  if (A.length !== B.length) return false;
  return crypto.timingSafeEqual(A, B);
}

function setAuthCookie(res, token){
  const cookie = [
    `${COOKIE_NAME}=${encodeURIComponent(token)}`,
    `HttpOnly`,
    `Secure`,
    `SameSite=None`,
    `Path=/`,
    `Max-Age=${COOKIE_MAX_AGE}`
  ].join('; ');
  res.setHeader('Set-Cookie', cookie);
}

module.exports = async (req, res) => {
  cors(res);
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  if (!AUTH_SECRET || !ADMIN_PASS) {
    return res.status(500).json({ error: 'Server not configured (missing AUTH_SECRET or ADMIN_PASS)' });
  }

  try {
    let body = req.body;
    if (!body || typeof body === 'string') {
      try { body = JSON.parse(body || '{}'); } catch { body = {}; }
    }
    const email = String(body.email || '').trim().toLowerCase();
    const password = String(body.password || '');

    // allow-list check
    const allowList = ADMIN_EMAILS.split(',')
      .map(e => e.trim().toLowerCase())
      .filter(Boolean);

    if (!email || !allowList.includes(email)) {
      return res.status(401).json({ error: 'Unauthorized (email not allowed)' });
    }

    // password check (constant-time)
    if (!safeEqual(password, ADMIN_PASS)) {
      return res.status(401).json({ error: 'Unauthorized (invalid credentials)' });
    }

    // issue JWT (24h)
    const now = Math.floor(Date.now()/1000);
    const payload = {
      sub: email,
      role: 'admin',
      iat: now,
      nbf: now,
      exp: now + COOKIE_MAX_AGE,
      iss: JWT_ISSUER
    };
    const token = signJWT(payload, AUTH_SECRET);

    setAuthCookie(res, token);
    return res.status(200).json({ ok: true, user: { email, role: 'admin' } });
  } catch (e) {
    return res.status(500).json({ error: e.message || 'Internal error' });
  }
};
