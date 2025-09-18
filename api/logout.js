// /api/logout.js
// POST -> clears bb_auth cookie

const ORIGIN = process.env.SITE_ORIGIN || 'https://anu1209823.github.io';

function cors(res) {
  res.setHeader('Access-Control-Allow-Origin', ORIGIN);
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Headers', 'content-type');
  res.setHeader('Access-Control-Allow-Methods', 'POST,OPTIONS');
}

module.exports = async (req, res) => {
  cors(res);
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  // expire cookie immediately
  res.setHeader('Set-Cookie', 'bb_auth=; HttpOnly; Secure; SameSite=None; Path=/; Max-Age=0');
  return res.status(200).json({ ok: true });
};
