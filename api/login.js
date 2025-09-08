// POST {email, password} -> sets httpOnly auth cookie if allowed
const crypto = require('crypto');

const ORIGIN = process.env.SITE_ORIGIN || 'https://YOUR-USER.github.io';
const ADMIN_EMAILS = (process.env.ADMIN_EMAILS || '')
  .split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
const ADMIN_PASS = process.env.ADMIN_PASS;            // set in Vercel
const AUTH_SECRET = process.env.AUTH_SECRET || crypto.randomBytes(32).toString('hex');

function b64url(obj){ return Buffer.from(JSON.stringify(obj)).toString('base64url'); }
function signJWT(payload){
  const header = { alg:'HS256', typ:'JWT' };
  const now = Math.floor(Date.now()/1000);
  const body = { ...payload, iat:now, exp: now + 60*60*8 }; // 8h
  const data = `${b64url(header)}.${b64url(body)}`;
  const sig = crypto.createHmac('sha256', AUTH_SECRET).update(data).digest('base64url');
  return `${data}.${sig}`;
}
function cors(res){
  res.setHeader('Access-Control-Allow-Origin', ORIGIN);
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Headers', 'content-type');
  res.setHeader('Access-Control-Allow-Methods', 'POST,OPTIONS');
}

module.exports = async (req, res) => {
  cors(res);
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({error:'Method not allowed'});
  try{
    let body = req.body;
    if (typeof body === 'string') { try{ body = JSON.parse(body); }catch{ body = {}; } }
    const { email, password } = body || {};
    if (!email || !password) return res.status(400).json({error:'Missing email/password'});
    if (!ADMIN_EMAILS.includes(String(email).toLowerCase())) return res.status(401).json({error:'Not allowed'});
    if (password !== ADMIN_PASS) return res.status(401).json({error:'Invalid credentials'});

    const token = signJWT({ sub: email, role:'admin' });
    // Important: cross-site cookie (github.io -> vercel.app)
    res.setHeader('Set-Cookie',
      `bb_auth=${token}; HttpOnly; Secure; SameSite=None; Path=/; Max-Age=28800`
    );
    return res.status(200).json({ ok:true, email });
  }catch(e){
    return res.status(500).json({error:e.message});
  }
};
