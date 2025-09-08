// POST {name, recipientName, recipientEmail, skills[], description, image?}
// -> creates registry/<uuid>.json + updates registry/registry.json via GitHub API
const crypto = require('crypto');

const ORIGIN = process.env.SITE_ORIGIN || 'https://YOUR-USER.github.io';
const AUTH_SECRET = process.env.AUTH_SECRET;
const GITHUB_TOKEN = process.env.GITHUB_TOKEN;           // PAT with "repo" scope
const GITHUB_OWNER = process.env.GITHUB_OWNER || 'YOUR-USER';
const GITHUB_REPO  = process.env.GITHUB_REPO  || 'digital-badge-system';
const GITHUB_BRANCH= process.env.GITHUB_BRANCH|| 'main';
const SITE_BASE    = process.env.SITE_BASE    || `https://${GITHUB_OWNER}.github.io/${GITHUB_REPO}/site/`;

function cors(res){
  res.setHeader('Access-Control-Allow-Origin', ORIGIN);
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Headers', 'content-type');
  res.setHeader('Access-Control-Allow-Methods', 'POST,OPTIONS');
}
function verifyJWT(token){
  try{
    const [h,p,sig] = (token||'').split('.');
    if(!h||!p||!sig) return null;
    const check = crypto.createHmac('sha256', AUTH_SECRET).update(`${h}.${p}`).digest('base64url');
    if (check !== sig) return null;
    const payload = JSON.parse(Buffer.from(p,'base64url').toString('utf8'));
    if (payload.exp && payload.exp < Math.floor(Date.now()/1000)) return null;
    return payload;
  }catch{ return null; }
}
function uuid(){
  return (crypto.randomUUID && crypto.randomUUID()) ||
         ([1e7]+-1e3+-4e3+-8e3+-1e11).replace(/[018]/g, c =>
           (c ^ crypto.randomBytes(1)[0] & 15 >> c / 4).toString(16));
}
async function ghGet(path){
  const r = await fetch(`https://api.github.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/contents/${path}?ref=${GITHUB_BRANCH}`, {
    headers: { Authorization: `Bearer ${GITHUB_TOKEN}`, 'User-Agent':'bugbox-badge' }
  });
  if (r.status === 404) return null;
  if (!r.ok) throw new Error(`GitHub GET ${path}: ${r.status}`);
  return r.json();
}
async function ghPut(path, contentStr, message, sha){
  const body = {
    message, branch: GITHUB_BRANCH,
    content: Buffer.from(contentStr).toString('base64'),
    ...(sha ? {sha} : {})
  };
  const r = await fetch(`https://api.github.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/contents/${path}`, {
    method:'PUT',
    headers: {
      Authorization: `Bearer ${GITHUB_TOKEN}`,
      'User-Agent':'bugbox-badge',
      'Content-Type':'application/json'
    },
    body: JSON.stringify(body)
  });
  if (!r.ok) {
    const t = await r.text();
    throw new Error(`GitHub PUT ${path}: ${r.status} ${t}`);
  }
  return r.json();
}

module.exports = async (req, res) => {
  cors(res);
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({error:'Method not allowed'});

  try{
    // auth via httpOnly cookie
    const cookie = req.headers.cookie || '';
    const token = (cookie.split(';').find(c=>c.trim().startsWith('bb_auth='))||'').split('=')[1];
    const me = verifyJWT(token);
    if (!me || me.role !== 'admin') return res.status(401).json({error:'Unauthorized'});

    // parse body
    let body = req.body;
    if (typeof body === 'string') { try{ body = JSON.parse(body); }catch{ body = {}; } }
    const id = uuid();
    const issuedOn = new Date().toISOString();
    const skills = Array.isArray(body.skills) ? body.skills
                  : String(body.skills||'').split(',').map(s=>s.trim()).filter(Boolean);
    const verifyUrl = `${SITE_BASE}#id=${id}`;

    const badge = {
      id,
      name: body.name || 'BugBox – Certified Badge',
      description: body.description || '',
      recipient: { name: body.recipientName || '', email: body.recipientEmail || undefined },
      issuer: { name: 'BugBox', website: '' },
      issuedOn,
      skills,
      image: body.image || 'assets/badges/sample.png',
      verifyUrl
    };

    // write per-badge file
    await ghPut(`registry/${id}.json`, JSON.stringify(badge, null, 2), `Add badge ${id} for ${badge.recipient.name || 'Recipient'}`);

    // update registry.json
    let reg = { issuer: {name:'BugBox', website:''}, badges: [] }, sha;
    const existing = await ghGet('registry/registry.json');
    if (existing && existing.content) {
      sha = existing.sha;
      reg = JSON.parse(Buffer.from(existing.content, 'base64').toString('utf8'));
      if (!Array.isArray(reg.badges)) reg.badges = [];
    }
    reg.badges = reg.badges.filter(b => b.id !== id);
    reg.badges.unshift(badge);

    await ghPut('registry/registry.json', JSON.stringify(reg, null, 2), `Update registry with ${id}`, sha);

    return res.status(200).json({ ok:true, id, verifyUrl });
  }catch(e){
    return res.status(500).json({error:e.message});
  }
};
