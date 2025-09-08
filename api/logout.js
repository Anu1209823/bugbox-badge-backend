// clears cookie
const ORIGIN = process.env.SITE_ORIGIN || 'https://YOUR-USER.github.io';
module.exports = (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', ORIGIN);
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  // cross-site cookie needs SameSite=None
  res.setHeader('Set-Cookie', 'bb_auth=; HttpOnly; Secure; SameSite=None; Path=/; Max-Age=0');
  res.status(200).json({ok:true});
};
