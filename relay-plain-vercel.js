// FILE PATH: api/webhook.js (at the repo root, or inside whichever folder is set
// as Root Directory for that Vercel project)
//
// Use this version ONLY if justservices.pro does NOT have an app/ or pages/
// folder (i.e. it's plain Node/Express, not Next.js). Vercel auto-detects any
// file under /api as a serverless function regardless of framework.

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ ok: false });

  const body = req.body;
  const verifHash = req.headers['verif-hash'];

  const routes = [
    { prefix: 'AAH-', url: 'https://api.appaholic.justservices.pro/api/webhook' },
    // { prefix: 'XYZ-', url: 'https://api.otherproduct.justservices.pro/api/webhook' },
  ];

  const txRef = body && body.data && body.data.tx_ref;
  const match = routes.find((r) => txRef && txRef.startsWith(r.prefix));

  res.status(200).json({ ok: true }); // acknowledge immediately

  if (match) {
    try {
      await fetch(match.url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'verif-hash': verifHash || '' },
        body: JSON.stringify(body),
      });
    } catch (err) {
      console.error('Webhook relay to', match.url, 'failed:', err.message);
    }
  } else {
    console.log('Webhook: no matching product for tx_ref', txRef);
  }
};
