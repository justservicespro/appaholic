// FILE PATH: pages/api/webhook.js
// Add this exact file at this exact path in the justservices.pro repo.
// Next.js (Pages Router) auto-detects any file under pages/api/ as an endpoint —
// no registration, no import elsewhere needed. Commit + push to main, Vercel deploys it.

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ ok: false });

  const body = req.body;
  const verifHash = req.headers['verif-hash'];

  // Route by tx_ref prefix. Add more products here the same way as they come online.
  const routes = [
    { prefix: 'AAH-', url: 'https://api.appaholic.justservices.pro/api/webhook' },
    // { prefix: 'XYZ-', url: 'https://api.otherproduct.justservices.pro/api/webhook' },
  ];

  const txRef = body?.data?.tx_ref;
  const match = routes.find((r) => txRef && txRef.startsWith(r.prefix));

  // Acknowledge immediately — Flutterwave retries aggressively on non-200s.
  res.status(200).json({ ok: true });

  if (match) {
    try {
      await fetch(match.url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'verif-hash': verifHash || '',
        },
        body: JSON.stringify(body),
      });
    } catch (err) {
      console.error('Webhook relay to', match.url, 'failed:', err.message);
    }
  } else {
    console.log('Webhook: no matching product for tx_ref', txRef);
  }
}
