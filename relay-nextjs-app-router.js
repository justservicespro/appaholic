// FILE PATH: app/api/webhook/route.js
// Add this exact file at this exact path in the justservices.pro repo.
// Next.js (App Router) auto-detects any route.js file under app/api/ as an endpoint —
// no registration, no import elsewhere needed. Commit + push to main, Vercel deploys it.

export async function POST(request) {
  const body = await request.json();
  const verifHash = request.headers.get('verif-hash');

  // Route by tx_ref prefix. Add more products here the same way as they come online.
  const routes = [
    { prefix: 'AAH-', url: 'https://api.appaholic.justservices.pro/api/webhook' },
    // { prefix: 'XYZ-', url: 'https://api.otherproduct.justservices.pro/api/webhook' },
  ];

  const txRef = body?.data?.tx_ref;
  const match = routes.find((r) => txRef && txRef.startsWith(r.prefix));

  if (match) {
    // Forward in the background — don't make Flutterwave wait on the downstream call.
    fetch(match.url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'verif-hash': verifHash || '',
      },
      body: JSON.stringify(body),
    }).catch((err) => console.error('Webhook relay to', match.url, 'failed:', err.message));
  } else {
    console.log('Webhook: no matching product for tx_ref', txRef);
  }

  // Acknowledge immediately regardless — Flutterwave retries aggressively on non-200s.
  return Response.json({ ok: true });
}
