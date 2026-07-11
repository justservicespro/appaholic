# Flutterwave Webhook Relay

Your Flutterwave account is shared across multiple JustServicesPro products,
and Flutterwave only allows **one** webhook URL per account. That URL is:

```
https://justservices.pro/api/webhook
```

This file is code to add **in the `justservices.pro` project** (not this
AppAholic repo) — a thin relay that inspects every incoming Flutterwave event
and forwards only AppAholic's events to AppAholic's own webhook, unmodified.

## How it identifies AppAholic's events

Every transaction AppAholic creates has a `tx_ref` starting with `AAH-`
(e.g. `AAH-SUB-pro-1720000000-x7k2p9`, `AAH-PUR-invoicekit-...`). The relay
checks that prefix and forwards matching events — nothing else needs to know
about AppAholic's internals.

## The relay code (Express — adapt to whatever justservices.pro runs on)

```javascript
// Add this route to the justservices.pro server. If justservices.pro isn't
// Express, the logic is the same regardless of framework: read the raw body,
// check tx_ref prefix, forward with headers intact.

app.post('/api/webhook', express.json(), async (req, res) => {
  // Acknowledge immediately — Flutterwave retries aggressively if this is slow.
  res.status(200).json({ ok: true });

  const txRef = req.body && req.body.data && req.body.data.tx_ref;
  const verifHash = req.headers['verif-hash'];

  // Route by prefix. Add more products here the same way as they come online.
  const routes = [
    { prefix: 'AAH-', url: 'https://api.appaholic.justservices.pro/api/webhook' },
    // { prefix: 'XYZ-', url: 'https://api.otherproduct.justservices.pro/api/webhook' },
  ];

  const match = routes.find(r => txRef && txRef.startsWith(r.prefix));
  if (!match) {
    console.log('Webhook: no matching product for tx_ref', txRef);
    return;
  }

  try {
    await fetch(match.url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'verif-hash': verifHash || '', // forward unchanged — the receiving product verifies this itself
      },
      body: JSON.stringify(req.body),
    });
  } catch (err) {
    console.error('Webhook relay to', match.url, 'failed:', err.message);
    // Consider logging this to a monitoring channel — a failed relay means a
    // payment succeeded but the downstream product never found out.
  }
});
```

## Setup checklist

1. Add the route above to the `justservices.pro` project, deploy it.
2. In Flutterwave Dashboard → Settings → Webhooks:
   - Webhook URL: `https://justservices.pro/api/webhook` (unchanged — this is already what's registered)
   - Secret Hash: pick a value, save it there
3. Set that **same** Secret Hash value as `FLW_WEBHOOK_SECRET_HASH` in **this** AppAholic server project's env vars (Vercel → `appaholiclive` → Environment Variables). The relay forwards Flutterwave's original `verif-hash` header through untouched, so AppAholic's own verification (which checks that header against `FLW_WEBHOOK_SECRET_HASH`) works without any further change.
4. Test: make a small real or sandbox subscription/purchase on AppAholic, confirm a row appears in Supabase (`subscriptions` or `purchases` table) and a confirmation email arrives.

## Why forward rather than have the relay do the work directly

Keeping the relay "dumb" (route by prefix, forward untouched) means AppAholic's
webhook logic, database access, and email sending all stay inside the
AppAholic project. The central relay never needs Supabase credentials, email
credentials, or any product-specific logic — it only needs to know URL
prefixes. Adding a new product later means adding one line to the `routes`
array, nothing else.
