# AppAholic — Setup (Rebuild v2)

This is a full rewrite: new design system, real database via Supabase, signed
sessions, and a real (non-fake) dashboard. Follow these steps in order —
each one depends on the last.

## 1. Create the Supabase project (you're already doing this)

Once created, go to **Project Settings → API** and copy two values:
- **Project URL** → `SUPABASE_URL`
- **service_role key** (NOT the `anon` key — this one is secret, server-only) → `SUPABASE_SERVICE_ROLE_KEY`

## 2. Run the schema

In your Supabase project: **SQL Editor → New query**, paste the entire
contents of `supabase_schema.sql` (in this zip's root), and run it. This
creates all tables (profiles, apps, purchases, downloads, app_requests,
contact_messages), sets up Row Level Security, and seeds the 15-app catalogue.

Safe to re-run if you need to — it uses `IF NOT EXISTS` / `ON CONFLICT DO NOTHING`
throughout.

## 3. Enable Google OAuth as a Supabase provider — NOT required

This rebuild keeps your **existing** custom Google OAuth flow (the one using
`GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` / `GOOGLE_CALLBACK_URL` you
already have set in Vercel). Supabase is used only as the database here, not
as the auth provider — so there's nothing to configure in Supabase's Auth
settings, and no new redirect URI to add in Google Cloud Console. Your
existing Google Cloud Console redirect URI configuration is unchanged.

## 4. Add two new env vars to your **server** Vercel project

Everything you've already set (`GMAIL_USER`, `GMAIL_APP_PASSWORD`,
`GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `GOOGLE_CALLBACK_URL`,
`SESSION_SECRET`, `ADMIN_EMAIL`, `SITE_URL`, `ALLOWED_ORIGIN`) is reused
as-is — nothing to change there. Add these two:

```
SUPABASE_URL=https://xxxxxxxxxxxx.supabase.co
SUPABASE_SERVICE_ROLE_KEY=eyJ...   (the service_role key, not anon)
```

Set both for **Production and Preview**, same as your other variables.

## 5. Delete the old repo contents, push everything in this zip

Structure:
```
/                     → frontend (root Vercel project)
/server               → API (separate Vercel project, Root Directory = server)
/assets               → shared theme.css + app.js — every page links these
supabase_schema.sql   → run once in Supabase SQL Editor
```

## 6. Redeploy both Vercel projects

## 7. Verify

Visit `https://api.appaholic.justservices.pro/api/health` — you should see:
```json
{"ok":true,"smtp":true,"oauth":true,"database":true,"session":true}
```
If any of those four are `false`, that tells you exactly which env var is
still missing on the server project.

Then test the real flow: sign in with Google on `/auth` → should land on
`/dashboard` showing an empty state (no fake data) → submit a request on
`/request` → check it appears in Supabase under `app_requests`.

## 8. Set up file storage for app downloads (when you're ready to upload the first real app)

Desktop/Mobile apps need actual installer files hosted somewhere. This uses
Supabase Storage — same account, same dashboard, no new service.

1. Supabase dashboard → **Storage** (left sidebar) → **New bucket**
2. Name it exactly: `app-files`
3. **Leave it Private** (do NOT make it public) — downloads are only ever
   handed out through `/api/download/:appId`, which checks the person
   actually owns the app first, then generates a link that expires in 5
   minutes. A public bucket would skip that check entirely.
4. Upload each app's installer under a path matching its app ID, e.g.
   `focusdesk/FocusDesk-Setup-v1.2.exe`
5. In the `apps` table (Table Editor), set that app's `storage_path` column
   to the exact path you uploaded to, e.g. `focusdesk/FocusDesk-Setup-v1.2.exe`

For **Web apps** (no file — just a running page), set `launch_url` instead:
either an internal path like `/invoicekit` if it's built into this project,
or a full external URL if it lives elsewhere.

---

## What changed architecturally


- **Sessions**: the old base64 "session" (unsigned, anyone could forge it)
  is replaced with a real signed JWT using `SESSION_SECRET` — the variable
  you already had set but the old code never actually used.
- **Dashboard**: no more hardcoded demo data. It calls `/api/dashboard`
  with your session token and renders real purchases/downloads/requests
  from Supabase, with proper empty states for new users.
- **Marketplace**: apps are now rows in Supabase (`apps` table), fetched via
  `/api/apps`, instead of a hardcoded array duplicated across files.
- **Design**: new "stockroom ledger" visual system — warm paper background,
  ink-navy, ochre accents, Fraunces/Work Sans/IBM Plex Mono — replacing the
  old near-black/acid-green look, shared via `/assets/theme.css` and
  `/assets/app.js` instead of being copy-pasted into every page.

## Pages included in this pass

Rebuilt: `index`, `auth`, `dashboard`, `marketplace`, `request`, `contact`,
`offline`, plus the full server and schema.

**Not yet rebuilt in the new design**: `about`, `privacy`, `terms`,
`invoicekit`, `admin`. Say the word and I'll continue through these next —
flagging this explicitly rather than quietly shipping old-styled pages
alongside the new ones.
