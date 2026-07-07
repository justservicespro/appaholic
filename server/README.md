# AppAholic Server — Deploy Guide

## Structure

```
appaholic.justservices.pro        →  HTML pages     (deploy repo root as Project 1)
api.appaholic.justservices.pro    →  this /server   (deploy /server as Project 2)
```

---

## Deploy Project 2 (the server)

In Vercel dashboard → **Add New Project** → import same GitHub repo →
**Root Directory: set to `server`** → Deploy.

Then in that project → **Settings → Domains** → add `api.appaholic.justservices.pro`.
Vercel shows you a CNAME — add it in your DNS exactly like you did for appaholic.justservices.pro.

That's it. Your server is live at `https://api.appaholic.justservices.pro`.

---

## Environment Variables (server project only)

In Vercel → server project → **Settings → Environment Variables**:

| Variable | Value |
|---|---|
| `GMAIL_USER` | `info@justservices.pro` |
| `GMAIL_APP_PASSWORD` | 16-char App Password from myaccount.google.com/apppasswords |
| `ADMIN_EMAIL` | `info@justservices.pro` |
| `SITE_URL` | `https://appaholic.justservices.pro` |
| `ALLOWED_ORIGIN` | `https://appaholic.justservices.pro` |
| `GOOGLE_CLIENT_ID` | already saved on Vercel — copy to this project too |
| `GOOGLE_CLIENT_SECRET` | already saved on Vercel — copy to this project too |
| `GOOGLE_CALLBACK_URL` | `https://api.appaholic.justservices.pro/auth/google/callback` |
| `SESSION_SECRET` | run `openssl rand -hex 32`, paste result |
| `FLUTTERWAVE_SECRET_KEY` | from Flutterwave dashboard |

---

## Google Cloud Console — one-time addition

Go to your OAuth credential → **Authorised redirect URIs** → add:
```
https://api.appaholic.justservices.pro/auth/google/callback
```

---

## Verify it works

```
https://api.appaholic.justservices.pro/api/health
```
Should return: `{ "ok": true, "smtp": true, "oauth": true }`

---

## How OAuth flows end-to-end

```
User clicks "Continue with Google" on appaholic.justservices.pro/auth
  ↓
Browser → GET https://api.appaholic.justservices.pro/auth/google
  ↓
Server redirects to accounts.google.com consent screen
  ↓
User approves → Google redirects to:
  https://api.appaholic.justservices.pro/auth/google/callback?code=...
  ↓
Server exchanges code → gets name, email, avatar from Google
  ↓
Server redirects to:
  https://appaholic.justservices.pro/dashboard?oauth_session=<token>
  ↓
Frontend decodes token → saves to sessionStorage → nav shows user name
```
