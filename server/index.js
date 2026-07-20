/**
 * AppAholic — API Server (v2)
 * Auth:    Google OAuth 2.0 (googleapis) — issues a signed JWT session
 * Data:    Supabase (Postgres) — profiles, apps, purchases, downloads, requests, contact
 * Email:   Gmail SMTP via Nodemailer
 *
 * Deploy: Vercel (serverless, entry at /api/index.js) or any Node.js host (npm start)
 */

const express       = require('express');
const cors          = require('cors');
const helmet        = require('helmet');
const rateLimit     = require('express-rate-limit');
const nodemailer    = require('nodemailer');
const jwt           = require('jsonwebtoken');
const { google }    = require('googleapis');
const { createClient } = require('@supabase/supabase-js');
const crypto        = require('crypto');
const multer         = require('multer');
require('dotenv').config();

/* ── ENV VALIDATION ──────────────────────────────────────────────────
   Fail loudly at boot (logs only — never crash a live serverless
   function) so a missing var is obvious in the deploy logs instead of
   surfacing as a vague "can't reach server" in the browser. */
// Accept either naming for the Google OAuth env vars — some dashboards/docs
// use GOOGLE_CLIENT_ID, others GOOGLE_OAUTH_CLIENT_ID. Both work.
const GOOGLE_CLIENT_ID     = process.env.GOOGLE_CLIENT_ID || process.env.GOOGLE_OAUTH_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || process.env.GOOGLE_OAUTH_CLIENT_SECRET;

const REQUIRED = {
  GMAIL_USER: 'Gmail SMTP sending will fail',
  GMAIL_APP_PASSWORD: 'Gmail SMTP sending will fail',
  SESSION_SECRET: 'sessions cannot be signed — auth will be rejected',
  SUPABASE_URL: 'database reads/writes will fail',
  SUPABASE_SERVICE_ROLE_KEY: 'database reads/writes will fail',
};
const missing = Object.keys(REQUIRED).filter(k => !process.env[k]);
if (!GOOGLE_CLIENT_ID) missing.push('GOOGLE_CLIENT_ID'), console.error('❌ Missing GOOGLE_CLIENT_ID (or GOOGLE_OAUTH_CLIENT_ID) — /auth/google will fail');
if (!GOOGLE_CLIENT_SECRET) missing.push('GOOGLE_CLIENT_SECRET'), console.error('❌ Missing GOOGLE_CLIENT_SECRET (or GOOGLE_OAUTH_CLIENT_SECRET) — /auth/google will fail');
missing.forEach(k => REQUIRED[k] && console.error(`❌ Missing env var ${k} — ${REQUIRED[k]}`));

const app = express();

/* ── SECURITY / PARSING MIDDLEWARE ──────────────────────────────────── */
app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false, crossOriginResourcePolicy: { policy: 'cross-origin' } }));
app.use(express.json({ limit: '150kb' }));

const allowedOrigins = process.env.ALLOWED_ORIGIN
  ? process.env.ALLOWED_ORIGIN.split(',').map(s => s.trim())
  : ['https://appaholic.justservices.pro', 'http://localhost:3000'];

app.use(cors({
  origin(origin, cb) { (!origin || allowedOrigins.includes(origin)) ? cb(null, true) : cb(new Error('Not allowed by CORS')); },
  credentials: true,
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

const globalLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 300, standardHeaders: true, legacyHeaders: false });
app.use(globalLimiter);

const strictLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, limit: 20, standardHeaders: true, legacyHeaders: false,
  message: { ok: false, error: 'Too many requests. Please try again later.' },
});

/* ── HELPERS ─────────────────────────────────────────────────────────── */
function esc(v) {
  if (v === undefined || v === null) return '';
  return String(v).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}
function cleanHeader(v) { return String(v || '').replace(/[\r\n]+/g, ' ').trim(); }
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
function isValidEmail(v) { return typeof v === 'string' && EMAIL_RE.test(v) && v.length <= 254; }
function safeUrl(v, fallback) {
  try { const u = new URL(v); if (u.protocol === 'http:' || u.protocol === 'https:') return u.toString(); } catch {}
  return fallback;
}
function asyncRoute(fn) { return (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next); }

/* ── SUPABASE (service role — bypasses RLS, server-trusted only) ────── */
const supabase = (process.env.SUPABASE_URL && process.env.SUPABASE_SERVICE_ROLE_KEY)
  ? createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession: false } })
  : null;

function requireSupabase(res) {
  if (!supabase) { res.status(503).json({ ok: false, error: 'Database not configured yet.' }); return false; }
  return true;
}

/* ── SESSIONS (signed JWT — replaces the old unsigned base64 token) ─── */
const SESSION_SECRET = process.env.SESSION_SECRET || 'insecure-dev-secret-do-not-use-in-production';
function signSession(user) {
  return jwt.sign({ sub: user.id, email: user.email, name: user.name, avatar: user.avatar }, SESSION_SECRET, { expiresIn: '30d' });
}
function verifySession(token) {
  try { return jwt.verify(token, SESSION_SECRET); } catch { return null; }
}
function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  const payload = token && verifySession(token);
  if (!payload) return res.status(401).json({ ok: false, error: 'Not signed in.' });
  req.user = payload;
  next();
}

/* ── ADMIN AUTH — separate from the Google/user session system entirely.
   Email+password, checked against a salted scrypt hash (Node's built-in
   crypto — no extra dependency). Admin JWTs carry role:'admin' and a short
   7-day expiry, verified with the same SESSION_SECRET but never accepted
   by requireAuth's user-facing routes since those don't check for role. ── */
const ADMIN_PANEL_EMAIL = process.env.ADMIN_PANEL_EMAIL;
const ADMIN_PANEL_PASSWORD_HASH = process.env.ADMIN_PANEL_PASSWORD_HASH; // format: "salt:hash"
if (!ADMIN_PANEL_EMAIL || !ADMIN_PANEL_PASSWORD_HASH) console.warn('⚠️  ADMIN_PANEL_EMAIL / ADMIN_PANEL_PASSWORD_HASH not set — admin panel login will always fail.');

function verifyAdminPassword(password) {
  if (!ADMIN_PANEL_PASSWORD_HASH || !password) return false;
  const [salt, storedHash] = ADMIN_PANEL_PASSWORD_HASH.split(':');
  if (!salt || !storedHash) return false;
  const attemptHash = crypto.scryptSync(password, salt, 64).toString('hex');
  const a = Buffer.from(attemptHash, 'hex');
  const b = Buffer.from(storedHash, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b); // constant-time compare — no timing side-channel
}
function signAdminSession(email) {
  return jwt.sign({ role: 'admin', email }, SESSION_SECRET, { expiresIn: '7d' });
}

// General-purpose versions of the same scrypt pattern above, for regular user
// accounts (email/password signup) rather than the single hardcoded admin login.
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}
function verifyPassword(password, stored) {
  if (!stored || !password) return false;
  const [salt, storedHash] = stored.split(':');
  if (!salt || !storedHash) return false;
  const attemptHash = crypto.scryptSync(password, salt, 64).toString('hex');
  const a = Buffer.from(attemptHash, 'hex');
  const b = Buffer.from(storedHash, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function requireAdmin(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  const payload = token && verifySession(token);
  if (!payload || payload.role !== 'admin') return res.status(401).json({ ok: false, error: 'Admin sign-in required.' });
  req.admin = payload;
  next();
}
// Login attempts are rate-limited hard — this endpoint is a real attack target.
const adminLoginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 8, standardHeaders: true, legacyHeaders: false, message: { ok: false, error: 'Too many attempts. Try again later.' } });

/* ── SMTP ────────────────────────────────────────────────────────────── */
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: { user: process.env.GMAIL_USER, pass: process.env.GMAIL_APP_PASSWORD },
});
if (process.env.GMAIL_USER && process.env.GMAIL_APP_PASSWORD) {
  transporter.verify(err => err ? console.error('❌ SMTP verify failed:', err.message) : console.log('✅ SMTP ready via', process.env.GMAIL_USER));
}
const FROM        = `"AppAholic" <${process.env.GMAIL_USER || 'no-reply@justservices.pro'}>`;
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || process.env.GMAIL_USER;
// Admin notifications are CC'd here too — defaults to the sending Gmail account,
// override with ADMIN_EMAIL_CC if you want a different second recipient.
const ADMIN_EMAIL_CC = process.env.ADMIN_EMAIL_CC || process.env.GMAIL_USER;
const SITE_URL    = process.env.SITE_URL || 'https://appaholic.justservices.pro';

/* ── SUBSCRIPTION PLANS (source of truth — frontend fetches this, never hardcodes prices) ── */
const PLANS = {
  free: {
    id: 'free', name: 'Free', tagline: 'Browse and buy one at a time',
    monthly: 0, yearly: 0,
    features: ['Browse the full catalogue', '1 free-tier app download per month', 'Standard 48-hour request review'],
  },
  pro: {
    id: 'pro', name: 'Pro', tagline: 'For freelancers and small teams',
    monthly: 4500, yearly: 45000,
    features: ['Unlimited downloads of any app priced ₦3,000 or under', 'Priority 24-hour request review', '10% off custom app builds', 'Email support'],
  },
  business: {
    id: 'business', name: 'Business', tagline: 'For growing companies',
    monthly: 12000, yearly: 120000,
    features: ['Unlimited downloads — every app, any price', '2 fast-tracked custom requests per month', '15% off additional custom builds', 'Priority WhatsApp support'],
  },
};

/* ── FLUTTERWAVE ─────────────────────────────────────────────────────── */
const FLW_SECRET_KEY = process.env.FLW_SECRET_KEY;
const FLW_PUBLIC_KEY = process.env.FLW_PUBLIC_KEY;
const FLW_WEBHOOK_SECRET_HASH = process.env.FLW_WEBHOOK_SECRET_HASH; // set the SAME value in Flutterwave Dashboard → Settings → Webhooks → Secret Hash
if (!FLW_SECRET_KEY) console.warn('⚠️  FLW_SECRET_KEY not set — subscription checkout will fail.');
if (!FLW_WEBHOOK_SECRET_HASH) console.warn('⚠️  FLW_WEBHOOK_SECRET_HASH not set — webhook events will be rejected for safety.');


async function sendMail({ to, subject, html, replyTo, cc }) {
  return transporter.sendMail({
    from: FROM, to: cleanHeader(to), subject: cleanHeader(subject), html,
    ...(replyTo ? { replyTo: cleanHeader(replyTo) } : {}),
    ...(cc && cc !== to ? { cc: cleanHeader(cc) } : {}),
  });
}

// Shorthand for the admin notification emails — always CC's the second admin address.
function sendAdminMail(opts) { return sendMail({ ...opts, to: ADMIN_EMAIL, cc: ADMIN_EMAIL_CC }); }

function wrapEmail({ preheader = '', title, bodyHtml, ctaText, ctaUrl }) {
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"/></head>
<body style="margin:0;padding:0;background:#F7F4EE;font-family:-apple-system,Segoe UI,Arial,sans-serif;">
  <span style="display:none;max-height:0;overflow:hidden;">${esc(preheader)}</span>
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#F7F4EE;padding:32px 16px;">
    <tr><td align="center">
      <table width="100%" style="max-width:520px;background:#fff;border-radius:12px;overflow:hidden;border:1px solid #D9D2C3;">
        <tr><td style="background:#14213D;padding:26px 32px;">
          <span style="font-size:19px;font-weight:800;color:#fff;letter-spacing:-.5px;">
            <span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:#E8A33D;margin-right:8px;"></span>
            AppAholic
          </span>
        </td></tr>
        <tr><td style="padding:30px 32px;">
          <h1 style="margin:0 0 14px;font-size:19px;font-weight:800;color:#14213D;">${title}</h1>
          <div style="font-size:14px;line-height:1.75;color:#2E2E3E;">${bodyHtml}</div>
          ${ctaText && ctaUrl ? `<div style="margin-top:26px;"><a href="${ctaUrl}" style="display:inline-block;background:#14213D;color:#fff;text-decoration:none;padding:12px 28px;border-radius:8px;font-size:14px;font-weight:700;">${esc(ctaText)}</a></div>` : ''}
        </td></tr>
        <tr><td style="padding:18px 32px;border-top:1px solid #D9D2C3;background:#F7F4EE;font-size:12px;color:#6B6458;line-height:1.6;">
          AppAholic — a product of <strong>JustServicesPro Management and Consulting Ltd</strong><br/>
          <a href="mailto:info@justservices.pro" style="color:#14213D;">info@justservices.pro</a>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body></html>`;
}

/* ── GOOGLE OAUTH CLIENT ─────────────────────────────────────────────── */
const oAuth2Client = new google.auth.OAuth2(
  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET,
  process.env.GOOGLE_CALLBACK_URL || 'https://api.appaholic.justservices.pro/auth/google/callback'
);
const OAUTH_SCOPES = ['https://www.googleapis.com/auth/userinfo.email', 'https://www.googleapis.com/auth/userinfo.profile', 'openid'];

/* ════════════════════════════════════════════════════════════════════
   AUTH ROUTES
   ════════════════════════════════════════════════════════════════════ */

app.get('/auth/google', strictLimiter, (req, res) => {
  if (missing.includes('GOOGLE_CLIENT_ID') || missing.includes('GOOGLE_CLIENT_SECRET')) {
    return res.redirect(`${SITE_URL}/auth?error=oauth_not_configured`);
  }
  const requested = typeof req.query.redirect === 'string' ? req.query.redirect : '';
  const redirectTarget = requested.startsWith(SITE_URL) ? requested : `${SITE_URL}/dashboard`;
  const url = oAuth2Client.generateAuthUrl({ access_type: 'offline', scope: OAUTH_SCOPES, prompt: 'select_account', state: redirectTarget });
  res.redirect(url);
});

app.get('/auth/google/callback', asyncRoute(async (req, res) => {
  const { code, state, error } = req.query;
  if (error || !code) return res.redirect(`${SITE_URL}/auth?error=oauth_denied`);

  try {
    const { tokens } = await oAuth2Client.getToken(code);
    oAuth2Client.setCredentials(tokens);
    const oauth2 = google.oauth2({ version: 'v2', auth: oAuth2Client });
    const { data: profile } = await oauth2.userinfo.get();

    const user = {
      id: profile.id, email: profile.email, name: profile.name,
      firstName: profile.given_name, lastName: profile.family_name,
      avatar: profile.picture, verified: profile.verified_email,
    };

    // Persist to Supabase — upsert by email so repeat sign-ins update the same row.
    let dbUserId = user.id;
    if (supabase) {
      const { data: existing } = await supabase.from('profiles').select('id').eq('email', user.email).maybeSingle();
      if (existing) {
        dbUserId = existing.id;
        await supabase.from('profiles').update({ full_name: user.name, avatar_url: user.avatar }).eq('id', dbUserId);
      } else {
        const { data: inserted, error: insertErr } = await supabase.from('profiles')
          .insert({ id: crypto.randomUUID(), email: user.email, full_name: user.name, avatar_url: user.avatar, provider: 'google' })
          .select('id').single();
        if (!insertErr && inserted) dbUserId = inserted.id;
      }
    }

    const session = signSession({ id: dbUserId, email: user.email, name: user.name, avatar: user.avatar });

    sendMail({
      to: user.email,
      subject: `Welcome to AppAholic, ${user.firstName || 'there'}!`,
      html: wrapEmail({
        preheader: 'Your AppAholic account is ready.',
        title: `Welcome, ${esc(user.firstName || 'there')}! 🎉`,
        bodyHtml: `<p>You signed in with Google. Browse Web, Desktop and Mobile apps whenever you like.</p>`,
        ctaText: 'Go to My Dashboard', ctaUrl: `${SITE_URL}/dashboard`,
      }),
    }).catch(e => console.warn('Welcome email failed (non-fatal):', e.message));

    sendAdminMail({
      
      subject: `New Google sign-in: ${cleanHeader(user.email)}`,
      html: wrapEmail({ title: 'New Google Sign-In', bodyHtml: `<p><strong>${esc(user.name)}</strong> (${esc(user.email)}) just signed in.</p>` }),
    }).catch(e => console.warn('Admin alert failed (non-fatal):', e.message));

    const redirectTo = state && String(state).startsWith(SITE_URL) ? state : `${SITE_URL}/dashboard`;
    res.redirect(`${redirectTo}?session=${encodeURIComponent(session)}`);
  } catch (err) {
    console.error('OAuth callback error:', err.message);
    res.redirect(`${SITE_URL}/auth?error=oauth_failed`);
  }
}));

// GET /auth/me — verify the current session token and return the live profile from Supabase.
app.get('/auth/me', requireAuth, asyncRoute(async (req, res) => {
  if (!supabase) return res.json({ ok: true, user: req.user });
  const { data, error } = await supabase.from('profiles').select('id, email, full_name, avatar_url').eq('id', req.user.sub).maybeSingle();
  if (error || !data) return res.json({ ok: true, user: req.user });
  res.json({ ok: true, user: { id: data.id, email: data.email, name: data.full_name, avatar: data.avatar_url } });
}));

app.post('/auth/logout', (req, res) => res.json({ ok: true }));

/* ════════════════════════════════════════════════════════════════════
   EMAIL / PASSWORD AUTH — alternative to Google OAuth. Issues the same
   kind of signed session JWT either way, so every other route (dashboard,
   downloads, purchases, etc.) works identically regardless of how someone
   signed in.
   ════════════════════════════════════════════════════════════════════ */

app.post('/auth/signup', strictLimiter, asyncRoute(async (req, res) => {
  if (!requireSupabase(res)) return;
  const { name, email, password } = req.body || {};
  if (!name || !email || !password) return res.status(400).json({ ok: false, error: 'Name, email and password are all required.' });
  if (!isValidEmail(email)) return res.status(400).json({ ok: false, error: 'Invalid email address.' });
  if (String(password).length < 8) return res.status(400).json({ ok: false, error: 'Password must be at least 8 characters.' });

  const { data: existing } = await supabase.from('profiles').select('id, provider').ilike('email', email).maybeSingle();
  if (existing) {
    const msg = existing.provider === 'google' ? 'This email is already registered via Google — use "Continue with Google" instead.' : 'An account with this email already exists. Try signing in.';
    return res.status(409).json({ ok: false, error: msg });
  }

  const { data: profile, error } = await supabase.from('profiles')
    .insert({ id: crypto.randomUUID(), email, full_name: name, provider: 'email', password_hash: hashPassword(password) })
    .select('id, email, full_name').single();
  if (error) { console.error('signup insert failed:', error.message); return res.status(500).json({ ok: false, error: 'Could not create your account. Please try again.' }); }

  const session = signSession({ id: profile.id, email: profile.email, name: profile.full_name, avatar: null });

  sendMail({
    to: email, subject: `Welcome to AppAholic, ${name.split(' ')[0]}!`,
    html: wrapEmail({
      preheader: 'Your AppAholic account is ready.',
      title: `Welcome, ${esc(name.split(' ')[0])}! 🎉`,
      bodyHtml: `<p>Your account is ready. Browse Web, Desktop and Mobile apps whenever you like.</p>`,
      ctaText: 'Go to My Dashboard', ctaUrl: `${SITE_URL}/dashboard`,
    }),
  }).catch(e => console.warn('Welcome email failed (non-fatal):', e.message));
  sendAdminMail({
    subject: `New signup: ${cleanHeader(email)}`,
    html: wrapEmail({ title: 'New Signup', bodyHtml: `<p><strong>${esc(name)}</strong> signed up with <strong>${esc(email)}</strong> (email/password).</p>` }),
  }).catch(e => console.warn('Admin signup alert failed (non-fatal):', e.message));

  res.json({ ok: true, token: session });
}));

app.post('/auth/login', strictLimiter, asyncRoute(async (req, res) => {
  if (!requireSupabase(res)) return;
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ ok: false, error: 'Email and password are required.' });

  const { data: profile } = await supabase.from('profiles').select('id, email, full_name, avatar_url, provider, password_hash').ilike('email', email).maybeSingle();
  if (!profile) return res.status(401).json({ ok: false, error: 'Invalid email or password.' });
  if (!profile.password_hash) return res.status(401).json({ ok: false, error: 'This email is registered via Google — use "Continue with Google" instead.' });
  if (!verifyPassword(password, profile.password_hash)) return res.status(401).json({ ok: false, error: 'Invalid email or password.' });

  const session = signSession({ id: profile.id, email: profile.email, name: profile.full_name, avatar: profile.avatar_url });
  res.json({ ok: true, token: session });
}));

app.post('/auth/forgot-password', strictLimiter, asyncRoute(async (req, res) => {
  if (!requireSupabase(res)) return;
  const { email } = req.body || {};
  if (!email || !isValidEmail(email)) return res.status(400).json({ ok: false, error: 'A valid email is required.' });

  const { data: profile } = await supabase.from('profiles').select('id, full_name, password_hash').ilike('email', email).maybeSingle();
  // Always respond ok, whether or not the account exists — prevents using this
  // endpoint to enumerate which emails have accounts.
  if (!profile || !profile.password_hash) { res.json({ ok: true }); return; }

  const rawToken = crypto.randomBytes(32).toString('hex');
  const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');
  const expires = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

  await supabase.from('profiles').update({ reset_token_hash: tokenHash, reset_token_expires: expires.toISOString() }).eq('id', profile.id);

  const resetUrl = `${SITE_URL}/auth?reset=${rawToken}&email=${encodeURIComponent(email)}`;
  sendMail({
    to: email, subject: 'Reset your AppAholic password',
    html: wrapEmail({
      preheader: 'Reset your password — link expires in 1 hour.',
      title: 'Reset your password',
      bodyHtml: `<p>Click below to reset your password. This link expires in 1 hour. Ignore this email if you didn't request it.</p>`,
      ctaText: 'Reset Password', ctaUrl: resetUrl,
    }),
  }).catch(e => console.warn('Reset email failed:', e.message));

  res.json({ ok: true });
}));

app.post('/auth/reset-password', strictLimiter, asyncRoute(async (req, res) => {
  if (!requireSupabase(res)) return;
  const { email, token, newPassword } = req.body || {};
  if (!email || !token || !newPassword) return res.status(400).json({ ok: false, error: 'Missing fields.' });
  if (String(newPassword).length < 8) return res.status(400).json({ ok: false, error: 'Password must be at least 8 characters.' });

  const { data: profile } = await supabase.from('profiles').select('id, reset_token_hash, reset_token_expires').ilike('email', email).maybeSingle();
  if (!profile || !profile.reset_token_hash) return res.status(400).json({ ok: false, error: 'Invalid or expired reset link.' });
  if (new Date(profile.reset_token_expires) < new Date()) return res.status(400).json({ ok: false, error: 'This reset link has expired. Request a new one.' });

  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  const a = Buffer.from(tokenHash, 'hex'), b = Buffer.from(profile.reset_token_hash, 'hex');
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return res.status(400).json({ ok: false, error: 'Invalid or expired reset link.' });

  await supabase.from('profiles').update({ password_hash: hashPassword(newPassword), reset_token_hash: null, reset_token_expires: null }).eq('id', profile.id);
  res.json({ ok: true });
}));

/* ════════════════════════════════════════════════════════════════════
   APPS (marketplace catalogue — read from Supabase)
   ════════════════════════════════════════════════════════════════════ */
// POST /api/checkout — initiates a one-off Flutterwave payment for a single app purchase.
// Uses the same AAH- tx_ref prefix as /api/subscribe so the shared cross-product webhook
// relay (see WEBHOOK_RELAY.md) can identify AppAholic events without knowing our internals.
app.post('/api/checkout', strictLimiter, asyncRoute(async (req, res) => {
  if (!FLW_SECRET_KEY) return res.status(503).json({ ok: false, error: 'Payments are not configured yet.' });
  const { appId, appName, amount } = req.body || {};
  let { email, name } = req.body || {};

  let userId = null;
  const authHeader = req.headers.authorization || '';
  if (authHeader.startsWith('Bearer ')) {
    const payload = verifySession(authHeader.slice(7));
    if (payload) {
      userId = payload.sub;
      email = email || payload.email;
      name = name || payload.name;
    }
  }

  if (!appId || !appName || !amount || !email) return res.status(400).json({ ok: false, error: 'Missing fields.' });
  if (!isValidEmail(email)) return res.status(400).json({ ok: false, error: 'Invalid email address.' });

  const txRef = `AAH-PUR-${appId}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;

  try {
    const flwRes = await fetch('https://api.flutterwave.com/v3/payments', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${FLW_SECRET_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        tx_ref: txRef,
        amount: Number(amount),
        currency: 'NGN',
        redirect_url: `${SITE_URL}/dashboard?purchased=${encodeURIComponent(appId)}`,
        customer: { email, name: name || email },
        customizations: { title: 'AppAholic', description: appName, logo: `${SITE_URL}/icons/icon-192.png` },
        meta: { user_id: userId, app_id: appId },
      }),
    });
    const flwData = await flwRes.json();
    if (flwData.status !== 'success' || !flwData.data || !flwData.data.link) {
      console.error('Flutterwave checkout init failed:', JSON.stringify(flwData));
      return res.status(502).json({ ok: false, error: 'Could not start checkout right now.' });
    }
    res.json({ ok: true, link: flwData.data.link, txRef });
  } catch (err) {
    console.error('checkout:', err.message);
    res.status(502).json({ ok: false, error: 'Could not start checkout right now.' });
  }
}));

/* ════════════════════════════════════════════════════════════════════
   SUBSCRIPTIONS
   ════════════════════════════════════════════════════════════════════ */

// GET /api/plans — public, the frontend pricing page fetches this instead of hardcoding prices.
app.get('/api/plans', (req, res) => res.json({ ok: true, plans: Object.values(PLANS) }));

// GET /api/subscription — authenticated, current user's subscription status for the dashboard.
app.get('/api/subscription', requireAuth, asyncRoute(async (req, res) => {
  if (!requireSupabase(res)) return;
  const { data } = await supabase.from('subscriptions').select('*').eq('user_id', req.user.sub).eq('status', 'active').order('created_at', { ascending: false }).limit(1).maybeSingle();
  res.json({ ok: true, subscription: data || { plan: 'free', status: 'active' } });
}));

// POST /api/subscribe — authenticated, body: { plan: 'pro'|'business', billingCycle: 'monthly'|'yearly' }
// Initiates a Flutterwave Standard checkout and returns the payment link for the frontend to redirect to.
app.post('/api/subscribe', requireAuth, strictLimiter, asyncRoute(async (req, res) => {
  if (!FLW_SECRET_KEY) return res.status(503).json({ ok: false, error: 'Payments are not configured yet.' });
  const { plan, billingCycle } = req.body || {};
  if (!PLANS[plan] || plan === 'free') return res.status(400).json({ ok: false, error: 'Invalid plan.' });
  const cycle = billingCycle === 'yearly' ? 'yearly' : 'monthly';
  const amount = PLANS[plan][cycle];
  const txRef = `AAH-SUB-${plan}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;

  try {
    const flwRes = await fetch('https://api.flutterwave.com/v3/payments', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${FLW_SECRET_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        tx_ref: txRef,
        amount,
        currency: 'NGN',
        redirect_url: `${SITE_URL}/dashboard?subscribed=1`,
        customer: { email: req.user.email, name: req.user.name || req.user.email },
        customizations: { title: 'AppAholic', description: `${PLANS[plan].name} plan — ${cycle}`, logo: `${SITE_URL}/icons/icon-192.png` },
        meta: { user_id: req.user.sub, plan, billing_cycle: cycle },
      }),
    });
    const flwData = await flwRes.json();
    if (flwData.status !== 'success' || !flwData.data || !flwData.data.link) {
      console.error('Flutterwave init failed:', JSON.stringify(flwData));
      return res.status(502).json({ ok: false, error: 'Could not start checkout right now.' });
    }
    res.json({ ok: true, link: flwData.data.link, txRef });
  } catch (err) {
    console.error('subscribe:', err.message);
    res.status(502).json({ ok: false, error: 'Could not start checkout right now.' });
  }
}));

// POST /api/webhook — receives Flutterwave payment events.
//
// IMPORTANT: this Flutterwave account is shared across multiple JustServicesPro
// products, and Flutterwave only supports one webhook URL per account. The single
// real webhook is registered at https://justservices.pro/api/webhook (a separate,
// central project) which relays only AppAholic-relevant events (tx_ref starting
// with "AAH-") to this endpoint, forwarding the original request headers —
// including 'verif-hash' — unchanged. See WEBHOOK_RELAY.md for the relay code.
//
// Verified via the 'verif-hash' header matching FLW_WEBHOOK_SECRET_HASH (set
// identically here and in the Flutterwave dashboard) — a shared-secret string
// compare, per Flutterwave's documented webhook verification method.
app.post('/api/webhook', asyncRoute(async (req, res) => {
  const incomingHash = req.headers['verif-hash'];
  if (!FLW_WEBHOOK_SECRET_HASH || !incomingHash || incomingHash !== FLW_WEBHOOK_SECRET_HASH) {
    console.warn('Webhook rejected: hash mismatch or not configured.');
    return res.status(401).json({ ok: false });
  }

  const event = req.body || {};
  res.status(200).json({ ok: true }); // ack immediately — Flutterwave retries if this is slow/fails

  if (event.event !== 'charge.completed' || !event.data || event.data.status !== 'successful') return;

  try {
    // Re-verify the transaction server-side with Flutterwave directly — never trust the webhook
    // payload alone, since anyone who guesses/leaks the hash could otherwise fake a payload.
    const verifyRes = await fetch(`https://api.flutterwave.com/v3/transactions/${event.data.id}/verify`, {
      headers: { Authorization: `Bearer ${FLW_SECRET_KEY}` },
    });
    const verified = await verifyRes.json();
    if (verified.status !== 'success' || verified.data.status !== 'successful') {
      console.warn('Webhook: transaction did not verify, ignoring.', event.data.id);
      return;
    }

    const meta = verified.data.meta || {};
    const amount = verified.data.amount;
    const email = verified.data.customer && verified.data.customer.email;

    if (meta.plan && PLANS[meta.plan] && meta.user_id && supabase) {
      const periodEnd = new Date();
      if (meta.billing_cycle === 'yearly') periodEnd.setFullYear(periodEnd.getFullYear() + 1);
      else periodEnd.setMonth(periodEnd.getMonth() + 1);

      await supabase.from('subscriptions').insert({
        user_id: meta.user_id, plan: meta.plan, status: 'active',
        billing_cycle: meta.billing_cycle || 'monthly', amount, currency: 'NGN',
        provider_ref: String(event.data.id), current_period_end: periodEnd.toISOString(),
      });

      if (email) {
        sendMail({
          to: email, subject: `You're on the ${PLANS[meta.plan].name} plan — AppAholic`,
          html: wrapEmail({
            preheader: 'Subscription confirmed.',
            title: `Welcome to ${esc(PLANS[meta.plan].name)}! 🎉`,
            bodyHtml: `<p>Your subscription is active. You now have <strong>${esc(PLANS[meta.plan].tagline)}</strong>.</p>`,
            ctaText: 'Go to Dashboard', ctaUrl: `${SITE_URL}/dashboard`,
          }),
        }).catch(e => console.warn('Subscription email failed:', e.message));
      }
      sendAdminMail({
        subject: `New ${meta.plan} subscription — ₦${amount}`,
        html: wrapEmail({ title: 'New Subscription', bodyHtml: `<p>${esc(email || 'A user')} subscribed to <strong>${esc(PLANS[meta.plan].name)}</strong> (${esc(meta.billing_cycle)}) — ₦${amount}.</p>` }),
      }).catch(e => console.warn('Admin subscription alert failed:', e.message));
    } else {
      // Not a subscription charge — a one-off app purchase went through Flutterwave directly.
      // Record it the same way /api/order-confirmation does, keyed by whatever the frontend put in meta.
      if (meta.app_id && supabase) {
        await supabase.from('purchases').insert({
          user_id: meta.user_id || null, app_id: meta.app_id, email: email || 'unknown',
          amount, currency: 'NGN', status: 'completed', provider_ref: String(event.data.id),
        });
      }
    }
  } catch (err) {
    console.error('webhook processing error:', err.message);
  }
}));

// Shared entitlement check — free apps, purchased apps, or subscription-covered apps.
// Used by both the lightweight /api/entitlement check (for button labeling) and the
// actual /api/download route (which needs entitlement confirmed before handing out a file).
async function checkEntitlement(userId, app) {
  if (Number(app.price) === 0) return true;
  const { data: purchase } = await supabase.from('purchases').select('id').eq('user_id', userId).eq('app_id', app.id).eq('status', 'completed').maybeSingle();
  if (purchase) return true;
  const { data: sub } = await supabase.from('subscriptions').select('plan').eq('user_id', userId).eq('status', 'active').order('created_at', { ascending: false }).limit(1).maybeSingle();
  if (sub) {
    if (sub.plan === 'business') return true;
    if (sub.plan === 'pro' && Number(app.price) <= 3000) return true;
  }
  return false;
}

// GET /api/entitlement/:appId — lightweight, no signed URL generated. Used by the
// marketplace to decide the correct button label (Get / Download / Install) *before*
// the user clicks anything, not just react after the fact.
app.get('/api/entitlement/:appId', requireAuth, asyncRoute(async (req, res) => {
  if (!requireSupabase(res)) return;
  const { data: app, error: appErr } = await supabase.from('apps').select('id, price, platform, launch_url, storage_path').eq('id', req.params.appId).eq('active', true).maybeSingle();
  if (appErr || !app) return res.status(404).json({ ok: false, error: 'App not found.' });
  const entitled = await checkEntitlement(req.user.sub, app);
  res.json({ ok: true, entitled, deliveryType: app.launch_url ? 'install' : (app.storage_path ? 'download' : 'unavailable') });
}));

// GET /api/download/:appId — authenticated. Checks the user is actually entitled to this
// app (free, purchased, or covered by their subscription tier) before handing out anything.
// Desktop/Mobile apps get a short-lived signed Supabase Storage URL; Web apps get their launch_url.
app.get('/api/download/:appId', requireAuth, asyncRoute(async (req, res) => {
  if (!requireSupabase(res)) return;
  const { appId } = req.params;

  const { data: app, error: appErr } = await supabase.from('apps').select('*').eq('id', appId).eq('active', true).maybeSingle();
  if (appErr || !app) return res.status(404).json({ ok: false, error: 'App not found.' });

  const entitled = await checkEntitlement(req.user.sub, app);
  if (!entitled) return res.status(402).json({ ok: false, error: 'Purchase or a subscription that covers this app is required.', requiresPurchase: true });

  // ── If a launch_url is set, use it regardless of platform label ──
  // Lets a "mobile" catalog entry be honestly satisfied by a responsive
  // web/PWA build when no native binary exists, instead of hiding that fact.
  if (app.launch_url) {
    // Log this the same way an actual file download is logged — every acquisition
    // (bought or free, file or web/install) should show up in the user's dashboard.
    supabase.from('downloads').insert({ user_id: req.user.sub, app_id: appId, device: 'web-install' })
      .then(({ error }) => { if (error) console.error('install log insert failed:', error.message); });
    return res.json({ ok: true, type: 'launch', url: app.launch_url });
  }

  // ── Otherwise, this needs an actual file — generate a short-lived signed link ──
  if (!app.storage_path) return res.status(503).json({ ok: false, error: 'This app is not available for download yet — check back soon.' });

  const { data: signed, error: signErr } = await supabase.storage.from('app-files').createSignedUrl(app.storage_path, 300); // 5 minutes
  if (signErr || !signed) {
    console.error('createSignedUrl failed:', signErr && signErr.message);
    return res.status(500).json({ ok: false, error: 'Could not prepare your download. Please try again.' });
  }

  // Record the download (best-effort — don't fail the response if this write has an issue).
  supabase.from('downloads').insert({ user_id: req.user.sub, app_id: appId, device: req.headers['user-agent'] || null })
    .then(({ error }) => { if (error) console.error('download log insert failed:', error.message); });

  res.json({ ok: true, type: 'download', url: signed.signedUrl, expiresIn: 300 });
}));

app.get('/api/apps', asyncRoute(async (req, res) => {
  if (!requireSupabase(res)) return;
  const { platform, category } = req.query;
  let q = supabase.from('apps').select('*').eq('active', true).order('created_at', { ascending: true });
  if (platform && ['web', 'desktop', 'mobile'].includes(platform)) q = q.eq('platform', platform);
  if (category) q = q.eq('category', category);
  const { data, error } = await q;
  if (error) return res.status(500).json({ ok: false, error: 'Could not load apps.' });
  res.json({ ok: true, apps: data });
}));

/* ════════════════════════════════════════════════════════════════════
   DASHBOARD (authenticated — real data, no more fake demo content)
   ════════════════════════════════════════════════════════════════════ */
app.get('/api/dashboard', requireAuth, asyncRoute(async (req, res) => {
  if (!requireSupabase(res)) return;
  const uid = req.user.sub;

  const [purchases, downloads, requests] = await Promise.all([
    supabase.from('purchases').select('*, apps(name, icon)').eq('user_id', uid).order('created_at', { ascending: false }),
    supabase.from('downloads').select('*, apps(name, icon)').eq('user_id', uid).order('created_at', { ascending: false }),
    supabase.from('app_requests').select('*').eq('user_id', uid).order('created_at', { ascending: false }),
  ]);

  res.json({
    ok: true,
    profile: { email: req.user.email, name: req.user.name, avatar: req.user.avatar },
    purchases: purchases.data || [],
    downloads: downloads.data || [],
    requests: requests.data || [],
    stats: {
      appsPurchased: (purchases.data || []).length,
      totalDownloads: (downloads.data || []).length,
      appRequests: (requests.data || []).length,
      totalSpent: (purchases.data || []).reduce((sum, p) => sum + Number(p.amount || 0), 0),
    },
  });
}));

// POST /api/downloads — record a download event for the signed-in user
app.post('/api/downloads', requireAuth, asyncRoute(async (req, res) => {
  if (!requireSupabase(res)) return;
  const { appId, version, device } = req.body || {};
  if (!appId) return res.status(400).json({ ok: false, error: 'appId is required.' });
  const { error } = await supabase.from('downloads').insert({ user_id: req.user.sub, app_id: appId, version: version || null, device: device || null });
  if (error) return res.status(500).json({ ok: false, error: 'Could not record download.' });
  res.json({ ok: true });
}));

/* ════════════════════════════════════════════════════════════════════
   REQUEST-APP / CONTACT / ORDERS / INVOICE / ALERTS
   ════════════════════════════════════════════════════════════════════ */

app.post('/api/request-app', strictLimiter, asyncRoute(async (req, res) => {
  const { name, email, phone, role, title, category, platform, audience, users, problem, features,
          inspiration, integrations, extra, timeline, budget, delivery, source } = req.body || {};

  if (!name || !email || !title || !problem) return res.status(400).json({ ok: false, error: 'Missing required fields.' });
  if (!isValidEmail(email)) return res.status(400).json({ ok: false, error: 'Invalid email address.' });

  let userId = null;
  const authHeader = req.headers.authorization || '';
  if (authHeader.startsWith('Bearer ')) {
    const payload = verifySession(authHeader.slice(7));
    if (payload) userId = payload.sub;
  }

  try {
    if (supabase) {
      const { error: dbErr } = await supabase.from('app_requests').insert({
        user_id: userId, name, email, phone, role, title, category, platform, audience,
        users_estimate: users, problem, features, inspiration, integrations, extra,
        timeline, budget, delivery, source,
      });
      if (dbErr) console.error('app_requests insert failed:', dbErr.message);
    }

    await sendMail({
      to: email,
      subject: `We received your app request: "${cleanHeader(title)}"`,
      html: wrapEmail({
        preheader: 'Your AppAholic app request has been received.',
        title: `Thanks, ${esc(String(name).split(' ')[0])} 🎉`,
        bodyHtml: `<p>We've received your request for <strong>${esc(title)}</strong> and will review it within <strong>48 hours</strong>.</p>
          <table width="100%" style="margin:18px 0;border-collapse:collapse;font-size:13px;">
            <tr><td style="padding:7px 0;color:#6B6458;">Category</td><td style="padding:7px 0;text-align:right;font-weight:600;">${esc(category)||'—'}</td></tr>
            <tr style="border-top:1px solid #D9D2C3;"><td style="padding:7px 0;color:#6B6458;">Platform</td><td style="padding:7px 0;text-align:right;font-weight:600;">${esc(platform)||'—'}</td></tr>
            <tr style="border-top:1px solid #D9D2C3;"><td style="padding:7px 0;color:#6B6458;">Budget</td><td style="padding:7px 0;text-align:right;font-weight:600;">${esc(budget)||'Flexible'}</td></tr>
          </table>`,
        ctaText: 'Browse Apps', ctaUrl: SITE_URL,
      }),
    });
    await sendAdminMail({
      replyTo: email,
      subject: `New app request: "${cleanHeader(title)}" from ${cleanHeader(name)}`,
      html: wrapEmail({
        title: 'New App Request',
        bodyHtml: `<table width="100%" style="border-collapse:collapse;font-size:13px;">
          ${[['Requester', `${esc(name)} (${esc(email)}${phone ? ', ' + esc(phone) : ''})`], ['Title', esc(title)],
             ['Category', esc(category) || '—'], ['Platform', esc(platform) || '—'], ['Problem', esc(problem)],
             ['Features', esc(features) || '—'], ['Budget', esc(budget) || 'Flexible'], ['Timeline', esc(timeline) || 'No rush']]
            .map(([l, v]) => `<tr><td style="padding:5px 0;color:#6B6458;width:120px;">${l}</td><td style="padding:5px 0;">${v}</td></tr>`).join('')}
        </table>`,
      }),
    });
    res.json({ ok: true });
  } catch (err) {
    console.error('request-app:', err.message);
    res.status(502).json({ ok: false, error: 'Could not send email right now.' });
  }
}));

app.post('/api/contact', strictLimiter, asyncRoute(async (req, res) => {
  const { name, email, topic, message } = req.body || {};
  if (!name || !email || !message) return res.status(400).json({ ok: false, error: 'Missing required fields.' });
  if (!isValidEmail(email)) return res.status(400).json({ ok: false, error: 'Invalid email address.' });
  if (String(message).length > 5000) return res.status(400).json({ ok: false, error: 'Message is too long.' });

  const topicLabel = ['General', 'Support', 'Partnership', 'Press', 'Billing'].includes(topic) ? topic : 'General';
  let userId = null;
  const authHeader = req.headers.authorization || '';
  if (authHeader.startsWith('Bearer ')) {
    const payload = verifySession(authHeader.slice(7));
    if (payload) userId = payload.sub;
  }

  try {
    if (supabase) {
      const { error: dbErr } = await supabase.from('contact_messages').insert({ user_id: userId, name, email, topic: topicLabel, message });
      if (dbErr) console.error('contact_messages insert failed:', dbErr.message);
    }
    await sendMail({
      to: email, subject: 'We received your message — AppAholic',
      html: wrapEmail({
        preheader: 'Thanks for reaching out.',
        title: `Thanks, ${esc(String(name).split(' ')[0])} 🎉`,
        bodyHtml: `<p>We've received your message and typically reply within <strong>one business day</strong>.</p>
          <p style="color:#6B6458;font-size:13px;border-top:1px solid #D9D2C3;padding-top:12px;">Your message:<br/>${esc(message)}</p>`,
      }),
    });
    await sendAdminMail({
      replyTo: email,
      subject: `New contact message [${cleanHeader(topicLabel)}] from ${cleanHeader(name)}`,
      html: wrapEmail({ title: 'New Contact Message', bodyHtml: `<p><strong>${esc(name)}</strong> (${esc(email)}) — ${esc(topicLabel)}</p><p style="margin-top:10px;white-space:pre-wrap;">${esc(message)}</p>` }),
    });
    res.json({ ok: true });
  } catch (err) {
    console.error('contact:', err.message);
    res.status(502).json({ ok: false, error: 'Could not send email right now.' });
  }
}));

app.post('/api/order-confirmation', strictLimiter, asyncRoute(async (req, res) => {
  const { email, name, appId, appName, amount, currency, ref, downloadUrl } = req.body || {};
  if (!email || !appName) return res.status(400).json({ ok: false, error: 'Missing fields.' });
  if (!isValidEmail(email)) return res.status(400).json({ ok: false, error: 'Invalid email address.' });

  let userId = null;
  const authHeader = req.headers.authorization || '';
  if (authHeader.startsWith('Bearer ')) {
    const payload = verifySession(authHeader.slice(7));
    if (payload) userId = payload.sub;
  }

  const isFree = !amount || Number(amount) === 0;
  const amountStr = Number.isFinite(Number(amount)) ? Number(amount).toLocaleString() : '0';

  try {
    if (supabase) {
      const { error: dbErr } = await supabase.from('purchases').insert({
        user_id: userId, app_id: appId || null, email, amount: Number(amount) || 0,
        currency: currency || 'NGN', status: 'completed', provider_ref: ref || null,
      });
      if (dbErr) console.error('purchases insert failed:', dbErr.message);
    }
    await sendMail({
      to: email,
      subject: isFree ? `Your download: ${cleanHeader(appName)}` : `Receipt — ${cleanHeader(appName)} (₦${amountStr})`,
      html: wrapEmail({
        title: isFree ? `${esc(appName)} is ready` : 'Payment received — thank you!',
        bodyHtml: `<p>Hi ${esc(name)||'there'},</p><p>${isFree?`Your free download of <strong>${esc(appName)}</strong> is ready.`:`We received your payment of <strong>${esc(currency)||'₦'}${amountStr}</strong> for <strong>${esc(appName)}</strong>.`}${ref?`<br/><small>Ref: ${esc(ref)}</small>`:''}</p>`,
        ctaText: 'Go to Dashboard', ctaUrl: safeUrl(downloadUrl, `${SITE_URL}/dashboard`),
      }),
    });
    await sendAdminMail({
      
      subject: `${isFree?'Free download':'Sale'}: ${cleanHeader(appName)} — ${cleanHeader(name||email)}`,
      html: wrapEmail({ title: isFree?'Free Download':'New Sale', bodyHtml: `<p><strong>${esc(appName)}</strong> ${isFree?'downloaded':'purchased for '+(esc(currency)||'₦')+amountStr} by ${esc(name)||''} (${esc(email)}).</p>` }),
    });
    res.json({ ok: true });
  } catch (err) {
    console.error('order:', err.message);
    res.status(502).json({ ok: false, error: 'Could not send email right now.' });
  }
}));

app.post('/api/send-invoice', strictLimiter, asyncRoute(async (req, res) => {
  const { clientEmail, clientName, invoiceNum, businessName, total, dueDate, pdfUrl } = req.body || {};
  if (!clientEmail || !invoiceNum) return res.status(400).json({ ok: false, error: 'Missing fields.' });
  if (!isValidEmail(clientEmail)) return res.status(400).json({ ok: false, error: 'Invalid email address.' });
  const totalStr = Number.isFinite(Number(total)) ? Number(total).toLocaleString() : '0';
  try {
    await sendMail({
      to: clientEmail, subject: `Invoice ${cleanHeader(invoiceNum)} from ${cleanHeader(businessName||'AppAholic')}`,
      html: wrapEmail({
        title: `Invoice ${esc(invoiceNum)}`,
        bodyHtml: `<p>Hi ${esc(clientName)||'there'},</p><table width="100%" style="margin:16px 0;border-collapse:collapse;font-size:13px;">
          <tr><td style="padding:6px 0;color:#6B6458;">Invoice #</td><td style="text-align:right;font-weight:600;">${esc(invoiceNum)}</td></tr>
          <tr style="border-top:1px solid #D9D2C3;"><td style="padding:6px 0;color:#6B6458;">Amount Due</td><td style="text-align:right;font-weight:800;">₦${totalStr}</td></tr>
          ${dueDate?`<tr style="border-top:1px solid #D9D2C3;"><td style="padding:6px 0;color:#6B6458;">Due Date</td><td style="text-align:right;font-weight:600;">${esc(dueDate)}</td></tr>`:''}
        </table>`,
        ...(pdfUrl ? { ctaText: 'View / Download Invoice', ctaUrl: safeUrl(pdfUrl, `${SITE_URL}/invoicekit`) } : {}),
      }),
    });
    res.json({ ok: true });
  } catch (err) {
    console.error('invoice:', err.message);
    res.status(502).json({ ok: false, error: 'Could not send email right now.' });
  }
}));

app.post('/api/admin-alert', strictLimiter, asyncRoute(async (req, res) => {
  const { subject, message } = req.body || {};
  try {
    await sendAdminMail({ subject: `Alert: ${cleanHeader(subject||'AppAholic Alert')}`, html: wrapEmail({ title: esc(subject)||'Alert', bodyHtml: `<p>${esc(message)||''}</p>` }) });
    res.json({ ok: true });
  } catch (err) {
    console.error('admin-alert:', err.message);
    res.status(502).json({ ok: false, error: 'Could not send email right now.' });
  }
}));

/* ════════════════════════════════════════════════════════════════════
   FOCUSCLOCK — per-app API. Session logging + stats.
   Catalogue promises "website & app blocker" and "Google Calendar sync" —
   neither is built: a webpage genuinely cannot block other browser tabs or
   OS-level apps (no such capability exists in the browser sandbox), and
   calendar sync needs an additional OAuth scope beyond what's currently
   requested at sign-in. Stated here rather than silently dropped.
   ════════════════════════════════════════════════════════════════════ */

app.get('/api/focusclock/sessions', requireAuth, asyncRoute(async (req, res) => {
  if (!requireSupabase(res)) return;
  const { data, error } = await supabase.from('focusclock_sessions').select('*').eq('user_id', req.user.sub).order('started_at', { ascending: false }).limit(200);
  if (error) { console.error('focusclock GET sessions failed:', error.message); return res.status(500).json({ ok: false, error: 'Could not load sessions.' }); }
  res.json({ ok: true, sessions: data });
}));

app.post('/api/focusclock/sessions', requireAuth, asyncRoute(async (req, res) => {
  if (!requireSupabase(res)) return;
  const { sessionType, durationSecs, completed, label, startedAt } = req.body || {};
  if (!['focus', 'break'].includes(sessionType) || !durationSecs) return res.status(400).json({ ok: false, error: 'Missing session details.' });
  const { data, error } = await supabase.from('focusclock_sessions').insert({
    user_id: req.user.sub, session_type: sessionType, duration_secs: Math.round(durationSecs),
    completed: !!completed, label: label || null, started_at: startedAt || new Date().toISOString(), ended_at: new Date().toISOString(),
  }).select('*').single();
  if (error) { console.error('focusclock POST session failed:', error.message); return res.status(500).json({ ok: false, error: 'Could not save session.' }); }
  res.json({ ok: true, session: data });
}));

/* ════════════════════════════════════════════════════════════════════
   TASKMIND — per-app API. Real task CRUD + deterministic smart-sort.
   Catalogue says "AI-powered" — honestly: prioritization is rule-based
   (deadline proximity + priority + estimated time) by default. If
   ANTHROPIC_API_KEY is set in env, /api/taskmind/focus-plan calls a real
   LLM for a genuine AI-generated daily plan; without it, that route
   returns a clearly-labeled rule-based plan instead of faking AI output.
   ════════════════════════════════════════════════════════════════════ */

app.get('/api/taskmind/tasks', requireAuth, asyncRoute(async (req, res) => {
  if (!requireSupabase(res)) return;
  const { data, error } = await supabase.from('taskmind_tasks').select('*').eq('user_id', req.user.sub).order('created_at', { ascending: false });
  if (error) { console.error('taskmind GET tasks failed:', error.message); return res.status(500).json({ ok: false, error: 'Could not load tasks.' }); }
  res.json({ ok: true, tasks: data });
}));

app.post('/api/taskmind/tasks', requireAuth, asyncRoute(async (req, res) => {
  if (!requireSupabase(res)) return;
  const { title, notes, priority, dueDate, estimatedMinutes } = req.body || {};
  if (!title) return res.status(400).json({ ok: false, error: 'Task title is required.' });
  const { data, error } = await supabase.from('taskmind_tasks').insert({
    user_id: req.user.sub, title: String(title).slice(0, 300), notes: notes || null,
    priority: ['low', 'medium', 'high'].includes(priority) ? priority : 'medium',
    due_date: dueDate || null, estimated_minutes: estimatedMinutes || null,
  }).select('*').single();
  if (error) { console.error('taskmind POST task failed:', error.message); return res.status(500).json({ ok: false, error: 'Could not create task.' }); }
  res.json({ ok: true, task: data });
}));

app.put('/api/taskmind/tasks/:id', requireAuth, asyncRoute(async (req, res) => {
  if (!requireSupabase(res)) return;
  const { title, notes, priority, dueDate, estimatedMinutes, completed } = req.body || {};
  const updates = {};
  if (title !== undefined) updates.title = String(title).slice(0, 300);
  if (notes !== undefined) updates.notes = notes;
  if (priority !== undefined && ['low', 'medium', 'high'].includes(priority)) updates.priority = priority;
  if (dueDate !== undefined) updates.due_date = dueDate;
  if (estimatedMinutes !== undefined) updates.estimated_minutes = estimatedMinutes;
  if (completed !== undefined) { updates.completed = !!completed; updates.completed_at = completed ? new Date().toISOString() : null; }
  const { data, error } = await supabase.from('taskmind_tasks').update(updates).eq('id', req.params.id).eq('user_id', req.user.sub).select('*').maybeSingle();
  if (error) console.error('taskmind PUT task failed:', error.message);
  if (error || !data) return res.status(404).json({ ok: false, error: 'Task not found.' });
  res.json({ ok: true, task: data });
}));

app.delete('/api/taskmind/tasks/:id', requireAuth, asyncRoute(async (req, res) => {
  if (!requireSupabase(res)) return;
  const { error, count } = await supabase.from('taskmind_tasks').delete({ count: 'exact' }).eq('id', req.params.id).eq('user_id', req.user.sub);
  if (error) { console.error('taskmind DELETE task failed:', error.message); return res.status(500).json({ ok: false, error: 'Could not delete task.' }); }
  if (!count) return res.status(404).json({ ok: false, error: 'Task not found.' });
  res.json({ ok: true });
}));

const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;

app.get('/api/taskmind/focus-plan', requireAuth, asyncRoute(async (req, res) => {
  if (!requireSupabase(res)) return;
  const { data: tasks, error } = await supabase.from('taskmind_tasks').select('*').eq('user_id', req.user.sub).eq('completed', false);
  if (error) return res.status(500).json({ ok: false, error: 'Could not load tasks.' });
  if (!tasks.length) return res.json({ ok: true, plan: 'No open tasks — you\'re all caught up.', ranked: [], source: 'rule-based' });

  // Deterministic rule-based ranking (always computed, used as the fallback and as
  // the ordering AI mode is asked to work from — never invented from nothing).
  const now = Date.now();
  const scored = tasks.map(t => {
    let score = 0;
    if (t.priority === 'high') score += 30; else if (t.priority === 'medium') score += 15;
    if (t.due_date) {
      const daysUntil = (new Date(t.due_date).getTime() - now) / 86400000;
      if (daysUntil < 0) score += 50; else if (daysUntil < 1) score += 40; else if (daysUntil < 3) score += 25; else if (daysUntil < 7) score += 10;
    }
    return { ...t, _score: score };
  }).sort((a, b) => b._score - a._score);

  if (!ANTHROPIC_API_KEY) {
    return res.json({ ok: true, source: 'rule-based', ranked: scored.map(({ _score, ...t }) => t),
      plan: 'Ranked by priority and due date. Add an ANTHROPIC_API_KEY to enable an AI-written daily plan summary.' });
  }

  try {
    const taskList = scored.slice(0, 10).map(t => `- ${t.title}${t.due_date ? ` (due ${t.due_date})` : ''} [${t.priority} priority]${t.estimated_minutes ? `, ~${t.estimated_minutes}min` : ''}`).join('\n');
    const aiRes = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'x-api-key': ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01', 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: 'claude-sonnet-4-5', max_tokens: 300,
        messages: [{ role: 'user', content: `Here are my open tasks, already ranked by urgency:\n${taskList}\n\nWrite a short (3-4 sentence), encouraging daily focus plan telling me what to tackle first and why. Be specific, reference the actual task titles.` }],
      }),
    });
    const aiData = await aiRes.json();
    const planText = aiData.content && aiData.content[0] && aiData.content[0].text;
    if (!planText) throw new Error('No plan text returned');
    res.json({ ok: true, source: 'ai', ranked: scored.map(({ _score, ...t }) => t), plan: planText });
  } catch (err) {
    console.error('taskmind AI focus-plan failed, falling back to rule-based:', err.message);
    res.json({ ok: true, source: 'rule-based', ranked: scored.map(({ _score, ...t }) => t), plan: 'Ranked by priority and due date. (AI plan temporarily unavailable.)' });
  }
}));

/* ════════════════════════════════════════════════════════════════════
   INVOICEKIT — per-app API. Clients + invoices, both scoped to the owner.
   ════════════════════════════════════════════════════════════════════ */

app.get('/api/invoicekit/clients', requireAuth, asyncRoute(async (req, res) => {
  if (!requireSupabase(res)) return;
  const { data, error } = await supabase.from('invoicekit_clients').select('*').eq('user_id', req.user.sub).order('name', { ascending: true });
  if (error) { console.error('invoicekit GET clients failed:', error.message); return res.status(500).json({ ok: false, error: 'Could not load clients.' }); }
  res.json({ ok: true, clients: data });
}));

app.post('/api/invoicekit/clients', requireAuth, asyncRoute(async (req, res) => {
  if (!requireSupabase(res)) return;
  const { name, email, phone, address } = req.body || {};
  if (!name) return res.status(400).json({ ok: false, error: 'Client name is required.' });
  const { data, error } = await supabase.from('invoicekit_clients')
    .insert({ user_id: req.user.sub, name: String(name).slice(0, 200), email: email || null, phone: phone || null, address: address || null })
    .select('*').single();
  if (error) { console.error('invoicekit POST client failed:', error.message); return res.status(500).json({ ok: false, error: 'Could not create client.' }); }
  res.json({ ok: true, client: data });
}));

app.put('/api/invoicekit/clients/:id', requireAuth, asyncRoute(async (req, res) => {
  if (!requireSupabase(res)) return;
  const { name, email, phone, address } = req.body || {};
  const { data, error } = await supabase.from('invoicekit_clients')
    .update({ name, email, phone, address }).eq('id', req.params.id).eq('user_id', req.user.sub)
    .select('*').maybeSingle();
  if (error) console.error('invoicekit PUT client failed:', error.message);
  if (error || !data) return res.status(404).json({ ok: false, error: 'Client not found.' });
  res.json({ ok: true, client: data });
}));

app.delete('/api/invoicekit/clients/:id', requireAuth, asyncRoute(async (req, res) => {
  if (!requireSupabase(res)) return;
  const { error, count } = await supabase.from('invoicekit_clients').delete({ count: 'exact' }).eq('id', req.params.id).eq('user_id', req.user.sub);
  if (error) { console.error('invoicekit DELETE client failed:', error.message); return res.status(500).json({ ok: false, error: 'Could not delete client.' }); }
  if (!count) return res.status(404).json({ ok: false, error: 'Client not found.' });
  res.json({ ok: true });
}));

app.get('/api/invoicekit/invoices', requireAuth, asyncRoute(async (req, res) => {
  if (!requireSupabase(res)) return;
  const { data, error } = await supabase.from('invoicekit_invoices').select('*, invoicekit_clients(name, email)').eq('user_id', req.user.sub).order('created_at', { ascending: false });
  if (error) { console.error('invoicekit GET invoices failed:', error.message); return res.status(500).json({ ok: false, error: 'Could not load invoices.' }); }
  res.json({ ok: true, invoices: data });
}));

app.post('/api/invoicekit/invoices', requireAuth, asyncRoute(async (req, res) => {
  if (!requireSupabase(res)) return;
  const { clientId, invoiceNumber, businessName, items, vatRate, whtRate, dueDate } = req.body || {};
  if (!invoiceNumber || !Array.isArray(items) || !items.length) return res.status(400).json({ ok: false, error: 'Invoice number and at least one line item are required.' });

  const subtotal = items.reduce((sum, i) => sum + (Number(i.qty) || 0) * (Number(i.price) || 0), 0);
  const vat = Math.round(subtotal * (Number(vatRate) || 0) / 100);
  const wht = Math.round(subtotal * (Number(whtRate) || 0) / 100);
  const total = subtotal + vat - wht;

  const { data, error } = await supabase.from('invoicekit_invoices').insert({
    user_id: req.user.sub, client_id: clientId || null, invoice_number: invoiceNumber, business_name: businessName || null,
    items, vat_rate: vatRate || 0, wht_rate: whtRate || 0, subtotal, vat_amount: vat, wht_amount: wht, total,
    due_date: dueDate || null,
  }).select('*').single();
  if (error) { console.error('invoicekit POST invoice failed:', error.message); return res.status(500).json({ ok: false, error: 'Could not create invoice.' }); }
  res.json({ ok: true, invoice: data });
}));

app.put('/api/invoicekit/invoices/:id', requireAuth, asyncRoute(async (req, res) => {
  if (!requireSupabase(res)) return;
  const { status, items, vatRate, whtRate, dueDate } = req.body || {};
  const updates = { updated_at: new Date().toISOString() };
  if (status !== undefined) {
    if (!['draft', 'sent', 'paid', 'overdue'].includes(status)) return res.status(400).json({ ok: false, error: 'Invalid status.' });
    updates.status = status;
    if (status === 'paid') updates.paid_at = new Date().toISOString();
  }
  if (Array.isArray(items) && items.length) {
    const subtotal = items.reduce((sum, i) => sum + (Number(i.qty) || 0) * (Number(i.price) || 0), 0);
    const vat = Math.round(subtotal * (Number(vatRate) || 0) / 100);
    const wht = Math.round(subtotal * (Number(whtRate) || 0) / 100);
    Object.assign(updates, { items, vat_rate: vatRate || 0, wht_rate: whtRate || 0, subtotal, vat_amount: vat, wht_amount: wht, total: subtotal + vat - wht });
  }
  if (dueDate !== undefined) updates.due_date = dueDate;

  const { data, error } = await supabase.from('invoicekit_invoices').update(updates).eq('id', req.params.id).eq('user_id', req.user.sub).select('*').maybeSingle();
  if (error) console.error('invoicekit PUT invoice failed:', error.message);
  if (error || !data) return res.status(404).json({ ok: false, error: 'Invoice not found.' });
  res.json({ ok: true, invoice: data });
}));

app.delete('/api/invoicekit/invoices/:id', requireAuth, asyncRoute(async (req, res) => {
  if (!requireSupabase(res)) return;
  const { error, count } = await supabase.from('invoicekit_invoices').delete({ count: 'exact' }).eq('id', req.params.id).eq('user_id', req.user.sub);
  if (error) { console.error('invoicekit DELETE invoice failed:', error.message); return res.status(500).json({ ok: false, error: 'Could not delete invoice.' }); }
  if (!count) return res.status(404).json({ ok: false, error: 'Invoice not found.' });
  res.json({ ok: true });
}));

/* ════════════════════════════════════════════════════════════════════
   FOCUSCLOCK — Pomodoro timer sessions + settings.
   ════════════════════════════════════════════════════════════════════ */

app.get('/api/focusclock/settings', requireAuth, asyncRoute(async (req, res) => {
  if (!requireSupabase(res)) return;
  const { data, error } = await supabase.from('focusclock_settings').select('*').eq('user_id', req.user.sub).maybeSingle();
  if (error) { console.error('focusclock GET settings failed:', error.message); return res.status(500).json({ ok: false, error: 'Could not load settings.' }); }
  res.json({ ok: true, settings: data || { work_minutes: 25, break_minutes: 5, long_break_minutes: 15, sessions_before_long_break: 4 } });
}));

app.put('/api/focusclock/settings', requireAuth, asyncRoute(async (req, res) => {
  if (!requireSupabase(res)) return;
  const { workMinutes, breakMinutes, longBreakMinutes, sessionsBeforeLongBreak } = req.body || {};
  const payload = {
    user_id: req.user.sub,
    work_minutes: Math.max(1, Math.min(120, Number(workMinutes) || 25)),
    break_minutes: Math.max(1, Math.min(60, Number(breakMinutes) || 5)),
    long_break_minutes: Math.max(1, Math.min(60, Number(longBreakMinutes) || 15)),
    sessions_before_long_break: Math.max(1, Math.min(12, Number(sessionsBeforeLongBreak) || 4)),
    updated_at: new Date().toISOString(),
  };
  const { data, error } = await supabase.from('focusclock_settings').upsert(payload, { onConflict: 'user_id' }).select('*').single();
  if (error) { console.error('focusclock PUT settings failed:', error.message); return res.status(500).json({ ok: false, error: 'Could not save settings.' }); }
  res.json({ ok: true, settings: data });
}));

app.post('/api/focusclock/sessions', requireAuth, asyncRoute(async (req, res) => {
  if (!requireSupabase(res)) return;
  const { sessionType, durationMin, completed } = req.body || {};
  if (!['work', 'break', 'long_break'].includes(sessionType)) return res.status(400).json({ ok: false, error: 'Invalid session type.' });
  const { data, error } = await supabase.from('focusclock_sessions')
    .insert({ user_id: req.user.sub, session_type: sessionType, duration_min: Number(durationMin) || 0, completed: !!completed, ended_at: completed ? new Date().toISOString() : null })
    .select('*').single();
  if (error) { console.error('focusclock POST session failed:', error.message); return res.status(500).json({ ok: false, error: 'Could not log session.' }); }
  res.json({ ok: true, session: data });
}));

app.get('/api/focusclock/stats', requireAuth, asyncRoute(async (req, res) => {
  if (!requireSupabase(res)) return;
  const since = new Date(); since.setDate(since.getDate() - 7);
  const { data, error } = await supabase.from('focusclock_sessions').select('*').eq('user_id', req.user.sub).gte('started_at', since.toISOString()).order('started_at', { ascending: true });
  if (error) { console.error('focusclock GET stats failed:', error.message); return res.status(500).json({ ok: false, error: 'Could not load stats.' }); }
  const workSessions = data.filter(s => s.session_type === 'work' && s.completed);
  res.json({
    ok: true,
    sessions: data,
    totals: { completedWorkSessions: workSessions.length, totalFocusMinutes: workSessions.reduce((s, x) => s + x.duration_min, 0) },
  });
}));

/* ════════════════════════════════════════════════════════════════════
   DATAPULSE — CSV-backed datasets rendered as charts. NOTE ON SCOPE: the
   catalogue description mentions a live Google Sheets connector — that
   needs real Google Sheets API OAuth scopes this pass doesn't wire up.
   What's actually built: paste/upload CSV data, pick a chart type and
   columns, get an instant chart, save it, export as PDF.
   ════════════════════════════════════════════════════════════════════ */

app.get('/api/datapulse/datasets', requireAuth, asyncRoute(async (req, res) => {
  if (!requireSupabase(res)) return;
  const { data, error } = await supabase.from('datapulse_datasets').select('*').eq('user_id', req.user.sub).order('updated_at', { ascending: false });
  if (error) { console.error('datapulse GET datasets failed:', error.message); return res.status(500).json({ ok: false, error: 'Could not load datasets.' }); }
  res.json({ ok: true, datasets: data });
}));

app.post('/api/datapulse/datasets', requireAuth, asyncRoute(async (req, res) => {
  if (!requireSupabase(res)) return;
  const { name, headers, rows, chartType, xColumn, yColumn } = req.body || {};
  if (!name || !Array.isArray(headers) || !Array.isArray(rows)) return res.status(400).json({ ok: false, error: 'Name, headers and rows are required.' });
  const { data, error } = await supabase.from('datapulse_datasets')
    .insert({ user_id: req.user.sub, name: String(name).slice(0, 200), headers, rows, chart_type: chartType || 'bar', x_column: xColumn || 0, y_column: yColumn || 1 })
    .select('*').single();
  if (error) { console.error('datapulse POST dataset failed:', error.message); return res.status(500).json({ ok: false, error: 'Could not save dataset.' }); }
  res.json({ ok: true, dataset: data });
}));

app.put('/api/datapulse/datasets/:id', requireAuth, asyncRoute(async (req, res) => {
  if (!requireSupabase(res)) return;
  const { name, chartType, xColumn, yColumn } = req.body || {};
  const updates = { updated_at: new Date().toISOString() };
  if (name !== undefined) updates.name = String(name).slice(0, 200);
  if (chartType !== undefined) updates.chart_type = chartType;
  if (xColumn !== undefined) updates.x_column = xColumn;
  if (yColumn !== undefined) updates.y_column = yColumn;
  const { data, error } = await supabase.from('datapulse_datasets').update(updates).eq('id', req.params.id).eq('user_id', req.user.sub).select('*').maybeSingle();
  if (error) console.error('datapulse PUT dataset failed:', error.message);
  if (error || !data) return res.status(404).json({ ok: false, error: 'Dataset not found.' });
  res.json({ ok: true, dataset: data });
}));

app.delete('/api/datapulse/datasets/:id', requireAuth, asyncRoute(async (req, res) => {
  if (!requireSupabase(res)) return;
  const { error, count } = await supabase.from('datapulse_datasets').delete({ count: 'exact' }).eq('id', req.params.id).eq('user_id', req.user.sub);
  if (error) { console.error('datapulse DELETE dataset failed:', error.message); return res.status(500).json({ ok: false, error: 'Could not delete dataset.' }); }
  if (!count) return res.status(404).json({ ok: false, error: 'Dataset not found.' });
  res.json({ ok: true });
}));

/* ════════════════════════════════════════════════════════════════════
   TASKMIND — task manager with a heuristic (not machine-learned) smart
   sort. NOTE ON SCOPE: the catalogue description implies genuine AI/ML
   that "learns your habits" — what's actually built is a transparent
   rule-based priority score (deadline proximity + priority + energy
   match to time of day), explained as such in the UI, not marketed as
   real AI. Calendar sync needs real Google/Outlook OAuth this pass
   doesn't wire up.
   ════════════════════════════════════════════════════════════════════ */

app.get('/api/taskmind/tasks', requireAuth, asyncRoute(async (req, res) => {
  if (!requireSupabase(res)) return;
  const { data, error } = await supabase.from('taskmind_tasks').select('*').eq('user_id', req.user.sub).order('created_at', { ascending: false });
  if (error) { console.error('taskmind GET tasks failed:', error.message); return res.status(500).json({ ok: false, error: 'Could not load tasks.' }); }
  res.json({ ok: true, tasks: data });
}));

app.post('/api/taskmind/tasks', requireAuth, asyncRoute(async (req, res) => {
  if (!requireSupabase(res)) return;
  const { title, notes, dueDate, priority, energyTag } = req.body || {};
  if (!title) return res.status(400).json({ ok: false, error: 'Task title is required.' });
  const { data, error } = await supabase.from('taskmind_tasks')
    .insert({ user_id: req.user.sub, title: String(title).slice(0, 300), notes: notes || null, due_date: dueDate || null, priority: priority || 'medium', energy_tag: energyTag || 'any' })
    .select('*').single();
  if (error) { console.error('taskmind POST task failed:', error.message); return res.status(500).json({ ok: false, error: 'Could not create task.' }); }
  res.json({ ok: true, task: data });
}));

app.put('/api/taskmind/tasks/:id', requireAuth, asyncRoute(async (req, res) => {
  if (!requireSupabase(res)) return;
  const { title, notes, dueDate, priority, energyTag, status } = req.body || {};
  const updates = {};
  if (title !== undefined) updates.title = String(title).slice(0, 300);
  if (notes !== undefined) updates.notes = notes;
  if (dueDate !== undefined) updates.due_date = dueDate;
  if (priority !== undefined) updates.priority = priority;
  if (energyTag !== undefined) updates.energy_tag = energyTag;
  if (status !== undefined) {
    if (!['todo', 'in_progress', 'done'].includes(status)) return res.status(400).json({ ok: false, error: 'Invalid status.' });
    updates.status = status;
    updates.completed_at = status === 'done' ? new Date().toISOString() : null;
  }
  const { data, error } = await supabase.from('taskmind_tasks').update(updates).eq('id', req.params.id).eq('user_id', req.user.sub).select('*').maybeSingle();
  if (error) console.error('taskmind PUT task failed:', error.message);
  if (error || !data) return res.status(404).json({ ok: false, error: 'Task not found.' });
  res.json({ ok: true, task: data });
}));

app.delete('/api/taskmind/tasks/:id', requireAuth, asyncRoute(async (req, res) => {
  if (!requireSupabase(res)) return;
  const { error, count } = await supabase.from('taskmind_tasks').delete({ count: 'exact' }).eq('id', req.params.id).eq('user_id', req.user.sub);
  if (error) { console.error('taskmind DELETE task failed:', error.message); return res.status(500).json({ ok: false, error: 'Could not delete task.' }); }
  if (!count) return res.status(404).json({ ok: false, error: 'Task not found.' });
  res.json({ ok: true });
}));

/* ════════════════════════════════════════════════════════════════════
   TEAMPING — shared channels + messages. See schema comment: this is one
   open workspace shared across all AppAholic users, not isolated private
   teams. Polling-based (no websockets/Supabase Realtime wired up), so the
   frontend refetches periodically rather than getting a live push.
   ════════════════════════════════════════════════════════════════════ */

app.get('/api/teamping/channels', requireAuth, asyncRoute(async (req, res) => {
  if (!requireSupabase(res)) return;
  const { data, error } = await supabase.from('teamping_channels').select('*').order('created_at', { ascending: true });
  if (error) { console.error('teamping GET channels failed:', error.message); return res.status(500).json({ ok: false, error: 'Could not load channels.' }); }
  res.json({ ok: true, channels: data });
}));

app.post('/api/teamping/channels', requireAuth, asyncRoute(async (req, res) => {
  if (!requireSupabase(res)) return;
  const { name } = req.body || {};
  if (!name) return res.status(400).json({ ok: false, error: 'Channel name is required.' });
  const { data, error } = await supabase.from('teamping_channels').insert({ name: String(name).slice(0, 80), created_by: req.user.sub }).select('*').single();
  if (error) { console.error('teamping POST channel failed:', error.message); return res.status(500).json({ ok: false, error: 'Could not create channel.' }); }
  res.json({ ok: true, channel: data });
}));

app.get('/api/teamping/channels/:id/messages', requireAuth, asyncRoute(async (req, res) => {
  if (!requireSupabase(res)) return;
  const { data, error } = await supabase.from('teamping_messages').select('*, profiles(full_name, email, avatar_url)').eq('channel_id', req.params.id).order('created_at', { ascending: true }).limit(200);
  if (error) { console.error('teamping GET messages failed:', error.message); return res.status(500).json({ ok: false, error: 'Could not load messages.' }); }
  res.json({ ok: true, messages: data });
}));

app.post('/api/teamping/channels/:id/messages', requireAuth, strictLimiter, asyncRoute(async (req, res) => {
  if (!requireSupabase(res)) return;
  const { content } = req.body || {};
  if (!content || !content.trim()) return res.status(400).json({ ok: false, error: 'Message cannot be empty.' });
  if (content.length > 2000) return res.status(400).json({ ok: false, error: 'Message is too long.' });
  const { data, error } = await supabase.from('teamping_messages')
    .insert({ channel_id: req.params.id, user_id: req.user.sub, content: content.trim() })
    .select('*, profiles(full_name, email, avatar_url)').single();
  if (error) { console.error('teamping POST message failed:', error.message); return res.status(500).json({ ok: false, error: 'Could not send message.' }); }
  res.json({ ok: true, message: data });
}));

/* ════════════════════════════════════════════════════════════════════
   QUICKNOTE — per-app API. Pattern for future web apps: namespaced routes,
   same requireAuth + Supabase service-role pattern as everything else.
   ════════════════════════════════════════════════════════════════════ */

app.get('/api/quicknote/notes', requireAuth, asyncRoute(async (req, res) => {
  if (!requireSupabase(res)) return;
  const { data, error } = await supabase.from('quicknote_notes').select('*').eq('user_id', req.user.sub).order('updated_at', { ascending: false });
  if (error) { console.error('quicknote GET notes failed:', error.message, '| user_id:', req.user.sub); return res.status(500).json({ ok: false, error: 'Could not load notes.' }); }
  res.json({ ok: true, notes: data });
}));

app.post('/api/quicknote/notes', requireAuth, asyncRoute(async (req, res) => {
  if (!requireSupabase(res)) return;
  const { title, content, tags } = req.body || {};
  const { data, error } = await supabase.from('quicknote_notes')
    .insert({ user_id: req.user.sub, title: (title || 'Untitled').slice(0, 200), content: content || '', tags: Array.isArray(tags) ? tags.slice(0, 20) : [] })
    .select('*').single();
  if (error) { console.error('quicknote POST note failed:', error.message, '| user_id:', req.user.sub); return res.status(500).json({ ok: false, error: 'Could not create note.' }); }
  res.json({ ok: true, note: data });
}));

app.put('/api/quicknote/notes/:id', requireAuth, asyncRoute(async (req, res) => {
  if (!requireSupabase(res)) return;
  const { title, content, tags } = req.body || {};
  const updates = { updated_at: new Date().toISOString() };
  if (title !== undefined) updates.title = String(title).slice(0, 200) || 'Untitled';
  if (content !== undefined) updates.content = String(content);
  if (tags !== undefined) updates.tags = Array.isArray(tags) ? tags.slice(0, 20) : [];

  const { data, error } = await supabase.from('quicknote_notes')
    .update(updates).eq('id', req.params.id).eq('user_id', req.user.sub) // scoped to owner — can't touch someone else's note
    .select('*').maybeSingle();
  if (error) { console.error('quicknote PUT note failed:', error.message, '| user_id:', req.user.sub); return res.status(500).json({ ok: false, error: 'Could not save note.' }); }
  if (!data) return res.status(404).json({ ok: false, error: 'Note not found.' });
  res.json({ ok: true, note: data });
}));

app.delete('/api/quicknote/notes/:id', requireAuth, asyncRoute(async (req, res) => {
  if (!requireSupabase(res)) return;
  const { error, count } = await supabase.from('quicknote_notes').delete({ count: 'exact' }).eq('id', req.params.id).eq('user_id', req.user.sub);
  if (error) { console.error('quicknote DELETE note failed:', error.message, '| user_id:', req.user.sub); return res.status(500).json({ ok: false, error: 'Could not delete note.' }); }
  if (!count) return res.status(404).json({ ok: false, error: 'Note not found.' });
  res.json({ ok: true });
}));

/* ════════════════════════════════════════════════════════════════════
   ADMIN PANEL — separate auth, read-mostly views over the business data.
   ════════════════════════════════════════════════════════════════════ */

app.post('/api/admin/login', adminLoginLimiter, asyncRoute(async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ ok: false, error: 'Email and password required.' });
  if (!ADMIN_PANEL_EMAIL || !ADMIN_PANEL_PASSWORD_HASH) return res.status(503).json({ ok: false, error: 'Admin panel is not configured yet.' });

  // Constant-time-ish: always run the password check even on email mismatch, so a wrong
  // email doesn't return faster than a wrong password (avoids trivially timing email guesses).
  const emailMatches = email.toLowerCase() === ADMIN_PANEL_EMAIL.toLowerCase();
  const passwordMatches = verifyAdminPassword(password);
  if (!emailMatches || !passwordMatches) return res.status(401).json({ ok: false, error: 'Invalid email or password.' });

  res.json({ ok: true, token: signAdminSession(ADMIN_PANEL_EMAIL) });
}));

app.get('/api/admin/me', requireAdmin, (req, res) => res.json({ ok: true, admin: { email: req.admin.email } }));

app.get('/api/admin/overview', requireAdmin, asyncRoute(async (req, res) => {
  if (!requireSupabase(res)) return;
  const [profiles, requests, messages, purchases, subs] = await Promise.all([
    supabase.from('profiles').select('id', { count: 'exact', head: true }),
    supabase.from('app_requests').select('id', { count: 'exact', head: true }),
    supabase.from('contact_messages').select('id', { count: 'exact', head: true }),
    supabase.from('purchases').select('amount').eq('status', 'completed'),
    supabase.from('subscriptions').select('id', { count: 'exact', head: true }).eq('status', 'active'),
  ]);
  const totalRevenue = (purchases.data || []).reduce((sum, p) => sum + Number(p.amount || 0), 0);
  res.json({
    ok: true,
    stats: {
      totalUsers: profiles.count || 0,
      totalRequests: requests.count || 0,
      totalMessages: messages.count || 0,
      totalPurchases: (purchases.data || []).length,
      totalRevenue,
      activeSubscriptions: subs.count || 0,
    },
  });
}));

app.get('/api/admin/requests', requireAdmin, asyncRoute(async (req, res) => {
  if (!requireSupabase(res)) return;
  const { data, error } = await supabase.from('app_requests').select('*').order('created_at', { ascending: false }).limit(200);
  if (error) return res.status(500).json({ ok: false, error: 'Could not load requests.' });
  res.json({ ok: true, requests: data });
}));

app.patch('/api/admin/requests/:id', requireAdmin, asyncRoute(async (req, res) => {
  if (!requireSupabase(res)) return;
  const { status } = req.body || {};
  if (!['submitted', 'in_progress', 'under_review', 'built', 'declined'].includes(status)) return res.status(400).json({ ok: false, error: 'Invalid status.' });
  const { data, error } = await supabase.from('app_requests').update({ status }).eq('id', req.params.id).select('*').maybeSingle();
  if (error || !data) return res.status(500).json({ ok: false, error: 'Could not update request.' });
  res.json({ ok: true, request: data });
}));

app.get('/api/admin/messages', requireAdmin, asyncRoute(async (req, res) => {
  if (!requireSupabase(res)) return;
  const { data, error } = await supabase.from('contact_messages').select('*').order('created_at', { ascending: false }).limit(200);
  if (error) return res.status(500).json({ ok: false, error: 'Could not load messages.' });
  res.json({ ok: true, messages: data });
}));

app.get('/api/admin/purchases', requireAdmin, asyncRoute(async (req, res) => {
  if (!requireSupabase(res)) return;
  const { data, error } = await supabase.from('purchases').select('*, apps(name)').order('created_at', { ascending: false }).limit(200);
  if (error) return res.status(500).json({ ok: false, error: 'Could not load purchases.' });
  res.json({ ok: true, purchases: data });
}));

app.get('/api/admin/subscriptions', requireAdmin, asyncRoute(async (req, res) => {
  if (!requireSupabase(res)) return;
  const { data, error } = await supabase.from('subscriptions').select('*').order('created_at', { ascending: false }).limit(200);
  if (error) return res.status(500).json({ ok: false, error: 'Could not load subscriptions.' });
  res.json({ ok: true, subscriptions: data });
}));

/* ════════════════════════════════════════════════════════════════════
   ADMIN — APPS CATALOGUE MANAGEMENT. Add/edit catalogue entries, wire
   launch_url (web apps) or storage_path (files), toggle active state.
   ════════════════════════════════════════════════════════════════════ */

// GET all apps regardless of active state (the public /api/apps only returns active ones).
app.get('/api/admin/apps', requireAdmin, asyncRoute(async (req, res) => {
  if (!requireSupabase(res)) return;
  const { data, error } = await supabase.from('apps').select('*').order('created_at', { ascending: false });
  if (error) { console.error('admin GET apps failed:', error.message); return res.status(500).json({ ok: false, error: 'Could not load apps.' }); }
  res.json({ ok: true, apps: data });
}));

app.post('/api/admin/apps', requireAdmin, asyncRoute(async (req, res) => {
  if (!requireSupabase(res)) return;
  const b = req.body || {};
  if (!b.id || !b.name || !b.category || !b.platform) return res.status(400).json({ ok: false, error: 'id, name, category and platform are required.' });
  if (!/^[a-z0-9-]+$/.test(b.id)) return res.status(400).json({ ok: false, error: 'id must be lowercase letters, numbers and hyphens only (used in URLs and storage paths).' });
  if (!['web', 'desktop', 'mobile'].includes(b.platform)) return res.status(400).json({ ok: false, error: 'platform must be web, desktop or mobile.' });

  const { data, error } = await supabase.from('apps').insert({
    id: b.id, name: b.name, category: b.category, platform: b.platform,
    os: Array.isArray(b.os) ? b.os : [], price: Number(b.price) || 0,
    tag: b.tag || null, icon: b.icon || '📦', banner_color: b.bannerColor || '#F0EBDF',
    description: b.description || '', long_description: b.longDescription || '',
    features: Array.isArray(b.features) ? b.features : [], tags: Array.isArray(b.tags) ? b.tags : [],
    launch_url: b.launchUrl || null, storage_path: b.storagePath || null, active: b.active !== false,
  }).select('*').single();
  if (error) { console.error('admin POST app failed:', error.message); return res.status(500).json({ ok: false, error: error.message.includes('duplicate') ? 'An app with this id already exists.' : 'Could not create app.' }); }
  res.json({ ok: true, app: data });
}));

app.put('/api/admin/apps/:id', requireAdmin, asyncRoute(async (req, res) => {
  if (!requireSupabase(res)) return;
  const b = req.body || {};
  const updates = {};
  const map = {
    name: 'name', category: 'category', platform: 'platform', os: 'os', price: 'price',
    tag: 'tag', icon: 'icon', bannerColor: 'banner_color', description: 'description',
    longDescription: 'long_description', features: 'features', tags: 'tags',
    launchUrl: 'launch_url', storagePath: 'storage_path', active: 'active', rating: 'rating',
  };
  Object.keys(map).forEach(k => { if (b[k] !== undefined) updates[map[k]] = b[k]; });
  if (updates.platform && !['web', 'desktop', 'mobile'].includes(updates.platform)) return res.status(400).json({ ok: false, error: 'Invalid platform.' });

  const { data, error } = await supabase.from('apps').update(updates).eq('id', req.params.id).select('*').maybeSingle();
  if (error) console.error('admin PUT app failed:', error.message);
  if (error || !data) return res.status(404).json({ ok: false, error: 'App not found.' });
  res.json({ ok: true, app: data });
}));

app.delete('/api/admin/apps/:id', requireAdmin, asyncRoute(async (req, res) => {
  if (!requireSupabase(res)) return;
  const { error, count } = await supabase.from('apps').delete({ count: 'exact' }).eq('id', req.params.id);
  if (error) { console.error('admin DELETE app failed:', error.message); return res.status(500).json({ ok: false, error: 'Could not delete app. If it has purchases/downloads linked, deactivate it instead (active: false) rather than deleting.' }); }
  if (!count) return res.status(404).json({ ok: false, error: 'App not found.' });
  res.json({ ok: true });
}));

// POST an installer file (.apk, .exe, .dmg, etc.) — uploads to Supabase Storage and
// sets that app's storage_path automatically.
//
// REAL CONSTRAINT, not hidden: this proxies the upload through this Vercel serverless
// function, which has a platform-level request body size cap that Express config
// cannot override (varies by Vercel plan, commonly a few MB on lower tiers). Small
// files will work fine here. For anything large — most real .apk/.exe/.dmg installers
// easily exceed that — upload the file directly via the Supabase dashboard's Storage
// section instead (Storage → app-files bucket → upload → copy the resulting path),
// then paste that path into the "Storage Path" field in the edit form below rather
// than using this upload button. This route stays useful for smaller files and for
// icons/screenshots.
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 20 * 1024 * 1024 } }); // 20MB soft cap — see note above

app.post('/api/admin/apps/:id/upload', requireAdmin, (req, res, next) => {
  upload.single('file')(req, res, (err) => {
    if (err) return res.status(413).json({ ok: false, error: err.code === 'LIMIT_FILE_SIZE' ? 'File too large for direct upload here (20MB limit on this route) — use the Supabase dashboard to upload larger files directly, then paste the resulting Storage Path into the edit form.' : 'Upload failed.' });
    next();
  });
}, asyncRoute(async (req, res) => {
  if (!requireSupabase(res)) return;
  if (!req.file) return res.status(400).json({ ok: false, error: 'No file provided.' });

  const { data: app } = await supabase.from('apps').select('id').eq('id', req.params.id).maybeSingle();
  if (!app) return res.status(404).json({ ok: false, error: 'App not found.' });

  const safeFilename = req.file.originalname.replace(/[^a-zA-Z0-9._-]/g, '_');
  const storagePath = `${req.params.id}/${Date.now()}-${safeFilename}`;

  const { error: uploadErr } = await supabase.storage.from('app-files').upload(storagePath, req.file.buffer, { contentType: req.file.mimetype, upsert: false });
  if (uploadErr) { console.error('admin file upload failed:', uploadErr.message); return res.status(500).json({ ok: false, error: 'Upload to storage failed: ' + uploadErr.message }); }

  const { data, error } = await supabase.from('apps').update({ storage_path: storagePath }).eq('id', req.params.id).select('*').single();
  if (error) { console.error('admin update storage_path failed:', error.message); return res.status(500).json({ ok: false, error: 'File uploaded but could not update the app record. Set Storage Path manually to: ' + storagePath }); }
  res.json({ ok: true, app: data, storagePath });
}));

app.get('/api/health', (req, res) => res.json({
  ok: true,
  smtp: !missing.includes('GMAIL_USER') && !missing.includes('GMAIL_APP_PASSWORD'),
  oauth: !missing.includes('GOOGLE_CLIENT_ID') && !missing.includes('GOOGLE_CLIENT_SECRET'),
  database: !!supabase,
  session: !missing.includes('SESSION_SECRET'),
  admin: !!(ADMIN_PANEL_EMAIL && ADMIN_PANEL_PASSWORD_HASH),
  uptime: process.uptime(),
}));

/* ── 404 + ERROR HANDLERS ─────────────────────────────────────────── */
app.use((req, res) => res.status(404).json({ ok: false, error: 'Not found' }));
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  if (err && err.message === 'Not allowed by CORS') return res.status(403).json({ ok: false, error: 'Origin not allowed.' });
  console.error('Unhandled error:', err);
  res.status(500).json({ ok: false, error: 'Internal server error.' });
});

const PORT = process.env.PORT || 4000;
if (require.main === module) app.listen(PORT, () => console.log(`✅ AppAholic server on :${PORT}`));
process.on('unhandledRejection', reason => console.error('Unhandled rejection:', reason));

module.exports = app;
