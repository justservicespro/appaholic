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
const SITE_URL    = process.env.SITE_URL || 'https://appaholic.justservices.pro';

async function sendMail({ to, subject, html, replyTo }) {
  return transporter.sendMail({ from: FROM, to: cleanHeader(to), subject: cleanHeader(subject), html, ...(replyTo ? { replyTo: cleanHeader(replyTo) } : {}) });
}

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

    sendMail({
      to: ADMIN_EMAIL,
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
   APPS (marketplace catalogue — read from Supabase)
   ════════════════════════════════════════════════════════════════════ */
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
    await sendMail({
      to: ADMIN_EMAIL, replyTo: email,
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
    await sendMail({
      to: ADMIN_EMAIL, replyTo: email,
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
    await sendMail({
      to: ADMIN_EMAIL,
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
    await sendMail({ to: ADMIN_EMAIL, subject: `Alert: ${cleanHeader(subject||'AppAholic Alert')}`, html: wrapEmail({ title: esc(subject)||'Alert', bodyHtml: `<p>${esc(message)||''}</p>` }) });
    res.json({ ok: true });
  } catch (err) {
    console.error('admin-alert:', err.message);
    res.status(502).json({ ok: false, error: 'Could not send email right now.' });
  }
}));

/* ── HEALTH ── */
app.get('/api/health', (req, res) => res.json({
  ok: true,
  smtp: !missing.includes('GMAIL_USER') && !missing.includes('GMAIL_APP_PASSWORD'),
  oauth: !missing.includes('GOOGLE_CLIENT_ID') && !missing.includes('GOOGLE_CLIENT_SECRET'),
  database: !!supabase,
  session: !missing.includes('SESSION_SECRET'),
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
