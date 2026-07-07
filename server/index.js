/**
 * AppAholic — Email + Auth Server
 * Gmail SMTP (Nodemailer) + Google OAuth 2.0
 *
 * Deploy: Vercel (serverless) or any Node.js host
 * Local:  npm install && npm run dev
 */

const express       = require('express');
const cors          = require('cors');
const helmet        = require('helmet');
const rateLimit     = require('express-rate-limit');
const nodemailer    = require('nodemailer');
const { google }    = require('googleapis');
require('dotenv').config();

/* ── ENV VALIDATION ──────────────────────────────────────────────── */
// Fail loudly (but don't crash a running process) if required config is missing.
const REQUIRED_ENV = ['GMAIL_USER', 'GMAIL_APP_PASSWORD'];
const OAUTH_ENV    = ['GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET'];
const missingRequired = REQUIRED_ENV.filter(k => !process.env[k]);
const missingOAuth    = OAUTH_ENV.filter(k => !process.env[k]);

if (missingRequired.length) {
  console.error(`❌ Missing required env vars: ${missingRequired.join(', ')}. Email sending will fail until these are set.`);
}
if (missingOAuth.length) {
  console.warn(`⚠️  Missing Google OAuth env vars: ${missingOAuth.join(', ')}. /auth/google routes will fail until these are set.`);
}

const app = express();

/* ── SECURITY / PARSING MIDDLEWARE ───────────────────────────────── */
app.disable('x-powered-by');
app.set('trust proxy', 1); // required on Vercel/behind a proxy so rate-limit + req.ip work correctly

app.use(helmet({
  contentSecurityPolicy: false, // this is a JSON API, not serving HTML — CSP not applicable
  crossOriginResourcePolicy: { policy: 'cross-origin' },
}));

app.use(express.json({ limit: '100kb' }));

const allowedOrigins = process.env.ALLOWED_ORIGIN
  ? process.env.ALLOWED_ORIGIN.split(',').map(s => s.trim())
  : ['https://appaholic.justservices.pro', 'http://localhost:3000'];

app.use(cors({
  origin(origin, callback) {
    // Allow same-origin/non-browser requests (no Origin header) and health checks.
    if (!origin || allowedOrigins.includes(origin)) return callback(null, true);
    return callback(new Error('Not allowed by CORS'));
  },
  credentials: true,
}));

// Global request rate limit — protects against basic abuse/DoS.
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 300,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(globalLimiter);

// Stricter limit on endpoints that send email or touch auth — prevents spam/email-bombing.
const strictLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { ok: false, error: 'Too many requests. Please try again later.' },
});

/* ── HELPERS ──────────────────────────────────────────────────────── */

// Escape user-supplied text before it's interpolated into HTML emails.
// Prevents HTML/script injection into outgoing mail (stored/reflected XSS via email clients).
function esc(value) {
  if (value === undefined || value === null) return '';
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// Strip line breaks from anything that ends up in an email header (subject, to, from)
// to prevent SMTP header injection.
function cleanHeader(value) {
  return String(value || '').replace(/[\r\n]+/g, ' ').trim();
}

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
function isValidEmail(value) {
  return typeof value === 'string' && EMAIL_RE.test(value) && value.length <= 254;
}

// Only allow http(s) URLs into email CTA buttons/links — blocks javascript: and data: URIs.
function safeUrl(value, fallback) {
  try {
    const u = new URL(value);
    if (u.protocol === 'http:' || u.protocol === 'https:') return u.toString();
  } catch { /* fall through */ }
  return fallback;
}

/* ── SMTP ────────────────────────────────────────────────────────── */
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: { user: process.env.GMAIL_USER, pass: process.env.GMAIL_APP_PASSWORD },
});

if (!missingRequired.length) {
  transporter.verify(err =>
    err
      ? console.error('❌ SMTP verify failed:', err.message)
      : console.log('✅ SMTP ready via', process.env.GMAIL_USER)
  );
}

const FROM        = `"AppAholic" <${process.env.GMAIL_USER || 'no-reply@justservices.pro'}>`;
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || process.env.GMAIL_USER;
const SITE_URL    = process.env.SITE_URL    || 'https://appaholic.justservices.pro';

/* ── GOOGLE OAUTH CLIENT ─────────────────────────────────────────── */
const oAuth2Client = new google.auth.OAuth2(
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET,
  process.env.GOOGLE_CALLBACK_URL || 'https://api.appaholic.justservices.pro/auth/google/callback'
);

const OAUTH_SCOPES = [
  'https://www.googleapis.com/auth/userinfo.email',
  'https://www.googleapis.com/auth/userinfo.profile',
  'openid',
];

/* ── EMAIL TEMPLATE ──────────────────────────────────────────────── */
function wrapEmail({ preheader = '', title, bodyHtml, ctaText, ctaUrl }) {
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"/></head>
<body style="margin:0;padding:0;background:#F7F7FB;font-family:-apple-system,Segoe UI,Inter,Arial,sans-serif;">
  <span style="display:none;max-height:0;overflow:hidden;">${esc(preheader)}</span>
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#F7F7FB;padding:32px 16px;">
    <tr><td align="center">
      <table width="100%" style="max-width:520px;background:#fff;border-radius:20px;overflow:hidden;border:1px solid #E4E4F0;">
        <tr><td style="background:#0A0A0F;padding:26px 32px;">
          <span style="font-size:19px;font-weight:800;color:#fff;letter-spacing:-.5px;">
            <span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:#C8FF00;margin-right:8px;"></span>
            AppAholic
          </span>
        </td></tr>
        <tr><td style="padding:30px 32px;">
          <h1 style="margin:0 0 14px;font-size:19px;font-weight:800;color:#0A0A0F;letter-spacing:-.3px;">${title}</h1>
          <div style="font-size:14px;line-height:1.75;color:#2E2E3E;">${bodyHtml}</div>
          ${ctaText && ctaUrl ? `<div style="margin-top:26px;"><a href="${ctaUrl}" style="display:inline-block;background:#0A0A0F;color:#fff;text-decoration:none;padding:12px 28px;border-radius:999px;font-size:14px;font-weight:700;">${esc(ctaText)}</a></div>` : ''}
        </td></tr>
        <tr><td style="padding:18px 32px;border-top:1px solid #E4E4F0;background:#F7F7FB;font-size:12px;color:#6B6B85;line-height:1.6;">
          AppAholic — a product of <strong>JustServicesPro Management and Consulting Ltd</strong><br/>
          <a href="mailto:info@justservices.pro" style="color:#4B3EFF;">info@justservices.pro</a>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body></html>`;
}

async function sendMail({ to, subject, html, replyTo }) {
  return transporter.sendMail({
    from: FROM,
    to: cleanHeader(to),
    subject: cleanHeader(subject),
    html,
    ...(replyTo ? { replyTo: cleanHeader(replyTo) } : {}),
  });
}

// Wraps a route handler so thrown/rejected errors land in the global error handler
// instead of crashing the process or hanging the request.
function asyncRoute(fn) {
  return (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
}

/* ════════════════════════════════════════════════════════════════════
   GOOGLE OAUTH ROUTES
   ════════════════════════════════════════════════════════════════════ */

/**
 * GET /auth/google
 * Redirect user to Google's consent screen.
 * Frontend: window.location.href = API_BASE + '/auth/google'
 */
app.get('/auth/google', strictLimiter, (req, res) => {
  if (missingOAuth.length) {
    return res.redirect(`${SITE_URL}/auth?error=oauth_not_configured`);
  }
  // Only allow redirecting back to our own site — prevents open-redirect via ?redirect=
  const requested = typeof req.query.redirect === 'string' ? req.query.redirect : '';
  const redirectTarget = requested.startsWith(SITE_URL) ? requested : `${SITE_URL}/dashboard`;

  const url = oAuth2Client.generateAuthUrl({
    access_type: 'offline',
    scope: OAUTH_SCOPES,
    prompt: 'select_account',
    state: redirectTarget,
  });
  res.redirect(url);
});

/**
 * GET /auth/google/callback
 * Google redirects here after user consents.
 * Exchanges code for tokens, fetches profile, creates/updates user session.
 */
app.get('/auth/google/callback', asyncRoute(async (req, res) => {
  const { code, state, error } = req.query;

  if (error || !code) {
    console.error('OAuth error:', error);
    return res.redirect(`${SITE_URL}/auth?error=oauth_denied`);
  }

  try {
    // Exchange code for tokens
    const { tokens } = await oAuth2Client.getToken(code);
    oAuth2Client.setCredentials(tokens);

    // Fetch user profile from Google
    const oauth2 = google.oauth2({ version: 'v2', auth: oAuth2Client });
    const { data: profile } = await oauth2.userinfo.get();

    const user = {
      id:        profile.id,
      email:     profile.email,
      name:      profile.name,
      firstName: profile.given_name,
      lastName:  profile.family_name,
      avatar:    profile.picture,
      provider:  'google',
      verified:  profile.verified_email,
    };

    // Send welcome email on first login (best-effort — never blocks the redirect)
    sendMail({
      to: user.email,
      subject: `Welcome to AppAholic, ${user.firstName || 'there'}!`,
      html: wrapEmail({
        preheader: 'Your AppAholic account is ready.',
        title: `Welcome, ${esc(user.firstName || 'there')}! 🎉`,
        bodyHtml: `<p>You signed in with Google. Your account is ready — browse Web, Desktop and Mobile apps whenever you like.</p>`,
        ctaText: 'Go to My Dashboard',
        ctaUrl: `${SITE_URL}/dashboard`,
      }),
    }).catch(mailErr => console.warn('Welcome email failed (non-fatal):', mailErr.message));

    sendMail({
      to: ADMIN_EMAIL,
      subject: `New Google sign-in: ${cleanHeader(user.email)}`,
      html: wrapEmail({
        title: 'New Google Sign-In',
        bodyHtml: `<p><strong>${esc(user.name)}</strong> (${esc(user.email)}) just signed in via Google OAuth.</p>`,
      }),
    }).catch(mailErr => console.warn('Admin alert email failed (non-fatal):', mailErr.message));

    // Encode user data and redirect to frontend with session token.
    // NOTE: this is a lightweight, unsigned payload meant only for pre-filling the UI —
    // it is not a verified session. Do not use it server-side to authorize privileged
    // actions. For real authenticated sessions, replace with a signed JWT or a
    // server-side session store (Redis/DB) before adding paid/admin features that
    // depend on trusting this identity.
    const userPayload = Buffer.from(JSON.stringify(user)).toString('base64url');
    const redirectTo  = state && String(state).startsWith(SITE_URL) ? state : `${SITE_URL}/dashboard`;
    res.redirect(`${redirectTo}?oauth_session=${userPayload}`);

  } catch (err) {
    console.error('OAuth callback error:', err.message);
    res.redirect(`${SITE_URL}/auth?error=oauth_failed`);
  }
}));

/**
 * POST /auth/session
 * Frontend sends the oauth_session token to decode and get user data back.
 * See note above re: this not being a verified/signed session.
 */
app.post('/auth/session', (req, res) => {
  const { token } = req.body || {};
  if (!token || typeof token !== 'string') return res.status(401).json({ ok: false, error: 'No token' });
  try {
    const user = JSON.parse(Buffer.from(token, 'base64url').toString('utf8'));
    res.json({ ok: true, user });
  } catch {
    res.status(401).json({ ok: false, error: 'Invalid token' });
  }
});

/**
 * POST /auth/logout
 */
app.post('/auth/logout', (req, res) => {
  res.json({ ok: true });
});

/* ════════════════════════════════════════════════════════════════════
   EMAIL ROUTES
   ════════════════════════════════════════════════════════════════════ */

app.post('/api/request-app', strictLimiter, asyncRoute(async (req, res) => {
  const { name, email, phone, role, title, category, platform, audience,
          users, problem, features, inspiration, integrations, extra,
          timeline, budget, delivery, source } = req.body || {};

  if (!name || !email || !title || !problem)
    return res.status(400).json({ ok: false, error: 'Missing required fields.' });
  if (!isValidEmail(email))
    return res.status(400).json({ ok: false, error: 'Invalid email address.' });

  try {
    await sendMail({
      to: email,
      subject: `We received your app request: "${cleanHeader(title)}"`,
      html: wrapEmail({
        preheader: 'Your AppAholic app request has been received.',
        title: `Thanks, ${esc(String(name).split(' ')[0])} 🎉`,
        bodyHtml: `
          <p>We've received your request for <strong>${esc(title)}</strong> and will review it within <strong>48 hours</strong>.</p>
          <table width="100%" style="margin:18px 0;border-collapse:collapse;font-size:13px;">
            <tr><td style="padding:7px 0;color:#6B6B85;">Category</td><td style="padding:7px 0;text-align:right;font-weight:600;">${esc(category)||'—'}</td></tr>
            <tr style="border-top:1px solid #E4E4F0;"><td style="padding:7px 0;color:#6B6B85;">Platform</td><td style="padding:7px 0;text-align:right;font-weight:600;">${esc(platform)||'—'}</td></tr>
            <tr style="border-top:1px solid #E4E4F0;"><td style="padding:7px 0;color:#6B6B85;">Budget</td><td style="padding:7px 0;text-align:right;font-weight:600;">${esc(budget)||'Flexible'}</td></tr>
            <tr style="border-top:1px solid #E4E4F0;"><td style="padding:7px 0;color:#6B6B85;">Timeline</td><td style="padding:7px 0;text-align:right;font-weight:600;">${esc(timeline)||'No rush'}</td></tr>
          </table>
          <p>If your request enters the build queue, you'll get early access for free as a thank-you.</p>`,
        ctaText: 'Browse Apps', ctaUrl: SITE_URL,
      }),
    });
    await sendMail({
      to: ADMIN_EMAIL, replyTo: isValidEmail(email) ? email : undefined,
      subject: `New app request: "${cleanHeader(title)}" from ${cleanHeader(name)}`,
      html: wrapEmail({
        title: 'New App Request',
        bodyHtml: `
          <table width="100%" style="border-collapse:collapse;font-size:13px;">
            ${[
              ['Requester', `${esc(name)} (${esc(email)}${phone ? ', ' + esc(phone) : ''})`],
              ['Role', esc(role) || '—'],
              ['App Title', esc(title)],
              ['Category', esc(category) || '—'],
              ['Platform', esc(platform) || '—'],
              ['Audience', `${esc(audience) || '—'} (${esc(users) || '?'} users)`],
              ['Problem', esc(problem)],
              ['Features', esc(features) || '—'],
              ['Inspiration', esc(inspiration) || '—'],
              ['Integrations', esc(integrations) || '—'],
              ['Budget', esc(budget) || 'Flexible'],
              ['Timeline', esc(timeline) || 'No rush'],
              ['Delivery', esc(delivery) || '—'],
              ['Source', esc(source) || '—'],
              ['Extra', esc(extra) || '—'],
            ].map(([l, v]) => `<tr><td style="padding:5px 0;color:#6B6B85;width:130px;">${l}</td><td style="padding:5px 0;font-weight:500;">${v}</td></tr>`).join('')}
          </table>`,
        ctaText: 'Admin Dashboard', ctaUrl: `${SITE_URL}/admin`,
      }),
    });
    res.json({ ok: true });
  } catch (err) {
    console.error('request-app:', err.message);
    res.status(502).json({ ok: false, error: 'Could not send email right now.' });
  }
}));

app.post('/api/signup', strictLimiter, asyncRoute(async (req, res) => {
  const { firstName, email } = req.body || {};
  if (!email) return res.status(400).json({ ok: false, error: 'Email required.' });
  if (!isValidEmail(email)) return res.status(400).json({ ok: false, error: 'Invalid email address.' });

  try {
    await sendMail({
      to: email, subject: 'Welcome to AppAholic',
      html: wrapEmail({
        preheader: 'Your AppAholic account is ready.',
        title: `Welcome, ${esc(firstName) || 'there'}!`,
        bodyHtml: `<p>Your account is ready. Browse Web, Desktop and Mobile apps and re-download any purchase anytime from your dashboard.</p>`,
        ctaText: 'Go to Dashboard', ctaUrl: `${SITE_URL}/dashboard`,
      }),
    });
    await sendMail({
      to: ADMIN_EMAIL, subject: `New signup: ${cleanHeader(email)}`,
      html: wrapEmail({ title: 'New Signup', bodyHtml: `<p><strong>${esc(firstName)||''}</strong> signed up with <strong>${esc(email)}</strong>.</p>` }),
    });
    res.json({ ok: true });
  } catch (err) {
    console.error('signup:', err.message);
    res.status(502).json({ ok: false, error: 'Could not send email right now.' });
  }
}));

app.post('/api/forgot-password', strictLimiter, asyncRoute(async (req, res) => {
  const { email, resetLink } = req.body || {};
  if (!email) return res.status(400).json({ ok: false, error: 'Email required.' });
  if (!isValidEmail(email)) return res.status(400).json({ ok: false, error: 'Invalid email address.' });

  try {
    await sendMail({
      to: email, subject: 'Reset your AppAholic password',
      html: wrapEmail({
        preheader: 'Reset your password — link expires in 30 minutes.',
        title: 'Reset your password',
        bodyHtml: `<p>Click below to reset your password. This link expires in 30 minutes. Ignore this email if you didn't request a reset.</p>`,
        ctaText: 'Reset Password', ctaUrl: safeUrl(resetLink, `${SITE_URL}/auth`),
      }),
    });
    res.json({ ok: true });
  } catch (err) {
    console.error('forgot-password:', err.message);
    res.status(502).json({ ok: false, error: 'Could not send email right now.' });
  }
}));

app.post('/api/order-confirmation', strictLimiter, asyncRoute(async (req, res) => {
  const { email, name, appName, amount, currency, ref, downloadUrl } = req.body || {};
  if (!email || !appName) return res.status(400).json({ ok: false, error: 'Missing fields.' });
  if (!isValidEmail(email)) return res.status(400).json({ ok: false, error: 'Invalid email address.' });

  const isFree = !amount || Number(amount) === 0;
  const amountStr = Number.isFinite(Number(amount)) ? Number(amount).toLocaleString() : '0';

  try {
    await sendMail({
      to: email,
      subject: isFree ? `Your download: ${cleanHeader(appName)}` : `Receipt — ${cleanHeader(appName)} (₦${amountStr})`,
      html: wrapEmail({
        preheader: `${esc(appName)} is ready`,
        title: isFree ? `${esc(appName)} is ready` : 'Payment received — thank you!',
        bodyHtml: `<p>Hi ${esc(name)||'there'},</p><p>${isFree?`Your free download of <strong>${esc(appName)}</strong> is ready.`:`We received your payment of <strong>${esc(currency)||'₦'}${amountStr}</strong> for <strong>${esc(appName)}</strong>.`}${ref?`<br/><small style="color:#6B6B85;">Ref: ${esc(ref)}</small>`:''}</p><p>Your purchase is saved in your dashboard for re-download anytime.</p>`,
        ctaText: 'Download Now', ctaUrl: safeUrl(downloadUrl, `${SITE_URL}/dashboard`),
      }),
    });
    await sendMail({
      to: ADMIN_EMAIL,
      subject: `${isFree?'Free download':'Sale'}: ${cleanHeader(appName)} — ${cleanHeader(name||email)}`,
      html: wrapEmail({ title: isFree?'Free Download':'New Sale', bodyHtml: `<p><strong>${esc(appName)}</strong> ${isFree?'downloaded':'purchased for '+(esc(currency)||'₦')+amountStr} by ${esc(name)||''} (${esc(email)}).${ref?' Ref: '+esc(ref):''}</p>` }),
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
      to: clientEmail,
      subject: `Invoice ${cleanHeader(invoiceNum)} from ${cleanHeader(businessName||'AppAholic')}`,
      html: wrapEmail({
        preheader: `Invoice ${esc(invoiceNum)} — ₦${totalStr} due`,
        title: `Invoice ${esc(invoiceNum)}`,
        bodyHtml: `<p>Hi ${esc(clientName)||'there'},</p><p>${esc(businessName)||'We'} sent you a new invoice.</p>
          <table width="100%" style="margin:16px 0;border-collapse:collapse;font-size:13px;">
            <tr><td style="padding:6px 0;color:#6B6B85;">Invoice #</td><td style="text-align:right;font-weight:600;">${esc(invoiceNum)}</td></tr>
            <tr style="border-top:1px solid #E4E4F0;"><td style="padding:6px 0;color:#6B6B85;">Amount Due</td><td style="text-align:right;font-weight:800;font-size:16px;">₦${totalStr}</td></tr>
            ${dueDate?`<tr style="border-top:1px solid #E4E4F0;"><td style="padding:6px 0;color:#6B6B85;">Due Date</td><td style="text-align:right;font-weight:600;">${esc(dueDate)}</td></tr>`:''}
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
    await sendMail({
      to: ADMIN_EMAIL, subject: `Alert: ${cleanHeader(subject||'AppAholic Alert')}`,
      html: wrapEmail({ title: esc(subject)||'Alert', bodyHtml: `<p>${esc(message)||''}</p>` }),
    });
    res.json({ ok: true });
  } catch (err) {
    console.error('admin-alert:', err.message);
    res.status(502).json({ ok: false, error: 'Could not send email right now.' });
  }
}));

/* ── Health ── */
app.get('/api/health', (req, res) =>
  res.json({
    ok: true,
    smtp: missingRequired.length === 0,
    oauth: missingOAuth.length === 0,
    uptime: process.uptime(),
  })
);

/* ── 404 + ERROR HANDLERS ─────────────────────────────────────────── */
app.use((req, res) => {
  res.status(404).json({ ok: false, error: 'Not found' });
});

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  if (err && err.message === 'Not allowed by CORS') {
    return res.status(403).json({ ok: false, error: 'Origin not allowed.' });
  }
  console.error('Unhandled error:', err);
  res.status(500).json({ ok: false, error: 'Internal server error.' });
});

/* ── START ────────────────────────────────────────────────────────── */
const PORT = process.env.PORT || 4000;
if (require.main === module) {
  app.listen(PORT, () => console.log(`✅ AppAholic server on :${PORT}`));
}

process.on('unhandledRejection', (reason) => {
  console.error('Unhandled rejection:', reason);
});

module.exports = app;
