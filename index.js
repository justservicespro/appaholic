/**
 * AppAholic — Email + Auth Server
 * Gmail SMTP (Nodemailer) + Google OAuth 2.0
 *
 * Deploy: Vercel (serverless) or any Node.js host
 * Local:  npm install && npm run dev
 */

const express    = require('express');
const cors       = require('cors');
const nodemailer = require('nodemailer');
const { google } = require('googleapis');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors({
  origin: process.env.ALLOWED_ORIGIN
    ? process.env.ALLOWED_ORIGIN.split(',').map(s => s.trim())
    : ['https://appaholic.justservices.pro', 'http://localhost:3000'],
  credentials: true,
}));

/* ── SMTP ────────────────────────────────────────────────────────── */
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: { user: process.env.GMAIL_USER, pass: process.env.GMAIL_APP_PASSWORD },
});
transporter.verify(err =>
  err
    ? console.error('❌ SMTP:', err.message)
    : console.log('✅ SMTP ready via', process.env.GMAIL_USER)
);

const FROM        = `"AppAholic" <${process.env.GMAIL_USER}>`;
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
  <span style="display:none;max-height:0;overflow:hidden;">${preheader}</span>
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
          ${ctaText && ctaUrl ? `<div style="margin-top:26px;"><a href="${ctaUrl}" style="display:inline-block;background:#0A0A0F;color:#fff;text-decoration:none;padding:12px 28px;border-radius:999px;font-size:14px;font-weight:700;">${ctaText}</a></div>` : ''}
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
    from: FROM, to, subject, html,
    ...(replyTo ? { replyTo } : {}),
  });
}

/* ════════════════════════════════════════════════════════════════════
   GOOGLE OAUTH ROUTES
   ════════════════════════════════════════════════════════════════════ */

/**
 * GET /auth/google
 * Redirect user to Google's consent screen.
 * Frontend: window.location.href = API_BASE + '/auth/google'
 */
app.get('/auth/google', (req, res) => {
  const url = oAuth2Client.generateAuthUrl({
    access_type: 'offline',
    scope: OAUTH_SCOPES,
    prompt: 'select_account',
    state: req.query.redirect || SITE_URL + '/dashboard',
  });
  res.redirect(url);
});

/**
 * GET /auth/google/callback
 * Google redirects here after user consents.
 * Exchanges code for tokens, fetches profile, creates/updates user session.
 */
app.get('/auth/google/callback', async (req, res) => {
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
      id:         profile.id,
      email:      profile.email,
      name:       profile.name,
      firstName:  profile.given_name,
      lastName:   profile.family_name,
      avatar:     profile.picture,
      provider:   'google',
      verified:   profile.verified_email,
    };

    // Send welcome email on first login (best-effort)
    try {
      await sendMail({
        to: user.email,
        subject: `Welcome to AppAholic, ${user.firstName}!`,
        html: wrapEmail({
          preheader: 'Your AppAholic account is ready.',
          title: `Welcome, ${user.firstName}! 🎉`,
          bodyHtml: `<p>You signed in with Google. Your account is ready — browse Web, Desktop and Mobile apps whenever you like.</p>`,
          ctaText: 'Go to My Dashboard',
          ctaUrl: `${SITE_URL}/dashboard`,
        }),
      });
      await sendMail({
        to: ADMIN_EMAIL,
        subject: `👤 New Google sign-in: ${user.email}`,
        html: wrapEmail({
          title: 'New Google Sign-In',
          bodyHtml: `<p><strong>${user.name}</strong> (${user.email}) just signed in via Google OAuth.</p>`,
        }),
      });
    } catch (mailErr) {
      console.warn('Welcome email failed (non-fatal):', mailErr.message);
    }

    // Encode user data and redirect to frontend with session token
    // In production: store in a real session (Redis/DB) and pass a session ID
    // For now: pass user data as base64 URL param (frontend stores in sessionStorage)
    const userPayload = Buffer.from(JSON.stringify(user)).toString('base64url');
    const redirectTo  = state && state.startsWith(SITE_URL) ? state : `${SITE_URL}/dashboard`;
    res.redirect(`${redirectTo}?oauth_session=${userPayload}`);

  } catch (err) {
    console.error('OAuth callback error:', err.message);
    res.redirect(`${SITE_URL}/auth?error=oauth_failed`);
  }
});

/**
 * POST /auth/session
 * Frontend sends the oauth_session token to verify and get user data back.
 */
app.post('/auth/session', (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(401).json({ ok: false, error: 'No token' });
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
   EMAIL ROUTES (unchanged from before)
   ════════════════════════════════════════════════════════════════════ */

app.post('/api/request-app', async (req, res) => {
  try {
    const { name, email, phone, role, title, category, platform, audience,
            users, problem, features, inspiration, integrations, extra,
            timeline, budget, delivery, source } = req.body;
    if (!name || !email || !title || !problem)
      return res.status(400).json({ ok: false, error: 'Missing required fields.' });

    await sendMail({
      to: email,
      subject: `We received your app request: "${title}"`,
      html: wrapEmail({
        preheader: 'Your AppAholic app request has been received.',
        title: `Thanks, ${name.split(' ')[0]} 🎉`,
        bodyHtml: `
          <p>We've received your request for <strong>${title}</strong> and will review it within <strong>48 hours</strong>.</p>
          <table width="100%" style="margin:18px 0;border-collapse:collapse;font-size:13px;">
            <tr><td style="padding:7px 0;color:#6B6B85;">Category</td><td style="padding:7px 0;text-align:right;font-weight:600;">${category||'—'}</td></tr>
            <tr style="border-top:1px solid #E4E4F0;"><td style="padding:7px 0;color:#6B6B85;">Platform</td><td style="padding:7px 0;text-align:right;font-weight:600;">${platform||'—'}</td></tr>
            <tr style="border-top:1px solid #E4E4F0;"><td style="padding:7px 0;color:#6B6B85;">Budget</td><td style="padding:7px 0;text-align:right;font-weight:600;">${budget||'Flexible'}</td></tr>
            <tr style="border-top:1px solid #E4E4F0;"><td style="padding:7px 0;color:#6B6B85;">Timeline</td><td style="padding:7px 0;text-align:right;font-weight:600;">${timeline||'No rush'}</td></tr>
          </table>
          <p>If your request enters the build queue, you'll get early access for free as a thank-you.</p>`,
        ctaText: 'Browse Apps', ctaUrl: SITE_URL,
      }),
    });
    await sendMail({
      to: ADMIN_EMAIL, replyTo: email,
      subject: `📬 New app request: "${title}" from ${name}`,
      html: wrapEmail({
        title: 'New App Request',
        bodyHtml: `
          <table width="100%" style="border-collapse:collapse;font-size:13px;">
            ${[['Requester',`${name} (${email}${phone?', '+phone:''})`],['Role',role||'—'],['App Title',title],['Category',category||'—'],['Platform',platform||'—'],['Audience',`${audience||'—'} (${users||'?'} users)`],['Problem',problem],['Features',features||'—'],['Integrations',integrations||'—'],['Budget',budget||'Flexible'],['Timeline',timeline||'No rush'],['Delivery',delivery||'—'],['Source',source||'—'],['Extra',extra||'—']].map(([l,v])=>`<tr><td style="padding:5px 0;color:#6B6B85;width:130px;">${l}</td><td style="padding:5px 0;font-weight:500;">${v}</td></tr>`).join('')}
          </table>`,
        ctaText: 'Admin Dashboard', ctaUrl: `${SITE_URL}/admin`,
      }),
    });
    res.json({ ok: true });
  } catch (err) { console.error('request-app:', err); res.status(500).json({ ok: false }); }
});

app.post('/api/signup', async (req, res) => {
  try {
    const { firstName, email } = req.body;
    if (!email) return res.status(400).json({ ok: false, error: 'Email required.' });
    await sendMail({
      to: email, subject: 'Welcome to AppAholic 🎉',
      html: wrapEmail({
        preheader: 'Your AppAholic account is ready.',
        title: `Welcome, ${firstName||'there'}!`,
        bodyHtml: `<p>Your account is ready. Browse Web, Desktop and Mobile apps and re-download any purchase anytime from your dashboard.</p>`,
        ctaText: 'Go to Dashboard', ctaUrl: `${SITE_URL}/dashboard`,
      }),
    });
    await sendMail({
      to: ADMIN_EMAIL, subject: `👤 New signup: ${email}`,
      html: wrapEmail({ title: 'New Signup', bodyHtml: `<p><strong>${firstName||''}</strong> signed up with <strong>${email}</strong>.</p>` }),
    });
    res.json({ ok: true });
  } catch (err) { console.error('signup:', err); res.status(500).json({ ok: false }); }
});

app.post('/api/forgot-password', async (req, res) => {
  try {
    const { email, resetLink } = req.body;
    if (!email) return res.status(400).json({ ok: false, error: 'Email required.' });
    await sendMail({
      to: email, subject: 'Reset your AppAholic password',
      html: wrapEmail({
        preheader: 'Reset your password — link expires in 30 minutes.',
        title: 'Reset your password',
        bodyHtml: `<p>Click below to reset your password. This link expires in 30 minutes. Ignore this email if you didn't request a reset.</p>`,
        ctaText: 'Reset Password', ctaUrl: resetLink || `${SITE_URL}/auth`,
      }),
    });
    res.json({ ok: true });
  } catch (err) { console.error('forgot-password:', err); res.status(500).json({ ok: false }); }
});

app.post('/api/order-confirmation', async (req, res) => {
  try {
    const { email, name, appName, amount, currency, ref, downloadUrl } = req.body;
    if (!email || !appName) return res.status(400).json({ ok: false, error: 'Missing fields.' });
    const isFree = !amount || Number(amount) === 0;
    await sendMail({
      to: email,
      subject: isFree ? `Your download: ${appName}` : `Receipt — ${appName} (₦${Number(amount).toLocaleString()})`,
      html: wrapEmail({
        preheader: `${appName} is ready`,
        title: isFree ? `${appName} is ready` : 'Payment received — thank you!',
        bodyHtml: `<p>Hi ${name||'there'},</p><p>${isFree?`Your free download of <strong>${appName}</strong> is ready.`:`We received your payment of <strong>${currency||'₦'}${Number(amount).toLocaleString()}</strong> for <strong>${appName}</strong>.`}${ref?`<br/><small style="color:#6B6B85;">Ref: ${ref}</small>`:''}</p><p>Your purchase is saved in your dashboard for re-download anytime.</p>`,
        ctaText: 'Download Now', ctaUrl: downloadUrl || `${SITE_URL}/dashboard`,
      }),
    });
    await sendMail({
      to: ADMIN_EMAIL,
      subject: `💰 ${isFree?'Free download':'Sale'}: ${appName} — ${name||email}`,
      html: wrapEmail({ title: isFree?'Free Download':'New Sale', bodyHtml: `<p><strong>${appName}</strong> ${isFree?'downloaded':'purchased for '+(currency||'₦')+Number(amount).toLocaleString()} by ${name||''} (${email}).${ref?' Ref: '+ref:''}</p>` }),
    });
    res.json({ ok: true });
  } catch (err) { console.error('order:', err); res.status(500).json({ ok: false }); }
});

app.post('/api/send-invoice', async (req, res) => {
  try {
    const { clientEmail, clientName, invoiceNum, businessName, total, dueDate, pdfUrl } = req.body;
    if (!clientEmail || !invoiceNum) return res.status(400).json({ ok: false, error: 'Missing fields.' });
    await sendMail({
      to: clientEmail,
      subject: `Invoice ${invoiceNum} from ${businessName||'AppAholic'}`,
      html: wrapEmail({
        preheader: `Invoice ${invoiceNum} — ₦${Number(total||0).toLocaleString()} due`,
        title: `Invoice ${invoiceNum}`,
        bodyHtml: `<p>Hi ${clientName||'there'},</p><p>${businessName||'We'} sent you a new invoice.</p>
          <table width="100%" style="margin:16px 0;border-collapse:collapse;font-size:13px;">
            <tr><td style="padding:6px 0;color:#6B6B85;">Invoice #</td><td style="text-align:right;font-weight:600;">${invoiceNum}</td></tr>
            <tr style="border-top:1px solid #E4E4F0;"><td style="padding:6px 0;color:#6B6B85;">Amount Due</td><td style="text-align:right;font-weight:800;font-size:16px;">₦${Number(total||0).toLocaleString()}</td></tr>
            ${dueDate?`<tr style="border-top:1px solid #E4E4F0;"><td style="padding:6px 0;color:#6B6B85;">Due Date</td><td style="text-align:right;font-weight:600;">${dueDate}</td></tr>`:''}
          </table>`,
        ...(pdfUrl ? { ctaText: 'View / Download Invoice', ctaUrl: pdfUrl } : {}),
      }),
    });
    res.json({ ok: true });
  } catch (err) { console.error('invoice:', err); res.status(500).json({ ok: false }); }
});

app.post('/api/admin-alert', async (req, res) => {
  try {
    const { subject, message } = req.body;
    await sendMail({
      to: ADMIN_EMAIL, subject: `🔔 ${subject||'AppAholic Alert'}`,
      html: wrapEmail({ title: subject||'Alert', bodyHtml: `<p>${message||''}</p>` }),
    });
    res.json({ ok: true });
  } catch (err) { console.error('admin-alert:', err); res.status(500).json({ ok: false }); }
});

/* ── Health ── */
app.get('/api/health', (req, res) =>
  res.json({ ok: true, smtp: !!process.env.GMAIL_USER, oauth: !!process.env.GOOGLE_CLIENT_ID })
);

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`✅ AppAholic server on :${PORT}`));
module.exports = app;
