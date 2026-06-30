/**
 * AppAholic — Email Alert Server
 * Sends transactional emails via Gmail SMTP (Nodemailer).
 *
 * Deploy: Vercel (as a serverless function) or any Node host (Render, Railway, etc).
 * Local dev: `npm install` then `npm run dev`
 *
 * REQUIRED ENV VARS (see .env.example):
 *   GMAIL_USER          - your full Gmail address
 *   GMAIL_APP_PASSWORD  - 16-character Gmail App Password (NOT your normal password)
 *   ADMIN_EMAIL         - where admin alerts (new requests, new orders) are sent
 *   ALLOWED_ORIGIN       - your frontend's deployed URL, for CORS
 */

const express = require('express');
const cors = require('cors');
const nodemailer = require('nodemailer');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors({
  origin: process.env.ALLOWED_ORIGIN ? process.env.ALLOWED_ORIGIN.split(',') : '*',
}));

/* ──────────────────────────────────────────────────────────────────
   SMTP TRANSPORT — Gmail
   To get a Gmail App Password:
   1. Enable 2-Step Verification on your Google Account
   2. Go to myaccount.google.com/apppasswords
   3. Generate a password for "Mail" — use that 16-char code below, NOT your login password
   ────────────────────────────────────────────────────────────────── */
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_APP_PASSWORD,
  },
});

// Verify SMTP connection on boot (logs only, doesn't crash the server)
transporter.verify((err) => {
  if (err) console.error('❌ SMTP connection failed:', err.message);
  else console.log('✅ SMTP connected — ready to send via', process.env.GMAIL_USER);
});

const FROM = `"AppAholic" <${process.env.GMAIL_USER}>`;
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || process.env.GMAIL_USER;
const BRAND_COLOR = '#0A0A0F';
const ACCENT_COLOR = '#C8FF00';

/* ──────────────────────────────────────────────────────────────────
   EMAIL TEMPLATE WRAPPER — consistent branded HTML shell
   ────────────────────────────────────────────────────────────────── */
function wrapEmail({ preheader = '', title, bodyHtml, ctaText, ctaUrl }) {
  return `<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/></head>
<body style="margin:0;padding:0;background:#F7F7FB;font-family:-apple-system,Segoe UI,Inter,Arial,sans-serif;">
  <span style="display:none;max-height:0;overflow:hidden;">${preheader}</span>
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#F7F7FB;padding:32px 16px;">
    <tr><td align="center">
      <table width="100%" style="max-width:520px;background:#ffffff;border-radius:20px;overflow:hidden;border:1px solid #E4E4F0;">
        <tr><td style="background:${BRAND_COLOR};padding:28px 32px;">
          <table width="100%"><tr>
            <td style="font-size:20px;font-weight:800;color:#fff;letter-spacing:-0.5px;">
              <span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:${ACCENT_COLOR};margin-right:8px;"></span>
              AppAholic
            </td>
          </tr></table>
        </td></tr>
        <tr><td style="padding:32px;">
          <h1 style="margin:0 0 16px;font-size:20px;font-weight:800;color:${BRAND_COLOR};letter-spacing:-0.3px;">${title}</h1>
          <div style="font-size:14px;line-height:1.7;color:#2E2E3E;">${bodyHtml}</div>
          ${ctaText ? `<div style="margin-top:28px;">
            <a href="${ctaUrl}" style="display:inline-block;background:${BRAND_COLOR};color:#fff;text-decoration:none;padding:13px 28px;border-radius:999px;font-size:14px;font-weight:700;">${ctaText}</a>
          </div>` : ''}
        </td></tr>
        <tr><td style="padding:20px 32px;border-top:1px solid #E4E4F0;background:#F7F7FB;">
          <p style="margin:0;font-size:12px;color:#6B6B85;line-height:1.6;">
            AppAholic — a product of <strong>JustServicesPro Management and Consulting Ltd</strong><br/>
            Questions? <a href="mailto:info@justservices.pro" style="color:#4B3EFF;">info@justservices.pro</a>
          </p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>`;
}

async function sendMail({ to, subject, html, replyTo }) {
  return transporter.sendMail({
    from: FROM,
    to,
    subject,
    html,
    ...(replyTo ? { replyTo } : {}),
  });
}

/* ════════════════════════════════════════════════════════════════
   ROUTE 1 — App Request Form (index.html → #request)
   Sends: (a) confirmation to the requester, (b) alert to admin
   ════════════════════════════════════════════════════════════════ */
app.post('/api/request-app', async (req, res) => {
  try {
    const {
      name, email, phone, role, title, category, platform,
      audience, users, problem, features, inspiration,
      integrations, extra, timeline, budget, delivery, source,
    } = req.body;

    if (!name || !email || !title || !problem) {
      return res.status(400).json({ ok: false, error: 'Missing required fields.' });
    }

    // 1. Confirmation to requester
    await sendMail({
      to: email,
      subject: `We received your app request: "${title}"`,
      html: wrapEmail({
        preheader: 'Your AppAholic app request has been received.',
        title: `Thanks, ${name.split(' ')[0]} 🎉`,
        bodyHtml: `
          <p>We've received your request for <strong>${title}</strong> and our team will review it within <strong>48 hours</strong>.</p>
          <table width="100%" style="margin:20px 0;border-collapse:collapse;font-size:13px;">
            <tr><td style="padding:8px 0;color:#6B6B85;">Category</td><td style="padding:8px 0;text-align:right;font-weight:600;">${category || '—'}</td></tr>
            <tr style="border-top:1px solid #E4E4F0;"><td style="padding:8px 0;color:#6B6B85;">Platform</td><td style="padding:8px 0;text-align:right;font-weight:600;">${platform || '—'}</td></tr>
            <tr style="border-top:1px solid #E4E4F0;"><td style="padding:8px 0;color:#6B6B85;">Budget</td><td style="padding:8px 0;text-align:right;font-weight:600;">${budget || 'Flexible'}</td></tr>
            <tr style="border-top:1px solid #E4E4F0;"><td style="padding:8px 0;color:#6B6B85;">Timeline</td><td style="padding:8px 0;text-align:right;font-weight:600;">${timeline || 'No rush'}</td></tr>
          </table>
          <p>If your request goes into the build queue, you'll get early access for free as a thank-you. We'll keep you posted by email at every stage.</p>
        `,
        ctaText: 'View Marketplace',
        ctaUrl: process.env.SITE_URL || 'https://appaholic.justservices.pro',
      }),
    });

    // 2. Alert to admin with full detail
    await sendMail({
      to: ADMIN_EMAIL,
      replyTo: email,
      subject: `📬 New app request: "${title}" from ${name}`,
      html: wrapEmail({
        preheader: `New request from ${name}`,
        title: `New App Request`,
        bodyHtml: `
          <table width="100%" style="border-collapse:collapse;font-size:13px;">
            <tr><td style="padding:6px 0;color:#6B6B85;width:140px;">Requester</td><td style="padding:6px 0;font-weight:600;">${name} (${email}${phone ? ', ' + phone : ''})</td></tr>
            <tr><td style="padding:6px 0;color:#6B6B85;">Role</td><td style="padding:6px 0;">${role || '—'}</td></tr>
            <tr><td style="padding:6px 0;color:#6B6B85;">App Title</td><td style="padding:6px 0;font-weight:600;">${title}</td></tr>
            <tr><td style="padding:6px 0;color:#6B6B85;">Category</td><td style="padding:6px 0;">${category || '—'}</td></tr>
            <tr><td style="padding:6px 0;color:#6B6B85;">Platform</td><td style="padding:6px 0;">${platform || '—'}</td></tr>
            <tr><td style="padding:6px 0;color:#6B6B85;">Audience</td><td style="padding:6px 0;">${audience || '—'} (${users || 'unknown'} users)</td></tr>
            <tr><td style="padding:6px 0;color:#6B6B85;vertical-align:top;">Problem</td><td style="padding:6px 0;">${problem}</td></tr>
            <tr><td style="padding:6px 0;color:#6B6B85;vertical-align:top;">Features</td><td style="padding:6px 0;white-space:pre-line;">${features || '—'}</td></tr>
            <tr><td style="padding:6px 0;color:#6B6B85;">Inspiration</td><td style="padding:6px 0;">${inspiration || '—'}</td></tr>
            <tr><td style="padding:6px 0;color:#6B6B85;">Integrations</td><td style="padding:6px 0;">${integrations || '—'}</td></tr>
            <tr><td style="padding:6px 0;color:#6B6B85;">Budget</td><td style="padding:6px 0;">${budget || 'Flexible'}</td></tr>
            <tr><td style="padding:6px 0;color:#6B6B85;">Timeline</td><td style="padding:6px 0;">${timeline || 'No rush'}</td></tr>
            <tr><td style="padding:6px 0;color:#6B6B85;">Delivery</td><td style="padding:6px 0;">${delivery || '—'}</td></tr>
            <tr><td style="padding:6px 0;color:#6B6B85;">Source</td><td style="padding:6px 0;">${source || '—'}</td></tr>
            <tr><td style="padding:6px 0;color:#6B6B85;vertical-align:top;">Extra notes</td><td style="padding:6px 0;">${extra || '—'}</td></tr>
          </table>
        `,
        ctaText: 'Open Admin Dashboard',
        ctaUrl: (process.env.SITE_URL || '') + '/admin.html',
      }),
    });

    res.json({ ok: true });
  } catch (err) {
    console.error('request-app error:', err);
    res.status(500).json({ ok: false, error: 'Failed to send email.' });
  }
});

/* ════════════════════════════════════════════════════════════════
   ROUTE 2 — Signup welcome email (auth.html)
   ════════════════════════════════════════════════════════════════ */
app.post('/api/signup', async (req, res) => {
  try {
    const { firstName, email } = req.body;
    if (!email) return res.status(400).json({ ok: false, error: 'Email required.' });

    await sendMail({
      to: email,
      subject: 'Welcome to AppAholic 🎉',
      html: wrapEmail({
        preheader: 'Your AppAholic account is ready.',
        title: `Welcome, ${firstName || 'there'}!`,
        bodyHtml: `
          <p>Your account is ready. From your dashboard you can:</p>
          <ul style="padding-left:18px;margin:12px 0;">
            <li>Re-download any app you purchase, anytime</li>
            <li>Track the status of your custom app requests</li>
            <li>Get early access to new releases</li>
          </ul>
          <p>Browse Web, Desktop and Mobile apps whenever you're ready.</p>
        `,
        ctaText: 'Go to My Dashboard',
        ctaUrl: (process.env.SITE_URL || '') + '/dashboard.html',
      }),
    });

    await sendMail({
      to: ADMIN_EMAIL,
      subject: `👤 New signup: ${email}`,
      html: wrapEmail({
        title: 'New User Signup',
        bodyHtml: `<p><strong>${firstName || ''}</strong> just created an account with <strong>${email}</strong>.</p>`,
      }),
    });

    res.json({ ok: true });
  } catch (err) {
    console.error('signup error:', err);
    res.status(500).json({ ok: false, error: 'Failed to send email.' });
  }
});

/* ════════════════════════════════════════════════════════════════
   ROUTE 3 — Password reset email (auth.html)
   ════════════════════════════════════════════════════════════════ */
app.post('/api/forgot-password', async (req, res) => {
  try {
    const { email, resetLink } = req.body;
    if (!email) return res.status(400).json({ ok: false, error: 'Email required.' });

    await sendMail({
      to: email,
      subject: 'Reset your AppAholic password',
      html: wrapEmail({
        preheader: 'Reset your password',
        title: 'Reset your password',
        bodyHtml: `<p>Click the button below to reset your password. This link expires in 30 minutes. If you didn't request this, you can safely ignore this email.</p>`,
        ctaText: 'Reset Password',
        ctaUrl: resetLink || ((process.env.SITE_URL || '') + '/auth.html'),
      }),
    });

    res.json({ ok: true });
  } catch (err) {
    console.error('forgot-password error:', err);
    res.status(500).json({ ok: false, error: 'Failed to send email.' });
  }
});

/* ════════════════════════════════════════════════════════════════
   ROUTE 4 — Purchase / Order confirmation (marketplace.html, index.html)
   Call this from your Flutterwave webhook handler after a successful charge.
   ════════════════════════════════════════════════════════════════ */
app.post('/api/order-confirmation', async (req, res) => {
  try {
    const { email, name, appName, amount, currency, ref, downloadUrl } = req.body;
    if (!email || !appName) return res.status(400).json({ ok: false, error: 'Missing fields.' });

    const isFree = !amount || amount === 0;

    await sendMail({
      to: email,
      subject: isFree ? `Your download: ${appName}` : `Receipt — ${appName} (₦${Number(amount).toLocaleString()})`,
      html: wrapEmail({
        preheader: `${appName} is ready`,
        title: isFree ? `${appName} is ready to download` : `Payment received — thank you!`,
        bodyHtml: `
          <p>Hi ${name || 'there'},</p>
          <p>${isFree ? `Your free download of <strong>${appName}</strong> is ready.` : `We've received your payment of <strong>${currency || '₦'}${Number(amount).toLocaleString()}</strong> for <strong>${appName}</strong>.`}</p>
          ${ref ? `<p style="font-size:12px;color:#6B6B85;">Reference: ${ref}</p>` : ''}
          <p>Your purchase is also saved in your AppAholic dashboard for re-download anytime.</p>
        `,
        ctaText: 'Download Now',
        ctaUrl: downloadUrl || ((process.env.SITE_URL || '') + '/dashboard.html'),
      }),
    });

    await sendMail({
      to: ADMIN_EMAIL,
      subject: `💰 ${isFree ? 'Free download' : 'Sale'}: ${appName} — ${name || email}`,
      html: wrapEmail({
        title: isFree ? 'New Free Download' : 'New Sale',
        bodyHtml: `<p><strong>${appName}</strong> ${isFree ? 'downloaded' : 'purchased for ' + (currency || '₦') + Number(amount).toLocaleString()} by ${name || ''} (${email}).${ref ? ' Ref: ' + ref : ''}</p>`,
      }),
    });

    res.json({ ok: true });
  } catch (err) {
    console.error('order-confirmation error:', err);
    res.status(500).json({ ok: false, error: 'Failed to send email.' });
  }
});

/* ════════════════════════════════════════════════════════════════
   ROUTE 5 — InvoiceKit: send invoice to client
   ════════════════════════════════════════════════════════════════ */
app.post('/api/send-invoice', async (req, res) => {
  try {
    const { clientEmail, clientName, invoiceNum, businessName, total, dueDate, pdfUrl } = req.body;
    if (!clientEmail || !invoiceNum) return res.status(400).json({ ok: false, error: 'Missing fields.' });

    await sendMail({
      to: clientEmail,
      subject: `Invoice ${invoiceNum} from ${businessName || 'AppAholic'}`,
      html: wrapEmail({
        preheader: `Invoice ${invoiceNum}`,
        title: `New Invoice: ${invoiceNum}`,
        bodyHtml: `
          <p>Hi ${clientName || 'there'},</p>
          <p>${businessName || 'We'} sent you a new invoice.</p>
          <table width="100%" style="margin:16px 0;border-collapse:collapse;font-size:13px;">
            <tr><td style="padding:6px 0;color:#6B6B85;">Invoice #</td><td style="padding:6px 0;text-align:right;font-weight:600;">${invoiceNum}</td></tr>
            <tr style="border-top:1px solid #E4E4F0;"><td style="padding:6px 0;color:#6B6B85;">Amount Due</td><td style="padding:6px 0;text-align:right;font-weight:800;font-size:16px;">₦${Number(total || 0).toLocaleString()}</td></tr>
            ${dueDate ? `<tr style="border-top:1px solid #E4E4F0;"><td style="padding:6px 0;color:#6B6B85;">Due Date</td><td style="padding:6px 0;text-align:right;font-weight:600;">${dueDate}</td></tr>` : ''}
          </table>
        `,
        ctaText: pdfUrl ? 'View / Download Invoice' : undefined,
        ctaUrl: pdfUrl,
      }),
    });

    res.json({ ok: true });
  } catch (err) {
    console.error('send-invoice error:', err);
    res.status(500).json({ ok: false, error: 'Failed to send email.' });
  }
});

/* ════════════════════════════════════════════════════════════════
   ROUTE 6 — Generic admin alert (used by admin dashboard actions,
   e.g. marking a request "In Progress", low-stock-style alerts, etc.)
   ════════════════════════════════════════════════════════════════ */
app.post('/api/admin-alert', async (req, res) => {
  try {
    const { subject, message } = req.body;
    await sendMail({
      to: ADMIN_EMAIL,
      subject: `🔔 ${subject || 'AppAholic Alert'}`,
      html: wrapEmail({ title: subject || 'Alert', bodyHtml: `<p>${message || ''}</p>` }),
    });
    res.json({ ok: true });
  } catch (err) {
    console.error('admin-alert error:', err);
    res.status(500).json({ ok: false, error: 'Failed to send email.' });
  }
});

/* ── Health check ── */
app.get('/api/health', (req, res) => res.json({ ok: true, smtp: !!process.env.GMAIL_USER }));

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`✅ AppAholic email server running on port ${PORT}`));

module.exports = app;
