-- ═══════════════════════════════════════════════════════════════════
-- AppAholic — Supabase Schema
-- Run this once in Supabase SQL Editor (Project → SQL Editor → New query)
-- Safe to re-run: uses IF NOT EXISTS / OR REPLACE throughout.
-- ═══════════════════════════════════════════════════════════════════

-- ── EXTENSIONS ──────────────────────────────────────────────────────
create extension if not exists "pgcrypto";

-- ── PROFILES ─────────────────────────────────────────────────────────
-- One row per Supabase Auth user. Created automatically on signup via trigger below.
create table if not exists public.profiles (
  id            uuid primary key references auth.users(id) on delete cascade,
  email         text not null,
  full_name     text,
  avatar_url    text,
  provider      text default 'email',
  created_at    timestamptz not null default now()
);

alter table public.profiles enable row level security;

drop policy if exists "profiles_select_own" on public.profiles;
create policy "profiles_select_own" on public.profiles
  for select using (auth.uid() = id);

drop policy if exists "profiles_update_own" on public.profiles;
create policy "profiles_update_own" on public.profiles
  for update using (auth.uid() = id);

-- Auto-create a profile row whenever a new auth user is created (email or Google OAuth)
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer set search_path = public
as $$
begin
  insert into public.profiles (id, email, full_name, avatar_url, provider)
  values (
    new.id,
    new.email,
    coalesce(new.raw_user_meta_data->>'full_name', new.raw_user_meta_data->>'name'),
    new.raw_user_meta_data->>'avatar_url',
    coalesce(new.raw_app_meta_data->>'provider', 'email')
  )
  on conflict (id) do nothing;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute procedure public.handle_new_user();

-- ── APPS (marketplace catalogue) ─────────────────────────────────────
create table if not exists public.apps (
  id              text primary key,              -- slug, e.g. 'focusclock'
  name            text not null,
  category        text not null,
  platform        text not null check (platform in ('web','desktop','mobile')),
  os              text[] not null default '{}',   -- ['windows','mac'] etc.
  price           numeric not null default 0,     -- 0 = free
  rating          numeric default 0,
  downloads_count integer default 0,
  tag             text,                           -- 'top' | 'new' | 'free' | 'paid'
  icon            text,
  banner_color    text,
  description     text,
  long_description text,
  features        text[] default '{}',
  tags            text[] default '{}',
  active          boolean not null default true,
  created_at      timestamptz not null default now()
);

alter table public.apps enable row level security;

drop policy if exists "apps_select_all" on public.apps;
create policy "apps_select_all" on public.apps
  for select using (active = true);

-- Only the service role (server) can write to apps — no public policy for insert/update/delete.

-- ── PURCHASES ─────────────────────────────────────────────────────────
create table if not exists public.purchases (
  id              uuid primary key default gen_random_uuid(),
  user_id         uuid references public.profiles(id) on delete set null,
  app_id          text references public.apps(id) on delete set null,
  email           text not null,                  -- kept even if user_id is null (guest checkout)
  amount          numeric not null default 0,
  currency        text default 'NGN',
  status          text not null default 'completed' check (status in ('pending','completed','failed','refunded')),
  provider_ref    text,                            -- Flutterwave transaction ref
  created_at      timestamptz not null default now()
);

alter table public.purchases enable row level security;

drop policy if exists "purchases_select_own" on public.purchases;
create policy "purchases_select_own" on public.purchases
  for select using (auth.uid() = user_id);

-- Inserts/updates happen only via the server (service role), e.g. after a Flutterwave webhook.

-- ── DOWNLOADS ─────────────────────────────────────────────────────────
create table if not exists public.downloads (
  id          uuid primary key default gen_random_uuid(),
  user_id     uuid references public.profiles(id) on delete set null,
  app_id      text references public.apps(id) on delete set null,
  version     text,
  device      text,
  file_size   text,
  created_at  timestamptz not null default now()
);

alter table public.downloads enable row level security;

drop policy if exists "downloads_select_own" on public.downloads;
create policy "downloads_select_own" on public.downloads
  for select using (auth.uid() = user_id);

drop policy if exists "downloads_insert_own" on public.downloads;
create policy "downloads_insert_own" on public.downloads
  for insert with check (auth.uid() = user_id);

-- ── APP REQUESTS ─────────────────────────────────────────────────────
create table if not exists public.app_requests (
  id              uuid primary key default gen_random_uuid(),
  user_id         uuid references public.profiles(id) on delete set null,
  name            text not null,
  email           text not null,
  phone           text,
  role            text,
  title           text not null,
  category        text,
  platform        text,
  audience        text,
  users_estimate  text,
  problem         text not null,
  features        text,
  inspiration     text,
  integrations    text,
  extra           text,
  timeline        text,
  budget          text,
  delivery        text,
  source          text,
  status          text not null default 'submitted' check (status in ('submitted','in_progress','under_review','built','declined')),
  votes           integer not null default 0,
  created_at      timestamptz not null default now()
);

alter table public.app_requests enable row level security;

drop policy if exists "requests_select_own" on public.app_requests;
create policy "requests_select_own" on public.app_requests
  for select using (auth.uid() = user_id or user_id is null);

-- Inserts happen via the server using the service role (keeps email/spam validation server-side).

-- ── CONTACT MESSAGES ──────────────────────────────────────────────────
create table if not exists public.contact_messages (
  id          uuid primary key default gen_random_uuid(),
  user_id     uuid references public.profiles(id) on delete set null,
  name        text not null,
  email       text not null,
  topic       text default 'General',
  message     text not null,
  created_at  timestamptz not null default now()
);

alter table public.contact_messages enable row level security;
-- No public select policy — contact messages are only readable via the service role (admin/server).

-- ── SUBSCRIPTIONS ─────────────────────────────────────────────────────
create table if not exists public.subscriptions (
  id                  uuid primary key default gen_random_uuid(),
  user_id             uuid references public.profiles(id) on delete cascade,
  plan                text not null check (plan in ('free','pro','business')),
  status              text not null default 'active' check (status in ('active','past_due','cancelled','expired')),
  billing_cycle       text not null default 'monthly' check (billing_cycle in ('monthly','yearly')),
  amount              numeric not null default 0,
  currency            text default 'NGN',
  provider_ref        text,                 -- Flutterwave tx_ref of the most recent successful charge
  current_period_end  timestamptz,
  cancelled_at        timestamptz,
  created_at          timestamptz not null default now()
);

alter table public.subscriptions enable row level security;

drop policy if exists "subscriptions_select_own" on public.subscriptions;
create policy "subscriptions_select_own" on public.subscriptions
  for select using (auth.uid() = user_id);

-- Only one active subscription per user — enforced at the app level on write,
-- indexed here for fast lookup.
create index if not exists idx_subscriptions_user on public.subscriptions(user_id);

-- ── INDEXES ───────────────────────────────────────────────────────────
create index if not exists idx_purchases_user   on public.purchases(user_id);
create index if not exists idx_downloads_user   on public.downloads(user_id);
create index if not exists idx_requests_user    on public.app_requests(user_id);
create index if not exists idx_apps_platform    on public.apps(platform);
create index if not exists idx_apps_category    on public.apps(category);

-- ── APPS: file hosting columns ──────────────────────────────────────
-- storage_path: path inside the Supabase Storage 'app-files' bucket, for
--   Desktop/Mobile installers (e.g. 'focusdesk/FocusDesk-Setup-v1.2.exe').
--   Null until the actual app is built and uploaded.
-- launch_url: for Web apps — either an internal path (e.g. '/invoicekit')
--   or an external URL where the running app lives. Null for Desktop/Mobile.
alter table public.apps add column if not exists storage_path text;
alter table public.apps add column if not exists launch_url text;

-- ── INVOICEKIT — per-app data tables ────────────────────────────────
create table if not exists public.invoicekit_clients (
  id          uuid primary key default gen_random_uuid(),
  user_id     uuid not null references public.profiles(id) on delete cascade,
  name        text not null,
  email       text,
  phone       text,
  address     text,
  created_at  timestamptz not null default now()
);

alter table public.invoicekit_clients enable row level security;
drop policy if exists "invoicekit_clients_all_own" on public.invoicekit_clients;
create policy "invoicekit_clients_all_own" on public.invoicekit_clients
  for all using (auth.uid() = user_id) with check (auth.uid() = user_id);

create table if not exists public.invoicekit_invoices (
  id              uuid primary key default gen_random_uuid(),
  user_id         uuid not null references public.profiles(id) on delete cascade,
  client_id       uuid references public.invoicekit_clients(id) on delete set null,
  invoice_number  text not null,
  business_name   text,
  items           jsonb not null default '[]',   -- [{description, qty, price}]
  vat_rate        numeric not null default 7.5,   -- Nigeria standard VAT %
  wht_rate        numeric not null default 0,     -- withholding tax %, 0 unless applicable
  subtotal        numeric not null default 0,
  vat_amount      numeric not null default 0,
  wht_amount      numeric not null default 0,
  total           numeric not null default 0,
  status          text not null default 'draft' check (status in ('draft','sent','paid','overdue')),
  due_date        date,
  paid_at         timestamptz,
  created_at      timestamptz not null default now(),
  updated_at      timestamptz not null default now()
);

alter table public.invoicekit_invoices enable row level security;
drop policy if exists "invoicekit_invoices_all_own" on public.invoicekit_invoices;
create policy "invoicekit_invoices_all_own" on public.invoicekit_invoices
  for all using (auth.uid() = user_id) with check (auth.uid() = user_id);

create index if not exists idx_invoicekit_clients_user on public.invoicekit_clients(user_id);
create index if not exists idx_invoicekit_invoices_user on public.invoicekit_invoices(user_id);

-- ── QUICKNOTE — per-app data table ──────────────────────────────────
-- Pattern to follow for future web apps: one table per app, namespaced
-- routes under /api/{app-slug}/..., all authenticated via the same
-- requireAuth middleware and signed session already built.
create table if not exists public.quicknote_notes (
  id          uuid primary key default gen_random_uuid(),
  user_id     uuid not null references public.profiles(id) on delete cascade,
  title       text not null default 'Untitled',
  content     text not null default '',
  tags        text[] not null default '{}',
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);

alter table public.quicknote_notes enable row level security;

drop policy if exists "quicknote_notes_all_own" on public.quicknote_notes;
create policy "quicknote_notes_all_own" on public.quicknote_notes
  for all using (auth.uid() = user_id) with check (auth.uid() = user_id);

create index if not exists idx_quicknote_notes_user on public.quicknote_notes(user_id);

-- ── SEED DATA: the 15-app catalogue ──────────────────────────────────
insert into public.apps (id, name, category, platform, os, price, rating, downloads_count, tag, icon, banner_color, description, long_description, features, tags) values
('focusclock','FocusClock','Productivity','web','{web}',1200,4.9,3200,'top','⏱️','#FFF3E0','Pomodoro focus timer with smart break scheduling and distraction blocking.','FocusClock is a precision focus tool built on the Pomodoro technique extended with AI-driven break scheduling. It learns your energy patterns and suggests optimal work blocks.',ARRAY['Smart Pomodoro sessions','Website & app blocker','Productivity analytics dashboard','Google Calendar sync','Daily & weekly PDF reports'],ARRAY['Focus','Timer','Pomodoro','Productivity']),
('datapulse','DataPulse','Analytics','web','{web}',3500,4.8,1800,'paid','📊','#E8F5E9','Business analytics dashboard. Connect data sources and generate client-ready reports.','DataPulse connects to Google Sheets, Excel or your database and turns raw numbers into clean shareable dashboards. Export polished PDF reports in seconds.',ARRAY['Google Sheets & Excel connector','Auto-generated PDF reports','Live shareable dashboard link','Drag-and-drop chart builder','Scheduled email reports'],ARRAY['Analytics','Dashboard','Reports','Data']),
('invoicekit','InvoiceKit','Finance','web','{web}',2500,4.6,4500,'top','🧾','#F3E5F5','Professional invoice generator. VAT/WHT support, PDF export, payment tracking.','InvoiceKit lets you create, send, and track invoices in under 60 seconds. Branded PDFs, recurring invoices, VAT & WHT calculation all in one clean web app.',ARRAY['Branded PDF invoice export','Client & product database','Payment status tracking','Recurring invoice scheduling','VAT & WHT tax calculation'],ARRAY['Invoice','Finance','Billing','Freelance']),
('taskmind','TaskMind AI','AI Tools','web','{web}',5000,4.9,900,'new','🤖','#E8EAF6','AI-powered task manager that learns your habits and builds your optimal work day.','TaskMind connects to your calendar and to-do list then uses AI to reorder priorities based on deadlines, energy levels, and meeting gaps.',ARRAY['AI-powered task prioritization','Google & Outlook calendar sync','Daily AI-generated focus plan','Energy level tracking','Weekly productivity insights'],ARRAY['AI','Tasks','Productivity','Automation']),
('teamping','TeamPing','Communication','web','{web}',1800,4.4,1200,'new','💬','#E0F7FA','Minimal team chat for small teams. Threads and status, no noise.','TeamPing is a deliberately minimal messaging tool. Threaded conversations, status indicators, and file sharing. Built for teams under 25.',ARRAY['Threaded conversations','Real-time status indicators','File sharing up to 50MB','Read receipts per message','Fully mobile-responsive'],ARRAY['Chat','Team','Communication','Messaging']),
('quicknote','QuickNote','Productivity','web','{web}',0,4.3,8900,'free','📝','#FFFDE7','Lightweight markdown note-taking. Fast, keyboard-first, instant search.','QuickNote is built for speed. Open with a hotkey, type in markdown, auto-save. Tags, folders, and full-text search keep everything findable.',ARRAY['Full markdown editor with preview','Instant full-text search','Tags, folders & notebooks','Keyboard-first shortcuts','Export to PDF or HTML'],ARRAY['Notes','Markdown','Writing','Free']),
('vaultsync','VaultSync','Storage','desktop','{windows,mac}',0,4.5,6100,'free','🗂️','#E3F2FD','Free file organizer for Windows & Mac. Auto-sort folders, sync across 2 devices.','VaultSync watches your folders and auto-organizes files by type, date and project. Syncs across two devices on the free plan.',ARRAY['Auto file sorting by type & date','2-device sync on free plan','Duplicate file finder','Folder templates & presets','Quick preview panel'],ARRAY['Files','Sync','Organizer','Free','Storage']),
('lockbox','LockBox','Security','desktop','{windows,mac}',2000,4.7,2400,'paid','🔐','#FCE4EC','Password manager & secure vault for Windows & Mac. AES-256, fully offline.','LockBox stores credentials and secure notes in an AES-256 encrypted local vault. No cloud dependency required.',ARRAY['AES-256 local encryption','Fully offline, no cloud required','Strong password generator','Encrypted notes & file attachments','Browser extension coming soon'],ARRAY['Security','Passwords','Encryption','Privacy']),
('focusdesk','FocusDesk','Productivity','desktop','{windows,mac}',1500,4.6,2100,'paid','🎯','#FFF8E1','Native desktop focus timer. System-level blocking, starts with your OS.','FocusDesk runs natively on Windows and Mac, blocking distracting sites at the system level. Starts automatically with your OS.',ARRAY['System-level website blocking','Pomodoro & custom intervals','Starts with OS login automatically','Detailed daily productivity logs','Dark and light mode'],ARRAY['Focus','Desktop','Blocking','Productivity']),
('fileforge','FileForge','Utilities','desktop','{windows}',3000,4.5,980,'paid','🛠️','#F3E5F5','Windows bulk file renamer, converter and organizer. Handles thousands of files.','FileForge is a powerful Windows utility for bulk renaming, format conversion and folder organization with regex support and full undo history.',ARRAY['Bulk file renaming with regex','Format conversion for images & docs','Folder tree reorganizer','Full undo history for every action','Command-line mode available'],ARRAY['Files','Windows','Utilities','Bulk']),
('macvault','MacVault','Security','desktop','{mac}',2500,4.7,760,'new','🔒','#E8F5E9','Mac-only folder encryption with Touch ID. Right-click to protect from Finder.','MacVault integrates with macOS Finder to add AES-256 encryption to any folder. Authenticate with Touch ID to unlock.',ARRAY['Finder context-menu integration','Touch ID authentication','AES-256 folder encryption','Auto-locks on screen sleep','Encrypted iCloud backups'],ARRAY['Mac','Security','Encryption','Touch ID']),
('quicknote-m','QuickNote Mobile','Productivity','mobile','{android,ios}',0,4.4,5200,'free','📱','#FFFDE7','Markdown notes on the go. Syncs with QuickNote web. Android & iOS.','The mobile companion to QuickNote. Capture notes on your phone, sync instantly to the web app. Works offline.',ARRAY['Full markdown editor on mobile','Offline mode with auto-sync','Voice-to-note recording','Shares to QuickNote web','Dark mode & custom themes'],ARRAY['Notes','Mobile','Offline','Free']),
('paytrack','PayTrack','Finance','mobile','{android,ios}',800,4.6,3400,'top','💸','#E8F5E9','Track income and expenses on your phone. Monthly summaries with charts.','PayTrack is a clean, fast expense tracker. Snap receipts, tag categories, set budgets, and get weekly summaries.',ARRAY['Receipt photo capture','Expense category tagging','Daily & monthly chart summaries','Budget limit alerts','Export to Excel or CSV'],ARRAY['Finance','Expenses','Budget','Mobile']),
('staffcheck','StaffCheck','Productivity','mobile','{android}',1200,4.5,1900,'new','✅','#E0F7FA','Android attendance app for SMEs. GPS clock-in/out, late alerts, admin reports.','StaffCheck lets employees clock in and out via Android phone with GPS tagging. Admin gets a real-time attendance dashboard.',ARRAY['GPS-tagged clock in & clock out','Real-time attendance dashboard','Late arrival SMS alerts','Monthly PDF attendance reports','Multi-location support'],ARRAY['HR','Attendance','Android','Team']),
('invkit-m','InvoiceKit Mobile','Finance','mobile','{android,ios}',1500,4.7,2800,'paid','🧾','#F3E5F5','Create and send professional invoices from your phone. Syncs with InvoiceKit web.','Send invoices on the go. Full InvoiceKit features in your pocket, synced in real time with your web account.',ARRAY['Full invoice creation on mobile','PDF generation & WhatsApp sharing','Real-time payment notifications','Client database sync with web','Flutterwave payment link generation'],ARRAY['Invoice','Mobile','Finance','WhatsApp'])
on conflict (id) do nothing;

-- ── APP LAUNCH URLS — run/re-run this section any time an app goes live ──
-- ON CONFLICT DO NOTHING above means re-running the seed never updates an
-- existing row, so launch_url/storage_path are set here instead, separately,
-- as each app actually gets built. Safe to re-run — it's just an UPDATE.
update public.apps set launch_url = '/quicknote' where id = 'quicknote';

-- QuickNote Mobile: HELD, on purpose. No native Android/iOS build exists, and
-- an earlier attempt to substitute the web app instead was explicitly declined —
-- native mobile apps wait for real development elsewhere (Claude Code, etc.),
-- not a web-app stand-in. This line reverses that substitution if it was ever
-- applied to your database; it's a no-op (both already null) otherwise.
update public.apps set launch_url = null where id = 'quicknote-m';
update public.apps set launch_url = '/invoicekit' where id = 'invoicekit';
