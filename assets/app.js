/* ═══════════════════════════════════════════════════════════════════
   AppAholic — Shared App JS
   Session handling, nav/drawer behavior, authFetch, toast.
   Loaded by every page after theme.css.
   ═══════════════════════════════════════════════════════════════════ */

window.API_BASE = 'https://api.appaholic.justservices.pro';
var SESSION_KEY = 'aah_session';

/* ── SESSION (signed JWT from the server — not decoded/trusted client-side) ── */
var Session = {
  get: function () { return localStorage.getItem(SESSION_KEY) || null; },
  set: function (token) { localStorage.setItem(SESSION_KEY, token); },
  clear: function () { localStorage.removeItem(SESSION_KEY); },
  isSignedIn: function () { return !!Session.get(); },
};
window.Session = Session;

/* Pick up ?session=... from the OAuth redirect, store it, clean the URL. */
(function captureSessionFromUrl() {
  var params = new URLSearchParams(window.location.search);
  var token = params.get('session');
  if (token) {
    Session.set(token);
    params.delete('session');
    var clean = window.location.pathname + (params.toString() ? '?' + params.toString() : '');
    history.replaceState({}, '', clean);
  }
})();

/* ── authFetch — attaches the session token; use for any authenticated API call ── */
function authFetch(path, options) {
  options = options || {};
  var headers = Object.assign({}, options.headers || {});
  var token = Session.get();
  if (token) headers['Authorization'] = 'Bearer ' + token;
  return fetch(window.API_BASE + path, Object.assign({}, options, { headers: headers }));
}
window.authFetch = authFetch;

/* ── TOAST ── */
function showToast(msg, icon) {
  var t = document.getElementById('toast');
  if (!t) return;
  var msgEl = document.getElementById('toastMsg');
  var iconEl = document.getElementById('toastIcon');
  if (msgEl) msgEl.textContent = msg;
  if (iconEl) iconEl.textContent = icon || '✅';
  t.classList.add('show');
  setTimeout(function () { t.classList.remove('show'); }, 3500);
}
window.showToast = showToast;

/* ── SCROLL-REVEAL — fade+rise elements into view as the user scrolls ── */
document.addEventListener('DOMContentLoaded', function () {
  var revealEls = document.querySelectorAll('[data-reveal]');
  if (!revealEls.length) return;

  if (!('IntersectionObserver' in window) || window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
    revealEls.forEach(function (el) { el.classList.add('reveal-visible'); });
    return;
  }

  var observer = new IntersectionObserver(function (entries) {
    entries.forEach(function (entry) {
      if (entry.isIntersecting) {
        entry.target.classList.add('reveal-visible');
        observer.unobserve(entry.target);
      }
    });
  }, { threshold: 0.12, rootMargin: '0px 0px -40px 0px' });

  revealEls.forEach(function (el, i) {
    el.style.transitionDelay = Math.min(i % 6, 5) * 60 + 'ms';
    observer.observe(el);
  });
});

/* ── PWA INSTALL — captures the browser's install prompt so any page can trigger it.
   Real constraint, stated plainly rather than hidden: Chrome/Edge/Android support this
   event; Safari/iOS does not — there, "Install" falls back to a hint about the browser's
   own "Add to Home Screen" menu option, since no JS API can trigger that on iOS. ── */
var _deferredInstallPrompt = null;
var INSTALL_DISMISS_KEY = 'aah_install_dismissed_at';
var INSTALL_DISMISS_COOLDOWN_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

window.addEventListener('beforeinstallprompt', function(e) {
  e.preventDefault();
  _deferredInstallPrompt = e;
  maybeShowInstallBanner();
});

function maybeShowInstallBanner() {
  if (!_deferredInstallPrompt) return;
  // Don't show on an app's own page (quicknote.html, invoicekit.html handle
  // their own install flow already) — only on general site pages.
  if (document.body.getAttribute('data-no-install-banner') === 'true') return;
  var dismissedAt = Number(localStorage.getItem(INSTALL_DISMISS_KEY) || 0);
  if (Date.now() - dismissedAt < INSTALL_DISMISS_COOLDOWN_MS) return;
  renderInstallBanner();
}

function renderInstallBanner() {
  if (document.getElementById('installBanner')) return; // already showing
  var banner = document.createElement('div');
  banner.id = 'installBanner';
  banner.className = 'install-banner';
  banner.innerHTML =
    '<span class="install-banner__icon">📲</span>' +
    '<span class="install-banner__text"><strong>Install AppAholic</strong> — add it to your home screen or desktop for one-tap access.</span>' +
    '<button class="btn btn-ochre btn-sm install-banner__install">Install</button>' +
    '<button class="install-banner__dismiss" aria-label="Dismiss">&#x2715;</button>';
  document.body.appendChild(banner);
  requestAnimationFrame(function () { requestAnimationFrame(function () { banner.classList.add('show'); }); });

  banner.querySelector('.install-banner__install').addEventListener('click', function () {
    window.AppInstall.prompt().then(function (outcome) {
      if (outcome !== 'unavailable') dismissInstallBanner();
      if (typeof showToast === 'function' && outcome === 'accepted') showToast('Installed! Check your home screen / desktop.', '✅');
    });
  });
  banner.querySelector('.install-banner__dismiss').addEventListener('click', dismissInstallBanner);
}

function dismissInstallBanner() {
  var banner = document.getElementById('installBanner');
  if (banner) { banner.classList.remove('show'); setTimeout(function () { banner.remove(); }, 300); }
  localStorage.setItem(INSTALL_DISMISS_KEY, String(Date.now()));
}

window.AppInstall = {
  isAvailable: function () { return !!_deferredInstallPrompt; },
  prompt: function () {
    if (!_deferredInstallPrompt) return Promise.resolve('unavailable');
    var evt = _deferredInstallPrompt;
    _deferredInstallPrompt = null;
    evt.prompt();
    return evt.userChoice.then(function (choice) { return choice.outcome; }); // 'accepted' | 'dismissed'
  },
  // Call this on an app's own page. Checks for ?install=1 in the URL (set when
  // arriving from the marketplace's Install button), cleans it from the URL, and
  // waits briefly for the browser's install prompt to become available — it can
  // fire a moment after page load, not always instantly. Falls back to a toast
  // hint if it never arrives (Safari/iOS has no such event at all; Chrome may
  // withhold it on a very first visit until its own engagement heuristics are met —
  // neither is something a webpage can force).
  tryAutoPromptFromUrl: function () {
    var params = new URLSearchParams(window.location.search);
    if (!params.get('install')) return;
    params.delete('install');
    var clean = window.location.pathname + (params.toString() ? '?' + params.toString() : '');
    history.replaceState({}, '', clean);

    var attempts = 0;
    var maxAttempts = 10; // ~5 seconds
    var self = this;
    (function poll() {
      if (self.isAvailable()) {
        self.prompt().then(function (outcome) {
          if (typeof showToast === 'function') {
            showToast(outcome === 'accepted' ? 'Installed! Check your home screen / desktop.' : 'Install dismissed — you can try again anytime from here.', outcome === 'accepted' ? '✅' : 'ℹ️');
          }
        });
        return;
      }
      attempts++;
      if (attempts < maxAttempts) { setTimeout(poll, 500); return; }
      if (typeof showToast === 'function') {
        showToast('Use your browser\'s install icon (address bar) or menu → "Add to Home Screen" / "Install App".', 'ℹ️');
      }
    })();
  },
};

/* ── NAV / DRAWER / SIGNED-IN STATE (runs on every page) ── */
document.addEventListener('DOMContentLoaded', function () {
  var hamburger = document.getElementById('navHamburger');
  var drawer    = document.getElementById('mobileDrawer');
  var backdrop  = document.getElementById('drawerBackdrop');
  var closeBtn  = document.getElementById('drawerClose');

  function openDrawer(){ if(!drawer) return; drawer.classList.add('open'); backdrop.classList.add('show'); drawer.setAttribute('aria-hidden','false'); hamburger.setAttribute('aria-expanded','true'); document.body.style.overflow='hidden'; if(closeBtn) closeBtn.focus(); }
  function closeDrawer(){ if(!drawer) return; drawer.classList.remove('open'); backdrop.classList.remove('show'); drawer.setAttribute('aria-hidden','true'); hamburger.setAttribute('aria-expanded','false'); document.body.style.overflow=''; if(hamburger) hamburger.focus(); }
  window.closeDrawer = closeDrawer;

  if (hamburger) hamburger.addEventListener('click', openDrawer);
  if (closeBtn) closeBtn.addEventListener('click', closeDrawer);
  if (backdrop) backdrop.addEventListener('click', closeDrawer);
  document.addEventListener('keydown', function(e){ if(e.key==='Escape' && drawer && drawer.classList.contains('open')) closeDrawer(); });

  var yr = document.getElementById('footerYear');
  if (yr) yr.textContent = new Date().getFullYear();

  // Reflect signed-in state in the nav (works across every page since Session is shared via localStorage)
  var navSignIn = document.getElementById('navSignIn');
  if (navSignIn && Session.isSignedIn()) {
    navSignIn.textContent = 'Dashboard';
    navSignIn.setAttribute('href', '/dashboard');
  }
  var mobileSignIn = document.getElementById('mobileSignIn');
  if (mobileSignIn && Session.isSignedIn()) {
    mobileSignIn.textContent = 'Dashboard';
    mobileSignIn.setAttribute('href', '/dashboard');
  }

  // Service worker
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('/sw.js', { scope: '/' })
      .then(function (reg) { setInterval(function () { reg.update(); }, 60000); })
      .catch(function () {});
  }
});
