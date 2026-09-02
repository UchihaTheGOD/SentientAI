/* public.js — Sentient Community Platform */
'use strict';

document.addEventListener('DOMContentLoaded', () => {

  // ---- Mobile nav toggle ----
  const toggle = document.getElementById('mobile-nav-toggle');
  const nav = document.getElementById('primary-nav');
  if (toggle && nav) {
    toggle.addEventListener('click', () => {
      nav.classList.toggle('mobile-open');
    });
  }

  // ---- User dropdown ----
  const userMenuToggle = document.getElementById('user-menu-toggle');
  const userDropdown = document.getElementById('user-dropdown');
  if (userMenuToggle && userDropdown) {
    userMenuToggle.addEventListener('click', (e) => {
      e.stopPropagation();
      userDropdown.classList.toggle('open');
    });
    document.addEventListener('click', () => {
      userDropdown.classList.remove('open');
    });
  }

  // ---- Reply toggle ----
  document.querySelectorAll('[data-reply-toggle]').forEach(btn => {
    btn.addEventListener('click', () => {
      const targetId = btn.dataset.replyToggle;
      const form = document.getElementById(targetId);
      if (form) form.classList.toggle('open');
    });
  });

  // ---- Auto-dismiss alerts ----
  document.querySelectorAll('.alert[data-autodismiss]').forEach(el => {
    setTimeout(() => el.remove(), 4000);
  });

  // ---- Prevent double-submit ----
  // The clicked button is deliberately NOT disabled inside the submit handler:
  // the browser builds the form data after this event runs, and a disabled
  // submitter is left out of it — which would silently drop fields like the
  // publish/draft choice. Mark the form instead, then disable on the next tick.
  document.querySelectorAll('form[data-once]').forEach(form => {
    form.addEventListener('submit', (event) => {
      if (form.dataset.submitting === 'true') {
        event.preventDefault();
        return;
      }
      form.dataset.submitting = 'true';
      form.querySelectorAll('[type=submit]').forEach(btn => {
        if (btn.dataset.loading) btn.textContent = btn.dataset.loading;
        btn.classList.add('is-busy');
      });
      setTimeout(() => {
        form.querySelectorAll('[type=submit]').forEach(btn => { btn.disabled = true; });
      }, 0);
    });
  });

  // ---- Copy link button ----
  document.querySelectorAll('[data-copy-link]').forEach(btn => {
    btn.addEventListener('click', () => {
      navigator.clipboard.writeText(btn.dataset.copyLink || window.location.href)
        .then(() => {
          const orig = btn.textContent;
          btn.textContent = 'Copied!';
          setTimeout(() => btn.textContent = orig, 2000);
        });
    });
  });

  // ---- Confirm destructive submits ----
  // A progressive-enhancement guard for forms that delete things: if JS is on,
  // ask before the POST goes out. The server still enforces its own checks
  // (CSRF, admin auth, typed-in confirmation), so this is convenience, not
  // security — with JS off the form still submits and the server decides.
  document.querySelectorAll('form[data-confirm]').forEach(form => {
    form.addEventListener('submit', (event) => {
      if (!window.confirm(form.dataset.confirm || 'Are you sure?')) {
        event.preventDefault();
      }
    });
  });

});
