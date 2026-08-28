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
  document.querySelectorAll('form[data-once]').forEach(form => {
    form.addEventListener('submit', () => {
      form.querySelectorAll('[type=submit]').forEach(btn => {
        btn.disabled = true;
        btn.textContent = btn.dataset.loading || 'Saving…';
      });
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

});
