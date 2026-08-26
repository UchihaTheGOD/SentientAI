/* SentientAI — Minimal client-side JS */

document.addEventListener('DOMContentLoaded', function() {
    // Mobile nav toggle
    const toggle = document.querySelector('.nav-toggle');
    const navLinks = document.querySelector('.nav-links');
    if (toggle && navLinks) {
        toggle.addEventListener('click', function() {
            navLinks.classList.toggle('open');
        });
    }

    // Auto-dismiss alerts after 5s
    document.querySelectorAll('.alert[data-dismiss]').forEach(function(el) {
        setTimeout(function() {
            el.style.opacity = '0';
            el.style.transition = 'opacity 300ms ease';
            setTimeout(function() { el.remove(); }, 300);
        }, 5000);
    });

    // Lab form submission — prevent double-submit
    document.querySelectorAll('.lab-form').forEach(function(form) {
        form.addEventListener('submit', function() {
            var btn = form.querySelector('button[type="submit"]');
            if (btn) {
                btn.disabled = true;
                btn.textContent = 'Analyzing...';
            }
        });
    });
});
