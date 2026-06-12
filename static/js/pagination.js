// pagination.js — barre de pagination CLIENT unifiée (listes chargées en AJAX).
//
// Pendant client de l'UIModule serveur ``app.ui_modules.Pagination`` :
// MÊME algorithme de fenêtrage, MÊMES icônes (Première ⏮ · Précédente ‹ ·
// numéros avec « … » · Suivante › · Dernière ⏭), MÊME habillage dark-mode.
// Source UNIQUE de vérité pour les pagers JS — contacts / reports /
// email-history / data-privacy l'appellent au lieu de réimplémenter.
//
// Contrat public :
//   window.KomptiaPagination.render(container, {
//       page:        Number,   // page courante (1-based)
//       totalPages:  Number,   // total de pages (barre masquée si <= 1)
//       onNavigate:  function(page) {},  // appelé au clic d'un contrôle
//       countText:   String,   // optionnel — ex "42 contacts" (textContent, anti-XSS)
//       siblingCount:Number,   // défaut 2 (current ± 2)
//       boundaryCount:Number,  // défaut 1 (1ère + dernière)
//   })
//   window.KomptiaPagination.buildWindow(page, totalPages, sibling, boundary)
//       → Array<Number|null>  (null = ellipse) — exposé pour les tests de parité.
//
// Doctrine
// --------
//  1. CSP-safe : addEventListener uniquement, zéro ``onclick`` inline. Chargé
//     via ``<script src>`` avec nonce CSP dans base.html, AVANT ``{% block scripts %}``
//     pour être dispo dans les scripts inline des pages enfants.
//  2. Idempotent boot : garde ``__komptiaPaginationInit``.
//  3. Anti-XSS : les numéros sont des entiers (textContent) ; ``countText`` est
//     rendu en textContent ; ``innerHTML`` n'est utilisé QUE pour des constantes
//     SVG internes (jamais de donnée externe).
//  4. Re-render propre : ``render`` vide le conteneur et reconstruit — aucun
//     listener fantôme (les anciens nœuds sont collectés).
//  5. A11y : ``<nav aria-label>``, ``aria-current="page"`` sur la page active,
//     ``aria-label`` FR sur chaque contrôle, bornes via ``<button disabled>``.
(function () {
    'use strict';
    if (window.__komptiaPaginationInit) { return; }
    window.__komptiaPaginationInit = true;

    // Icônes — chevrons identiques à templates/_partials/pagination_ssr.html.
    var ICONS = {
        first: '<svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M18.75 19.5l-7.5-7.5 7.5-7.5m-6 15L5.25 12l7.5-7.5"/></svg>',
        prev: '<svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M15.75 19.5L8.25 12l7.5-7.5"/></svg>',
        next: '<svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M8.25 4.5l7.5 7.5-7.5 7.5"/></svg>',
        last: '<svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M11.25 4.5l7.5 7.5-7.5 7.5m-6-15l7.5 7.5-7.5 7.5"/></svg>'
    };

    var BTN = 'inline-flex items-center justify-center px-2.5 py-1 text-xs border border-gray-300 rounded text-gray-700 dark:text-gray-300 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-800';
    var BTN_OFF = 'inline-flex items-center justify-center px-2.5 py-1 text-xs border border-gray-300 rounded text-gray-700 dark:text-gray-300 dark:border-gray-700 disabled:opacity-40 disabled:cursor-not-allowed';
    var CUR = 'inline-flex items-center justify-center px-2.5 py-1 text-xs border rounded bg-gray-900 text-white border-gray-900 dark:bg-gray-100 dark:text-gray-900 dark:border-gray-100';
    var ELL = 'inline-flex items-center px-1 text-xs text-gray-400 dark:text-gray-500 select-none';

    function toInt(v, fallback) {
        var n = parseInt(v, 10);
        return (isNaN(n)) ? fallback : n;
    }

    // Réplique EXACTE de app.ui_modules.build_pagination_window (parité testée).
    function buildWindow(page, totalPages, sibling, boundary) {
        totalPages = toInt(totalPages, 0);
        if (!(totalPages > 1)) { return []; }
        page = toInt(page, 1);
        if (page < 1) { page = 1; }
        if (page > totalPages) { page = totalPages; }
        sibling = (sibling == null) ? 2 : Math.max(0, toInt(sibling, 2));
        boundary = (boundary == null) ? 1 : Math.max(1, toInt(boundary, 1));

        var keep = {};
        var i;
        for (i = 1; i <= boundary; i++) {
            keep[i] = true;
            keep[totalPages - i + 1] = true;
        }
        for (var p = page - sibling; p <= page + sibling; p++) {
            keep[p] = true;
        }
        var ordered = Object.keys(keep)
            .map(Number)
            .filter(function (n) { return n >= 1 && n <= totalPages; })
            .sort(function (a, b) { return a - b; });

        var result = [];
        var prev = 0;
        for (var k = 0; k < ordered.length; k++) {
            var n = ordered[k];
            var gap = n - prev;
            if (gap === 2) { result.push(prev + 1); }   // comble un trou d'1 page
            else if (gap > 2) { result.push(null); }    // ellipse « … »
            result.push(n);
            prev = n;
        }
        return result;
    }

    function iconControl(kind, targetPage, enabled, ariaLabel, onNavigate) {
        var btn = document.createElement('button');
        btn.type = 'button';
        btn.setAttribute('aria-label', ariaLabel);
        btn.title = ariaLabel;
        btn.innerHTML = ICONS[kind]; // constante SVG interne — jamais de donnée externe
        if (enabled) {
            btn.className = BTN;
            btn.addEventListener('click', function () { onNavigate(targetPage); });
        } else {
            btn.className = BTN_OFF;
            btn.disabled = true;
        }
        return btn;
    }

    function pageControl(num, current, onNavigate) {
        if (num === current) {
            var cur = document.createElement('span');
            cur.className = CUR;
            cur.setAttribute('aria-current', 'page');
            cur.setAttribute('aria-label', 'Page ' + num + ', page courante');
            cur.textContent = String(num);
            return cur;
        }
        var btn = document.createElement('button');
        btn.type = 'button';
        btn.className = BTN;
        btn.setAttribute('aria-label', 'Page ' + num);
        btn.textContent = String(num);
        btn.addEventListener('click', function () { onNavigate(num); });
        return btn;
    }

    function render(container, opts) {
        if (!container) { return; }
        opts = opts || {};
        var totalPages = toInt(opts.totalPages, 0);
        var onNavigate = (typeof opts.onNavigate === 'function') ? opts.onNavigate : function () {};

        // Reconstruction complète : vide le conteneur (pas de listener fantôme).
        container.textContent = '';
        if (!(totalPages > 1)) { return; }  // rien à paginer → barre masquée

        var page = toInt(opts.page, 1);
        if (page < 1) { page = 1; }
        if (page > totalPages) { page = totalPages; }

        var nav = document.createElement('nav');
        nav.setAttribute('role', 'navigation');
        nav.setAttribute('aria-label', 'Pagination');
        nav.className = 'flex items-center justify-center gap-1 flex-wrap';

        var atFirst = page <= 1;
        var atLast = page >= totalPages;

        nav.appendChild(iconControl('first', 1, !atFirst, 'Première page', onNavigate));
        nav.appendChild(iconControl('prev', page - 1, !atFirst, 'Page précédente', onNavigate));

        var win = buildWindow(page, totalPages, opts.siblingCount, opts.boundaryCount);
        for (var i = 0; i < win.length; i++) {
            var it = win[i];
            if (it === null) {
                var ell = document.createElement('span');
                ell.className = ELL;
                ell.setAttribute('aria-hidden', 'true');
                ell.textContent = '…';
                nav.appendChild(ell);
            } else {
                nav.appendChild(pageControl(it, page, onNavigate));
            }
        }

        nav.appendChild(iconControl('next', page + 1, !atLast, 'Page suivante', onNavigate));
        nav.appendChild(iconControl('last', totalPages, !atLast, 'Dernière page', onNavigate));

        container.appendChild(nav);

        if (opts.countText != null && opts.countText !== '') {
            var cnt = document.createElement('span');
            cnt.className = 'text-xs text-gray-500 ml-2 dark:text-gray-400';
            cnt.textContent = String(opts.countText); // textContent → anti-XSS
            container.appendChild(cnt);
        }
    }

    window.KomptiaPagination = { render: render, buildWindow: buildWindow };
})();
