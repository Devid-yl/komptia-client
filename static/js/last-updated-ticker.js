/**
 * last-updated-ticker.js — ticker "Dernière mise à jour il y a Xs".
 *
 * Bug 2026-05-26 (AI-10 + P-3 dedup) : avant ce fichier, la fonction
 * ``updateRelativeTime`` était dupliquée inline dans /admin/performance.html.
 * Avec /admin/ai-performance qui veut le même comportement (AI-10), on
 * extrait le ticker dans un module partagé pour respecter la doctrine SSoT.
 *
 * Contrat :
 * 1. Cherche TOUS les éléments ``[data-ts]`` avec ``id="last-updated-ticker"``
 *    OU avec la classe ``komptia-last-updated`` (pour réutilisation future).
 * 2. Met à jour leur ``textContent`` toutes les 10 secondes avec une chaîne
 *    relative en français : "à l'instant", "il y a 12 s", "il y a 4 min",
 *    "il y a 2 h".
 * 3. CSP-safe : zéro innerHTML, pure textContent.
 * 4. Idempotent : guard ``window.__komptiaLastUpdatedTickerInitialized``.
 * 5. Pas d'API publique nécessaire — auto-démarre au DOMContentLoaded.
 */
(function () {
    'use strict';
    if (window.__komptiaLastUpdatedTickerInitialized) return;
    window.__komptiaLastUpdatedTickerInitialized = true;

    var SELECTOR = '#last-updated-ticker, .komptia-last-updated';
    var INTERVAL_MS = 10_000;

    function _format(diffSec) {
        if (diffSec < 5) return "à l'instant";
        if (diffSec < 60) return 'il y a ' + diffSec + ' s';
        if (diffSec < 3600) return 'il y a ' + Math.floor(diffSec / 60) + ' min';
        return 'il y a ' + Math.floor(diffSec / 3600) + ' h';
    }

    function _tick() {
        var nodes = document.querySelectorAll(SELECTOR);
        var now = Date.now();
        for (var i = 0; i < nodes.length; i++) {
            var el = nodes[i];
            var ts = el.getAttribute('data-ts');
            if (!ts) continue;
            var then = new Date(ts);
            var t = then.getTime();
            if (isNaN(t)) continue;
            var diffSec = Math.max(0, Math.floor((now - t) / 1000));
            el.textContent = _format(diffSec);
        }
    }

    function _start() {
        _tick();
        setInterval(_tick, INTERVAL_MS);
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', _start);
    } else {
        _start();
    }
})();
