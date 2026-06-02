/**
 * reload-scroll-preserve.js — preserve scroll position across location.reload().
 *
 * Bug 2026-05-26 (AT-M4 + #66 polish) : avant ce helper, ``location.reload()``
 * après CRUD ramenait l'admin en haut de page. UX dégradée pour les workflows
 * « scroll en bas, action sur ligne 47, attendre toast, continuer le ménage ».
 *
 * Helper extrait depuis ``templates/admin/ai_training.html`` (AT-M4) pour
 * réutilisation sur les autres pages /admin* (performance, ai_performance,
 * data_access). Évite la duplication inline (SSoT).
 *
 * Contrat public :
 * - ``window.komptiaReload.preservingScroll()`` — remplace ``location.reload()``.
 *   Sauve ``window.scrollY`` dans sessionStorage (clé URL-scoped) avant reload.
 *
 * Au DOMContentLoaded du document suivant, le helper restaure la position
 * (rAF pour scroll après le layout) puis purge la clé (anti-survie F5 manuel).
 *
 * Notes design :
 * - sessionStorage et NON localStorage : sessionStorage est par-onglet,
 *   évite la fuite cross-tab (un admin qui scroll dans Tab 1 ne pollue pas
 *   Tab 2).
 * - Clé scopée par URL (pathname + search) : différents filtres → scrolls
 *   indépendants (« /admin/ai-training?type=ddl » distinct de « ?type=question_sql »).
 * - Idempotent : guard ``window.__komptiaReloadHelperInit``.
 */
(function () {
    'use strict';
    if (window.__komptiaReloadHelperInit) return;
    window.__komptiaReloadHelperInit = true;

    var KEY_PREFIX = 'komptia_scroll_';

    function _key() {
        return KEY_PREFIX + window.location.pathname + window.location.search;
    }

    function preservingScroll() {
        try {
            sessionStorage.setItem(_key(), String(window.scrollY));
        } catch (e) { /* sessionStorage indisponible (mode privé strict) */ }
        location.reload();
    }

    function _restoreOnLoad() {
        try {
            var raw = sessionStorage.getItem(_key());
            if (!raw) return;
            var y = parseInt(raw, 10);
            if (!Number.isFinite(y) || y <= 0) return;
            // Purge la clé AVANT de scroller — sinon un F5 manuel après la
            // restauration re-scroll automatiquement (surprenant pour l'user).
            sessionStorage.removeItem(_key());
            (window.requestAnimationFrame || function (cb) { setTimeout(cb, 16); })(
                function () { window.scrollTo({ top: y, behavior: 'instant' }); }
            );
        } catch (e) { /* defensive */ }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', _restoreOnLoad);
    } else {
        _restoreOnLoad();
    }

    window.komptiaReload = {
        preservingScroll: preservingScroll,
    };
})();
