// privacy-badge.js — anon-impl-loop #14.
//
// Badge global "X termes critiques visibles par l'IA" affiche un compteur
// cliquable dans le header de toutes les pages (sauf /data/privacy elle-meme,
// gere cote template). Click → /data/privacy.
//
// Source de verite : ``GET /api/anonymization/stats`` → ``stats.critical_visible``
// (nombre de termes ``risk_level=critical`` AND ``enabled=False``, cf.
// ``app/services/anonymization/api_service.py:599`` ``stats_for_user``).
//
// Doctrine
// --------
// 1. **CSP-safe** — script externe avec nonce (cf. base.html). Aucun
//    ``onclick`` inline, ``addEventListener`` partout.
// 2. **Cache localStorage 30s** — multi-onglets : 5 onglets ouverts ne
//    spamment pas l'API (rate-limit 60/min cote serveur). Une mise a jour
//    dans un onglet est visible dans les autres via l'event ``storage``.
// 3. **Pause quand onglet hidden** — ``visibilitychange`` : pas de poll
//    quand la page est en arriere-plan (axe Komptia "pas de croissance non
//    bornee" + economie de batterie mobile).
// 4. **Silent on errors** — un 401/5xx/network ne doit pas spammer de toast :
//    le user n'a rien demande, c'est un poll de fond. On garde la derniere
//    valeur cachee.
// 5. **Adaptive placement** — par defaut ``position: fixed`` top-right. Si
//    la page expose une topbar (``.iris-topbar`` Iris ou ``#app-topbar``
//    sidebar collapsed), le badge est deplace dedans (``--inline``) pour
//    eviter un overlap avec les boutons existants.
// 6. **Anti-flicker** — le DOM est rendu avec ``hidden`` cote serveur. Le JS
//    applique l'etat depuis le cache instantanement, puis fetch en
//    arriere-plan. Pas de "0 → N" visible.
// 7. **bfcache friendly** — ``pageshow`` event refresh au retour Back/Forward.
// 8. **Anti-XSS** — count + text sont injectes via ``textContent`` (jamais
//    ``innerHTML``). Le label texte est statique (FR), pas user-controlled.

(function () {
    'use strict';

    // Prefixe localStorage — namespace komptia_ pour eviter les collisions.
    // La cle finale est ``<prefix>__<user_id>`` (cf. cacheKeyForUser) pour
    // eviter le leak cross-user sur poste partage (findings adversarial C1).
    var CACHE_KEY_PREFIX = 'komptia_privacy_critical_v1';
    // TTL cache : 30s (cf. description tache #14). Aligne avec le refresh
    // poll : on ne refetch pas si une autre tab vient de fetch.
    var CACHE_TTL_MS = 30 * 1000;
    // Periode de poll quand l'onglet est visible. On reverifie le cache a
    // chaque tick — si frais, on skip le fetch.
    var POLL_INTERVAL_MS = 30 * 1000;
    // Backoff exponentiel apres erreur successive (M3 review).
    // Croit jusqu'a un cap pour eviter le flood quand l'API est down.
    var POLL_BACKOFF_MAX_MS = 5 * 60 * 1000; // 5 minutes
    // URL du endpoint stats (cf. app/handlers/anonymization.py:911
    // AnonymizationStatsAPIHandler).
    var STATS_URL = '/api/anonymization/stats';
    // Custom event : permet aux modules tiers (privacy-page.js, iris-grid.js)
    // de signaler une mise a jour des termes → invalide cache + refetch.
    var CHANGE_EVENT = 'komptia:anonymization-changed';

    // ── Helpers purs (testables Node) ─────────────────────────────────

    /**
     * Construit le label FR du badge.
     *
     * @param {number} count - Nombre de termes critiques visibles.
     * @returns {string} Label complet ("3 termes critiques visibles par l'IA")
     *                   ou chaine vide si count <= 0 (badge cache).
     */
    function formatLabel(count) {
        var n = (typeof count === 'number' && isFinite(count) && count > 0)
            ? Math.floor(count) : 0;
        if (n <= 0) return '';
        var noun = (n === 1) ? 'terme critique visible' : 'termes critiques visibles';
        return n + ' ' + noun + " par l'IA";
    }

    /**
     * Parse une reponse JSON ``{stats: {...}}`` en compteur entier >= 0.
     * Defensive : tout shape inattendu → 0 (badge cache).
     *
     * @param {*} data - Payload retourne par fetch().json().
     * @returns {number} Compteur entier >= 0.
     */
    function parseStatsResponse(data) {
        if (!data || typeof data !== 'object') return 0;
        var stats = data.stats;
        if (!stats || typeof stats !== 'object') return 0;
        var raw = stats.critical_visible;
        var n = (typeof raw === 'number' && isFinite(raw)) ? Math.floor(raw) : 0;
        return n > 0 ? n : 0;
    }

    /**
     * Determine si une entree de cache est encore valable.
     *
     * @param {object|null} cache - {count, ts} ou null.
     * @param {number} nowMs - Date.now() au moment de l'appel.
     * @param {number} ttlMs - TTL en millisecondes.
     * @returns {boolean}
     */
    function isCacheFresh(cache, nowMs, ttlMs) {
        if (!cache || typeof cache !== 'object') return false;
        if (typeof cache.ts !== 'number' || !isFinite(cache.ts)) return false;
        if (typeof nowMs !== 'number' || typeof ttlMs !== 'number') return false;
        return (nowMs - cache.ts) < ttlMs;
    }

    /**
     * Selectionne le delai (ms) avant le prochain fetch, en tenant compte
     * du cache existant. Si une autre tab a fetch recemment, on attend
     * le solde de TTL avant de re-fetch.
     *
     * @param {object|null} cache - Cache courant.
     * @param {number} nowMs - Date.now().
     * @param {number} ttlMs - TTL.
     * @returns {number} Delai ms (>= 0).
     */
    function pickRefreshDelay(cache, nowMs, ttlMs) {
        if (!cache || typeof cache.ts !== 'number') return 0;
        var elapsed = nowMs - cache.ts;
        if (elapsed >= ttlMs) return 0;
        return Math.max(0, ttlMs - elapsed);
    }

    // ── DOM / runtime (skippe en environnement Node pour les tests) ───

    if (typeof document === 'undefined' || typeof window === 'undefined') {
        // Mode Node (tests purs) : on s'arrete ici, les exports en bas suffisent.
        // eslint-disable-next-line no-undef
        if (typeof module !== 'undefined' && module.exports) {
            module.exports = {
                formatLabel: formatLabel,
                parseStatsResponse: parseStatsResponse,
                isCacheFresh: isCacheFresh,
                pickRefreshDelay: pickRefreshDelay,
            };
        }
        return;
    }

    /**
     * Construit la cle localStorage pour l'user donne. Sans user_id (pas de
     * data-user-id sur le badge → element non rendu, edge case), on retourne
     * une cle de fallback "anon" qui n'est jamais peuplee (init exit avant).
     */
    function cacheKeyForUser(userId) {
        var safe = (userId && /^[0-9]+$/.test(String(userId))) ? String(userId) : 'anon';
        return CACHE_KEY_PREFIX + '__' + safe;
    }

    /**
     * Purge tous les caches de la cle prefix sauf celui de l'user courant.
     * Defense in-depth contre le leak cross-user : si user A s'est logue puis
     * user B sans purge, la cle de A reste en localStorage avec une valeur
     * stale. On nettoie au boot pour ne pas accumuler.
     */
    function purgeOtherUserCaches(currentUserId) {
        try {
            var keep = cacheKeyForUser(currentUserId);
            var stale = [];
            for (var i = 0; i < window.localStorage.length; i++) {
                var k = window.localStorage.key(i);
                if (k && k.indexOf(CACHE_KEY_PREFIX) === 0 && k !== keep) {
                    stale.push(k);
                }
            }
            for (var j = 0; j < stale.length; j++) {
                window.localStorage.removeItem(stale[j]);
            }
        } catch (_e) {}
    }

    function readCache(userId) {
        try {
            var raw = window.localStorage.getItem(cacheKeyForUser(userId));
            if (!raw) return null;
            var parsed = JSON.parse(raw);
            if (!parsed || typeof parsed !== 'object') return null;
            // Defense : count entier >= 0.
            var n = (typeof parsed.count === 'number' && isFinite(parsed.count))
                ? Math.floor(parsed.count) : 0;
            var ts = (typeof parsed.ts === 'number' && isFinite(parsed.ts))
                ? parsed.ts : 0;
            return { count: n > 0 ? n : 0, ts: ts };
        } catch (_e) {
            return null;
        }
    }

    function writeCache(userId, count) {
        try {
            window.localStorage.setItem(cacheKeyForUser(userId), JSON.stringify({
                count: count, ts: Date.now(),
            }));
        } catch (_e) {
            // localStorage indisponible (mode private Safari, quota, etc.)
            // → on reste en memoire seulement.
        }
    }

    function clearCache(userId) {
        try {
            window.localStorage.removeItem(cacheKeyForUser(userId));
        } catch (_e) {}
    }

    function findBadge() {
        return document.getElementById('komptia-privacy-badge');
    }

    /**
     * Deplace le badge dans la topbar adequate. Idempotent : appele plusieurs
     * fois sans creer de doublon.
     *
     * Priorite : .iris-topbar > #app-topbar (visible) > body fixed.
     *
     * Pourquoi pas une simple regle CSS ``:has()`` ? Parce que le test
     * "topbar visible" depend de ``style.display`` set par le sidebar
     * toggle JS — non observable depuis CSS.
     */
    function placeBadge(badge) {
        if (!badge) return;
        // Si deja inline et l'ancre cible existe, on ne deplace pas.
        var iris = document.querySelector('.iris-topbar');
        if (iris) {
            if (badge.parentNode !== iris) {
                iris.appendChild(badge);
            }
            badge.classList.add('komptia-privacy-badge--inline');
            return;
        }
        var topbar = document.getElementById('app-topbar');
        if (topbar) {
            // Le topbar est ``display: none`` par defaut, set a flex quand
            // sidebar collapsed. On insert quand meme : si display none,
            // le badge sera invisible (cohérent — sidebar visible suffit
            // a l'utilisateur), mais reste pret au toggle.
            var isVisible = topbar.style.display !== 'none';
            if (isVisible) {
                if (badge.parentNode !== topbar) {
                    var user = topbar.querySelector('.topbar-user');
                    if (user) {
                        topbar.insertBefore(badge, user);
                    } else {
                        topbar.appendChild(badge);
                    }
                }
                badge.classList.add('komptia-privacy-badge--inline');
                return;
            }
        }
        // Fallback : fixed top-right (state initial du DOM).
        badge.classList.remove('komptia-privacy-badge--inline');
        if (badge.parentNode !== document.body) {
            document.body.appendChild(badge);
        }
    }

    function render(badge, count) {
        if (!badge) return;
        var n = (typeof count === 'number' && count > 0) ? Math.floor(count) : 0;
        if (n <= 0) {
            badge.hidden = true;
            badge.setAttribute('aria-hidden', 'true');
            return;
        }
        var countEl = badge.querySelector('[data-role="count"]');
        var textEl = badge.querySelector('[data-role="text"]');
        if (countEl) countEl.textContent = String(n);
        if (textEl) {
            textEl.textContent = (n === 1)
                ? "terme critique visible par l'IA"
                : "termes critiques visibles par l'IA";
        }
        var label = formatLabel(n);
        badge.setAttribute('aria-label', label + ". Ouvrir la page Confidentialite.");
        badge.setAttribute('title', label);
        badge.hidden = false;
        badge.removeAttribute('aria-hidden');
    }

    var _inflight = null;

    /**
     * GET ``/api/anonymization/stats`` sans declencher l'auto-redirect
     * 401 du wrapper fetch global (cf. base.html ``setupSessionExpiryWatcher``).
     *
     * Pourquoi pas ``fetch`` ? ``base.html`` wrappe ``window.fetch`` pour
     * rediriger sur ``/login`` quand une reponse renvoie 401. Notre poll
     * tourne en arriere-plan toutes les 30s — si la session expire pendant
     * que l'utilisateur est inactif, le poll ferait sauter l'utilisateur
     * vers ``/login`` SANS qu'il ait initie une action. Surprenant et
     * destructeur (perte du formulaire/draft en cours).
     *
     * On utilise XMLHttpRequest pour bypasser ce wrap : c'est l'API
     * native, jamais interceptee. Code defensif : on n'a aucun side-effect
     * sur la session du user, on retourne juste une Promise<count|null>.
     *
     * ``_inflight`` clear via ``onloadend`` (post-resolve, sans race window
     * ouverte par ``then(...)``) — review C2.
     */
    function fetchStats() {
        if (_inflight) return _inflight;
        _inflight = new Promise(function (resolve) {
            var xhr;
            try {
                xhr = new XMLHttpRequest();
                xhr.open('GET', STATS_URL, true);
                xhr.withCredentials = true;
                xhr.setRequestHeader('Accept', 'application/json');
                xhr.setRequestHeader('X-Requested-With', 'XMLHttpRequest');
                // Pas de cache disque → headers no-store cote serveur de
                // toute facon (cf. _set_no_store_headers anonymization.py).
                xhr.timeout = 8000; // 8s : largement plus que la latence p99.
                xhr.onload = function () {
                    // 401/5xx/4xx → on garde le cache, pas de redirect.
                    if (xhr.status < 200 || xhr.status >= 300) {
                        resolve(null);
                        return;
                    }
                    var data = null;
                    try { data = JSON.parse(xhr.responseText || 'null'); }
                    catch (_e) { data = null; }
                    resolve(parseStatsResponse(data));
                };
                xhr.onerror = function () { resolve(null); };
                xhr.ontimeout = function () { resolve(null); };
                xhr.onabort = function () { resolve(null); };
                // ``onloadend`` est garanti d'etre appele apres
                // load/error/timeout/abort, et avant que l'event loop ne
                // dispatche un autre microtask. C'est l'endroit safe pour
                // clear ``_inflight`` sans race ``then``.
                xhr.onloadend = function () { _inflight = null; };
                xhr.send();
            } catch (_e) {
                _inflight = null;
                resolve(null);
            }
        });
        return _inflight;
    }

    var _consecutiveErrors = 0;

    function refresh(badge, userId, force) {
        var cached = readCache(userId);
        if (!force && isCacheFresh(cached, Date.now(), CACHE_TTL_MS)) {
            render(badge, cached.count);
            return Promise.resolve(cached.count);
        }
        return fetchStats().then(function (count) {
            if (count === null) {
                // Fetch failed → si on a un cache, on le garde affiche tel quel.
                _consecutiveErrors += 1;
                if (cached) render(badge, cached.count);
                return cached ? cached.count : 0;
            }
            _consecutiveErrors = 0;
            writeCache(userId, count);
            render(badge, count);
            return count;
        });
    }

    var _pollTimer = null;

    /**
     * Calcule le delai du prochain poll en tenant compte d'un backoff
     * exponentiel sur erreurs consecutives (M3 review).
     *
     * Sequence : 30s → 60s → 120s → 240s → cap a 5min.
     * Reset a 30s sur le 1er succes (cf. ``_consecutiveErrors = 0`` plus haut).
     */
    function nextPollDelay(cached, nowMs) {
        var base = pickRefreshDelay(cached, nowMs, POLL_INTERVAL_MS);
        if (base <= 0) base = POLL_INTERVAL_MS;
        if (_consecutiveErrors <= 0) return base;
        var multiplier = Math.min(Math.pow(2, _consecutiveErrors), 16);
        return Math.min(base * multiplier, POLL_BACKOFF_MAX_MS);
    }

    function schedulePoll(badge, userId) {
        if (_pollTimer) {
            window.clearTimeout(_pollTimer);
            _pollTimer = null;
        }
        if (document.hidden) return; // ne pas poller en background
        var cached = readCache(userId);
        var delay = nextPollDelay(cached, Date.now());
        _pollTimer = window.setTimeout(function () {
            _pollTimer = null;
            refresh(badge, userId, false).then(function () {
                schedulePoll(badge, userId);
            });
        }, delay);
    }

    function init() {
        var badge = findBadge();
        if (!badge) return; // page sans badge (login, /data/privacy, ...)

        // user_id depuis ``data-user-id`` rendu par le template (cf.
        // base.html — namespace cache localStorage par user, defense
        // anti-leak cross-user sur poste partage).
        var userId = (badge.dataset && badge.dataset.userId) || null;
        var cacheKey = cacheKeyForUser(userId);

        // 0. Purge les caches d'anciens users avant de lire le notre.
        purgeOtherUserCaches(userId);

        // 1. Render instantane depuis cache si dispo (anti-flicker).
        var cached = readCache(userId);
        if (cached && cached.count > 0) {
            render(badge, cached.count);
        }
        placeBadge(badge);

        // 2. Refresh + schedule poll.
        refresh(badge, userId, false).then(function () {
            schedulePoll(badge, userId);
        });

        // 3. Listeners cross-tab + cycle de vie.
        // 3a. ``storage`` : un autre onglet a update le cache → on re-render.
        //     Permet aux 2nd/3rd tabs de voir une mise a jour sans fetch.
        //     Attention : on filtre par cle namespacee pour ne pas reagir
        //     aux caches d'autres users (mode partage).
        //     Si ``ev.newValue === null`` (autre onglet a clear le cache via
        //     ``komptia:anonymization-changed``), on force un refetch au
        //     lieu d'afficher 0 transitoire (UX coherente).
        window.addEventListener('storage', function (ev) {
            if (!ev || ev.key !== cacheKey) return;
            if (ev.newValue === null) {
                refresh(badge, userId, true).then(function () {
                    schedulePoll(badge, userId);
                });
                return;
            }
            var fresh = readCache(userId);
            render(badge, fresh ? fresh.count : 0);
        });

        // 3b. ``visibilitychange`` : pause poll quand cache, reprend visible.
        document.addEventListener('visibilitychange', function () {
            if (document.hidden) {
                if (_pollTimer) {
                    window.clearTimeout(_pollTimer);
                    _pollTimer = null;
                }
                return;
            }
            // Visible : refresh si cache stale, puis re-schedule.
            refresh(badge, userId, false).then(function () {
                schedulePoll(badge, userId);
            });
        });

        // 3c. ``pageshow`` : retour bfcache (Safari iOS, FF). Le state
        //     localStorage peut avoir change pendant que la page etait gelee.
        window.addEventListener('pageshow', function (ev) {
            if (ev && ev.persisted) {
                refresh(badge, userId, false).then(function () {
                    schedulePoll(badge, userId);
                });
            }
        });

        // 3d. ``komptia:anonymization-changed`` : custom event dispatchable
        //     par les modules tiers (privacy-page.js apres wipe/PUT terms).
        //     Force-invalide le cache puis refetch.
        window.addEventListener(CHANGE_EVENT, function () {
            clearCache(userId);
            refresh(badge, userId, true).then(function () {
                schedulePoll(badge, userId);
            });
        });

        // 3e. Resize : la sidebar peut etre toggle programmatique → re-place.
        window.addEventListener('resize', function () {
            placeBadge(badge);
        });

        // 3f. M1 review : sidebar toggle (Ctrl+B / hamburger) ne dispatche
        //     pas de resize. On observe le changement de style.display sur
        //     ``#app-topbar`` (passe '' ↔ 'none') et le toggle de la classe
        //     ``komptia-edit-main.palette-collapsed`` qui peuvent affecter
        //     la presence d'une topbar visible.
        try {
            var observed = [];
            var topbar = document.getElementById('app-topbar');
            if (topbar) observed.push(topbar);
            var sidebar = document.getElementById('app-sidebar');
            if (sidebar) observed.push(sidebar);
            if (observed.length && typeof MutationObserver !== 'undefined') {
                var mo = new MutationObserver(function () { placeBadge(badge); });
                for (var i = 0; i < observed.length; i++) {
                    mo.observe(observed[i], {
                        attributes: true,
                        attributeFilter: ['style', 'class'],
                    });
                }
            }
        } catch (_e) { /* MutationObserver indisponible : tant pis. */ }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

    // API debug / interop tiers (privacy-page.js peut appeler
    // ``window.KomptiaPrivacyBadge.invalidate()`` apres un PUT terms).
    // Equivalent a un dispatch de l'event CHANGE_EVENT pour les callers
    // qui prefereraient un event au lieu d'un appel direct.
    window.KomptiaPrivacyBadge = {
        invalidate: function () {
            try {
                window.dispatchEvent(new CustomEvent(CHANGE_EVENT));
            } catch (_e) {
                // CustomEvent indispo (vieux IE — pas une cible) → noop.
            }
        },
        getCount: function () {
            var b = findBadge();
            var uid = (b && b.dataset && b.dataset.userId) || null;
            var c = readCache(uid);
            return c ? c.count : 0;
        },
    };

    // Exports Node (tests purs des helpers — pas de DOM).
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = {
            formatLabel: formatLabel,
            parseStatsResponse: parseStatsResponse,
            isCacheFresh: isCacheFresh,
            pickRefreshDelay: pickRefreshDelay,
        };
    }
})();
