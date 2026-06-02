/**
 * Onboarding Tour — modal de bienvenue à la première visite d'une page.
 *
 * Doctrine
 * --------
 * 1. **Découverte douce** : pas de spotlight invasif sur des éléments
 *    spécifiques (fragile aux changements de layout). Modal centré avec
 *    3-4 steps explicatifs, chacun avec une icône et un texte court.
 * 2. **CSP-safe** : aucun innerHTML avec interpolation user, tout via
 *    createElement + textContent. Aucune dépendance externe.
 * 3. **Idempotent** : l'état est persisté côté serveur (BDD via
 *    ``/api/onboarding/*``) avec fallback ``localStorage`` quand l'API
 *    n'est pas disponible (offline, page publique non-authentifiée).
 *    Une clé par tour (admin vs user, version pour réinitialiser au besoin).
 * 4. **Accessibilité** : ``role="dialog"``, ``aria-modal``, focus-trap,
 *    Escape ferme, premier bouton focusé au mount.
 * 5. **Skippable** : le user peut fermer à tout moment (X), refuser
 *    (bouton "Passer"), ou aller jusqu'au bout.
 * 6. **Anti-cascade** : maximum UN modal d'onboarding par session
 *    utilisateur. Si l'utilisateur visite plusieurs pages neuves dans
 *    la même session, seul le premier tour s'affiche en modal — les
 *    autres restent disponibles via le menu d'aide. Cela évite l'effet
 *    « 18 modales successives » qui pousse à l'abandon.
 *
 * Persistence côté serveur
 * ------------------------
 * - ``GET /api/onboarding/state`` au load (préchargement) → liste des
 *   tours déjà ``completed`` / ``skipped`` côté BDD.
 * - ``POST /api/onboarding/tour/start`` à l'affichage du modal.
 * - ``POST /api/onboarding/tour/step`` à chaque changement d'étape.
 * - ``POST /api/onboarding/tour/complete`` à la fin (dernier bouton).
 * - ``POST /api/onboarding/tour/skip`` à la fermeture sans achever.
 *
 * Le ``localStorage`` reste écrit en miroir : si le serveur tombe ou
 * si l'utilisateur n'est pas authentifié, le tour ne se ré-affiche
 * quand même pas. Source de vérité = serveur > localStorage.
 *
 * API publique
 * ------------
 *   window.KomptiaOnboarding.start({
 *       key: 'dashboard_user_v1',
 *       title: 'Bienvenue sur Komptia',
 *       steps: [
 *           { icon: 'sparkle', title: '...', text: '...' },
 *           ...
 *       ],
 *       force: false,  // afficher même si déjà vu (debug/replay)
 *   });
 *
 * Le caller (template dashboard) appelle ``start()`` une fois au load.
 * Si le user a déjà vu côté serveur OU localStorage, no-op.
 */
(function () {
    'use strict';

    if (window.KomptiaOnboarding) return; // idempotent

    var STORAGE_PREFIX = 'komptia_onboarding_';
    var STATE_ENDPOINT = '/api/onboarding/state';
    var TOUR_ENDPOINT_PREFIX = '/api/onboarding/tour/';
    // Signature posée sur chaque body sibling qu'on rend `inert`. Permet au
    // cleanup défensif (et seulement à lui) de distinguer notre `inert` de
    // celui posé légitimement par un autre composant (globalSyncOverlay, etc.).
    var INERT_SIG = 'data-onboarding-inert';
    // Mémorise si l'élément avait DÉJÀ `inert` avant qu'on intervienne, pour
    // ne pas l'écraser au cleanup défensif (cas rare : un autre composant
    // l'avait posé avant nous).
    var INERT_HAD = 'data-onboarding-inert-had';
    // Watchdog : si l'overlay reste ouvert plus longtemps que ça sans aucune
    // interaction, on force le close. Couvre le cas où l'utilisateur a oublié
    // un onglet ouvert pendant la nuit puis bascule sur l'app → écran figé.
    var WATCHDOG_MS = 30 * 60 * 1000;

    // ── Module-level state ──
    // Cache de l'état serveur. ``null`` = pas encore chargé.
    // Format : ``{tours: {tour_key: {state, completed_at, skipped_at, ...}}, activity: {...}}``
    var _serverState = null;
    // ``true`` ssi le fetch ``/api/onboarding/state`` a réussi (HTTP 200).
    // Critique pour distinguer « BDD chargée, ce user n'a fait aucun tour »
    // (→ ignorer localStorage car le navigateur peut être partagé entre
    // plusieurs comptes : un admin précédent a pu remplir localStorage)
    // de « BDD inaccessible, fallback localStorage légitime » (offline,
    // user anonyme). Sans ce flag, le localStorage du navigateur fuit
    // entre comptes — bug constaté avec test2 le 2026-05-18 sur le même
    // navigateur où david-admin avait déjà vu les tours.
    var _serverStateLoaded = false;
    // Promise du fetch en cours (évite N requêtes parallèles si plusieurs
    // ``start()`` sont appelés en rafale au load).
    var _serverStatePromise = null;
    // Garde anti-cascade : passe à ``true`` dès qu'un tour s'affiche en
    // modal — les ``start()`` suivants dans la même session sont skip
    // (sauf ``force=true`` debug). Reset au prochain page-load.
    var _sessionTourShown = false;
    // Cache du token XSRF (cookie ``_xsrf`` Tornado natif). Évite un parse
    // de ``document.cookie`` à chaque POST.
    var _xsrfTokenCache = null;

    // ── Cleanup défensif ──
    // Au load de la lib, si on détecte des signatures `[data-onboarding-inert]`
    // SANS overlay actif dans le DOM, c'est qu'un cycle précédent s'est terminé
    // anormalement (crash JS dans close, navigation pendant transition, etc.).
    // On retire les `inert` orphelins. Sans ça : DOM figé silencieusement
    // jusqu'au prochain hard-reload — incident 2026-05-11 (David ne pouvait
    // plus rien cliquer ET ne pouvait même plus ouvrir F12).
    function _defensiveCleanup() {
        try {
            var hasActiveOverlay = !!document.querySelector('.komptia-onboard-overlay');
            if (hasActiveOverlay) return; // un cycle est en cours → ne pas interférer
            var orphans = document.querySelectorAll('[' + INERT_SIG + ']');
            if (!orphans.length) return;
            var n = 0;
            for (var i = 0; i < orphans.length; i++) {
                var el = orphans[i];
                var hadBefore = el.getAttribute(INERT_HAD) === '1';
                if (!hadBefore) {
                    el.removeAttribute('inert');
                }
                el.removeAttribute(INERT_SIG);
                el.removeAttribute(INERT_HAD);
                n++;
            }
            if (window.console && console.warn) {
                console.warn(
                    '[onboarding-tour] Cleanup défensif : ' + n +
                    ' `inert` orphelin(s) retiré(s). Le tour précédent ' +
                    'ne s\'est pas fermé proprement.'
                );
            }
        } catch (e) { /* ignore */ }
    }
    // Exécuté immédiatement à l'IIFE-load. Idempotent.
    _defensiveCleanup();

    // ── Helpers réseau ──

    function _getXsrfToken() {
        // On ne cache que les valeurs NON-VIDES. Si le cookie ``_xsrf`` n'est
        // pas encore posé au moment du premier appel (ex : utilisateur
        // s'authentifie après le load JS), un cache à ``''`` empêcherait
        // toute lecture ultérieure et tous les POST seraient rejetés en 403
        // silencieusement. En recherchant à nouveau tant que le token n'est
        // pas trouvé, on absorbe ce cas sans surcoût (1 regex / POST).
        if (_xsrfTokenCache) return _xsrfTokenCache;
        try {
            // ``[^;\s]+`` exclut espaces (cookie corrompu type ``_xsrf=tok en``
            // donnait précédemment ``tok en`` → decodeURIComponent levait, le
            // try/catch retournait ``''`` et tous les POST échouaient en 403).
            var match = document.cookie.match(/(?:^|;)\s*_xsrf=([^;\s]+)/);
            _xsrfTokenCache = match ? decodeURIComponent(match[1]) : '';
        } catch (e) {
            _xsrfTokenCache = '';
        }
        return _xsrfTokenCache;
    }

    function _fetchJSON(url, options) {
        var opts = options || {};
        var method = opts.method || 'GET';
        var headers = { 'Accept': 'application/json' };
        if (method !== 'GET') {
            var token = _getXsrfToken();
            if (token) headers['X-Xsrftoken'] = token;
            if (opts.body) headers['Content-Type'] = 'application/json';
        }
        return fetch(url, {
            method: method,
            credentials: 'same-origin',
            headers: headers,
            body: opts.body || undefined,
        }).then(function (resp) {
            if (!resp.ok) {
                // 401 / 403 / 5xx : on rejette, le caller fallback localStorage.
                return Promise.reject(new Error('HTTP ' + resp.status));
            }
            return resp.json();
        });
    }

    function _loadServerState() {
        if (_serverState !== null) return Promise.resolve(_serverState);
        if (_serverStatePromise) return _serverStatePromise;
        _serverStatePromise = _fetchJSON(STATE_ENDPOINT).then(
            function (data) {
                _serverState = data || { tours: {}, activity: null };
                _serverStateLoaded = true;  // ← marque le SUCCESS du fetch
                _serverStatePromise = null;
                return _serverState;
            },
            function () {
                // Échec (401 anonyme, offline, endpoint indisponible).
                // On marque comme « chargé vide » → fallback localStorage prend
                // le relais. Pas de retry automatique : si l'user passe d'un
                // mode public à authentifié, un reload de page recharge tout.
                // ``_serverStateLoaded`` reste ``false`` → ``_hasSeenTour``
                // autorisera le fallback localStorage.
                _serverState = { tours: {}, activity: null };
                _serverStatePromise = null;
                return _serverState;
            }
        );
        return _serverStatePromise;
    }

    function _postTourAction(action, key, extra) {
        var body = { tour_key: key };
        if (extra) {
            for (var k in extra) {
                if (Object.prototype.hasOwnProperty.call(extra, k)) {
                    body[k] = extra[k];
                }
            }
        }
        return _fetchJSON(TOUR_ENDPOINT_PREFIX + action, {
            method: 'POST',
            body: JSON.stringify(body),
        }).then(
            function (data) {
                // Mettre à jour le cache local SEULEMENT si la réponse
                // correspond au tour qu'on vient de demander — protège contre
                // une réponse mal routée (proxy bug, cache HTTP cross-user)
                // qui polluerait le cache d'un autre tour avec un état stale
                // et re-déclencherait un tour déjà complété.
                if (
                    _serverState
                    && _serverState.tours
                    && data
                    && data.tour_key === key
                ) {
                    _serverState.tours[data.tour_key] = data;
                }
                return data;
            },
            function () {
                // Best-effort : la perte d'un POST n'altère pas l'UX (le
                // localStorage mirror garantit le no-replay). Le serveur
                // verra juste un tour incomplet — sans conséquence
                // fonctionnelle, c'est l'audit qui est imparfait.
                return null;
            }
        );
    }

    // ── Persistence locale (fallback) ──

    function _hasSeenTour(key) {
        // ``_serverStateLoaded`` est ``true`` quand le fetch
        // ``/api/onboarding/state`` a réussi : la BDD est ALORS source de
        // vérité unique. On ignore le ``localStorage`` qui est partagé
        // entre tous les comptes loggés depuis ce navigateur (cf. bug
        // constaté 2026-05-18 : test2 ne voyait pas les tours car le
        // navigateur avait gardé les clés ``komptia_onboarding_*`` d'un
        // admin précédent).
        if (_serverStateLoaded) {
            if (_serverState && _serverState.tours && _serverState.tours[key]) {
                var t = _serverState.tours[key];
                return !!(t.completed_at || t.skipped_at);
            }
            return false; // BDD chargée + pas d'entrée pour ce tour = pas vu
        }
        // Fallback ``localStorage`` UNIQUEMENT quand la BDD est inaccessible
        // (fetch échoué : 401 anonyme, offline, endpoint indisponible).
        // Permet de bloquer le re-affichage côté user déjà vu en mode
        // dégradé. Côté authentifié, le ``_serverStateLoaded`` ci-dessus
        // a déjà tranché et on ne passe pas ici.
        try {
            return !!localStorage.getItem(STORAGE_PREFIX + key);
        } catch (e) {
            return false; // localStorage indisponible (mode privé strict)
        }
    }

    function _markSeenLocal(key) {
        try {
            localStorage.setItem(STORAGE_PREFIX + key, String(Date.now()));
        } catch (e) { /* ignore */ }
    }

    // Préchargement opportuniste : le state est chargé dès le load JS,
    // même si aucun start() n'a encore été appelé. Réduit la latence au
    // premier start() (le fetch est typiquement déjà résolu quand la page
    // arrive à appeler start()).
    _loadServerState();

    // Icônes SVG built-in (référence par nom dans config). createElementNS
    // pour respecter le namespace SVG.
    var _ICONS = {
        sparkle: 'M9.813 15.904L9 18.75l-.813-2.846a4.5 4.5 0 00-3.09-3.09L2.25 12l2.846-.813a4.5 4.5 0 003.09-3.09L9 5.25l.813 2.846a4.5 4.5 0 003.09 3.09L15.75 12l-2.846.813a4.5 4.5 0 00-3.09 3.09zM18.259 8.715L18 9.75l-.259-1.035a3.375 3.375 0 00-2.455-2.456L14.25 6l1.036-.259a3.375 3.375 0 002.455-2.456L18 2.25l.259 1.035a3.375 3.375 0 002.455 2.456L21.75 6l-1.036.259a3.375 3.375 0 00-2.455 2.456z',
        chart: 'M3 13.125C3 12.504 3.504 12 4.125 12h2.25c.621 0 1.125.504 1.125 1.125v6.75C7.5 20.496 6.996 21 6.375 21h-2.25A1.125 1.125 0 013 19.875v-6.75zM9.75 8.625c0-.621.504-1.125 1.125-1.125h2.25c.621 0 1.125.504 1.125 1.125v11.25c0 .621-.504 1.125-1.125 1.125h-2.25a1.125 1.125 0 01-1.125-1.125V8.625zM16.5 4.125c0-.621.504-1.125 1.125-1.125h2.25C20.496 3 21 3.504 21 4.125v15.75c0 .621-.504 1.125-1.125 1.125h-2.25a1.125 1.125 0 01-1.125-1.125V4.125z',
        bell: 'M14.857 17.082a23.848 23.848 0 005.454-1.31A8.967 8.967 0 0118 9.75v-.7V9A6 6 0 006 9v.75a8.967 8.967 0 01-2.312 6.022c1.733.64 3.56 1.085 5.455 1.31m5.714 0a24.255 24.255 0 01-5.714 0m5.714 0a3 3 0 11-5.714 0',
        rocket: 'M15.59 14.37a6 6 0 01-5.84 7.38v-4.8m5.84-2.58a14.98 14.98 0 006.16-12.12A14.98 14.98 0 009.631 8.41m5.96 5.96a14.926 14.926 0 01-5.841 2.58m-.119-8.54a6 6 0 00-7.381 5.84h4.8m2.581-5.84a14.927 14.927 0 00-2.58 5.84m2.699 2.7c-.103.021-.207.041-.311.06a15.09 15.09 0 01-2.448-2.448 14.9 14.9 0 01.06-.312m-2.24 2.39a4.493 4.493 0 00-1.757 4.306 4.493 4.493 0 004.306-1.758M16.5 9a1.5 1.5 0 11-3 0 1.5 1.5 0 013 0z',
    };

    function _buildIcon(name) {
        var d = _ICONS[name] || _ICONS.sparkle;
        var svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
        svg.setAttribute('viewBox', '0 0 24 24');
        svg.setAttribute('width', '28');
        svg.setAttribute('height', '28');
        svg.setAttribute('fill', 'none');
        svg.setAttribute('stroke', 'currentColor');
        svg.setAttribute('stroke-width', '1.5');
        svg.setAttribute('stroke-linecap', 'round');
        svg.setAttribute('stroke-linejoin', 'round');
        svg.setAttribute('aria-hidden', 'true');
        var path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
        path.setAttribute('d', d);
        svg.appendChild(path);
        return svg;
    }

    function _el(tag, className, text) {
        var node = document.createElement(tag);
        if (className) node.className = className;
        if (text != null) node.textContent = String(text);
        return node;
    }

    /**
     * Point d'entrée public. Synchrone côté API mais déclenche le rendu
     * en async (après chargement du state serveur). Les templates n'ont
     * pas à attendre un retour ; si le user a déjà vu le tour (BDD ou
     * localStorage), aucun modal n'est créé.
     */
    function start(opts) {
        if (!opts || !opts.key || !Array.isArray(opts.steps) || opts.steps.length === 0) {
            return;
        }

        // Garde anti-cascade : si un autre tour s'est déjà affiché cette
        // session, on skip silencieusement — sauf en mode force (debug,
        // bouton « Refaire le tour » futur).
        if (_sessionTourShown && !opts.force) return;

        // Évite plusieurs tours actifs concurrents (ex: bug d'appel double).
        if (document.querySelector('.komptia-onboard-overlay')) return;

        // Skip si un modal système (sync schéma, confirm) est déjà visible —
        // sinon le tour s'ouvre derrière (z-index 9997 < 9999/10000) et capte
        // des clics sans être visible. Cf. review adversariale R2-A12. Depuis
        // l'unification 2026-05-26, l'unique modal sync est ``#globalSyncOverlay``
        // (z-index 10000, partial inclus pour tous les users authentifiés).
        var blockingModal = document.querySelector(
            '#globalSyncOverlay:not(.hidden), #appConfirmModal:not(.hidden)'
        );
        if (blockingModal) return;

        // Décide d'afficher après chargement du state serveur. ``_loadServerState``
        // résout en ~50ms typique (préchargé au load JS) ou ~0ms si déjà cache.
        _loadServerState().then(function () {
            if (!opts.force && _hasSeenTour(opts.key)) return;
            // Re-vérifie la garde anti-cascade après l'await — un autre tour
            // pourrait avoir gagné la course pendant le fetch.
            if (_sessionTourShown && !opts.force) return;
            // POSE LE FLAG IMMÉDIATEMENT, avant ``_renderTour``. Sinon 3
            // ``start()`` appelés au même tick résolvent leurs promises
            // quasi-simultanément dans la même microtask : tous les
            // callbacks lisent ``_sessionTourShown=false`` puis appellent
            // ``_renderTour`` → 3 modaux créés. Le garde DOM ``document.
            // querySelector('.komptia-onboard-overlay')`` ne protège pas
            // dans la même microtask car aucun overlay n'est encore inséré.
            _sessionTourShown = true;
            _renderTour(opts);
        });
    }

    /**
     * Construit et affiche le modal. Source de vérité du DOM du tour.
     * Appelé uniquement après que ``start()`` a confirmé que le tour
     * doit être affiché.
     */
    function _renderTour(opts) {
        var steps = opts.steps;
        var index = 0;
        var lastFocused = document.activeElement;
        var focusTimer = null;
        var cleanupTimer = null;
        var watchdogTimer = null;
        var pageHideHandler = null;
        // Garde anti-double-clic : un second clic sur ``nextBtn`` ou
        // ``skipBtn`` avant que les listeners ne soient retirés (cleanup
        // après transition CSS 220ms) déclencherait un second
        // ``close(true, 'complete')`` et un POST dupliqué. ``_closing``
        // verrouille la première fermeture comme définitive.
        var _closing = false;
        // Backup de l'état ``inert`` des body siblings AVANT qu'on les
        // verrouille — on les restaurera tels qu'à l'arrivée. Sans ce
        // backup, on perdrait un éventuel ``inert`` posé par un autre
        // composant pendant que le tour est ouvert.
        var inertBackup = [];

        // ── Construction DOM ──
        var overlay = _el('div', 'komptia-onboard-overlay');
        overlay.setAttribute('role', 'dialog');
        overlay.setAttribute('aria-modal', 'true');
        overlay.setAttribute('aria-labelledby', 'komptia-onboard-title');

        var modal = _el('div', 'komptia-onboard-modal');
        modal.tabIndex = -1;

        var header = _el('div', 'komptia-onboard-header');
        var title = _el('h2', 'komptia-onboard-title', opts.title || 'Bienvenue');
        title.id = 'komptia-onboard-title';
        var skipBtn = _el('button', 'komptia-onboard-skip', 'Passer');
        skipBtn.type = 'button';
        skipBtn.setAttribute('aria-label', 'Passer le tour de bienvenue');
        header.appendChild(title);
        header.appendChild(skipBtn);

        var body = _el('div', 'komptia-onboard-body');
        var iconWrap = _el('div', 'komptia-onboard-step-icon');
        var stepTitle = _el('h3', 'komptia-onboard-step-title');
        var stepText = _el('p', 'komptia-onboard-step-text');
        body.appendChild(iconWrap);
        body.appendChild(stepTitle);
        body.appendChild(stepText);

        var footer = _el('div', 'komptia-onboard-footer');
        var dotsWrap = _el('div', 'komptia-onboard-dots');
        for (var i = 0; i < steps.length; i++) {
            dotsWrap.appendChild(_el('span', 'komptia-onboard-dot'));
        }
        var actions = _el('div', 'komptia-onboard-actions');
        var prevBtn = _el('button', 'komptia-onboard-btn komptia-onboard-btn--ghost', 'Précédent');
        prevBtn.type = 'button';
        var nextBtn = _el('button', 'komptia-onboard-btn komptia-onboard-btn--primary', 'Suivant');
        nextBtn.type = 'button';
        actions.appendChild(prevBtn);
        actions.appendChild(nextBtn);
        footer.appendChild(dotsWrap);
        footer.appendChild(actions);

        modal.appendChild(header);
        modal.appendChild(body);
        modal.appendChild(footer);
        overlay.appendChild(modal);
        document.body.appendChild(overlay);

        // POST /start côté serveur — best-effort, fire-and-forget.
        _postTourAction('start', opts.key);

        function renderStep() {
            var step = steps[index];
            iconWrap.replaceChildren();
            iconWrap.appendChild(_buildIcon(step.icon || 'sparkle'));
            stepTitle.textContent = step.title || '';
            stepText.textContent = step.text || '';
            var dots = dotsWrap.querySelectorAll('.komptia-onboard-dot');
            for (var j = 0; j < dots.length; j++) {
                dots[j].classList.toggle('komptia-onboard-dot--active', j === index);
            }
            prevBtn.disabled = index === 0;
            nextBtn.textContent = index === steps.length - 1 ? 'Terminer' : 'Suivant';
        }

        /**
         * Ferme le modal.
         *
         * @param {boolean} seen — true si l'utilisateur a vu/skip/complet
         *   volontairement (X, Escape, Skip, Terminer). false uniquement
         *   pour les fermetures « techniques » (watchdog, pagehide,
         *   bfcache) — auquel cas l'utilisateur reverra le tour.
         * @param {string|null} action — 'complete', 'skip' ou null.
         *   Conditionne quel POST onboarding est envoyé au serveur.
         */
        function close(seen, action) {
            // Verrou anti-rentrée : un second clic (ou Escape pendant la
            // transition de fermeture) appelle close() à nouveau et
            // re-déclenche le POST. Le premier appel gagne.
            if (_closing) return;
            _closing = true;
            // Annule les timers en attente (race finding R2-A10) — sans
            // ça, ``focusTimer`` peut tirer après le close et appeler
            // focus() sur un bouton démontant.
            if (focusTimer) { clearTimeout(focusTimer); focusTimer = null; }
            if (cleanupTimer) { clearTimeout(cleanupTimer); cleanupTimer = null; }
            if (watchdogTimer) { clearTimeout(watchdogTimer); watchdogTimer = null; }
            if (pageHideHandler) {
                try {
                    window.removeEventListener('pagehide', pageHideHandler);
                    window.removeEventListener('beforeunload', pageHideHandler);
                } catch (e) { /* ignore */ }
                pageHideHandler = null;
            }

            // Restaure l'attribut ``inert`` des body siblings tel qu'à
            // l'origine (review R2-A5) ET retire la signature posée à
            // l'ouverture (sinon le cleanup défensif n'a plus rien à
            // observer mais ce n'est pas un bug — on reste propre).
            for (var bi = 0; bi < inertBackup.length; bi++) {
                var entry = inertBackup[bi];
                try {
                    if (entry.had) entry.el.setAttribute('inert', '');
                    else entry.el.removeAttribute('inert');
                    entry.el.removeAttribute(INERT_SIG);
                    entry.el.removeAttribute(INERT_HAD);
                } catch (e) { /* ignore */ }
            }
            inertBackup = [];

            overlay.classList.remove('komptia-onboard-overlay--open');
            if (seen) {
                _markSeenLocal(opts.key);
                if (action === 'complete' || action === 'skip') {
                    _postTourAction(action, opts.key);
                }
            }
            // Cleanup après transition
            cleanupTimer = setTimeout(function () {
                if (overlay.parentNode) overlay.parentNode.removeChild(overlay);
                document.removeEventListener('keydown', onKey);
            }, 220);
            try { if (lastFocused && lastFocused.focus) lastFocused.focus(); } catch (e) { /* ignore */ }
        }

        function onKey(ev) {
            if (ev.key === 'Escape') {
                ev.preventDefault();
                close(true, 'skip');
            } else if (ev.key === 'Tab') {
                // Focus trap : recalcule à chaque Tab les boutons activables
                // (sans ``[disabled]``) — sinon ``prevBtn`` au step 0 reste
                // exclu de l'array même si activable au step suivant.
                // Cf. review adversariale R2-A5.
                var focusables = modal.querySelectorAll('button:not([disabled])');
                if (!focusables.length) return;
                var first = focusables[0];
                var last = focusables[focusables.length - 1];
                if (ev.shiftKey && document.activeElement === first) {
                    ev.preventDefault();
                    last.focus();
                } else if (!ev.shiftKey && document.activeElement === last) {
                    ev.preventDefault();
                    first.focus();
                }
            }
        }

        skipBtn.addEventListener('click', function () { close(true, 'skip'); });
        prevBtn.addEventListener('click', function () {
            if (index > 0) {
                index--;
                renderStep();
                _postTourAction('step', opts.key, { step: index });
            }
        });
        nextBtn.addEventListener('click', function () {
            if (index < steps.length - 1) {
                index++;
                renderStep();
                _postTourAction('step', opts.key, { step: index });
            } else {
                close(true, 'complete');
            }
        });
        // Click sur l'overlay (pas le modal) ferme aussi — assimilé à un skip
        // (l'utilisateur n'a pas atteint le dernier step).
        overlay.addEventListener('click', function (ev) {
            if (ev.target === overlay) close(true, 'skip');
        });

        // Verrouille les body siblings via ``inert`` pour empêcher Tab/click
        // de sortir du modal vers le DOM derrière (review R2-A5). On stocke
        // l'état initial pour restauration au close, ET on signe chaque
        // élément avec ``data-onboarding-inert`` pour que le cleanup défensif
        // au prochain pageload puisse retirer un `inert` orphelin laissé par
        // un crash. Cf. incident 2026-05-11.
        try {
            var bodyChildren = document.body.children;
            for (var ci = 0; ci < bodyChildren.length; ci++) {
                var child = bodyChildren[ci];
                if (child === overlay) continue;
                var had = child.hasAttribute('inert');
                inertBackup.push({ el: child, had: had });
                child.setAttribute('inert', '');
                child.setAttribute(INERT_SIG, '1');
                child.setAttribute(INERT_HAD, had ? '1' : '0');
            }
        } catch (e) { /* ignore — inert non supporté = focus-trap dégradé */ }

        document.addEventListener('keydown', onKey);

        // Force-cleanup au déchargement de la page. Sans ça, fermer l'onglet
        // pendant le tour laisse l'overlay et les `inert` en place pour le
        // prochain visiteur (rare, mais cross-tab cache du browser peut
        // restaurer le DOM tel quel via bfcache). On utilise ``pagehide`` ET
        // ``beforeunload`` parce qu'ils ne se déclenchent pas dans les mêmes
        // conditions selon le browser (Safari bfcache, Chrome onload neuf).
        // Pas de POST serveur côté pagehide : on conserve l'état BDD
        // « in_progress » ; au prochain affichage le tour reprend.
        pageHideHandler = function () {
            try { close(false, null); } catch (e) { /* ignore */ }
        };
        try {
            window.addEventListener('pagehide', pageHideHandler);
            window.addEventListener('beforeunload', pageHideHandler);
        } catch (e) { /* ignore */ }

        // Watchdog : si l'overlay reste ouvert WATCHDOG_MS sans interaction,
        // on force le close avec ``seen=false`` (le user le reverra).
        // Couvre : utilisateur a oublié l'onglet ouvert toute la nuit, ou
        // changé de poste et revient des heures plus tard.
        watchdogTimer = setTimeout(function () {
            try { close(false, null); } catch (e) { /* ignore */ }
        }, WATCHDOG_MS);

        renderStep();

        requestAnimationFrame(function () {
            overlay.classList.add('komptia-onboard-overlay--open');
            // Double rAF (≈32ms à 60fps) pour laisser la transition CSS
            // démarrer AVANT le focus, sans setTimeout fixe (review R2-A10).
            // Le timer est tracké pour annulation au close.
            focusTimer = setTimeout(function () {
                requestAnimationFrame(function () {
                    try { nextBtn.focus(); } catch (e) { /* ignore */ }
                });
            }, 16);
        });
    }

    // Helper pour reset (debug / qa) : retire l'entrée localStorage. Le
    // state serveur n'est PAS reset par cette fonction (un reset serveur
    // nécessiterait un endpoint admin dédié, hors scope de la lib JS).
    // Pour rejouer un tour côté admin, passer ``force: true`` dans start().
    function reset(key) {
        try {
            localStorage.removeItem(STORAGE_PREFIX + key);
        } catch (e) { /* ignore */ }
    }

    window.KomptiaOnboarding = { start: start, reset: reset };
})();
