// network-status.js — composant global "offline + retry auto".
//
// Couvre le cas (d) de la taxonomie 4-cas erreurs Komptia : reseau frontend
// offline. Avant ce composant, l'event ``offline``/``online`` etait gere par
// un IIFE inline dans templates/base.html mais sans :
//
//   * detection ``TypeError: Failed to fetch`` (un fetch peut fail sans que
//     ``navigator.onLine`` change — typique des reverse proxys timeoutes ou
//     du captive portal qui declarent ``onLine=true`` mais bloquent reseau).
//   * retry automatique des requetes idempotent (GET/HEAD) avec exponential
//     backoff + jitter → ressuscite silencieusement les requetes ratees a
//     la reconnexion plutot que de laisser le user re-cliquer.
//
// Le composant est charge globalement via base.html (script externe avec
// nonce CSP). Le DOM banner ``#komptia-offline-banner`` est compatible avec
// le CSS existant dans base.html (selectors ``:has(#komptia-offline-banner
// :not(.hidden))`` qui pushent topbar/badge en bas pendant offline).
//
// Doctrine
// --------
//  1. CSP-safe : addEventListener uniquement, zero ``onclick`` inline.
//  2. Idempotent boot : ``__komptiaNetworkStatusInit`` guard — re-eval du
//     bundle ne reinstalle pas les listeners.
//  3. Retry uniquement GET/HEAD par defaut (RFC idempotent + safe). Les
//     callers qui veulent retry un POST doivent passer
//     ``komptiaRetry: true`` dans le init du fetch — opt-in explicite.
//     ⚠️ Retry POST sans opt-in = doublon serveur (creation comptes,
//     virements, etc.).
//  4. Wrap compose-safe : ``window.__komptiaNetworkWrapped`` flag distinct
//     de ``__komptiaFetchWrapped`` (feedback-reporter.js). Les deux wraps
//     composent : feedback wrap voit le resultat final apres retry.
//  5. Abort-aware : si ``init.signal.aborted`` au moment du retry → arret
//     immediat (le caller a renonce).
//  6. Jitter aleatoire 0-500ms : evite le thundering herd multi-onglets
//     (5 tabs ouvertes ne spamment pas le serveur a la milliseconde pres).
//  7. Pas de croissance non bornee : cap d'attempts (5) + cap de backoff
//     (16s) — meme avec un input attempt=Infinity, le delay reste borne.
//  8. Pas de notification toast persistante : le banner est sticky tant
//     que offline, le toast signale juste les transitions (cas d Komptia).
//  9. Anti-XSS : textContent uniquement (banner texte statique FR), aucun
//     innerHTML pour les valeurs computees.
//
// Tests : ``tests/unit/test_network_status_js.py`` (Node subprocess sur
// les helpers purs : isNetworkError, isIdempotentMethod, computeBackoffDelay,
// shouldRetryRequest). Pas de DOM dans Node.

(function () {
    'use strict';

    // ── Boot guard ────────────────────────────────────────────────────
    // Si le bundle est re-evalue (ex: HMR dev, ou inclusion redondante),
    // on no-op proprement. On reset les Node exports pour preserver la
    // testabilite des helpers purs.
    if (typeof window !== 'undefined' && window.__komptiaNetworkStatusInit) {
        if (typeof module !== 'undefined' && module.exports &&
            window.__komptiaNetworkStatusExports) {
            module.exports = window.__komptiaNetworkStatusExports;
        }
        return;
    }

    // ── Constants ─────────────────────────────────────────────────────
    var BANNER_ID = 'komptia-offline-banner';
    // Le texte du banner DOIT etre celui que le CSS de base.html attend
    // (cf. ``body:has(#komptia-offline-banner:not(.hidden))``). Le label
    // FR est aligne avec le contrat 4-cas erreurs Komptia.
    var BANNER_TEXT = "Connexion reseau perdue. Vos actions risquent " +
        "d'echouer jusqu'au retour online.";
    var TOAST_OFFLINE = "Connexion reseau perdue. Reconnexion " +
        "automatique au retour en ligne.";
    var TOAST_ONLINE = "Connexion retablie.";
    var NETWORK_CHANGED_EVENT = 'komptia:network-changed';

    // Retry config
    var DEFAULT_MAX_ATTEMPTS = 5;
    var DEFAULT_BASE_DELAY_MS = 1000;
    var DEFAULT_CAP_DELAY_MS = 16000;
    var DEFAULT_JITTER_MS = 500;

    // ── Helpers purs (testables Node) ─────────────────────────────────

    /**
     * Distingue les erreurs reseau (a retry) des autres erreurs (a propager).
     *
     * ⚠️ STRICT par design (review adversarial 2026-05-19) : un ``TypeError``
     * sans marker reseau dans le message N'EST PAS considere comme reseau.
     * Un ``TypeError: Cannot read properties of undefined`` thrown dans un
     * ``.then`` callback ne doit PAS declencher de retry (sinon le bug est
     * multiplie par maxAttempts, 5x les side effects serveur sur un GET
     * d'audit, 5x les tokens LLM sur un POST opt-in).
     *
     * Detecte :
     *  - ``err.name === 'NetworkError'`` (Firefox legacy)
     *  - ``err.message`` contenant "Failed to fetch" (Chrome/Edge/Safari
     *    standard), "Network request failed" (React Native), "NetworkError"
     *
     * NE PAS detecter (laisse propager) :
     *  - ``AbortError`` (caller a annule via AbortController)
     *  - ``SyntaxError`` (response.json() a fail apres reception OK)
     *  - ``TypeError`` generique sans marker reseau (bug programmation)
     *
     * Fail-safe : ``null``/``undefined``/non-Object → false (pas une erreur
     * reseau a retry, on laisse propager).
     *
     * @param {*} err - Erreur capturee par .catch ou throw.
     * @returns {boolean}
     */
    function isNetworkError(err) {
        if (!err) return false;
        if (typeof err !== 'object') return false;
        if (err.name === 'AbortError') return false;
        if (err.name === 'SyntaxError') return false;
        if (err.name === 'NetworkError') return true;
        var msg = typeof err.message === 'string' ? err.message : '';
        if (msg.indexOf('Failed to fetch') !== -1) return true;
        if (msg.indexOf('Network request failed') !== -1) return true;
        if (msg.indexOf('NetworkError') !== -1) return true;
        return false;
    }

    /**
     * Une methode HTTP est-elle safe a retry automatiquement ?
     *
     * Par RFC 7231, GET/HEAD/OPTIONS/PUT/DELETE sont idempotentes (l'effet
     * d'appeler N fois == 1 fois), mais PUT/DELETE peuvent muter — on les
     * exclut du retry-by-default (opt-in via ``komptiaRetry`` pour ces cas).
     *
     * POST/PATCH ne sont pas idempotentes → JAMAIS retry par defaut
     * (risque doublon = create/transfer).
     *
     * Defensive : ``undefined``/``null`` → defaut fetch = GET → idempotent.
     * Non-string → false.
     *
     * @param {string|undefined|null} method
     * @returns {boolean}
     */
    function isIdempotentMethod(method) {
        if (method === null || typeof method === 'undefined') return true;
        if (typeof method !== 'string') return false;
        var m = method.toUpperCase();
        return m === 'GET' || m === 'HEAD';
    }

    /**
     * Calcule le delay avant le prochain retry — exponential backoff + jitter.
     *
     *   delay = min(baseMs * 2^attempt, capMs) + random(0, jitterMs)
     *
     * Le jitter empeche les multi-onglets de spammer simultanement.
     * Le cap empeche le delay de croitre infiniment (anti croissance non
     * bornee, axe Komptia 21).
     *
     * Defensive : tous inputs non-finis → defaults raisonnables.
     *
     * @param {number} attempt - 0-based : 0 = premiere attente.
     * @param {number} baseMs - delay de base.
     * @param {number} capMs - delay maximum apres backoff (avant jitter).
     * @param {number} jitterMs - amplitude du jitter (0 → deterministe).
     * @returns {number} Delay en ms (>= 0).
     */
    function computeBackoffDelay(attempt, baseMs, capMs, jitterMs) {
        var a = (typeof attempt === 'number' && isFinite(attempt) && attempt >= 0)
            ? Math.floor(attempt) : 0;
        var b = (typeof baseMs === 'number' && isFinite(baseMs) && baseMs >= 0)
            ? baseMs : DEFAULT_BASE_DELAY_MS;
        var c = (typeof capMs === 'number' && isFinite(capMs) && capMs >= 0)
            ? capMs : DEFAULT_CAP_DELAY_MS;
        var j = (typeof jitterMs === 'number' && isFinite(jitterMs) && jitterMs >= 0)
            ? jitterMs : 0;
        // Math.pow(2, a) peut overflow vers Infinity pour a tres grand —
        // on utilise Math.min qui retourne le min finite.
        var exp = b * Math.pow(2, a);
        var d = (isFinite(exp) && exp < c) ? exp : c;
        if (j > 0) {
            d += Math.floor(Math.random() * j);
        }
        return d;
    }

    /**
     * Decide si une requete fail-network doit etre retry.
     *
     * Combine :
     *  - method idempotent (sauf opt-in)
     *  - attempt < maxAttempts (cap d'attempts)
     *  - signal pas aborted (le caller n'a pas renonce)
     *
     * ⚠️ Abort prevaut sur tout — meme idempotent + opt-in, si le caller
     * a abort, on respecte (probable navigation away ou unmount React).
     *
     * @param {string|undefined|null} method
     * @param {number} attempt - 0-based.
     * @param {number} maxAttempts - cap d'attempts.
     * @param {boolean} isAborted - signal.aborted ?
     * @param {boolean} optIn - caller a passe komptiaRetry: true ?
     * @returns {boolean}
     */
    function shouldRetryRequest(method, attempt, maxAttempts, isAborted, optIn) {
        if (isAborted === true) return false;
        var a = (typeof attempt === 'number' && attempt >= 0) ? attempt : 0;
        var max = (typeof maxAttempts === 'number' && maxAttempts > 0)
            ? maxAttempts : DEFAULT_MAX_ATTEMPTS;
        if (a >= max) return false;
        if (optIn === true) return true;
        return isIdempotentMethod(method);
    }

    // ── Exports Node (tests purs — pas de DOM dans Node) ──────────────
    var _exports = {
        isNetworkError: isNetworkError,
        isIdempotentMethod: isIdempotentMethod,
        computeBackoffDelay: computeBackoffDelay,
        shouldRetryRequest: shouldRetryRequest,
    };
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = _exports;
    }

    // ── Suite : DOM/runtime — skip si pas dans browser ────────────────
    if (typeof window === 'undefined' || typeof document === 'undefined') {
        return;
    }
    window.__komptiaNetworkStatusInit = true;
    window.__komptiaNetworkStatusExports = _exports;

    // ── DOM banner ────────────────────────────────────────────────────

    function ensureBanner() {
        if (!document.body) return null;
        var existing = document.getElementById(BANNER_ID);
        if (existing) return existing;
        var banner = document.createElement('div');
        banner.id = BANNER_ID;
        // role="alert" + aria-live="assertive" : screen readers
        // (NVDA/JAWS/VoiceOver) annoncent immediatement la perte reseau.
        banner.setAttribute('role', 'alert');
        banner.setAttribute('aria-live', 'assertive');
        // z-9000 < modals systeme (z-10010) : un banner ne doit pas masquer
        // un confirm modal actif (axe Komptia 17 "dernier ouvert devant").
        banner.className = 'fixed top-0 left-0 right-0 z-[9000] ' +
            'bg-amber-600 text-white text-sm py-2 px-4 text-center ' +
            'shadow-md hidden';
        // textContent (pas innerHTML) — anti-XSS defense en profondeur,
        // meme si le texte est statique FR.
        banner.textContent = BANNER_TEXT;
        document.body.appendChild(banner);
        return banner;
    }

    function showBanner() {
        var b = ensureBanner();
        if (b) b.classList.remove('hidden');
    }

    function hideBanner() {
        var b = document.getElementById(BANNER_ID);
        if (b) b.classList.add('hidden');
    }

    function safeToast(msg, type) {
        if (typeof window.showToast === 'function') {
            try { window.showToast(msg, type); } catch (_e) { /* noop */ }
        }
    }

    // ── State machine ─────────────────────────────────────────────────

    var _state = 'online';

    function setState(newState, sourceHint) {
        if (newState !== 'online' && newState !== 'offline') return;
        if (newState === _state) return;
        var prev = _state;
        _state = newState;
        if (newState === 'offline') {
            showBanner();
            // Toast uniquement sur transition (pas au boot offline pour
            // eviter un toast au load qui se cumule avec le banner).
            if (prev === 'online') {
                safeToast(TOAST_OFFLINE, 'warning');
            }
        } else {
            hideBanner();
            if (prev === 'offline') {
                safeToast(TOAST_ONLINE, 'success');
            }
        }
        try {
            window.dispatchEvent(new CustomEvent(NETWORK_CHANGED_EVENT, {
                detail: { state: newState, previous: prev,
                          source: sourceHint || 'event' }
            }));
        } catch (_e) {
            // CustomEvent indispo (vieux IE) — noop. La fonctionnalite
            // banner reste effective.
        }
    }

    // ── Fetch wrap (retry + offline detect) ───────────────────────────

    function extractMethod(input, init) {
        if (init && typeof init.method === 'string') return init.method;
        if (input && typeof input === 'object' && typeof input.method === 'string') {
            return input.method;
        }
        return 'GET';
    }

    function extractOptIn(input, init) {
        if (init && init.komptiaRetry === true) return true;
        if (input && typeof input === 'object' && input.komptiaRetry === true) {
            return true;
        }
        return false;
    }

    function isSignalAborted(init) {
        try {
            if (init && init.signal && init.signal.aborted === true) return true;
        } catch (_e) { /* signal getter throws — fail-safe */ }
        return false;
    }

    /**
     * Detecte un Request object (Fetch API). Le body d'un Request ne peut
     * etre consomme qu'UNE fois → re-passer le meme Request a origFetch au
     * retry leve ``TypeError: Body has already been read``. On ne retry
     * donc PAS les calls qui utilisent l'API Request directement (review
     * adversarial B3 2026-05-19). Caller doit utiliser ``fetch(url, init)``
     * pour beneficier du retry.
     */
    function isRequestObject(input) {
        try {
            return (typeof Request !== 'undefined') && (input instanceof Request);
        } catch (_e) { return false; }
    }

    /**
     * Delay annulable par signal abort. ``setTimeout`` est cleare et la
     * promesse rejette avec un ``AbortError`` synthetique (au lieu de la
     * network error originale) pour que les callers detectant
     * ``err.name === 'AbortError'`` puissent swallow correctement
     * (navigation away, React unmount).
     */
    function delayMs(ms, signal) {
        return new Promise(function (resolve, reject) {
            var t = setTimeout(resolve, ms);
            if (signal && typeof signal.addEventListener === 'function') {
                var onAbort = function () {
                    clearTimeout(t);
                    var e;
                    try {
                        e = new DOMException('aborted', 'AbortError');
                    } catch (_dom) {
                        e = new Error('aborted');
                        e.name = 'AbortError';
                    }
                    reject(e);
                };
                try { signal.addEventListener('abort', onAbort, { once: true }); }
                catch (_le) { signal.addEventListener('abort', onAbort); }
            }
        });
    }

    function wrapFetch() {
        if (typeof window.fetch !== 'function') return;
        if (window.__komptiaNetworkWrapped) return;
        var origFetch = window.fetch.bind(window);

        function attemptFetch(input, init, attempt, maxAttempts) {
            return origFetch(input, init).then(function (resp) {
                // Une reponse HTTP (meme 4xx/5xx) prouve qu'on est joignable.
                if (_state === 'offline') setState('online', 'fetch-success');
                return resp;
            }, function (err) {
                if (!isNetworkError(err)) throw err;
                // Erreur reseau confirmee : on bascule offline + tente retry.
                if (_state === 'online') setState('offline', 'fetch-error');
                // ⚠️ Request object → ne pas retry (body deja consomme).
                // Le caller verra l'erreur reseau originale, comportement
                // identique au pre-wrap, sans 5x les TypeErrors body-read.
                if (isRequestObject(input)) throw err;
                var method = extractMethod(input, init);
                var optIn = extractOptIn(input, init);
                var aborted = isSignalAborted(init);
                if (!shouldRetryRequest(method, attempt, maxAttempts,
                                        aborted, optIn)) {
                    throw err;
                }
                var d = computeBackoffDelay(attempt, DEFAULT_BASE_DELAY_MS,
                                            DEFAULT_CAP_DELAY_MS,
                                            DEFAULT_JITTER_MS);
                var signal = (init && init.signal) || null;
                return delayMs(d, signal).then(function () {
                    if (isSignalAborted(init)) {
                        // Abort survenu pendant le delai → throw AbortError
                        // (deja propage par delayMs en cas d'event 'abort').
                        // Cas du polling : aborted apres delay resolve sans
                        // event (shouldn't happen mais defense).
                        var e;
                        try { e = new DOMException('aborted', 'AbortError'); }
                        catch (_dom) { e = new Error('aborted'); e.name = 'AbortError'; }
                        throw e;
                    }
                    return attemptFetch(input, init, attempt + 1, maxAttempts);
                });
            });
        }

        window.fetch = function (input, init) {
            // Note : init peut etre undefined ; on laisse origFetch gerer
            // (notre wrap ne mute pas l'objet init pour eviter side-effects).
            return attemptFetch(input, init, 0, DEFAULT_MAX_ATTEMPTS);
        };
        window.__komptiaNetworkWrapped = true;
    }

    // ── Init ──────────────────────────────────────────────────────────

    function initListeners() {
        // Banner si offline au boot (sans toast — eviter spam au load).
        // ⚠️ Defense en profondeur (review I3) : si un fetch a fail AVANT
        // DOMContentLoaded (wrap installe en sync), setState('offline') a
        // ete appele mais ensureBanner() a retourne null (pas de body).
        // On force showBanner() ici quand _state est deja 'offline'.
        if (typeof navigator !== 'undefined' && navigator.onLine === false) {
            _state = 'offline';
            showBanner();
        } else if (_state === 'offline') {
            // Etat bascule par wrapFetch avant DOMContentLoaded → banner DOM
            // pas encore monte. Rattrapage ici.
            showBanner();
        }
        window.addEventListener('offline', function () {
            setState('offline', 'event-offline');
        });
        window.addEventListener('online', function () {
            setState('online', 'event-online');
        });
        // ``pageshow`` event (bfcache Safari/Firefox) : au retour
        // Back/Forward depuis le cache, ressyncer l'etat reel avec
        // navigator.onLine (un onglet en bfcache peut rater les events
        // online/offline pendant qu'il etait suspendu). On scope a
        // ``event.persisted === true`` pour eviter de fire sur chaque
        // navigation normale (M1 review).
        window.addEventListener('pageshow', function (ev) {
            if (!ev || ev.persisted !== true) return;
            if (typeof navigator !== 'undefined') {
                if (navigator.onLine === false && _state === 'online') {
                    setState('offline', 'pageshow-resync');
                } else if (navigator.onLine === true && _state === 'offline') {
                    setState('online', 'pageshow-resync');
                }
            }
        });
    }

    // Wrap fetch immediatement (avant tout autre script). Le DOM banner
    // attendra DOMContentLoaded car document.body peut etre null avant.
    wrapFetch();

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initListeners);
    } else {
        initListeners();
    }

    // ── Public API ────────────────────────────────────────────────────

    window.KomptiaNetworkStatus = {
        isOnline: function () { return _state === 'online'; },
        getState: function () { return _state; },
        /**
         * Ajoute un listener notifie a chaque transition.
         * @param {function({state, previous, source}): void} fn
         * @returns {function(): void} unsubscribe.
         */
        addListener: function (fn) {
            if (typeof fn !== 'function') return function () {};
            var handler = function (ev) {
                try { fn(ev.detail); } catch (_e) { /* noop */ }
            };
            window.addEventListener(NETWORK_CHANGED_EVENT, handler);
            return function () {
                window.removeEventListener(NETWORK_CHANGED_EVENT, handler);
            };
        },
    };
})();
