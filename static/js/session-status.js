// session-status.js -- composant global "401/403 -> banner + redirect login".
//
// Couvre le cas (b) de la taxonomie 4-cas erreurs Komptia : reponse 4xx
// liee a l'authentification. Quand un fetch retourne 401 (session expiree,
// non authentifie) ou 403 (XSRF rotate, role insuffisant, etc.) sur une
// route authentifiee, on affiche un banner sticky "Session expiree --
// reconnecte-toi" + redirect vers ``/login?next=<here>``.
//
// Pourquoi un composant separe (et pas un IIFE inline dans base.html) ?
//
//   * Single source of truth : evite la duplication d'un wrap fetch inline
//     vs externe (l'ancien IIFE inline ``setupSessionExpiryWatcher`` etait
//     dupliquer le risque de wraps non-coordonnees).
//   * Testabilite : les helpers purs (isAuthFailureStatus, isLoginPath,
//     shouldRedirectOnAuthFailure) sont exportes via ``module.exports``
//     pour les tests Node subprocess (cf. ``tests/unit/test_session_status_js.py``).
//   * Ordre de wrap explicite : le composant est charge dans <head> AVANT
//     ``feedback-reporter.js`` et ``network-status.js`` -- il devient
//     l'INNERMOST wrap. Quand un fetch resolve, le response transit par
//     network-status -> feedback-reporter -> session-status -> caller. Le
//     401/403 est detecte AVANT que le logger feedback-reporter ne tente
//     de capturer une erreur 401 comme bug applicatif (faux positif).
//
// Co-existence avec les inline 401 handlers (limitation connue)
// -------------------------------------------------------------
// Au moment de l'introduction du wrap, plusieurs callers historiques
// gardent un ``if (res.status === 401) window.location.href = '/login'``
// inline (settings.js, contacts.js, dashboard-charts.js, iris-grid.js,
// privacy-page.js, scan-progress.js, improve-pseudos.js). Ces inline
// gagnent la race contre le ``setTimeout(performRedirect, 3000)`` du
// wrap : le banner peut ne pas apparaitre sur ces pages. C'est une
// limitation acceptee pour cette iteration (cf.
// ``.claude/prod-loop/findings/discoveries.md``). La derive prevue :
// (1) exposer ``KomptiaSessionStatus.onBeforeRedirect(cb)`` pour
//     permettre a ``contacts.js`` de saveDraft avant le redirect global,
// (2) supprimer les inline une fois la hook disponible.
//
// Doctrine
// --------
//  1. CSP-safe : addEventListener uniquement, zero ``onclick`` inline.
//  2. Idempotent boot : ``__komptiaSessionStatusInit`` guard -- re-eval du
//     bundle ne reinstalle pas les listeners.
//  3. Wrap compose-safe : ``window.__komptiaSessionStatusWrapped`` flag
//     distinct de ``__komptiaFetchWrapped`` (feedback-reporter.js) et
//     ``__komptiaNetworkWrapped`` (network-status.js). Les trois wraps
//     composent ; session-status est INNERMOST.
//  4. Single redirect : ``_redirecting`` flag prevent les multiple
//     setTimeout en parallele (5 fetches 401 simultanes = 1 seul
//     window.location.href, pas 5).
//  5. Anti-loop : si la page courante est /login OU la requete cible
//     /login, on ne redirect PAS. Empeche la boucle infinie
//     /login -> 401 -> /login -> ...
//  6. Anti-faux-positif : isLoginPath('/loginx') === false (strict
//     boundary apres ``/login``). Sinon un endpoint /loginscreen ou
//     /loginx serait silencieusement skip-redirect.
//  7. Opt-out caller : ``init.komptiaSkipAuthBanner: true`` permet a un
//     caller (e.g., probe healthcheck auth) de bypasser le banner. Pas
//     active par defaut -- defense en profondeur.
//  8. Delay avant redirect : 3000ms (vs 800ms de l'ancien IIFE). Donne
//     a l'user le temps de lire le banner ET de copier des donnees non
//     sauvegardees si besoin. Le banner inclut un bouton "Se reconnecter"
//     pour skip le delai.
//  9. Pas de croissance non bornee : un seul banner DOM, un seul listener
//     button, un seul setTimeout actif.
// 10. Anti-XSS : textContent uniquement (pas innerHTML) sur le banner.
//
// Tests : ``tests/unit/test_session_status_js.py`` (Node subprocess sur
// les helpers purs : isAuthFailureStatus, isLoginPath, isLoginRequestUrl,
// extractRequestUrl, shouldRedirectOnAuthFailure). Pas de DOM dans Node.

(function () {
    'use strict';

    // == Boot guard ====================================================
    // Si le bundle est re-evalue (ex: HMR dev, ou inclusion redondante),
    // on no-op proprement. On reset les Node exports pour preserver la
    // testabilite des helpers purs.
    if (typeof window !== 'undefined' && window.__komptiaSessionStatusInit) {
        if (typeof module !== 'undefined' && module.exports &&
            window.__komptiaSessionStatusExports) {
            module.exports = window.__komptiaSessionStatusExports;
        }
        return;
    }

    // == Constants =====================================================
    var BANNER_ID = 'komptia-session-banner';
    var BANNER_BUTTON_ID = 'komptia-session-banner-action';
    var BANNER_TITLE = 'Session expiree -- reconnecte-toi';
    var BANNER_SUBTITLE = 'Tu vas etre redirige vers la page de connexion.';
    var BANNER_BUTTON_TEXT = 'Se reconnecter';
    var TOAST_TEXT = 'Session expiree -- redirection vers la connexion.';
    var REDIRECT_DELAY_MS = 3000;
    var LOGIN_URL = '/login';
    // ⚠️ Regex strict avec boundary : /login suivi de fin-de-string,
    // slash, query ``?``, ou hash ``#``. Pas de match sur /loginx ou
    // /loginscreen (defense en profondeur).
    var LOGIN_PATH_REGEX = /^\/login($|\/|\?|#)/;

    // == Helpers purs (testables Node) =================================

    /**
     * Une reponse HTTP a-t-elle un status d'echec auth ?
     *
     * ⚠️ STRICT par design : 401 (non authentifie) ET 403 (interdit --
     * XSRF rotate, role insuffisant, etc.) sont consideres comme
     * auth-failure car les deux beneficient d'une redirection vers
     * /login (re-auth + session reset).
     *
     * NE PAS inclure :
     *  - 400 (bad request, validation)
     *  - 402 (payment required, hors scope)
     *  - 404 (route disparue)
     *  - 5xx (erreur serveur, cas c taxonomie)
     *
     * Fail-safe : null/undefined/non-number → false.
     *
     * Note : le contrat strict number-only est volontaire. Un
     * response.status est toujours un number dans la Fetch API ;
     * recevoir un string ``"401"`` indique un bug de plumbing (e.g.,
     * un mock teste sans le bon type). On preserve la chaine d'echec
     * en retournant false plutot qu'en swallowant le bug.
     *
     * @param {*} status
     * @returns {boolean}
     */
    function isAuthFailureStatus(status) {
        if (typeof status !== 'number') return false;
        return status === 401 || status === 403;
    }

    /**
     * Le path donne correspond-il a la page UI /login (ou variante avec
     * trailing slash, query, hash) ?
     *
     * Boundary strict : ``/login``, ``/login/``, ``/login?next=x``,
     * ``/login#section`` matchent. ``/loginx``, ``/loginscreen``,
     * ``/api/login`` ne matchent PAS (anti-faux-positif).
     *
     * @param {string} path - path UI (window.location.pathname).
     * @returns {boolean}
     */
    function isLoginPath(path) {
        if (typeof path !== 'string') return false;
        return LOGIN_PATH_REGEX.test(path);
    }

    /**
     * Extrait le path d'une URL relative ou absolue.
     *
     * - ``/login`` → ``/login``
     * - ``/login?x=1`` → ``/login`` (query stripped)
     * - ``https://host/login`` → ``/login``
     * - ``https://host:8888/login?x=1`` → ``/login``
     *
     * Defensive : input non-string → null.
     *
     * @param {string} url
     * @returns {string|null}
     */
    function _extractPathFromUrl(url) {
        if (typeof url !== 'string' || url.length === 0) return null;
        // URL absolue : on parse manuellement (URL() en Node sans
        // dependance globale est dispo mais on evite par portabilite).
        var protoIdx = url.indexOf('://');
        var pathStart = 0;
        if (protoIdx !== -1) {
            // Apres ``://``, chercher le prochain ``/`` (debut du path).
            var afterProto = protoIdx + 3;
            var firstSlash = url.indexOf('/', afterProto);
            if (firstSlash === -1) return '/';
            pathStart = firstSlash;
        } else if (url.length >= 2 && url.charAt(0) === '/' && url.charAt(1) === '/') {
            // URL protocol-relative : ``//host/path`` (e.g., fetch dans une
            // page HTTPS qui veut suivre le scheme du parent). Le path
            // commence apres le prochain ``/`` (skip ``//host``). Sans ce
            // traitement, /login serait detecte comme ne commencant pas par
            // /login (string commence par //) → faux negatif anti-loop.
            var firstSlash2 = url.indexOf('/', 2);
            if (firstSlash2 === -1) return '/';
            pathStart = firstSlash2;
        }
        // Strip query (?) et hash (#) du path.
        var queryIdx = url.indexOf('?', pathStart);
        var hashIdx = url.indexOf('#', pathStart);
        var end = url.length;
        if (queryIdx !== -1 && queryIdx < end) end = queryIdx;
        if (hashIdx !== -1 && hashIdx < end) end = hashIdx;
        return url.substring(pathStart, end);
    }

    /**
     * L'URL de requete cible-t-elle ``/login`` ?
     *
     * Identique a isLoginPath mais extrait d'abord le path (gere les
     * URL absolues + query strings). Anti-faux-positif sur les query
     * strings qui CONTIENNENT /login mais dont le path n'est pas /login
     * (e.g., ``/api/foo?next=/login``).
     *
     * @param {string} url
     * @returns {boolean}
     */
    function isLoginRequestUrl(url) {
        var path = _extractPathFromUrl(url);
        if (path === null) return false;
        return isLoginPath(path);
    }

    /**
     * Normalise une input ``fetch(input, init)`` en string URL.
     *
     * Input fetch peut etre :
     *  - string : direct
     *  - Request object : ``.url``
     *  - URL object : ``.href``
     *  - autre : fallback toString() ou ''
     *
     * Defensive : null/undefined → '' (string vide, evite crash en
     * downstream regex).
     *
     * @param {*} input
     * @returns {string}
     */
    function extractRequestUrl(input) {
        if (input === null || typeof input === 'undefined') return '';
        if (typeof input === 'string') return input;
        if (typeof input === 'object') {
            // Request-like
            if (typeof input.url === 'string') return input.url;
            // URL-like
            if (typeof input.href === 'string') return input.href;
            // Fallback : toString (defensive)
            try {
                var s = String(input);
                return s;
            } catch (_e) {
                return '';
            }
        }
        return '';
    }

    /**
     * Decision composite : doit-on declencher le banner + redirect ?
     *
     * Skip dans les cas suivants :
     *  - status non auth-failure
     *  - currentPath est /login (anti-loop redirect)
     *  - requestUrl cible /login (le caller -- form login -- gere son erreur)
     *  - optOut === true (caller a opt-out via init.komptiaSkipAuthBanner)
     *
     * @param {number} status - response.status
     * @param {string} currentPath - window.location.pathname
     * @param {string} requestUrl - extractRequestUrl(fetch input)
     * @param {boolean} optOut - init.komptiaSkipAuthBanner === true
     * @returns {boolean}
     */
    function shouldRedirectOnAuthFailure(status, currentPath, requestUrl, optOut) {
        if (optOut === true) return false;
        if (!isAuthFailureStatus(status)) return false;
        if (isLoginPath(currentPath)) return false;
        if (isLoginRequestUrl(requestUrl)) return false;
        return true;
    }

    // == Exports Node (tests purs -- pas de DOM dans Node) =============
    var _exports = {
        isAuthFailureStatus: isAuthFailureStatus,
        isLoginPath: isLoginPath,
        isLoginRequestUrl: isLoginRequestUrl,
        extractRequestUrl: extractRequestUrl,
        shouldRedirectOnAuthFailure: shouldRedirectOnAuthFailure,
    };
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = _exports;
    }

    // == Suite : DOM/runtime -- skip si pas dans browser ===============
    if (typeof window === 'undefined' || typeof document === 'undefined') {
        return;
    }
    window.__komptiaSessionStatusInit = true;
    window.__komptiaSessionStatusExports = _exports;

    // == State =========================================================

    var _state = 'active'; // 'active' | 'expired'
    var _redirecting = false;
    var _redirectTimer = null;

    // == DOM banner ====================================================

    /**
     * Cree (ou recupere) le banner DOM. Style Tailwind aligne sur le
     * design system Komptia : bg-rose-700 (urgence auth), texte blanc,
     * sticky top, bouton CTA. Z-index 9050 = au-dessus du network
     * banner (9000) mais en-dessous des system modals (10010).
     */
    function ensureBanner() {
        if (!document.body) return null;
        var existing = document.getElementById(BANNER_ID);
        if (existing) return existing;
        var banner = document.createElement('div');
        banner.id = BANNER_ID;
        banner.setAttribute('role', 'alert');
        banner.setAttribute('aria-live', 'assertive');
        banner.className = 'fixed top-0 left-0 right-0 ' +
            'bg-rose-700 text-white text-sm py-3 px-4 shadow-md ' +
            'flex items-center justify-center gap-4 hidden';
        // z-index inline (style direct) : la classe arbitraire Tailwind
        // ``z-[9050]`` n'est pas dans le build static/css/tailwind.min.css
        // (seuls z-[9000] et z-[9999] y sont) et l'app n'a pas le JIT actif
        // en prod -- une classe arbitraire absente = z-index auto = banner
        // potentiellement masque. 9050 = au-dessus du network banner
        // (z-9000) ET en-dessous des system modals (z-10010, defini dans
        // overlay-layers.css). CSP-safe : valeur hardcodee, pas d'input
        // utilisateur dans le style.
        banner.style.zIndex = '9050';

        var textWrapper = document.createElement('div');
        textWrapper.className = 'flex flex-col items-start sm:items-center sm:flex-row sm:gap-2';

        var title = document.createElement('span');
        title.className = 'font-semibold';
        title.textContent = BANNER_TITLE;
        textWrapper.appendChild(title);

        var subtitle = document.createElement('span');
        subtitle.className = 'opacity-90 text-xs sm:text-sm';
        subtitle.textContent = BANNER_SUBTITLE;
        textWrapper.appendChild(subtitle);

        banner.appendChild(textWrapper);

        var btn = document.createElement('button');
        btn.id = BANNER_BUTTON_ID;
        btn.type = 'button';
        btn.className = 'ml-2 px-3 py-1 rounded bg-white text-rose-700 ' +
            'font-semibold text-xs hover:bg-rose-50 focus:outline-none ' +
            'focus:ring-2 focus:ring-white focus:ring-offset-2 ' +
            'focus:ring-offset-rose-700';
        btn.textContent = BANNER_BUTTON_TEXT;
        btn.addEventListener('click', function () {
            performRedirect();
        });
        banner.appendChild(btn);

        document.body.appendChild(banner);
        return banner;
    }

    function showBanner() {
        var b = ensureBanner();
        if (b) b.classList.remove('hidden');
    }

    function safeToast(msg, type) {
        if (typeof window.showToast === 'function') {
            try { window.showToast(msg, type); } catch (_e) { /* noop */ }
        }
    }

    // == Redirect ======================================================

    /**
     * Execute la redirection vers /login?next=<here>. Idempotent via
     * ``_redirecting`` flag : double-click sur le bouton, ou auto-redirect
     * + click manuel, n'execute qu'UNE redirection.
     */
    function performRedirect() {
        if (_redirecting) return;
        _redirecting = true;
        // Annuler le timer auto-redirect s'il est arme (le bouton a ete
        // clique en avance) -- evite que setTimeout fire apres la
        // navigation et tente un second window.location.href sur la page
        // de login (pas critique mais propre).
        if (_redirectTimer !== null) {
            clearTimeout(_redirectTimer);
            _redirectTimer = null;
        }
        try {
            var here = window.location.pathname + window.location.search;
            window.location.href = LOGIN_URL + '?next=' + encodeURIComponent(here);
        } catch (_e) {
            // Fallback si pathname/search throw (cas extreme : sandbox
            // iframe ou window.location.search incompatible).
            window.location.href = LOGIN_URL;
        }
    }

    /**
     * Programme la redirection apres REDIRECT_DELAY_MS. Si le timer est
     * deja arme, no-op (un seul timer actif).
     */
    function scheduleRedirect() {
        if (_redirecting) return;
        if (_redirectTimer !== null) return;
        _redirectTimer = setTimeout(performRedirect, REDIRECT_DELAY_MS);
    }

    /**
     * Bascule le state en 'expired' : banner + toast + scheduled redirect.
     * Idempotent : une seule transition active → expired.
     */
    function markExpired() {
        if (_state === 'expired') return;
        _state = 'expired';
        showBanner();
        safeToast(TOAST_TEXT, 'warning');
        scheduleRedirect();
    }

    // == Fetch wrap (detect 401/403) ===================================

    function extractOptOut(input, init) {
        if (init && init.komptiaSkipAuthBanner === true) return true;
        if (input && typeof input === 'object' &&
            input.komptiaSkipAuthBanner === true) return true;
        return false;
    }

    function wrapFetch() {
        if (typeof window.fetch !== 'function') return;
        if (window.__komptiaSessionStatusWrapped) return;
        var origFetch = window.fetch.bind(window);

        window.fetch = function (input, init) {
            return origFetch(input, init).then(function (response) {
                // Skip si deja en cours de redirect (eviter le banner
                // qui re-show entre 2 redirects).
                if (_redirecting) return response;
                // Defensive : response peut etre falsy si un wrap
                // descendant returns undefined (pathologique).
                if (!response) return response;
                var status = response.status;
                if (!isAuthFailureStatus(status)) return response;
                var currentPath = '';
                try {
                    currentPath = window.location.pathname || '';
                } catch (_e) { /* cas exotique */ }
                var requestUrl = extractRequestUrl(input);
                var optOut = extractOptOut(input, init);
                if (shouldRedirectOnAuthFailure(status, currentPath,
                                                 requestUrl, optOut)) {
                    markExpired();
                }
                return response;
            });
            // Note : on ne touche PAS au catch (errors network reseau
            // sont gerees par network-status.js -- l'outermost wrap).
            // Notre wrap voit seulement les responses (success ou
            // 4xx/5xx), pas les TypeErrors fetch.
        };
        window.__komptiaSessionStatusWrapped = true;
    }

    // == Init ==========================================================

    // Wrap fetch immediatement (avant tout autre script). Le banner DOM
    // attendra DOMContentLoaded car document.body peut etre null en head.
    wrapFetch();

    function initBanner() {
        // Si markExpired() a deja ete appele avant DOMContentLoaded
        // (impossible en pratique : un fetch resolve apres I/O, donc
        // apres DOMContentLoaded en general), on s'assure que le
        // banner est rendu maintenant.
        if (_state === 'expired') {
            showBanner();
        }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initBanner);
    } else {
        initBanner();
    }

    // Recovery bfcache (Safari/Firefox) : si l'utilisateur navigue away puis
    // hit back, la page est restauree depuis le bfcache avec _redirecting=true
    // ET _state='expired' s'il avait deja vu le banner avant. Le timer
    // setTimeout(performRedirect, 3000) a ete clearTimeout par la navigation,
    // donc l'auto-redirect ne re-fire pas. On reset _redirecting au retour
    // bfcache pour permettre une nouvelle detection d'expiration si l'user
    // reclique. Si _state etait 'expired', on re-arme le banner + timer.
    window.addEventListener('pageshow', function (ev) {
        if (!ev || ev.persisted !== true) return;
        // _redirecting peut etre reste true (navigation cancelled, ou
        // restoration apres back) -- on le reset pour ne pas bloquer les
        // detections suivantes.
        if (_redirecting) {
            _redirecting = false;
            if (_redirectTimer !== null) {
                clearTimeout(_redirectTimer);
                _redirectTimer = null;
            }
        }
        // Si _state expired persiste (user revient via back avant d'avoir
        // re-authentifie), re-show banner + re-schedule redirect.
        if (_state === 'expired') {
            showBanner();
            scheduleRedirect();
        }
    });

    // == Public API ====================================================

    window.KomptiaSessionStatus = {
        getState: function () { return _state; },
        /**
         * Force la redirection immediate (skip le delai). Usage : un
         * caller qui veut react a 401 sans attendre le banner (e.g.,
         * un middleware applicatif au-dela de session-status).
         */
        redirectNow: function () {
            markExpired();
            performRedirect();
        },
    };
})();
