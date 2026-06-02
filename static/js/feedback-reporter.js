/**
 * Feedback Reporter — capture les erreurs frontend et propose à l'utilisateur
 * de les signaler par mail.
 *
 * Doctrine
 * --------
 * 1. **Pas de bouton flottant permanent.** Le mécanisme est *réactif* : un
 *    banner discret n'apparaît QUE quand une erreur ou un warning grave
 *    est détecté côté navigateur.
 * 2. **Capture immédiate dès le chargement** (window.error,
 *    unhandledrejection, console.error/warn) AVANT que l'app utilisateur
 *    ne tourne — sans ça, une erreur de boot serait perdue.
 * 3. **Buffer borné** (50 dernières entrées, FIFO).
 * 4. **Grace period au boot** : 2s — quelques warnings de tiers au
 *    démarrage sont normaux et ne méritent pas un banner.
 * 5. **Dismiss persistant cross-tab** (localStorage avec timestamp de
 *    24h — si l'utilisateur ferme le banner, on respecte sur tous les
 *    onglets ouverts. Avant : sessionStorage = re-show sur chaque tab.)
 * 6. **CSP-friendly** : aucune dépendance externe, aucun ``eval``,
 *    aucune injection HTML d'input utilisateur (textContent uniquement).
 * 7. **Anonyme et connecté** : marche sur /login (anonyme) ET les pages
 *    connectées. XSRF géré via cookie ``_xsrf``.
 * 8. **Re-entry guard sur la capture console** : sans guard, un script
 *    tiers (DataDog/Sentry) qui a déjà wrappé console.error peut
 *    déclencher une boucle infinie via notre wrapper.
 * 9. **API publique figée via Object.defineProperty** : un script tiers
 *    ne peut pas écraser ``window.komptiaReportFeedback`` pour bloquer
 *    le signalement ou exfiltrer les messages.
 *
 * Convention CSS : toutes les classes commencent par ``komptia-fb-``.
 */
(function() {
    'use strict';

    if (window.__komptiaFeedbackInitialized) return;
    window.__komptiaFeedbackInitialized = true;

    // ── Configuration ──────────────────────────────────────────────────
    var ENDPOINT = '/api/feedback/report';
    var XSRF_REFRESH_ENDPOINT = '/api/auth/xsrf';
    var BUFFER_MAX = 50;
    var MESSAGE_MAX = 4000;
    var STACK_MAX = 8000;
    var REASON_MAX_LEN = 80;
    var FORMAT_ARGS_MAX = 4096;
    var SEND_TIMEOUT_MS = 15000;
    var BOOT_GRACE_MS = 2000;
    var DISMISS_KEY = 'komptia_fb_dismissed_until';
    var DISMISS_DURATION_MS = 24 * 60 * 60 * 1000; // 24h
    var SHOWN_FLAG = '__komptiaFbBannerShown';

    // Payload enrichi 2026-05-19 — caps anti-DoS sur les nouvelles sections.
    var NETWORK_BUFFER_MAX = 30;
    var NETWORK_URL_MAX = 500;
    var APP_STATE_VALUE_MAX = 500;
    var LOCALSTORAGE_VALUE_MAX = 500;
    var LOCALSTORAGE_KEYS_MAX = 30;
    // Fragments dans les noms de clés localStorage qui déclenchent un FILTRE
    // (anti-leak credential). Le serveur re-filtre aussi en defense in depth.
    var LOCALSTORAGE_SENSITIVE_FRAGMENTS = [
        'token', 'xsrf', 'session', 'auth', 'password',
        'secret', 'cookie', 'credential', 'private', 'jwt',
        'api_key', 'apikey',
    ];

    // Stack-trace heuristique : on accepte un buffer comme stack uniquement si
    // au moins une ligne match ce pattern (V8 / SpiderMonkey / WebKit). Sinon
    // un message "multi\nline" en console.error ne sera pas envoyé comme stack.
    var STACK_LINE_RE = /(?:^|\n)\s*(?:at\s+\S|[\w$]+@\S)/;

    // Caractères Unicode dangereux à neutraliser avant rendu dans le banner :
    // - \x00-\x1f : contrôle ASCII
    // - ‪-‮ : LRE/RLE/PDF/LRO/RLO (bidi override classique)
    // - ⁦-⁩ : LRI/RLI/FSI/PDI (bidi isolate)
    var DANGEROUS_CHARS_RE = /[\x00-\x1f‪-‮⁦-⁩]/g;

    // ── État interne ───────────────────────────────────────────────────
    var consoleBuffer = [];
    var networkBuffer = []; // FIFO des derniers fetches (2026-05-19)
    var modalRef = null;
    var bannerRef = null;
    var bootTime = Date.now();
    var lastFocusedBeforeOpen = null;
    var lastReasons = []; // historique des dernières raisons reçues
    var capturing = false; // re-entry guard pour le wrap console
    var submitting = false; // anti double-clic submit

    function pushNetwork(entry) {
        if (networkBuffer.length >= NETWORK_BUFFER_MAX) networkBuffer.shift();
        networkBuffer.push(entry);
    }

    function pushBuffer(entry) {
        if (consoleBuffer.length >= BUFFER_MAX) consoleBuffer.shift();
        consoleBuffer.push(entry);
    }
    function nowIso() {
        try { return new Date().toISOString(); } catch (e) { return ''; }
    }
    function safeStringifyValue(v) {
        try {
            if (v instanceof Error) {
                return v.name + ': ' + v.message + (v.stack ? '\n' + v.stack : '');
            }
            if (typeof v === 'object' && v !== null) {
                try { return JSON.stringify(v); }
                catch (e) { return String(v); }
            }
            return String(v);
        } catch (e) { return '[unserializable]'; }
    }
    function formatArgs(args) {
        var out = '';
        for (var i = 0; i < args.length; i++) {
            if (i > 0) out += ' ';
            out += safeStringifyValue(args[i]);
            if (out.length >= FORMAT_ARGS_MAX) {
                return out.slice(0, FORMAT_ARGS_MAX) + '…[truncated]';
            }
        }
        return out;
    }
    function sanitizeForBanner(str) {
        if (typeof str !== 'string') str = String(str);
        // Strip caractères de contrôle + bidi override (anti spoofing visuel)
        return str.replace(DANGEROUS_CHARS_RE, '');
    }
    function isBootGrace() {
        return (Date.now() - bootTime) < BOOT_GRACE_MS;
    }
    function isDismissed() {
        try {
            var until = parseInt(localStorage.getItem(DISMISS_KEY) || '0', 10);
            return Number.isFinite(until) && until > Date.now();
        } catch (e) { return false; }
    }
    function markDismissed() {
        try {
            localStorage.setItem(DISMISS_KEY, String(Date.now() + DISMISS_DURATION_MS));
        } catch (e) { /* ignore */ }
    }

    // ── Wrapper window.fetch (2026-05-19) ─────────────────────────────
    //
    // Capture les ~30 derniers fetches : url, method, status, duration_ms,
    // error. Le wrapping est ``compose-safe`` (passe à ``orig.apply`` ce
    // que reçoit le wrapper, peu importe son nombre d'args).
    //
    // **Anti-leak** :
    // - URL : query string strippée (PII potentielle dans ``?email=...``)
    // - Pas de body POST captée (peut contenir PII en clair)
    // - Pas de headers captés (XSRF, Authorization)
    //
    // **Single-wrap** : ``window.__komptiaFetchWrapped`` empêche le double
    // wrap (idempotent au boot, ré-exécutions de bundles). Pas de re-entry
    // guard runtime (les fetches concurrents sont OK — JS async natif).
    try {
        if (typeof window.fetch === 'function' && !window.__komptiaFetchWrapped) {
            var origFetch = window.fetch.bind(window);
            window.fetch = function() {
                var startMs = (typeof performance !== 'undefined' && performance.now)
                    ? performance.now() : Date.now();
                var url = '';
                var method = 'GET';
                try {
                    var input = arguments[0];
                    var init = arguments[1] || {};
                    if (typeof input === 'string') {
                        url = input;
                    } else if (input && typeof input.href === 'string') {
                        // URL object (fix #4 review 2026-05-19)
                        url = input.href;
                    } else if (input && input.url) {
                        // Request object
                        url = input.url;
                        if (input.method) method = input.method;
                    }
                    if (init && init.method) method = init.method;
                    // Fix #2 (review 2026-05-19) — anti-leak PII :
                    // strip query string AVANT capture. Le support reçoit
                    // l'URL de base + count des params, jamais les valeurs.
                    var qIdx = url.indexOf('?');
                    if (qIdx >= 0) {
                        url = url.substring(0, qIdx);
                    }
                    if (url.length > NETWORK_URL_MAX) url = url.substring(0, NETWORK_URL_MAX);
                } catch (e) { /* ignore — best-effort */ }

                return origFetch.apply(window, arguments).then(function(resp) {
                    try {
                        var dur = ((typeof performance !== 'undefined' && performance.now)
                            ? performance.now() : Date.now()) - startMs;
                        pushNetwork({
                            url: url,
                            method: method,
                            status: (resp && resp.status) || 0,
                            duration_ms: Math.round(dur),
                            error: '',
                        });
                    } catch (e) { /* ignore */ }
                    return resp;
                }, function(err) {
                    try {
                        var dur2 = ((typeof performance !== 'undefined' && performance.now)
                            ? performance.now() : Date.now()) - startMs;
                        pushNetwork({
                            url: url,
                            method: method,
                            status: 0,
                            duration_ms: Math.round(dur2),
                            error: (err && err.message) ? String(err.message).substring(0, 200) : 'network_error',
                        });
                    } catch (e) { /* ignore */ }
                    throw err;
                });
            };
            window.__komptiaFetchWrapped = true;
        }
    } catch (e) { /* ignore — environnements sans fetch */ }

    // ── Capture des erreurs globales ───────────────────────────────────
    window.addEventListener('error', function(ev) {
        if (capturing) return;
        capturing = true;
        try {
            var stack = ev.error && ev.error.stack ? ev.error.stack : '';
            pushBuffer('[' + nowIso() + '] [error] ' +
                (ev.message || '(message inconnu)') +
                (ev.filename ? ' @ ' + ev.filename + ':' + ev.lineno + ':' + ev.colno : '') +
                (stack ? '\n' + stack : ''));
            offerReport('Erreur JavaScript : ' + (ev.message || 'inconnue'));
        } catch (e) { /* ignore */ }
        finally { capturing = false; }
    }, true);

    window.addEventListener('unhandledrejection', function(ev) {
        if (capturing) return;
        capturing = true;
        try {
            var reason = ev.reason;
            var msg = safeStringifyValue(reason);
            pushBuffer('[' + nowIso() + '] [unhandled-promise] ' + msg);
            offerReport('Promesse non gérée : ' + msg.split('\n')[0]);
        } catch (e) { /* ignore */ }
        finally { capturing = false; }
    });

    // Wrap console.error / console.warn — sans casser le natif. Le re-entry
    // guard ``capturing`` empêche la récursion si un autre script tiers
    // (DataDog/Sentry/legacy) a déjà wrappé console et déclenche un appel
    // pendant notre traitement.
    //
    // Heuristique de seuil : ``console.error`` propose immédiatement le
    // banner. ``console.warn`` est buffer-only — beaucoup de libs (Plotly,
    // Tailwind dev, browser deprecations) émettent des warns bénins, on
    // veut éviter de spammer l'utilisateur. Le warn reste capturé pour
    // accompagner un futur signalement (contexte utile à l'équipe support).
    ['error', 'warn'].forEach(function(level) {
        try {
            var orig = console[level];
            if (typeof orig !== 'function') return;
            console[level] = function() {
                if (capturing) {
                    return orig.apply(console, arguments);
                }
                capturing = true;
                try {
                    var formatted = formatArgs(arguments);
                    pushBuffer('[' + nowIso() + '] [' + level + '] ' + formatted);
                    if (level === 'error') {
                        offerReport('console.error : ' + formatted.split('\n')[0]);
                    }
                } catch (e) { /* ignore */ }
                finally { capturing = false; }
                return orig.apply(console, arguments);
            };
        } catch (e) { /* ignore */ }
    });

    // ── Capture des violations CSP (securitypolicyviolation) ───────────
    //
    // Quand le navigateur bloque une ressource ou un inline script à cause
    // de la CSP, il émet un événement ``securitypolicyviolation`` ET un
    // POST au ``report-uri`` côté serveur. Le côté client est utile pour :
    //
    // 1. Détecter les CSP bloquantes en local (dev) AVANT un déploiement.
    // 2. Aider l'utilisateur à signaler "rien ne marche" même quand le
    //    bug vient d'une CSP trop stricte (script bloqué en silence).
    //
    // Le payload réel est aussi POST'é au serveur via la directive CSP
    // ``report-uri /api/csp-report`` (cf. middleware/security.py) — c'est
    // ce flux qui sert à l'admin pour audit. Côté front on se contente de
    // consigner dans le buffer + offrir un signalement (le user a
    // probablement vu une page cassée).
    window.addEventListener('securitypolicyviolation', function(ev) {
        if (capturing) return;
        capturing = true;
        try {
            var msg = '[csp] ' + (ev.violatedDirective || ev.effectiveDirective || 'directive?') +
                ' blocked: ' + (ev.blockedURI || ev.sourceFile || '?') +
                (ev.lineNumber ? ' @ line ' + ev.lineNumber : '');
            pushBuffer('[' + nowIso() + '] ' + msg);
            // Une violation CSP trahit soit (a) un bug code (oubli de nonce
            // ou ressource externe non autorisée), soit (b) une tentative
            // d'injection (XSS bloquée). Dans les deux cas l'utilisateur
            // doit pouvoir signaler — la page est probablement cassée.
            offerReport('Violation CSP : ' + (ev.violatedDirective || 'directive bloquée'));
        } catch (e) { /* ignore */ }
        finally { capturing = false; }
    }, true);

    // ── Helpers ────────────────────────────────────────────────────────
    function getCookie(name) {
        try {
            var prefix = name + '=';
            var parts = document.cookie ? document.cookie.split(';') : [];
            for (var i = 0; i < parts.length; i++) {
                var p = parts[i].replace(/^\s+/, '');
                if (p.indexOf(prefix) === 0) return decodeURIComponent(p.substring(prefix.length));
            }
        } catch (e) { /* ignore */ }
        return '';
    }
    // ── Helpers de capture pour le payload enrichi (2026-05-19) ───────

    function capturePerformanceTiming() {
        var out = {};
        try {
            if (typeof performance === 'undefined') return out;
            // Navigation timing (page load metrics).
            if (typeof performance.getEntriesByType === 'function') {
                var navs = performance.getEntriesByType('navigation');
                if (navs && navs.length) {
                    var n = navs[0];
                    out.dom_complete_ms = Math.round(n.domComplete || 0);
                    out.dom_interactive_ms = Math.round(n.domInteractive || 0);
                    out.load_event_end_ms = Math.round(n.loadEventEnd || 0);
                    out.response_end_ms = Math.round(n.responseEnd || 0);
                    out.transfer_size_bytes = n.transferSize || 0;
                }
                // Resources lentes > 1s (max 10 pour rester compact).
                var slowCount = 0;
                var resources = performance.getEntriesByType('resource') || [];
                for (var i = resources.length - 1; i >= 0 && slowCount < 10; i--) {
                    var r = resources[i];
                    if (r && r.duration > 1000) {
                        // #70 — strip la query de l'URL ressource (peut porter
                        // un token/signature, ex asset signé ?sig=…) AVANT
                        // l'envoi support. Mirror de la policy du wrap fetch
                        // (~ligne 182) ; le serveur re-strippe en defense-in-depth.
                        var resName = (r.name || '').split('?')[0];
                        out['slow_resource_' + slowCount] =
                            resName.substring(0, 200) + ' (' + Math.round(r.duration) + 'ms)';
                        slowCount++;
                    }
                }
            }
        } catch (e) { /* best-effort */ }
        return out;
    }

    function captureAppState() {
        var out = {};
        try {
            out.url = (window.location.href || '').substring(0, APP_STATE_VALUE_MAX);
            out.hash = (window.location.hash || '').substring(0, 200);
            out.title = (document.title || '').substring(0, 200);
            // Body classes (souvent : theme dark/light, page-X, etc.)
            var bc = (document.body && document.body.className) ? String(document.body.className) : '';
            out.body_classes = bc.substring(0, APP_STATE_VALUE_MAX);
            // Modal ouvert ? (heuristique : div.fixed avec classes Tailwind
            // de modal visible — cohérent avec les modals Komptia).
            var openModal = document.querySelector(
                'div.fixed.inset-0.flex, div.fixed.inset-0:not(.hidden)[role="dialog"]'
            );
            out.modal_open = openModal ? (openModal.id || 'unknown-modal') : 'none';
            // Compte les liens / boutons (vague indicateur de "page chargée").
            out.button_count = String((document.querySelectorAll('button') || []).length);
            out.input_count = String((document.querySelectorAll('input, textarea, select') || []).length);
        } catch (e) { /* best-effort */ }
        return out;
    }

    function captureLocalStorageDebug() {
        var out = {};
        try {
            if (typeof localStorage === 'undefined') return out;
            var pickedCount = 0;
            for (var i = 0; i < localStorage.length && pickedCount < LOCALSTORAGE_KEYS_MAX; i++) {
                var key = localStorage.key(i);
                if (!key || typeof key !== 'string') continue;
                // Filtre 1 : préfixe komptia_ uniquement (skip autres apps).
                if (key.indexOf('komptia_') !== 0) continue;
                // Filtre 2 anti-leak : skip si le nom de clé contient un
                // fragment sensible (token, xsrf, session, …).
                var lowered = key.toLowerCase();
                var sensitive = false;
                for (var f = 0; f < LOCALSTORAGE_SENSITIVE_FRAGMENTS.length; f++) {
                    if (lowered.indexOf(LOCALSTORAGE_SENSITIVE_FRAGMENTS[f]) !== -1) {
                        sensitive = true;
                        break;
                    }
                }
                if (sensitive) continue;
                var value = localStorage.getItem(key) || '';
                out[key] = String(value).substring(0, LOCALSTORAGE_VALUE_MAX);
                pickedCount++;
            }
        } catch (e) { /* best-effort */ }
        return out;
    }

    function detectBrowserVersion() {
        try {
            var ua = navigator.userAgent || '';
            var matches = [
                /Edg\/[\d.]+/, /Chrome\/[\d.]+/, /Firefox\/[\d.]+/,
                /Safari\/[\d.]+/, /OPR\/[\d.]+/
            ];
            for (var i = 0; i < matches.length; i++) {
                var m = ua.match(matches[i]);
                if (m) return m[0];
            }
            return ua.split(' ').slice(-1)[0] || '';
        } catch (e) { return ''; }
    }
    function showInternalToast(message, kind) {
        try {
            if (typeof window.showToast === 'function') {
                window.showToast(message, kind === 'error' ? 'error' : 'success');
                return;
            }
        } catch (e) { /* ignore */ }
        var t = document.createElement('div');
        t.className = 'komptia-fb-toast komptia-fb-toast--' + (kind || 'info');
        t.setAttribute('role', 'status');
        t.setAttribute('aria-live', 'polite');
        t.textContent = message;
        document.body.appendChild(t);
        setTimeout(function() {
            t.classList.add('komptia-fb-toast--leaving');
            setTimeout(function() { if (t.parentNode) t.parentNode.removeChild(t); }, 240);
        }, 4000);
    }

    // Détection d'une vraie stack trace dans une chaîne (vs un simple
    // message multi-ligne). Évite d'envoyer ``console.error("a\nb\nc")``
    // comme prétendue stack.
    function looksLikeStackTrace(str) {
        return typeof str === 'string' && STACK_LINE_RE.test(str);
    }

    // ── Modal de signalement ───────────────────────────────────────────
    function buildModal() {
        var overlay = document.createElement('div');
        overlay.className = 'komptia-fb-overlay';
        overlay.setAttribute('aria-hidden', 'true');

        var modal = document.createElement('div');
        modal.className = 'komptia-fb-modal';
        modal.setAttribute('role', 'dialog');
        modal.setAttribute('aria-modal', 'true');
        modal.setAttribute('aria-labelledby', 'komptia-fb-title');
        modal.tabIndex = -1;

        var title = document.createElement('h2');
        title.id = 'komptia-fb-title';
        title.className = 'komptia-fb-title';
        title.textContent = 'Signaler un problème';

        var hint = document.createElement('p');
        hint.className = 'komptia-fb-hint';
        hint.textContent = 'Décrivez ce qui ne fonctionne pas. Si vous le souhaitez, nous joindrons automatiquement les informations techniques (page, navigateur, erreurs récentes) pour aider l\'équipe support.';

        var labelMsg = document.createElement('label');
        labelMsg.htmlFor = 'komptia-fb-message';
        labelMsg.className = 'komptia-fb-label';
        labelMsg.textContent = 'Votre message';

        var textarea = document.createElement('textarea');
        textarea.id = 'komptia-fb-message';
        textarea.className = 'komptia-fb-textarea';
        textarea.maxLength = MESSAGE_MAX;
        textarea.rows = 6;
        textarea.placeholder = 'Ex : « Quand je clique sur X, l\'écran ne réagit pas »';

        var counter = document.createElement('div');
        counter.className = 'komptia-fb-counter';
        counter.textContent = '0 / ' + MESSAGE_MAX;
        textarea.addEventListener('input', function() {
            counter.textContent = textarea.value.length + ' / ' + MESSAGE_MAX;
        });

        var optWrap = document.createElement('label');
        optWrap.className = 'komptia-fb-optwrap';
        var attachCheckbox = document.createElement('input');
        attachCheckbox.type = 'checkbox';
        attachCheckbox.id = 'komptia-fb-attach';
        attachCheckbox.checked = true;
        var attachText = document.createElement('span');
        attachText.textContent = 'Joindre les informations techniques (recommandé)';
        optWrap.appendChild(attachCheckbox);
        optWrap.appendChild(attachText);

        var actions = document.createElement('div');
        actions.className = 'komptia-fb-actions';
        var btnCancel = document.createElement('button');
        btnCancel.type = 'button';
        btnCancel.className = 'komptia-fb-btn komptia-fb-btn--ghost';
        btnCancel.textContent = 'Annuler';
        var btnSend = document.createElement('button');
        btnSend.type = 'button';
        btnSend.className = 'komptia-fb-btn komptia-fb-btn--primary';
        btnSend.textContent = 'Envoyer';
        actions.appendChild(btnCancel);
        actions.appendChild(btnSend);

        modal.appendChild(title);
        modal.appendChild(hint);
        modal.appendChild(labelMsg);
        modal.appendChild(textarea);
        modal.appendChild(counter);
        modal.appendChild(optWrap);
        modal.appendChild(actions);
        overlay.appendChild(modal);

        function closeModal() {
            overlay.classList.remove('komptia-fb-overlay--open');
            overlay.setAttribute('aria-hidden', 'true');
            try { document.body.style.overflow = ''; } catch (_) {}
            try { if (lastFocusedBeforeOpen && lastFocusedBeforeOpen.focus) lastFocusedBeforeOpen.focus(); }
            catch (_) {}
            document.removeEventListener('keydown', onEscape);
            document.removeEventListener('keydown', trapFocus, true);
        }
        function onEscape(ev) { if (ev.key === 'Escape') closeModal(); }
        function trapFocus(ev) {
            if (ev.key !== 'Tab') return;
            var focusables = modal.querySelectorAll('textarea, input, button');
            if (!focusables.length) return;
            var first = focusables[0];
            var last = focusables[focusables.length - 1];
            if (ev.shiftKey && document.activeElement === first) { last.focus(); ev.preventDefault(); }
            else if (!ev.shiftKey && document.activeElement === last) { first.focus(); ev.preventDefault(); }
        }
        function setSubmitting(busy) {
            btnSend.disabled = busy;
            btnCancel.disabled = busy;
            btnSend.textContent = busy ? 'Envoi…' : 'Envoyer';
            btnSend.setAttribute('aria-busy', busy ? 'true' : 'false');
        }

        async function refreshXsrfCookie() {
            try {
                var r = await fetch(XSRF_REFRESH_ENDPOINT, {
                    method: 'GET',
                    credentials: 'same-origin',
                    headers: { 'X-Requested-With': 'XMLHttpRequest' },
                    // Opt-out du wrap session-status.js : ce module gère lui-même
                    // les 401/403 (refresh XSRF + retry). Sans cet opt-out, un
                    // 403 XSRF rotate déclencherait banner + redirect au lieu du
                    // refresh silencieux + retry. Idem postReport ci-dessous.
                    komptiaSkipAuthBanner: true
                });
                return r.ok;
            } catch (e) { return false; }
        }

        async function postReport(payload) {
            var ctrl = (typeof AbortController === 'function') ? new AbortController() : null;
            var timeout = ctrl ? setTimeout(function() { ctrl.abort(); }, SEND_TIMEOUT_MS) : null;
            try {
                var resp = await fetch(ENDPOINT, {
                    method: 'POST',
                    credentials: 'same-origin',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-Xsrftoken': getCookie('_xsrf'),
                        'X-Requested-With': 'XMLHttpRequest'
                    },
                    body: JSON.stringify(payload),
                    signal: ctrl ? ctrl.signal : undefined,
                    // Opt-out du wrap session-status.js (cf. refreshXsrfCookie).
                    komptiaSkipAuthBanner: true
                });
                if (timeout) clearTimeout(timeout);
                var data = null;
                try { data = await resp.json(); } catch (_) { /* ignore */ }
                return { ok: resp.ok, status: resp.status, data: data };
            } catch (e) {
                if (timeout) clearTimeout(timeout);
                return { ok: false, status: 0, data: null, aborted: e && e.name === 'AbortError' };
            }
        }

        async function submit() {
            // Anti-double-clic local : si déjà en cours d'envoi, ignorer.
            if (submitting) return;
            var msg = (textarea.value || '').trim();
            if (!msg) {
                textarea.focus();
                showInternalToast('Veuillez saisir un message avant d\'envoyer.', 'error');
                return;
            }
            submitting = true;
            setSubmitting(true);
            var captured_at = nowIso();
            var payload = {
                message: msg,
                page: window.location.pathname + window.location.search,
                captured_at: captured_at,
            };
            if (attachCheckbox.checked) {
                payload.user_agent = navigator.userAgent || '';
                payload.browser_version = detectBrowserVersion();
                payload.console_entries = consoleBuffer.slice(-BUFFER_MAX);
                // Stack trace = dernière entrée qui ressemble vraiment à
                // une stack (regex), pas n'importe quelle entrée multi-ligne.
                var lastStack = '';
                for (var i = consoleBuffer.length - 1; i >= 0; i--) {
                    if (looksLikeStackTrace(consoleBuffer[i])) {
                        lastStack = consoleBuffer[i].split('\n').slice(1).join('\n');
                        break;
                    }
                }
                if (lastStack) payload.stack_trace = lastStack.substring(0, STACK_MAX);
                payload.extras = {
                    'window.innerWidth': String(window.innerWidth || ''),
                    'window.innerHeight': String(window.innerHeight || ''),
                    'language': navigator.language || '',
                    'timeZone': (Intl && Intl.DateTimeFormat) ? (Intl.DateTimeFormat().resolvedOptions().timeZone || '') : '',
                    // Corrélation logs serveur ↔ rapport user : on capture le
                    // X-Request-ID + status HTTP du dernier fetch effectué par
                    // la page (posés par ``safeFetch`` côté caller). Permet à
                    // l'admin de retrouver instantanément la trace serveur
                    // associée au rapport. Vide si aucun fetch n'a précédé.
                    'last_request_id': String(window.__komptiaLastRequestId || ''),
                    'last_http_status': String(window.__komptiaLastHttpStatus || '')
                };
                // Payload enrichi 2026-05-19 — sections rajoutées.
                payload.network_requests = networkBuffer.slice(-NETWORK_BUFFER_MAX);
                payload.performance_timing = capturePerformanceTiming();
                payload.app_state = captureAppState();
                payload.localstorage_debug = captureLocalStorageDebug();
            }

            var result = await postReport(payload);
            // Retry une fois sur 403 XSRF (cookie pas encore posé suite à
            // un prepare() qui a planté avant la ligne xsrf_token, ou
            // expiration). On rafraîchit le cookie puis on re-poste.
            if (!result.ok && result.status === 403) {
                var refreshed = await refreshXsrfCookie();
                if (refreshed) {
                    result = await postReport(payload);
                }
            }
            submitting = false;
            setSubmitting(false);

            var success = !!(result.ok && result.data && result.data.ok);
            var serverMsg;
            if (success) {
                serverMsg = (result.data && result.data.message) || 'Merci, votre signalement a été envoyé.';
                showInternalToast(serverMsg, 'success');
                closeModal();
                hideBanner();
                markDismissed();
            } else if (result.aborted) {
                showInternalToast('L\'envoi a expiré (réseau lent ?). Réessayez.', 'error');
            } else if (result.status === 403) {
                showInternalToast('Session expirée. Rechargez la page puis réessayez.', 'error');
            } else if (result.status === 0) {
                showInternalToast('Impossible de joindre le serveur.', 'error');
            } else {
                serverMsg = (result.data && result.data.message)
                    || ('Échec de l\'envoi (HTTP ' + result.status + ').');
                showInternalToast(serverMsg, 'error');
            }
        }

        btnCancel.addEventListener('click', closeModal);
        btnSend.addEventListener('click', submit);
        overlay.addEventListener('click', function(ev) { if (ev.target === overlay) closeModal(); });

        return {
            element: overlay,
            textarea: textarea,
            counter: counter,
            attachCheckbox: attachCheckbox,
            open: function(prefill) {
                lastFocusedBeforeOpen = document.activeElement;
                overlay.classList.add('komptia-fb-overlay--open');
                overlay.setAttribute('aria-hidden', 'false');
                try { document.body.style.overflow = 'hidden'; } catch (_) {}
                textarea.value = prefill || '';
                counter.textContent = textarea.value.length + ' / ' + MESSAGE_MAX;
                attachCheckbox.checked = true;
                submitting = false;
                setSubmitting(false);
                document.addEventListener('keydown', onEscape);
                document.addEventListener('keydown', trapFocus, true);
                setTimeout(function() { textarea.focus(); }, 50);
            }
        };
    }
    function ensureModal() {
        if (modalRef) return modalRef;
        modalRef = buildModal();
        document.body.appendChild(modalRef.element);
        return modalRef;
    }

    // ── Banner réactif ─────────────────────────────────────────────────
    function buildBanner() {
        var wrap = document.createElement('div');
        wrap.className = 'komptia-fb-banner';
        wrap.setAttribute('role', 'alert');
        wrap.setAttribute('aria-live', 'polite');
        wrap.setAttribute('aria-hidden', 'true');

        var icon = document.createElement('div');
        icon.className = 'komptia-fb-banner__icon';
        icon.setAttribute('aria-hidden', 'true');
        icon.innerHTML = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' +
            '<circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>' +
            '</svg>';

        var text = document.createElement('div');
        text.className = 'komptia-fb-banner__text';
        var title = document.createElement('strong');
        title.textContent = 'Un problème technique est survenu';
        var desc = document.createElement('span');
        desc.className = 'komptia-fb-banner__desc';
        desc.textContent = 'Voulez-vous le signaler à l\'équipe support ?';
        text.appendChild(title);
        text.appendChild(document.createElement('br'));
        text.appendChild(desc);

        var actions = document.createElement('div');
        actions.className = 'komptia-fb-banner__actions';
        var btnReport = document.createElement('button');
        btnReport.type = 'button';
        btnReport.className = 'komptia-fb-btn komptia-fb-btn--primary';
        btnReport.textContent = 'Signaler';
        var btnDismiss = document.createElement('button');
        btnDismiss.type = 'button';
        btnDismiss.className = 'komptia-fb-btn komptia-fb-btn--ghost';
        btnDismiss.setAttribute('aria-label', 'Ignorer');
        btnDismiss.textContent = 'Ignorer';
        actions.appendChild(btnDismiss);
        actions.appendChild(btnReport);

        wrap.appendChild(icon);
        wrap.appendChild(text);
        wrap.appendChild(actions);

        btnReport.addEventListener('click', function() {
            hideBanner();
            ensureModal().open();
        });
        btnDismiss.addEventListener('click', function() {
            hideBanner();
            markDismissed();
        });

        return { element: wrap, descEl: desc };
    }
    function ensureBanner() {
        if (bannerRef) return bannerRef;
        bannerRef = buildBanner();
        document.body.appendChild(bannerRef.element);
        return bannerRef;
    }
    function hideBanner() {
        if (!bannerRef) return;
        bannerRef.element.classList.remove('komptia-fb-banner--open');
        bannerRef.element.setAttribute('aria-hidden', 'true');
        window[SHOWN_FLAG] = false;
    }
    function offerReport(reason) {
        if (isBootGrace()) return;
        if (isDismissed()) return;
        // Conserve l'historique pour pouvoir afficher la PLUS RÉCENTE
        // raison même si banner déjà ouvert (sinon on resterait coincé
        // sur le 1er warning bénin de tiers — Plotly deprecated, etc.).
        if (typeof reason === 'string') {
            lastReasons.push(reason);
            if (lastReasons.length > 10) lastReasons.shift();
        }
        if (modalRef && modalRef.element.classList.contains('komptia-fb-overlay--open')) return;
        var banner = ensureBanner();
        var displayReason = sanitizeForBanner(reason || '');
        if (displayReason && displayReason.length < REASON_MAX_LEN) {
            banner.descEl.textContent = displayReason + ' — voulez-vous le signaler ?';
        } else {
            banner.descEl.textContent = 'Voulez-vous le signaler à l\'équipe support ?';
        }
        if (window[SHOWN_FLAG]) return;  // déjà visible : on a juste mis à jour le texte
        window[SHOWN_FLAG] = true;
        banner.element.classList.add('komptia-fb-banner--open');
        banner.element.setAttribute('aria-hidden', 'false');
    }

    // ── API publique (figée pour empêcher l'override par script tiers) ─
    var publicReportFeedback = function(opts) {
        var modal = ensureModal();
        // Guard « déjà ouvert » : ne PAS réinitialiser le textarea si l'overlay
        // est déjà ouvert — sinon un 2ᵉ appel (auto-Signaler sur 5xx répété,
        // re-clic, retry d'une action en échec) écraserait la saisie en cours.
        // Miroir du guard du banner (``komptia-fb-overlay--open``).
        if (modal.element.classList.contains('komptia-fb-overlay--open')) return;
        var prefill = (opts && typeof opts.message === 'string') ? opts.message : '';
        modal.open(prefill);
    };
    try {
        Object.defineProperty(window, 'komptiaReportFeedback', {
            value: publicReportFeedback,
            writable: false,
            configurable: false,
            enumerable: false,
        });
    } catch (e) {
        // Vieux navigateur ou déjà défini : fallback en assignation simple.
        window.komptiaReportFeedback = publicReportFeedback;
    }

    // ── komptiaReportError : helper de centralisation pour la taxonomie ───
    // 4-cas Komptia (cf. mémoire ``feedback_error_taxonomy_4cases``).
    //
    // Bug 2026-05-26 (P-12+DA-M9 MOYEN) : avant ce helper, chaque page
    // dupliquait la logique de message d'erreur par code HTTP (ai_training,
    // settings, login, /admin, etc.). Drift garanti dès qu'une nouvelle
    // taxonomie est ajoutée.
    //
    // API : ``komptiaReportError(err, opts)``
    //   - ``err`` : peut être une Response ``fetch`` (avec ``.status``), un
    //     ``Error`` JS, ou un objet ``{status, message}``.
    //   - ``opts`` :
    //       - ``context`` (string) : contexte court ("Profil", "Training pair")
    //         — préfixé à tous les messages.
    //       - ``serverMsg`` (string) : message texte du serveur (extrait de
    //         ``await res.json().error``). Utilisé pour 400/422 surtout.
    //       - ``toast`` (function) : optionnel — sinon utilise ``showToast``.
    //
    // Le helper choisit le message FR en fonction de ``err.status`` (cas a/b/c/d)
    // et propose un bouton ``Signaler`` (5xx, et offline éventuel). Le caller
    // n'a plus qu'à passer son Response.
    var publicReportError = function (err, opts) {
        opts = opts || {};
        var ctx = opts.context ? (opts.context + ' : ') : '';
        var serverMsg = opts.serverMsg || '';
        var status = (err && typeof err.status === 'number') ? err.status : 0;
        var msg, openSignal = false;

        if (status === 0 || (err instanceof Error && /network|fetch/i.test(err.message || ''))) {
            // Cas (d) — réseau frontend
            msg = ctx + 'Erreur réseau. Vérifiez votre connexion puis réessayez.';
        } else if (status >= 500) {
            // Cas (c) — 5xx, propose Signaler
            msg = ctx + 'Une erreur est survenue. Cliquez sur « Signaler » pour la transmettre.';
            openSignal = true;
        } else if (status === 401 || status === 403) {
            msg = ctx + 'Vous n\'êtes pas autorisé. Reconnectez-vous éventuellement.';
        } else if (status === 404) {
            msg = ctx + (serverMsg || 'Ressource introuvable.');
        } else if (status === 409) {
            msg = ctx + (serverMsg || 'Conflit : ressource modifiée entre temps.');
        } else if (status === 429) {
            msg = ctx + (serverMsg || 'Trop de requêtes. Attendez quelques secondes.');
        } else if (status === 400 || status === 422) {
            msg = ctx + (serverMsg || 'Données invalides. Vérifiez le formulaire.');
        } else if (status >= 400) {
            msg = ctx + (serverMsg || ('Erreur (code ' + status + ').'));
        } else {
            // Cas (a) — métier prévue (non-HTTP)
            msg = ctx + (serverMsg || (err && err.message) || 'Une erreur est survenue.');
        }

        var toastFn = (typeof opts.toast === 'function')
            ? opts.toast
            : (typeof window.showToast === 'function' ? window.showToast : null);
        if (toastFn) toastFn(msg, 'error');

        if (openSignal) {
            // Petit délai : laisse le toast s'afficher avant l'overlay.
            setTimeout(function () {
                try {
                    publicReportFeedback({
                        message: 'Erreur ' + (status || '?') + ' — ' + (opts.context || '')
                            + (serverMsg ? ('\nDétail serveur : ' + serverMsg) : ''),
                    });
                } catch (e) { /* defensive */ }
            }, 400);
        }
        return msg;
    };
    try {
        Object.defineProperty(window, 'komptiaReportError', {
            value: publicReportError,
            writable: false,
            configurable: false,
            enumerable: false,
        });
    } catch (e) {
        window.komptiaReportError = publicReportError;
    }
})();
