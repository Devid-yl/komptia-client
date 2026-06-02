/* Komptia — Paramètres
 * Onglets Profil / Apparence, formulaires (profil, mot de passe) et sélecteur
 * de thème. Toutes les interactions passent par addEventListener (CSP stricte).
 *
 * Dépend de base.html :
 *   - getCookie(name)
 *   - showToast(msg, type)
 */
(function () {
    'use strict';

    // Clé localStorage SCOPÉE par user-id (anti cross-user leak — bug
    // 2026-05-26 S-2 + mémoire ``feedback_localstorage_cross_user_leak.md``).
    // ``window.komptiaThemeStorageKey`` est exposé par le bootstrap de
    // ``base.html`` → strict alignement entre les 2 sites d'écriture (boot
    // + settings.js). Fallback 'komptia_theme_anon' si le bootstrap n'a pas
    // tourné (test unitaire qui charge settings.js seul).
    var THEME_STORAGE_KEY = (typeof window !== 'undefined' && window.komptiaThemeStorageKey)
        || 'komptia_theme_anon';
    var VALID_THEMES = { light: 1, dark: 1, system: 1 };
    var themePutController = null;  // AbortController pour annuler la PUT en vol
    var irisConsentPutController = null;  // idem pour la pref consentement Iris
    var mqListenerAttached = false; // prefers-color-scheme attaché une seule fois

    // ── Utilitaires ────────────────────────────────────────────────────

    function xsrfHeader() {
        var t = (typeof getCookie === 'function') ? getCookie('_xsrf') : '';
        return t ? { 'X-Xsrftoken': t } : {};
    }

    function fetchJson(url, opts) {
        opts = opts || {};
        var headers = Object.assign(
            { 'Content-Type': 'application/json' },
            xsrfHeader(),
            opts.headers || {}
        );
        var init = {
            method: opts.method || 'GET',
            headers: headers,
            credentials: 'same-origin',
            body: opts.body != null ? opts.body : undefined,
        };
        if (opts.signal) init.signal = opts.signal;
        return fetch(url, init).then(function (r) {
            return r.json().then(function (data) {
                return { ok: r.ok, status: r.status, data: data || {} };
            }).catch(function () {
                return { ok: r.ok, status: r.status, data: {} };
            });
        });
    }

    function handleAuthError(res) {
        if (res.status === 401) {
            window.location.href = '/login';
            return true;
        }
        return false;
    }

    function errorMessage(res, fallback) {
        var d = res.data || {};
        return d.message || d.error || fallback || 'Erreur inattendue';
    }

    // Bug 2026-05-26 (Agent 1 brainstorm S-10) : normalise les erreurs
    // réseau (catch) en message FR uniforme. ``fetch`` peut lever des
    // messages locale-dépendants en EN ("Failed to fetch" Chrome,
    // "Load failed" Safari, "NetworkError" Firefox) — leak côté UI =
    // axe 5 erreur taxonomie violée. Distingue offline (cas d) vs
    // autre (4/5xx déjà géré par ``errorMessage(res)``).
    function networkErrorMessage(err, fallback) {
        if (err && (err.name === 'AbortError' || err.code === 20)) return null;
        if (typeof navigator !== 'undefined' && navigator.onLine === false) {
            return 'Hors-ligne. Reconnecte-toi pour réessayer.';
        }
        return fallback || 'Erreur réseau. Réessaye dans un instant.';
    }

    function formatDate(iso) {
        // Single source of truth : window.KomptiaFormat.dateTimeFr (format-helpers.js).
        if (!iso) return '—';
        return window.KomptiaFormat.dateTimeFr(iso);
    }

    function toastOk(msg) {
        if (typeof showToast === 'function') showToast(msg, 'success');
    }
    function toastErr(msg) {
        if (typeof showToast === 'function') showToast(msg, 'error');
    }

    // ── Profil ─────────────────────────────────────────────────────────

    function fillProfile(data) {
        var d = data || {};
        var set = function (id, val) {
            var el = document.getElementById(id);
            if (el) {
                if ('value' in el && el.tagName === 'INPUT') el.value = val || '';
                else el.textContent = val || '—';
            }
        };
        set('pf-display-name', d.display_name || '');
        set('pf-email', d.email || '');
        set('pf-username', d.username || '—');
        set('pf-role', d.role || '—');
        set('pf-last-login', formatDate(d.last_login));
    }

    function loadProfile() {
        return fetchJson('/api/settings/profile').then(function (res) {
            if (handleAuthError(res)) return;
            if (!res.ok) {
                toastErr(errorMessage(res, 'Impossible de charger le profil'));
                return;
            }
            fillProfile(res.data);
        });
    }

    function wireProfileForm() {
        var form = document.getElementById('form-profile');
        if (!form) return;
        var msg = document.getElementById('pf-msg');
        var submit = document.getElementById('pf-submit');

        form.addEventListener('submit', function (e) {
            e.preventDefault();
            if (msg) msg.textContent = 'Enregistrement…';
            if (submit) submit.disabled = true;

            var payload = {
                display_name: (document.getElementById('pf-display-name') || {}).value || '',
                email: ((document.getElementById('pf-email') || {}).value || '').trim(),
            };

            fetchJson('/api/settings/profile', {
                method: 'PUT',
                body: JSON.stringify(payload),
            }).then(function (res) {
                if (submit) submit.disabled = false;
                if (handleAuthError(res)) return;
                if (!res.ok) {
                    var m = errorMessage(res, 'Impossible de mettre à jour le profil');
                    if (msg) msg.textContent = m;
                    toastErr(m);
                    return;
                }
                fillProfile(res.data);
                if (msg) msg.textContent = 'Modifications enregistrées';
                toastOk('Profil mis à jour');
            }).catch(function (err) {
                // Bug 2026-05-26 (S-5+L-3) : message FR uniforme via helper
                // (gère offline, AbortError, autres). Évite ``Erreur réseau``
                // brut qui ne mentionne pas l'état offline.
                if (submit) submit.disabled = false;
                var m = networkErrorMessage(err, 'Erreur réseau. Réessaye dans un instant.');
                if (m) {
                    if (msg) msg.textContent = m;
                    toastErr(m);
                }
            });
        });
    }

    // ── Mot de passe ───────────────────────────────────────────────────

    function wirePasswordForm() {
        var form = document.getElementById('form-password');
        if (!form) return;
        var msg = document.getElementById('pw-msg');
        var submit = document.getElementById('pw-submit');
        var cur = document.getElementById('pw-current');
        var neu = document.getElementById('pw-new');
        var cfm = document.getElementById('pw-confirm');

        form.addEventListener('submit', function (e) {
            e.preventDefault();
            if (!cur || !neu || !cfm) return;

            if (neu.value.length < 8) {
                if (msg) msg.textContent = 'Minimum 8 caractères';
                neu.focus();
                return;
            }
            if (neu.value !== cfm.value) {
                if (msg) msg.textContent = 'Les mots de passe ne correspondent pas';
                cfm.focus();
                return;
            }
            if (cur.value === neu.value) {
                if (msg) msg.textContent = 'Le nouveau doit être différent de l\'actuel';
                neu.focus();
                return;
            }

            if (msg) msg.textContent = 'Mise à jour…';
            if (submit) submit.disabled = true;

            fetchJson('/api/settings/password', {
                method: 'PUT',
                body: JSON.stringify({
                    current_password: cur.value,
                    new_password: neu.value,
                }),
            }).then(function (res) {
                if (submit) submit.disabled = false;
                if (handleAuthError(res)) return;
                if (!res.ok) {
                    var m = errorMessage(res, 'Impossible de changer le mot de passe');
                    if (msg) msg.textContent = m;
                    toastErr(m);
                    return;
                }
                cur.value = '';
                neu.value = '';
                cfm.value = '';
                var revoked = (res.data && res.data.sessions_revoked) || 0;
                var suffix = revoked > 0 ? ' • ' + revoked + ' autre(s) session(s) déconnectée(s)' : '';
                if (msg) msg.textContent = 'Mot de passe mis à jour' + suffix;
                toastOk('Mot de passe mis à jour');
            }).catch(function (err) {
                // Bug 2026-05-26 (S-5+L-3) : helper FR uniforme + détection offline.
                if (submit) submit.disabled = false;
                var m = networkErrorMessage(err, 'Erreur réseau. Réessaye dans un instant.');
                if (m) {
                    if (msg) msg.textContent = m;
                    toastErr(m);
                }
            });
        });
    }

    // ── Apparence ──────────────────────────────────────────────────────

    function resolveEffectiveDark(mode) {
        if (mode === 'dark') return true;
        if (mode === 'light') return false;
        // system
        try {
            return !!(window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches);
        } catch (e) {
            return false;
        }
    }

    function applyThemeToDocument(mode) {
        // Délègue à l'API globale définie dans base.html (listener OS global,
        // broadcast `komptia:themechange`). Fallback si absente.
        if (typeof window.komptiaSetTheme === 'function') {
            window.komptiaSetTheme(mode);
            return;
        }
        var dark = resolveEffectiveDark(mode);
        document.documentElement.classList.toggle('dark', dark);
    }

    function persistThemeLocal(mode) {
        try { localStorage.setItem(THEME_STORAGE_KEY, mode); } catch (e) { /* ignore */ }
    }

    function updateThemeOptionsUi(mode) {
        var opts = document.querySelectorAll('.theme-option');
        opts.forEach(function (opt) {
            var active = opt.getAttribute('data-theme') === mode;
            var check = opt.querySelector('.theme-check');
            if (check) check.classList.toggle('hidden', !active);
            var input = opt.querySelector('input[type=radio]');
            if (input) input.checked = active;
            opt.classList.toggle('border-brand-500', active);
            opt.classList.toggle('ring-2', active);
            opt.classList.toggle('ring-brand-500/30', active);
            opt.classList.toggle('border-gray-200', !active);
            opt.classList.toggle('dark:border-gray-700', !active);
            opt.classList.toggle('hover:border-gray-300', !active);
            opt.classList.toggle('dark:hover:border-gray-600', !active);
        });
    }

    function selectTheme(mode, persistRemote) {
        if (!VALID_THEMES[mode]) mode = 'system';
        updateThemeOptionsUi(mode);
        persistThemeLocal(mode);
        applyThemeToDocument(mode);

        var msg = document.getElementById('ap-msg');
        if (!persistRemote) return;

        // Annule la PUT en vol précédente : seul le dernier clic est persisté
        // côté serveur, évitant une divergence DB/localStorage sur clics rapides.
        if (themePutController && typeof themePutController.abort === 'function') {
            try { themePutController.abort(); } catch (e) { /* ignore */ }
        }
        var controller = null;
        try { controller = new AbortController(); } catch (e) { controller = null; }
        themePutController = controller;

        if (msg) msg.textContent = 'Enregistrement…';
        fetchJson('/api/settings/appearance', {
            method: 'PUT',
            body: JSON.stringify({ theme_mode: mode }),
            signal: controller ? controller.signal : undefined,
        }).then(function (res) {
            if (themePutController === controller) themePutController = null;
            if (handleAuthError(res)) return;
            if (!res.ok) {
                var m = errorMessage(res, 'Impossible de changer le thème');
                if (msg) msg.textContent = m;
                toastErr(m);
                return;
            }
            if (msg) msg.textContent = 'Préférence enregistrée';
        }).catch(function (err) {
            if (themePutController === controller) themePutController = null;
            // Ignorer les abort (déclenchés par nous-même)
            if (err && (err.name === 'AbortError' || err.code === 20)) return;
            if (msg) msg.textContent = 'Erreur réseau — préférence sauvegardée localement';
        });
    }

    function attachSystemThemeListenerOnce() {
        // Ne rien faire : le listener global vit désormais dans base.html.
        // Fonction gardée pour compatibilité (init() l'appelle encore).
    }

    function wireAppearance() {
        var opts = document.querySelectorAll('.theme-option');
        opts.forEach(function (opt) {
            opt.addEventListener('click', function (e) {
                e.preventDefault();
                var mode = opt.getAttribute('data-theme');
                selectTheme(mode, true);
            });
        });
    }

    function loadAppearance() {
        return fetchJson('/api/settings/appearance').then(function (res) {
            if (handleAuthError(res)) return;
            var mode = 'system';
            if (res.ok && res.data && VALID_THEMES[res.data.theme_mode]) {
                mode = res.data.theme_mode;
            } else if (res.status === 401 || res.status === 403) {
                // Bug 2026-05-26 (S-7) : sur 401/403, NE PAS lire localStorage.
                // Une erreur d'auth signifie qu'on n'a pas le droit d'utiliser
                // la pref de cet user (session expirée, bascule de user) → on
                // laisse le bootstrap base.html / prefers-color-scheme trancher.
                // Continue sans modifier le DOM : selectTheme(mode='system', false)
                // ci-dessous ferait un toggle visible inutile. Le 401 est déjà
                // géré par handleAuthError (redirect /login).
                return;
            } else {
                // fallback localStorage SCOPÉ (clé komptia_theme_u<id> — pas
                // de cross-user leak parce qu'écrit/lu uniquement par le même
                // user). Cas typique : API 5xx transitoire, pas d'erreur auth.
                try {
                    var stored = localStorage.getItem(THEME_STORAGE_KEY);
                    if (VALID_THEMES[stored]) mode = stored;
                } catch (e) { /* ignore */ }
            }
            // Sync: applique + met à jour l'UI, mais SANS re-POST (persistRemote=false)
            selectTheme(mode, false);
        });
    }

    // ── Bootstrap ──────────────────────────────────────────────────────

    function init() {
        attachSystemThemeListenerOnce();
        wireProfileForm();
        wirePasswordForm();
        wireAppearance();
        wireCompanyForm();
        wireIrisConsent();
        loadProfile();
        loadAppearance();
        loadCompany();
        loadIrisConsent();
    }

    // ── Confidentialité Iris : pref de consentement lecture résultats SQL ─

    var _IRIS_CONSENT_VALUES = ['ask', 'always_allow', 'always_show_panel'];

    // Source de vérité côté client de la pref PERSISTÉE en BDD. Mise à
    // jour UNIQUEMENT quand le serveur a confirmé le write (200). Sert
    // de référence pour revert l'UI sur échec optimistic (cf.
    // ``wireIrisConsent``). ``'ask'`` par défaut tant que ``loadIrisConsent``
    // n'a pas répondu — cohérent avec le défaut backend.
    var _persistedIrisConsent = 'ask';

    function _updateIrisConsentSelection(value) {
        var inputs = document.querySelectorAll(
            '#iris-consent-options input[name="iris_data_read_consent"]'
        );
        for (var i = 0; i < inputs.length; i++) {
            inputs[i].checked = inputs[i].value === value;
        }
        // Mise à jour visuelle des cards (border accent sur la sélection).
        var labels = document.querySelectorAll('#iris-consent-options .iris-consent-option');
        for (var j = 0; j < labels.length; j++) {
            var isSel = labels[j].getAttribute('data-value') === value;
            labels[j].classList.toggle('border-brand-600', isSel);
            labels[j].classList.toggle('bg-brand-50', isSel);
            labels[j].classList.toggle('dark:bg-brand-900/20', isSel);
            labels[j].classList.toggle('border-gray-200', !isSel);
            labels[j].classList.toggle('dark:border-gray-800', !isSel);
        }
    }

    function loadIrisConsent() {
        var container = document.getElementById('iris-consent-options');
        if (!container) return;
        var msg = document.getElementById('iris-consent-msg');
        return fetchJson('/api/settings/iris-consent').then(function (res) {
            if (handleAuthError(res)) return;
            // ``fetchJson`` enveloppe la réponse dans ``{ok, status, data}``.
            // La valeur métier est dans ``res.data`` — toute lecture
            // directe sur ``res`` retournerait ``undefined`` → fallback
            // ``'ask'`` → l'UI affichait « Demander à chaque nouvelle
            // conversation » quelle que soit la valeur en BDD. Bug
            // 2026-05-22 : régression vs le pattern utilisé par
            // ``loadAppearance`` et ``wireProfileForm``. Verrouillé par
            // ``tests/unit/test_iris_consent_settings_wire.py``.
            if (!res.ok || !res.data) {
                // Taxonomie 4-cas Komptia (axe 5).
                var m;
                if (res.status >= 500) {
                    m = 'Erreur serveur lors du chargement de la préférence.';
                } else if (res.status === 429) {
                    m = 'Trop de requêtes. Réessaie dans un instant.';
                } else {
                    m = errorMessage(res, 'Impossible de charger la préférence.');
                }
                if (msg) msg.textContent = m;
                return;
            }
            var value = res.data.iris_data_read_consent;
            if (_IRIS_CONSENT_VALUES.indexOf(value) === -1) value = 'ask';
            // ``_persistedIrisConsent`` = SSoT côté client de la valeur
            // confirmée par le serveur. Sert de référence pour revert
            // sur échec optimistic dans ``wireIrisConsent``.
            _persistedIrisConsent = value;
            _updateIrisConsentSelection(value);
            if (msg) msg.textContent = '';
        }).catch(function () {
            if (msg) msg.textContent = 'Impossible de charger la préférence.';
        });
    }

    function wireIrisConsent() {
        var container = document.getElementById('iris-consent-options');
        if (!container) return;
        var msg = document.getElementById('iris-consent-msg');
        // ``previousValue`` = valeur PERSISTÉE (=BDD) au dernier check.
        // Mise à jour à la fin d'un PUT réussi UNIQUEMENT. Sert de
        // référence pour les revert optimistic. Initialisée par
        // ``loadIrisConsent`` ci-après via ``_persistedIrisConsent``.
        container.addEventListener('change', function (e) {
            var target = e.target;
            if (!target || target.name !== 'iris_data_read_consent') return;
            var value = target.value;
            if (_IRIS_CONSENT_VALUES.indexOf(value) === -1) return;

            // Snapshot AVANT optimistic update. On lit la valeur courante
            // de l'UI (= valeur PUT-confirmée à la dernière réussite, ou
            // valeur initiale chargée). Adversarial review BLOCKING #3 :
            // les anciennes versions cherchaient un input ``checked !==
            // value`` ce qui retournait ``null`` quand l'user cliquait
            // sur l'option déjà sélectionnée OU sur sa propre re-sélection
            // entre deux events ``change`` rapides — le revert sur échec
            // était alors silencieusement skippé, masquant la divergence
            // BDD/UI. On capture désormais la valeur persistée stockée
            // explicitement, jamais ``null``.
            var previousValue = _persistedIrisConsent || 'ask';

            _updateIrisConsentSelection(value);
            if (msg) msg.textContent = 'Enregistrement…';

            // ``AbortController`` annule la PUT en vol précédente — un
            // clic rapide ``ask → always_allow → always_show_panel`` ne
            // doit persister QUE la dernière intention. Sinon, deux PUT
            // concurrents finissent dans un ordre arbitraire et la BDD
            // ne reflète pas le dernier clic. Adversarial BLOCKING #1.
            if (irisConsentPutController && typeof irisConsentPutController.abort === 'function') {
                try { irisConsentPutController.abort(); } catch (e) { /* ignore */ }
            }
            var controller = null;
            try { controller = new AbortController(); } catch (e) { controller = null; }
            irisConsentPutController = controller;

            fetchJson('/api/settings/iris-consent', {
                method: 'PUT',
                body: JSON.stringify({ iris_data_read_consent: value }),
                signal: controller ? controller.signal : undefined,
            }).then(function (res) {
                if (irisConsentPutController === controller) irisConsentPutController = null;
                if (handleAuthError(res)) return;
                if (!res.ok) {
                    // Toujours revert sur ``previousValue`` (jamais
                    // conditionnel — cf. BLOCKING #3).
                    _updateIrisConsentSelection(previousValue);
                    // Taxonomie 4-cas Komptia (axe 5) : différencier
                    // 4xx retry vs 5xx incident pour donner à l'user
                    // une action pertinente. Le bouton « Signaler »
                    // (feedback-reporter.js) est exposé hors de cette
                    // surface ; ici on se contente du libellé clair.
                    var m;
                    if (res.status >= 500) {
                        m = 'Erreur serveur. Réessaie dans un instant ou clique sur « Signaler » en bas de page.';
                    } else if (res.status === 429) {
                        m = errorMessage(res, 'Trop de modifications rapprochées. Patiente quelques secondes.');
                    } else {
                        m = errorMessage(res, 'Échec de l\'enregistrement.');
                    }
                    if (msg) msg.textContent = m;
                    toastErr(m);
                    return;
                }
                _persistedIrisConsent = value;
                if (msg) msg.textContent = 'Enregistré.';
            }).catch(function (err) {
                if (irisConsentPutController === controller) irisConsentPutController = null;
                // ``AbortError`` = annulation volontaire par un clic suivant.
                // Ne PAS revert l'UI ni afficher d'erreur — le clic suivant
                // a déjà mis à jour l'état attendu.
                if (err && (err.name === 'AbortError' || err.code === 20)) return;
                _updateIrisConsentSelection(previousValue);
                var offlineMsg = (navigator && navigator.onLine === false)
                    ? 'Hors-ligne. Reconnecte-toi pour enregistrer.'
                    : 'Erreur réseau.';
                if (msg) msg.textContent = offlineMsg;
                toastErr(offlineMsg);
            });
        });
    }

    // ── Mon entreprise (admin only — section absente du DOM si non-admin)

    function loadCompany() {
        var form = document.getElementById('form-company');
        if (!form) return; // Section absente (user non-admin)
        var input = document.getElementById('cp-company-name');
        var msg = document.getElementById('cp-msg');
        fetchJson('/api/settings/company').then(function (res) {
            if (handleAuthError(res)) return;
            if (!res.ok) {
                if (msg) msg.textContent = errorMessage(res, 'Impossible de charger.');
                return;
            }
            var d = res.data || {};
            if (input) {
                input.value = (typeof d.company_name === 'string') ? d.company_name : '';
                if (typeof d.placeholder === 'string' && d.placeholder) {
                    input.placeholder = d.placeholder;
                }
            }
        }).catch(function () {
            if (msg) msg.textContent = 'Impossible de charger.';
        });
    }

    function wireCompanyForm() {
        var form = document.getElementById('form-company');
        if (!form) return; // Section absente (user non-admin)
        var input = document.getElementById('cp-company-name');
        var btn = document.getElementById('cp-submit');
        var msg = document.getElementById('cp-msg');
        form.addEventListener('submit', function (e) {
            e.preventDefault();
            if (btn) btn.disabled = true;
            if (msg) msg.textContent = 'Enregistrement…';
            fetchJson('/api/settings/company', {
                method: 'PUT',
                body: JSON.stringify({ company_name: (input && input.value) || '' }),
            }).then(function (res) {
                if (handleAuthError(res)) return;
                if (!res.ok) {
                    if (msg) msg.textContent = errorMessage(res, 'Échec.');
                    return;
                }
                if (msg) msg.textContent = 'Enregistré.';
                var d = res.data || {};
                if (input && typeof d.company_name === 'string') {
                    input.value = d.company_name;
                }
            }).catch(function (err) {
                // Bug 2026-05-26 (S-10) : message FR uniforme via helper —
                // évite la fuite ``Failed to fetch`` (Chrome) / ``Load failed``
                // (Safari) en EN. AbortError → null → on ne modifie pas le
                // message (l'utilisateur a annulé).
                var m = networkErrorMessage(err, 'Échec. Réessaye dans un instant.');
                if (m && msg) msg.textContent = m;
            }).finally(function () {
                if (btn) btn.disabled = false;
            });
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
