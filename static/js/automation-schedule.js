/**
 * Automation Schedule modal — pilote la planification d'UNE automation.
 *
 * Stack :
 *   - 5 modes radio (once / daily / weekly / monthly / cron)
 *   - sections conditionnelles (sr-only inputs + labels stylises CSS)
 *   - preview "5 prochaines executions" en debounce 300 ms via
 *     POST /api/automations/schedule/preview (dry-run, sans side-effect)
 *   - save via PUT /api/automations/:id/schedule (re-schedule live si actif)
 *   - heures stockees en TZ serveur (dynamique), affichees en TZ
 *     navigateur via window.LocalDatetime.formatLocal
 *
 * Securite :
 *   - XSRF header `X-Xsrftoken` sur toutes les requetes mutantes
 *     (PUT/POST). Helper getCookie defini dans base.html.
 *   - Pas d'innerHTML avec donnees serveur — uniquement textContent /
 *     createElement / Date.toLocaleString.
 *   - OverlayManager.open avec layer:'modal' + lockScroll + trapFocus
 *     pour la coordination z-index/Esc/Tab cross-overlays Komptia.
 *
 * Hook URL : la liste /automations propose un lien direct
 *   /automations/:id/edit#schedule qui ouvre auto la modal au mount.
 */
(function () {
    'use strict';

    // ── Constantes ───────────────────────────────────────────────
    const VALID_MODES = ['once', 'daily', 'weekly', 'monthly', 'cron'];
    const PREVIEW_DEBOUNCE_MS = 300;
    const DOW_LABELS_FR = {
        mon: 'Lundi', tue: 'Mardi', wed: 'Mercredi', thu: 'Jeudi',
        fri: 'Vendredi', sat: 'Samedi', sun: 'Dimanche',
    };

    // ── DOM refs (peuplees au DOMContentLoaded) ────────────────
    let modal = null;
    let openBtn = null;
    let closeBtn = null;
    let cancelBtn = null;
    let saveBtn = null;
    let summarySpan = null;
    let cronError = null;
    let previewList = null;
    let previewLoading = null;

    let _previewTimer = null;
    let _automationId = null;
    // A7-M6 — version optimistic-concurrency lue au GET et renvoyée en If-Match
    // au PUT (anti-overwrite silencieux multi-onglets). null = pas encore chargée.
    let _scheduleVersion = null;

    // ── Helpers ──────────────────────────────────────────────────

    function _xsrfHeader() {
        // getCookie est defini dans base.html (template global). Si absent
        // (page hors layout normal), on tente document.cookie en fallback.
        if (typeof window.getCookie === 'function') {
            return { 'X-Xsrftoken': window.getCookie('_xsrf') || '' };
        }
        const m = document.cookie.match(/(?:^|;\s*)_xsrf=([^;]+)/);
        return { 'X-Xsrftoken': m ? decodeURIComponent(m[1]) : '' };
    }

    /** S-03 fix : Komptia a 2 formats de reponse d'erreur dans la codebase :
     *   - Custom (handlers metier) : `{success: false, error: "msg"}`
     *   - write_error global       : `{error: true, status, message, request_id}`
     * On lit les deux formats pour que les 401/404/429 (qui passent par
     * write_error) affichent un toast lisible au lieu de "true".
     */
    function _extractErrorMsg(data, fallback) {
        if (data && typeof data.error === 'string' && data.error.trim()) {
            return data.error;
        }
        if (data && typeof data.message === 'string' && data.message.trim()) {
            return data.message;
        }
        return fallback || 'Erreur inconnue';
    }

    function _getMode() {
        const r = document.querySelector('input[name="schedule-mode"]:checked');
        return r ? r.value : 'daily';
    }

    function _setMode(mode) {
        const r = document.querySelector(`input[name="schedule-mode"][value="${mode}"]`);
        if (r) r.checked = true;
        // Toggle visibility des sections
        document.querySelectorAll('.schedule-section').forEach(function (sec) {
            sec.hidden = sec.dataset.mode !== mode;
        });
    }

    /** Convertit datetime ISO → input value `YYYY-MM-DDTHH:MM` (datetime-local).
     *  Le navigateur n'accepte pas les ISO avec timezone dans datetime-local,
     *  donc on tronque les secondes et la TZ. */
    function _isoToDatetimeLocal(iso) {
        if (!iso) return '';
        try {
            const d = new Date(iso);
            if (isNaN(d.getTime())) return '';
            const pad = (n) => String(n).padStart(2, '0');
            return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
        } catch (e) {
            return '';
        }
    }

    /** "09:00" → {hour: 9, minute: 0}. Defauts safe en cas de string vide. */
    function _parseTimeStr(str) {
        if (!str || typeof str !== 'string') return { hour: 9, minute: 0 };
        const parts = str.split(':');
        const h = parseInt(parts[0], 10);
        const m = parseInt(parts[1], 10);
        return {
            hour: isNaN(h) ? 9 : Math.max(0, Math.min(23, h)),
            minute: isNaN(m) ? 0 : Math.max(0, Math.min(59, m)),
        };
    }

    /** {hour: 9, minute: 0} → "09:00" pour input type="time". */
    function _formatTime(hour, minute) {
        const h = String(hour ?? 9).padStart(2, '0');
        const m = String(minute ?? 0).padStart(2, '0');
        return `${h}:${m}`;
    }

    /** Retourne le payload schedule_config courant selon le mode actif. */
    function _collectPayload() {
        const mode = _getMode();
        const config = {};

        if (mode === 'once') {
            const v = document.getElementById('komptia-sched-once-datetime').value;
            // TZ-2 (#48) — l'input datetime-local retourne "YYYY-MM-DDTHH:MM"
            // (NAÏF, heure NAVIGATEUR). On le convertit en UTC aware avant l'envoi
            // (new Date(local).toISOString()) : l'heure de fire devient l'instant
            // ABSOLU voulu par l'utilisateur, indépendamment du fuseau serveur.
            // AVANT : envoyé naïf → le backend l'interprétait en TZ serveur → fire
            // FAUX silencieux quand navigateur ≠ serveur. Re-affichage symétrique
            // via _isoToDatetimeLocal (UTC → heure navigateur).
            if (v) {
                const d = new Date(v);
                config.run_date = isNaN(d.getTime()) ? v : d.toISOString();
            } else {
                config.run_date = v;
            }
        } else if (mode === 'daily') {
            const t = _parseTimeStr(document.getElementById('komptia-sched-daily-time').value);
            config.hour = t.hour;
            config.minute = t.minute;
        } else if (mode === 'weekly') {
            const days = Array.from(
                document.querySelectorAll('input[name="schedule-dow"]:checked')
            ).map((x) => x.value);
            // S-06 fix : si aucun jour coche, on ne fallback PAS silencieusement
            // sur "mon" (l'ancien comportement laissait croire a l'utilisateur
            // que sa config "rien coche" donnait 5 lundis). On retourne une
            // chaine vide ; le serveur valide et renvoie 400 ; le JS bloque
            // le bouton Save et affiche le message dans la zone preview.
            config.day_of_week = days.join(',');
            const t = _parseTimeStr(document.getElementById('komptia-sched-weekly-time').value);
            config.hour = t.hour;
            config.minute = t.minute;
        } else if (mode === 'monthly') {
            const day = parseInt(
                document.getElementById('komptia-sched-monthly-day').value,
                10
            );
            config.day = isNaN(day) ? 1 : Math.max(1, Math.min(31, day));
            const t = _parseTimeStr(document.getElementById('komptia-sched-monthly-time').value);
            config.hour = t.hour;
            config.minute = t.minute;
        } else if (mode === 'cron') {
            config.cron = document.getElementById('komptia-sched-cron-expr').value || '';
        }

        return { schedule_type: mode, schedule_config: config };
    }

    /** Hydrate le formulaire depuis un payload renvoye par GET schedule. */
    function _populateForm(data) {
        const type = VALID_MODES.includes(data.schedule_type) ? data.schedule_type : 'daily';
        const cfg = data.schedule_config || {};

        _setMode(type);

        // Reset checkboxes weekly (peut-etre cochees par hydratation precedente)
        document.querySelectorAll('input[name="schedule-dow"]').forEach((cb) => {
            cb.checked = false;
        });

        if (type === 'once') {
            document.getElementById('komptia-sched-once-datetime').value =
                _isoToDatetimeLocal(cfg.run_date);
        } else if (type === 'daily') {
            document.getElementById('komptia-sched-daily-time').value =
                _formatTime(cfg.hour, cfg.minute);
        } else if (type === 'weekly') {
            const dow = (cfg.day_of_week || 'mon').toString();
            dow.split(',').forEach((d) => {
                const cb = document.querySelector(
                    `input[name="schedule-dow"][value="${d.trim()}"]`
                );
                if (cb) cb.checked = true;
            });
            document.getElementById('komptia-sched-weekly-time').value =
                _formatTime(cfg.hour, cfg.minute);
        } else if (type === 'monthly') {
            document.getElementById('komptia-sched-monthly-day').value = cfg.day || 1;
            document.getElementById('komptia-sched-monthly-time').value =
                _formatTime(cfg.hour, cfg.minute);
        } else if (type === 'cron') {
            document.getElementById('komptia-sched-cron-expr').value = cfg.cron || '';
        }

        // Mise a jour du badge top-bar (ex: "Daily 09:00")
        _updateSummary(type, cfg, data.is_active);

        // Lancer un preview initial pour montrer "5 prochaines"
        _refreshPreview();
    }

    /** Met a jour le petit badge du bouton "Planification" en top bar. */
    function _updateSummary(type, cfg, isActive) {
        if (!summarySpan) return;
        let label = '';
        if (type === 'once') {
            const dt = cfg.run_date ? new Date(cfg.run_date) : null;
            label = dt && !isNaN(dt.getTime())
                ? dt.toLocaleDateString('fr-FR', { day: '2-digit', month: '2-digit' })
                + ' ' + dt.toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' })
                : 'Une fois';
        } else if (type === 'daily') {
            label = `Quotidien ${_formatTime(cfg.hour, cfg.minute)}`;
        } else if (type === 'weekly') {
            const dow = (cfg.day_of_week || 'mon').split(',')
                .map((d) => DOW_LABELS_FR[d.trim()] || d.trim())
                .map((s) => s.slice(0, 3))
                .join('/');
            label = `${dow} ${_formatTime(cfg.hour, cfg.minute)}`;
        } else if (type === 'monthly') {
            label = `Le ${cfg.day || 1} a ${_formatTime(cfg.hour, cfg.minute)}`;
        } else if (type === 'cron') {
            label = `Cron : ${cfg.cron || ''}`;
        }
        if (!isActive) label = '⏸ ' + label;
        // Le span est un chip stylise (background gris, padding) — pas
        // besoin d'un prefix "· " dans le textContent (pollution visuelle).
        summarySpan.textContent = label;
        summarySpan.classList.remove('hidden');
    }

    /** Render la liste "5 prochaines executions" (TZ navigateur via Date). */
    function _renderPreview(runs, errorMsg) {
        if (!previewList) return;
        // Vider — pas d'innerHTML pour eviter XSS sur error.error remontes.
        while (previewList.firstChild) previewList.removeChild(previewList.firstChild);

        if (errorMsg) {
            const li = document.createElement('li');
            li.className = 'list-none italic text-red-600 dark:text-red-400';
            li.textContent = errorMsg;
            previewList.appendChild(li);
            return;
        }

        if (!runs || !runs.length) {
            const li = document.createElement('li');
            li.className = 'list-none italic text-gray-400 dark:text-gray-500';
            li.textContent = 'Aucune execution prevue avec cette configuration.';
            previewList.appendChild(li);
            return;
        }

        runs.forEach((iso) => {
            const li = document.createElement('li');
            // Format en heure locale via Date — le serveur renvoie ISO aware
            // TZ serveur (dynamique), le navigateur affiche dans la TZ de l'user.
            const d = new Date(iso);
            if (isNaN(d.getTime())) {
                li.textContent = iso;
            } else {
                li.textContent = d.toLocaleString('fr-FR', {
                    weekday: 'short',
                    day: '2-digit',
                    month: '2-digit',
                    year: 'numeric',
                    hour: '2-digit',
                    minute: '2-digit',
                });
            }
            previewList.appendChild(li);
        });
    }

    /** Court-circuit cote JS pour les payloads connus invalides — evite
     * un round-trip serveur inutile et donne un feedback instant a l'user. */
    function _localValidationError(payload) {
        if (payload.schedule_type === 'weekly') {
            const dow = (payload.schedule_config.day_of_week || '').trim();
            if (!dow) return 'Selectionnez au moins un jour de la semaine.';
        }
        if (payload.schedule_type === 'once') {
            if (!payload.schedule_config.run_date) {
                return 'Selectionnez une date et une heure.';
            }
        }
        return null;
    }

    function _setSaveDisabled(disabled) {
        if (saveBtn) saveBtn.disabled = !!disabled;
    }

    /** Appel POST preview avec le payload courant. Debounced. */
    async function _refreshPreview() {
        if (_previewTimer) clearTimeout(_previewTimer);
        _previewTimer = setTimeout(async function () {
            const payload = _collectPayload();

            // S-06 fix : check local avant d'appeler le serveur. Empeche le
            // fallback silencieux et donne un feedback immediat.
            const localErr = _localValidationError(payload);
            if (localErr) {
                _renderPreview(null, localErr);
                _setSaveDisabled(true);
                if (cronError && payload.schedule_type === 'cron') {
                    cronError.textContent = '';
                }
                return;
            }

            if (previewLoading) previewLoading.classList.remove('hidden');
            try {
                const res = await fetch('/api/automations/schedule/preview', {
                    method: 'POST',
                    headers: Object.assign(
                        { 'Content-Type': 'application/json' },
                        _xsrfHeader()
                    ),
                    body: JSON.stringify(payload),
                });
                // Lecture SÛRE : la frappe rapide du cron déclenche des POST
                // en rafale → 429 nginx (HTML) possible ; ne pas planter dessus.
                const _r = await window.komptiaReadJson(res);
                const data = _r.data || {};
                if (!res.ok || !data.success) {
                    const msg = _extractErrorMsg(data, _r.error || 'Configuration invalide.');
                    _renderPreview(null, msg);
                    _setSaveDisabled(true);
                    if (cronError && payload.schedule_type === 'cron') {
                        cronError.textContent = msg;
                    }
                } else {
                    _renderPreview(data.next_runs);
                    _setSaveDisabled(false);
                    if (cronError) cronError.textContent = '';
                }
            } catch (err) {
                _renderPreview(null, 'Reseau indisponible. Reessayez.');
                _setSaveDisabled(true);
            } finally {
                if (previewLoading) previewLoading.classList.add('hidden');
            }
        }, PREVIEW_DEBOUNCE_MS);
    }

    /** Save : PUT vers /api/automations/:id/schedule. */
    async function _save() {
        if (!_automationId) return;
        const payload = _collectPayload();
        saveBtn.disabled = true;
        const original = saveBtn.textContent;
        saveBtn.textContent = 'Enregistrement...';
        try {
            // A7-M6 — If-Match = version lue au GET → le serveur rejette en 409
            // si un autre onglet a sauvé entre temps (anti-overwrite silencieux).
            const _headers = Object.assign(
                { 'Content-Type': 'application/json' },
                _xsrfHeader()
            );
            if (_scheduleVersion != null) {
                _headers['If-Match'] = String(_scheduleVersion);
            }
            const res = await fetch(`/api/automations/${_automationId}/schedule`, {
                method: 'PUT',
                headers: _headers,
                body: JSON.stringify(payload),
            });
            // Lecture SÛRE : ne plante pas sur le HTML d'une erreur passerelle
            // (413/429/502/504). ``res.status``/``res.ok`` restent fiables pour
            // la logique 409/!ok ci-dessous ; ``data`` = JSON parsé ou {}.
            const _r = await window.komptiaReadJson(res);
            const data = _r.data || {};
            // A7-M6 (adversarial #4/#6) — 409 = conflit optimiste (un autre
            // onglet a sauvé entre temps). On NE remplace PAS le formulaire :
            // écraser les edits non sauvés de l'user serait une perte SILENCIEUSE
            // (doctrine anti-données-fausses). On met à jour la version depuis le
            // payload 409 (`current_version`, pas de 2e round-trip GET) et on
            // laisse l'user DÉCIDER : ré-Enregistrer (écrase avec SES valeurs,
            // intent explicite) ou fermer la modal (repartir de la version serveur).
            if (res.status === 409) {
                if (data && typeof data.current_version === 'number') {
                    _scheduleVersion = data.current_version;
                }
                if (typeof window.showToast === 'function') {
                    window.showToast(
                        'Conflit : la planification a été modifiée dans un autre '
                        + 'onglet. Ré-enregistrez pour écraser avec vos valeurs, ou '
                        + 'fermez pour repartir de la version serveur.',
                        'warning'
                    );
                }
                return;
            }
            if (!res.ok || !data.success) {
                // Message actionnable : priorité au message métier serveur,
                // sinon celui dérivé du status par le helper (413/429/5xx).
                const msg = _extractErrorMsg(data, _r.error || 'Erreur lors de la sauvegarde');
                if (typeof window.showToast === 'function') {
                    window.showToast(msg, 'error');
                } else {
                    // Cluster-O 2026-05-26 — fallback console (alert
                    // natif est non-stylable et bloque la page entière).
                    // Si showToast n'est pas chargé, c'est une régression
                    // d'init JS — log mais ne bloque pas l'UX.
                    console.error('[automation-schedule] showToast absent:', msg);
                }
                return;
            }
            // S-02 fix : le serveur signale via `scheduled` + `warning` quand
            // le re-add APScheduler a echoue (BDD ok mais job pas inscrit).
            // On affiche un toast warning au lieu d'un faux succes.
            if (data.scheduled === false && data.warning) {
                if (typeof window.showToast === 'function') {
                    window.showToast(data.warning, 'warning');
                }
            } else if (typeof window.showToast === 'function') {
                window.showToast('Planification enregistree', 'success');
            }
            // A7-M6 (adversarial #3) — le serveur a bumpé la version : on la
            // rafraîchit depuis la réponse PUT pour qu'un éventuel save ultérieur
            // SANS ré-ouverture de la modal n'émette pas un 409 fantôme.
            if (data && typeof data.version === 'number') {
                _scheduleVersion = data.version;
            }
            _updateSummary(data.schedule_type, data.schedule_config, data.is_active);
            _close();
        } catch (err) {
            if (typeof window.showToast === 'function') {
                // P6 (audit 2026-05-26) — Fallback "détail indisponible" si
                // err.message est undefined (sinon "Erreur reseau : undefined"
                // affiché à l'user).
                var _schedDetail = (err && err.message) ? String(err.message) : 'détail indisponible';
                window.showToast('Erreur reseau : ' + _schedDetail, 'error');
            }
        } finally {
            saveBtn.disabled = false;
            saveBtn.textContent = original;
        }
    }

    /** Charge l'etat actuel depuis le serveur et ouvre la modal. */
    async function _open() {
        if (!modal || !_automationId) return;
        try {
            const res = await fetch(`/api/automations/${_automationId}/schedule`, {
                method: 'GET',
                headers: { 'Accept': 'application/json' },
            });
            if (!res.ok) {
                if (typeof window.showToast === 'function') {
                    window.showToast('Impossible de charger la planification', 'error');
                }
                return;
            }
            const data = await res.json();
            _populateForm(data);
            // A7-M6 — capture la version pour le If-Match du prochain PUT.
            _scheduleVersion = (data && typeof data.version === 'number') ? data.version : null;
        } catch (err) {
            // A7-M6b (#61) — NE PAS peupler des defaults trompeurs (daily/inactif)
            // sur erreur réseau/parse : avec ``_scheduleVersion=null`` le PUT
            // partirait SANS ``If-Match`` (rétro-compat = overwrite) et écraserait
            // une config que l'user n'a JAMAIS vue (perte de données silencieuse).
            // On aligne sur le chemin ``!res.ok`` : toast + ne PAS ouvrir le modal.
            if (typeof window.showToast === 'function') {
                window.showToast(
                    'Impossible de charger la planification, rechargez la page',
                    'error'
                );
            }
            return;
        }

        modal.classList.remove('hidden');
        if (window.OverlayManager && typeof window.OverlayManager.open === 'function') {
            window.OverlayManager.open(modal, {
                layer: 'modal',
                lockScroll: true,
                trapFocus: true,
                onClose: function () { modal.classList.add('hidden'); },
            });
        }
    }

    function _close() {
        if (!modal) return;
        if (window.OverlayManager && typeof window.OverlayManager.close === 'function') {
            window.OverlayManager.close(modal);
        }
        modal.classList.add('hidden');
    }

    // ── Init au DOMContentLoaded ────────────────────────────────
    function _init() {
        modal = document.getElementById('komptia-schedule-modal');
        openBtn = document.getElementById('komptia-schedule-btn');
        closeBtn = document.getElementById('komptia-schedule-close');
        cancelBtn = document.getElementById('komptia-schedule-cancel');
        saveBtn = document.getElementById('komptia-schedule-save');
        summarySpan = document.getElementById('komptia-schedule-summary');
        cronError = document.getElementById('komptia-sched-cron-error');
        previewList = document.getElementById('komptia-sched-preview-list');
        previewLoading = document.getElementById('komptia-sched-preview-loading');

        if (!modal || !openBtn) return; // Page n'expose pas la modal

        // Recupere l'id automation depuis l'attribut du root
        const root = document.getElementById('komptia-edit-root');
        if (root && root.dataset.komptiaAutomationId) {
            _automationId = parseInt(root.dataset.komptiaAutomationId, 10);
        }
        if (!_automationId) return; // Pas d'id, modal inutile

        // Listeners principaux
        openBtn.addEventListener('click', _open);
        if (closeBtn) closeBtn.addEventListener('click', _close);
        if (cancelBtn) cancelBtn.addEventListener('click', _close);
        if (saveBtn) saveBtn.addEventListener('click', _save);

        // Toggle sections au changement de mode
        document.querySelectorAll('input[name="schedule-mode"]').forEach((r) => {
            r.addEventListener('change', function () {
                _setMode(_getMode());
                _refreshPreview();
            });
        });

        // Refresh preview a chaque modification de champ
        const watchInputs = [
            'komptia-sched-once-datetime',
            'komptia-sched-daily-time',
            'komptia-sched-weekly-time',
            'komptia-sched-monthly-day',
            'komptia-sched-monthly-time',
            'komptia-sched-cron-expr',
        ];
        watchInputs.forEach((id) => {
            const el = document.getElementById(id);
            if (el) el.addEventListener('input', _refreshPreview);
        });
        document.querySelectorAll('input[name="schedule-dow"]').forEach((cb) => {
            cb.addEventListener('change', _refreshPreview);
        });

        // Backdrop click ferme
        modal.addEventListener('click', function (e) {
            if (e.target === modal) _close();
        });

        // Esc ferme (en plus du focus-trap d'OverlayManager)
        document.addEventListener('keydown', function (e) {
            if (e.key === 'Escape' && !modal.classList.contains('hidden')) {
                _close();
            }
        });

        // Charger un GET initial pour peupler le badge top-bar avec
        // l'etat actuel (sans ouvrir la modal). Si erreur, on laisse vide.
        fetch(`/api/automations/${_automationId}/schedule`, {
            method: 'GET',
            headers: { 'Accept': 'application/json' },
        }).then((r) => r.ok ? r.json() : null).then((data) => {
            if (data) _updateSummary(data.schedule_type, data.schedule_config || {}, data.is_active);
        }).catch(() => { /* silencieux */ });

        // Deep-link via #schedule (depuis le kebab /automations -> Planification)
        if (window.location.hash === '#schedule') {
            // Laisser le DOM se stabiliser puis ouvrir
            setTimeout(_open, 50);
        }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', _init);
    } else {
        _init();
    }
})();
