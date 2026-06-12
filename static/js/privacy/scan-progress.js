/**
 * Privacy — scan-progress.js
 *
 * Module dédié à la modale de scan datastore (POST SSE) et à
 * l'auto-classification chunked (probe + boucle batch_size).
 *
 * Découplé de l'orchestrateur (privacy-page.js) via une API publique
 * minimale : ``window.PrivacyScanProgress``. Le caller fournit des
 * callbacks (onComplete, onClose, fetchJson, getXsrf) plutôt que
 * des dépendances codées en dur — ainsi le module est testable seul.
 *
 * Doctrine
 * --------
 * 1. **CSP-safe** : aucun ``onclick`` inline, ``addEventListener`` partout,
 *    nonce hérité du ``<script src=>`` parent.
 * 2. **No-op si DOM absent** : exporte les helpers purs (``parseSseEvent``,
 *    ``computeProgressPct``) sans toucher au DOM si les ID cibles manquent
 *    (utilisé pour les tests Node + import sécurisé partagé).
 * 3. **Annulation propre** : ``AbortController`` propage l'abort au fetch
 *    SSE ; ``on close modal`` purge l'état + libère le reader.
 * 4. **Taxonomie 4-cas erreurs** : (a) métier (LLM 503 → fallback regex),
 *    (b) 4xx (rate-limit, body, etc.), (c) 5xx (toast + log), (d) réseau
 *    (offline + retry suggéré). Le caller applique la taxonomie via
 *    ``fetchJson``.
 */
(function() {
    'use strict';

    /** Parse une trame SSE complète (séparateur ``\n\n``).
     *
     * Une trame peut contenir plusieurs lignes ``data:``, qui se
     * concatènent. Lignes commentaire (``: heartbeat``) sont ignorées.
     * Retourne le ``data`` parsé en objet, ``null`` si pas de data ou
     * JSON invalide.
     *
     * Cette fonction est PURE — testable en Node sans DOM.
     */
    function parseSseEvent(rawFrame) {
        if (typeof rawFrame !== 'string' || !rawFrame) return null;
        var lines = rawFrame.split('\n');
        var dataLine = '';
        for (var i = 0; i < lines.length; i++) {
            var line = lines[i];
            if (line.indexOf('data:') === 0) {
                // Strip prefix + 1 espace optionnel.
                var raw = line.slice(5);
                if (raw.charAt(0) === ' ') raw = raw.slice(1);
                dataLine += raw;
            }
        }
        if (!dataLine) return null;
        try {
            var evt = JSON.parse(dataLine);
            return (evt && typeof evt === 'object') ? evt : null;
        } catch (_e) {
            return null;
        }
    }

    /** Calcule un pourcentage entier [0, 100] borné défensivement. */
    function computeProgressPct(processed, total) {
        var p = Number(processed);
        var t = Number(total);
        if (!Number.isFinite(p) || p < 0) p = 0;
        if (!Number.isFinite(t) || t <= 0) return 0;
        var pct = Math.floor((100 * p) / t);
        if (pct < 0) return 0;
        if (pct > 100) return 100;
        return pct;
    }

    /** Sépare le buffer SSE en trames complètes selon ``\n\n``. */
    function splitFrames(buffer) {
        var frames = [];
        var rest = buffer;
        var idx;
        // eslint-disable-next-line no-cond-assign
        while ((idx = rest.indexOf('\n\n')) >= 0) {
            frames.push(rest.slice(0, idx));
            rest = rest.slice(idx + 2);
        }
        return { frames: frames, rest: rest };
    }

    // ── DOM bindings (browser only) ───────────────────────────────────
    function _attachBrowser() {
        if (typeof document === 'undefined') return;

        var state = {
            scanInFlight: false,
            scanController: null,
            classifyInFlight: false,
            modalLastFocus: null,
            // Casse la récursion ``OverlayManager.close → entry.onClose =
            // closeScanModal → OverlayManager.close → ...``. Aujourd'hui no-op
            // par chance (stack vide à la 2e tentative). Demain bombe si on
            // ajoute un side-effect non-idempotent. Pattern miroir du flag
            // ``resolved`` dans privacy-page.js ``_confirmBulkDelete``.
            modalClosing: false,
            backdropHandler: null,
        };

        function $(id) { return document.getElementById(id); }
        function show(el) { if (el) el.hidden = false; }
        function hide(el) { if (el) el.hidden = true; }

        // 2026-05-19 — Effet visuel "scan en cours" sur le bouton
        // ``#action-scan`` (header /data/privacy) ET ``#terms-empty-scan-btn``
        // (état empty). Le scan datastore peut prendre plusieurs secondes
        // sur un cabinet avec 50+ classeurs (asyncio.to_thread sur chaque
        // fichier + upsert BDD). Sans spinner, l'user clique 2-3 fois en
        // pensant que ça n'a pas marché.
        function setScanButtonLoading(loading) {
            var ids = ['action-scan', 'terms-empty-scan-btn'];
            for (var i = 0; i < ids.length; i++) {
                var btn = $(ids[i]);
                if (!btn) continue;
                if (loading) {
                    // Stocke le HTML original pour restore.
                    if (btn._origHtml == null) btn._origHtml = btn.innerHTML;
                    btn.disabled = true;
                    btn.setAttribute('aria-busy', 'true');
                    // Remplace par spinner CSS pur + label "Scan…".
                    // Spinner = un cercle border qui tourne (rotation CSS).
                    // Inline pour éviter de toucher un fichier CSS séparé.
                    btn.innerHTML =
                        '<span class="inline-block align-middle mr-1.5"' +
                        ' style="width:0.9rem;height:0.9rem;border:2px solid currentColor;' +
                        'border-top-color:transparent;border-radius:50%;' +
                        'animation:privacyScanSpin 0.7s linear infinite;"' +
                        ' aria-hidden="true"></span>' +
                        '<span>Scan en cours…</span>';
                } else {
                    btn.disabled = false;
                    btn.removeAttribute('aria-busy');
                    if (btn._origHtml != null) {
                        btn.innerHTML = btn._origHtml;
                        btn._origHtml = null;
                    }
                }
            }
            // Injecter la keyframe une seule fois (vérifie qu'elle n'existe
            // pas déjà — idempotent pour réouvertures).
            if (loading && !document.getElementById('privacy-scan-spin-style')) {
                var style = document.createElement('style');
                style.id = 'privacy-scan-spin-style';
                style.textContent =
                    '@keyframes privacyScanSpin { from { transform: rotate(0deg); }' +
                    ' to { transform: rotate(360deg); } }';
                document.head.appendChild(style);
            }
        }

        // Toggle visibilité Tailwind. Le template porte ``class="... hidden
        // items-center justify-center"`` : la classe Tailwind ``.hidden``
        // applique ``display:none`` (spécificité égale à l'attribut HTML
        // ``[hidden]`` mais déclarée APRÈS dans le bundle → gagne). Toggler
        // la propriété DOM ``modal.hidden`` ne retire QUE l'attribut HTML —
        // la classe persiste et la modal reste invisible. Bug observé en
        // navigateur, manqué par le test Node ``test_action_scan_button_*``
        // dont le mock ``classList`` était un no-op (cf. ce fix).
        function _setScanModalVisible(modal, visible) {
            if (visible) {
                modal.classList.remove('hidden');
                modal.classList.add('flex'); // rétablit ``display:flex`` requis par ``items-center justify-center``
                modal.setAttribute('aria-hidden', 'false');
            } else {
                modal.classList.add('hidden');
                modal.classList.remove('flex');
                modal.setAttribute('aria-hidden', 'true');
            }
        }

        function _onBackdropClick(ev) {
            // Click backdrop = ferme la modal (pattern Komptia
            // ``feedback_onboarding_overlay_non_bloquant.md``). On filtre par
            // ``ev.target === modal`` pour ignorer les clicks sur le contenu
            // interne (la dialog box centrée).
            var modal = $('modal-scan');
            if (!modal || ev.target !== modal) return;
            // Protection contre les double-clics rapides : si l'user clique 2x
            // sur "Scanner mes données", le 2e click peut frapper le backdrop
            // qui vient juste de se rendre → fermeture accidentelle + abort du
            // scan qui démarre. Pendant un scan en cours, le backdrop click
            // est neutralisé ; l'user doit utiliser explicitement le X, le
            // bouton Annuler, ou ESC pour fermer.
            if (state.scanInFlight) return;
            closeScanModal();
        }

        // Ouvre la modal ET démarre le scan immédiatement. C'est le SEUL flow
        // utilisateur (déclenché par ``#action-scan`` / ``#terms-empty-scan-btn``
        // via ``_triggerScanModal`` dans privacy-page.js). Pas de bouton
        // "Lancer le scan" / "Relancer" intra-modal : pour relancer après
        // succès ou échec, l'user ferme la modal et re-clique "Scanner mes
        // données" depuis le header.
        function openAndStartScan(deps) {
            openScanModal();
            if (deps) startScan(deps);
        }

        function openScanModal() {
            var modal = $('modal-scan');
            if (!modal) return;
            // Réinitialise les flags de fermeture (réouvrir après une close).
            state.modalClosing = false;
            // Message neutre — sera remplacé par "Connexion au serveur…" dès
            // que ``startScan`` démarre (immédiatement après via
            // ``openAndStartScan``).
            $('scan-status').textContent = 'Démarrage du scan…';
            $('scan-results').innerHTML = '';
            hide($('scan-results'));
            hide($('scan-progress-bar'));
            $('scan-progress-fill').style.width = '0%';
            hide($('modal-scan-cancel'));
            state.modalLastFocus = document.activeElement;
            _setScanModalVisible(modal, true);
            // Backdrop click → close (axe 4 UX intuitive + a11y).
            if (state.backdropHandler) {
                modal.removeEventListener('click', state.backdropHandler);
            }
            state.backdropHandler = _onBackdropClick;
            modal.addEventListener('click', state.backdropHandler);
            if (window.OverlayManager) {
                // ``onClose`` : OverlayManager gère ESC en LIFO (overlay-manager.js
                // ``_onKeydown``) → il dépile mais ne masque pas l'élément. Sans
                // ce callback, ESC laisse la modal visible en bas de stack. Le
                // flag ``state.modalClosing`` ci-dessous casse la récursion
                // ``OverlayManager.close → onClose → closeScanModal → close``.
                // ``trapFocus`` + ``inertSiblings`` : a11y axe 4 — Tab piégé
                // dans la modal, fond inerte pour screen readers.
                window.OverlayManager.open(modal, {
                    layer: 'modal',
                    lockScroll: true,
                    trapFocus: true,
                    inertSiblings: true,
                    onClose: closeScanModal,
                });
            }
            // Focus initial sur le bouton "Annuler" (fallback robuste : il
            // sera visible dès le démarrage du scan via ``startScan``). Sans
            // focus initial, ``trapFocus`` d'OverlayManager n'a pas d'ancre
            // et Tab peut sortir de la modal.
            var cancelBtn = $('modal-scan-cancel');
            if (cancelBtn) {
                try { cancelBtn.focus(); } catch (_e) { /* hidden au moment du focus initial — ignoré */ }
            }
        }

        function closeScanModal() {
            // Idempotence : ESC déclenche ``OverlayManager.close → onClose =
            // closeScanModal`` qui réappelle ``OverlayManager.close``. Sans ce
            // garde, side-effects (abort, focus) tournent 2 fois. Cf. review
            // adversariale 2026-05-19 finding #1+#2.
            if (state.modalClosing) return;
            state.modalClosing = true;
            if (state.scanInFlight && state.scanController) {
                try { state.scanController.abort(); } catch (_e) { /* déjà aborted */ }
            }
            state.scanInFlight = false;
            // Restore le spinner sur les boutons externes au cas où on
            // ferme le modal alors qu'un scan était en cours.
            setScanButtonLoading(false);
            var modal = $('modal-scan');
            if (!modal) {
                state.modalClosing = false;
                return;
            }
            if (state.backdropHandler) {
                modal.removeEventListener('click', state.backdropHandler);
                state.backdropHandler = null;
            }
            if (window.OverlayManager) window.OverlayManager.close(modal);
            _setScanModalVisible(modal, false);
            if (state.modalLastFocus && typeof state.modalLastFocus.focus === 'function') {
                try { state.modalLastFocus.focus(); } catch (_e) { /* élément détaché */ }
            }
            state.modalClosing = false;
        }

        // Active/désactive l'animation indéterminée de la progress bar (mode
        // "shimmer" pendant l'attente du serveur, avant le 1er event SSE).
        // Sinon l'user voit "Scan en cours…" + barre statique à 0% pendant le
        // RTT réseau (50-300ms typiquement, parfois beaucoup plus si rate-
        // limit côté serveur) et perçoit la modal comme morte.
        function _setProgressIndeterminate(on) {
            var fill = $('scan-progress-fill');
            if (!fill) return;
            if (on) {
                fill.style.width = '30%';
                fill.classList.add('scan-progress-indeterminate');
            } else {
                fill.classList.remove('scan-progress-indeterminate');
            }
            // Injection idempotente de la keyframe CSS (pas de fichier CSS
            // séparé pour ne pas multiplier les bundles ; pattern miroir de
            // ``setScanButtonLoading``).
            if (on && !document.getElementById('scan-indeterminate-style')) {
                var style = document.createElement('style');
                style.id = 'scan-indeterminate-style';
                style.textContent =
                    '@keyframes scanProgressSlide {' +
                    '  0% { transform: translateX(-110%); }' +
                    '  100% { transform: translateX(370%); }' +
                    '}' +
                    '.scan-progress-indeterminate {' +
                    '  animation: scanProgressSlide 1.2s ease-in-out infinite;' +
                    '}';
                document.head.appendChild(style);
            }
        }

        async function startScan(deps) {
            if (state.scanInFlight) return;
            state.scanInFlight = true;
            state.scanController = new AbortController();
            show($('modal-scan-cancel'));
            // Spinner sur le bouton externe (header /data/privacy + état empty).
            setScanButtonLoading(true);
            show($('scan-progress-bar'));
            // Statut explicite "connexion" pendant le RTT réseau (rate-limit
            // 429, latence Sage, etc.) — ``Scan en cours…`` aurait été
            // trompeur (rien ne tourne encore côté serveur tant que la
            // requête n'a pas été acceptée).
            $('scan-status').textContent = 'Connexion au serveur…';
            _setProgressIndeterminate(true);
            try {
                var resp = await fetch('/api/anonymization/scan', {
                    method: 'POST',
                    headers: {
                        'X-Xsrftoken': deps.getXsrf(),
                        'Accept': 'text/event-stream',
                        'X-Requested-With': 'XMLHttpRequest',
                    },
                    credentials: 'same-origin',
                    signal: state.scanController.signal,
                });
                if (!resp.ok) {
                    _setProgressIndeterminate(false);
                    $('scan-progress-fill').style.width = '0%';
                    if (resp.status === 429) {
                        $('scan-status').textContent = 'Trop de requêtes. Patientez avant de relancer le scan.';
                    } else if (resp.status === 401) {
                        $('scan-status').textContent = 'Session expirée. Reconnectez-vous.';
                    } else if (resp.status >= 500) {
                        $('scan-status').textContent = 'Erreur serveur (' + resp.status + '). Réessayez plus tard.';
                    } else {
                        $('scan-status').textContent = 'Erreur (' + resp.status + ') lors du scan.';
                    }
                    state.scanInFlight = false;
                    hide($('modal-scan-cancel'));
                    // Pas de bouton "Relancer" dans la modal — l'user ferme
                    // et re-clique "Scanner mes données" depuis le header.
                    return;
                }
                var reader = resp.body.getReader();
                var decoder = new TextDecoder();
                var buffer = '';
                while (true) {
                    var chunk = await reader.read();
                    if (chunk.done) break;
                    buffer += decoder.decode(chunk.value, { stream: true });
                    var split = splitFrames(buffer);
                    buffer = split.rest;
                    for (var i = 0; i < split.frames.length; i++) {
                        var evt = parseSseEvent(split.frames[i]);
                        if (!evt || typeof evt.step !== 'string') continue;
                        var procN = Number(evt.processed) || 0;
                        var totalN = Number(evt.total) || 0;
                        var tokensN = Number(evt.tokens_so_far) || 0;
                        if (evt.step === 'start') {
                            // Bascule en mode déterminé : le serveur a accepté
                            // la requête, on connaît le nombre de fichiers.
                            _setProgressIndeterminate(false);
                            $('scan-progress-fill').style.width = '0%';
                            $('scan-status').textContent = 'Scan en cours : '
                                + (Number(evt.total_files) || 0) + ' fichier(s).';
                        } else if (evt.step === 'file') {
                            var pct = computeProgressPct(procN, totalN);
                            $('scan-progress-fill').style.width = pct + '%';
                            $('scan-progress-bar').setAttribute('aria-valuenow', String(pct));
                            $('scan-status').textContent = 'Traité : ' + procN + '/' + totalN
                                + ' (' + tokensN + ' termes uniques).';
                        } else if (evt.step === 'dashboards_start') {
                            // Phase 2 (ajout 2026-05-20) — fin de la phase
                            // fichiers, début de la phase dashboards. Pas
                            // de pourcentage déterministe (les dashboards
                            // sont N classeurs en plus mais le total
                            // initial ne les incluait pas) — on bascule
                            // en indéterminé pour l'overlay status.
                            var totalDashN = Number(evt.total) || 0;
                            $('scan-status').textContent = 'Scan des tableaux de bord : '
                                + totalDashN + ' à analyser.';
                        } else if (evt.step === 'dashboard') {
                            // Un dashboard scanné. Affiche le nom pour
                            // feedback visuel — sécurité : le name vient
                            // de la BDD (admin-trusted), pas du payload
                            // client direct. textContent suffit.
                            var dashName = (typeof evt.name === 'string' && evt.name)
                                ? evt.name : ('#' + (evt.id || '?'));
                            $('scan-status').textContent = 'Tableau de bord scanné : ' + dashName + '.';
                        } else if (evt.step === 'migration_required') {
                            // BDD pré-existante : le CHECK constraint
                            // ck_anon_term_source rejette source='dashboard'.
                            // Émet un avertissement visible plutôt qu'un
                            // skip silencieux (review adversariale 2026-05-20).
                            var migMsg = (typeof evt.message === 'string' && evt.message)
                                ? evt.message
                                : 'Une migration de base de données est requise pour scanner les tableaux de bord.';
                            $('scan-status').textContent = '⚠ ' + migMsg;
                        } else if (evt.step === 'complete') {
                            $('scan-progress-fill').style.width = '100%';
                            $('scan-status').textContent = 'Scan terminé.';
                            var tokens = Array.isArray(evt.tokens_found) ? evt.tokens_found : [];
                            var stats = evt.stats || {};
                            var addedBdd = Number(stats.terms_added_to_bdd) || 0;
                            var filesScanned = Number(stats.files_scanned) || 0;
                            var dashboardsScanned = Number(stats.dashboards_scanned) || 0;
                            // #40 — libellé spécifique quand le cap touche les
                            // messages Iris : enjeu confidentialité (les plus
                            // anciens non scannés → leurs valeurs partent en clair
                            // au LLM tant qu'elles ne sont pas configurées à la main).
                            var trunc = '';
                            if (evt.iris_scan_error) {
                                // #40 review — la phase messages Iris a ÉCHOUÉ :
                                // aucun message couvert, relancer le scan.
                                trunc = ' (⚠ phase messages Iris NON terminée —'
                                    + ' relancez le scan pour les couvrir)';
                            } else if (evt.iris_truncated) {
                                trunc = ' (cap atteint : messages Iris les plus anciens'
                                    + ' NON scannés — configurez leurs termes manuellement)';
                            } else if (evt.truncated) {
                                trunc = ' (tronqué au cap serveur)';
                            }
                            // Pas d'innerHTML avec interpolation user — on construit
                            // les nodes via createElement + textContent (CSP-safe).
                            var resultsEl = $('scan-results');
                            resultsEl.innerHTML = '';
                            var p1 = document.createElement('p');
                            var strong = document.createElement('strong');
                            strong.textContent = tokens.length
                                + ' terme(s) unique(s) identifié(s)' + trunc + '.';
                            p1.appendChild(strong);
                            // Composer le résumé des sources scannées : classeurs +
                            // dashboards (si présent). Ajout 2026-05-20.
                            var sourcesSummary = filesScanned + ' classeur(s)';
                            if (dashboardsScanned > 0) {
                                sourcesSummary += ' + ' + dashboardsScanned + ' tableau(x) de bord';
                            }
                            sourcesSummary += ' scanné(s)';
                            var p2 = document.createElement('p');
                            p2.className = 'privacy-state-help';
                            p2.textContent = addedBdd > 0
                                ? (addedBdd + ' nouveau(x) terme(s) ajouté(s) à votre dictionnaire ('
                                    + sourcesSummary + '). '
                                    + 'Ouvrez le panneau pour les confirmer ou les anonymiser.')
                                : ('Tous les termes détectés étaient déjà dans votre dictionnaire. '
                                    + sourcesSummary + '.');
                            resultsEl.appendChild(p1);
                            resultsEl.appendChild(p2);
                            show(resultsEl);
                        } else if (evt.step === 'error') {
                            $('scan-status').textContent = 'Erreur scan : ' + (evt.error || 'inconnue');
                        }
                    }
                }
                if (typeof deps.onComplete === 'function') {
                    deps.onComplete();
                }
            } catch (err) {
                if (err && err.name === 'AbortError') {
                    $('scan-status').textContent = 'Scan annulé.';
                } else {
                    $('scan-status').textContent = 'Erreur réseau lors du scan.';
                }
            } finally {
                // Filet de sécurité : retire toujours l'animation indéterminée
                // (déjà retirée dans evt 'start' et if !resp.ok, mais le
                // ``catch`` réseau ou un abort avant le 1er event la laisserait
                // active sinon → barre qui translate à l'infini sur la modal
                // d'erreur, moche).
                _setProgressIndeterminate(false);
                state.scanInFlight = false;
                hide($('modal-scan-cancel'));
                // Restore bouton externe quoi qu'il arrive (succès / abort
                // / erreur). Sans ce restore, le bouton reste en spinner
                // perpétuel si l'user n'a pas explicitement fermé le modal.
                setScanButtonLoading(false);
            }
        }

        async function performAutoClassify(mode, deps) {
            // mode: 'llm' | 'regex'
            if (state.classifyInFlight) return;
            state.classifyInFlight = true;
            var status = $('classify-status');
            show(status);
            status.textContent = 'Préparation...';

            var pendingTerms = (deps && typeof deps.getPendingTerms === 'function')
                ? deps.getPendingTerms() : [];
            if (pendingTerms.length === 0) {
                status.textContent = "Aucun terme en attente de classification. Lancez d'abord un scan.";
                state.classifyInFlight = false;
                return;
            }
            var tokens = pendingTerms.map(function(t) { return t.term; });
            var url = mode === 'llm'
                ? '/api/anonymization/auto-classify'
                : '/api/anonymization/auto-classify/regex';

            // Probe pour récupérer batch_size côté LLM (le serveur cap
            // silencieusement à _AUTO_ANON_BATCH_SIZE).
            var batchSize = 200;
            try {
                if (mode === 'llm') {
                    var probe = await deps.fetchJson('/api/anonymization/auto-classify/probe', {
                        method: 'POST'
                    });
                    if (probe && typeof probe.batch_size === 'number' && probe.batch_size > 0) {
                        batchSize = probe.batch_size;
                    }
                }
            } catch (err) {
                if (err && err.status === 503 && mode === 'llm') {
                    status.textContent = 'LLM local non configuré. Bascule vers la regex...';
                    state.classifyInFlight = false;
                    return performAutoClassify('regex', deps);
                }
                // Probe rate-limit ou autre : on continue avec batchSize=200
                // (le serveur cappera dans tous les cas).
            }

            var totalFlagged = 0;
            var processed = 0;
            for (var i = 0; i < tokens.length; i += batchSize) {
                var chunk = tokens.slice(i, i + batchSize);
                try {
                    var data = await deps.fetchJson(url, {
                        method: 'POST',
                        body: JSON.stringify({ tokens: chunk }),
                    });
                    var flagged = Array.isArray(data.flagged) ? data.flagged : [];
                    totalFlagged += flagged.length;
                    processed += chunk.length;
                    // Task #10 : notif UI non-bloquante si Ollama a échoué
                    // sur ce chunk. L'app continue (les autres chunks essaient
                    // aussi) — c'est juste de l'observabilité.
                    if (data && data.status && data.status !== 'ok' && mode === 'llm') {
                        if (typeof deps.toast === 'function') {
                            var msgByStatus = {
                                'not_configured': 'LLM local non configuré — bascule sur la détection regex.',
                                'unreachable': data.error_message
                                    || 'LLM local injoignable (service arrêté ?) — bascule sur la détection regex.',
                                'timeout': 'LLM local lent — chunk non classifié, retentez.',
                                'error': data.error_message || 'Erreur LLM local — chunk non classifié.'
                            };
                            var toastMsg = msgByStatus[data.status] || ('Auto-classify : ' + data.status);
                            deps.toast(toastMsg, 'warning');
                        }
                        // LLM pas configuré OU injoignable (service éteint) :
                        // inutile de marteler les chunks suivants au même mur.
                        // On bascule sur la regex (qui ne dépend pas du LLM) pour
                        // que le scan ABOUTISSE quand même — dégradation gracieuse
                        // ET message clair, jamais un échec silencieux.
                        if (data.status === 'not_configured' || data.status === 'unreachable') {
                            state.classifyInFlight = false;
                            return performAutoClassify('regex', deps);
                        }
                    }
                    status.textContent = 'Classification en cours : '
                        + processed + '/' + tokens.length + ' analysés, '
                        + totalFlagged + ' identifiés.';
                } catch (err2) {
                    if (err2 && err2.status === 503 && mode === 'llm') {
                        status.textContent = 'LLM local indisponible. Bascule vers la regex...';
                        state.classifyInFlight = false;
                        return performAutoClassify('regex', deps);
                    }
                    status.textContent = 'Erreur après ' + processed + '/' + tokens.length + ' : '
                        + ((err2 && err2.message) || 'inconnue');
                    state.classifyInFlight = false;
                    return;
                }
            }
            status.textContent = 'Classification terminée : '
                + totalFlagged + '/' + tokens.length + ' identifiés comme termes confidentiels.';
            if (typeof deps.toast === 'function') {
                deps.toast('Classification terminée.', 'info');
            }
            if (typeof deps.onComplete === 'function') {
                deps.onComplete();
            }
            state.classifyInFlight = false;
        }

        window.PrivacyScanProgress = {
            openScanModal: openScanModal,
            openAndStartScan: openAndStartScan,
            closeScanModal: closeScanModal,
            startScan: startScan,
            performAutoClassify: performAutoClassify,
            isScanning: function() { return state.scanInFlight; },
            isClassifying: function() { return state.classifyInFlight; },
        };
    }

    _attachBrowser();

    // ── Exports Node (tests purs) ─────────────────────────────────────
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = {
            parseSseEvent: parseSseEvent,
            computeProgressPct: computeProgressPct,
            splitFrames: splitFrames,
        };
    }
})();
