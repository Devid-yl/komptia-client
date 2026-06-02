/**
 * Privacy — improve-pseudos.js
 *
 * Module dédié à la modale d'amélioration des pseudonymes via le LLM
 * local configuré dans /admin/ai-config (Ollama, LM Studio, TGI, vLLM,
 * ou tout endpoint OpenAI-compatible — provider-agnostic).
 *
 * Flow utilisateur :
 *
 *   1. L'user clique sur #action-improve-pseudos dans le header.
 *   2. La modal #modal-improve s'ouvre + démarre IMMÉDIATEMENT
 *      (``openAndStartImprove``, pas de bouton "Lancer" intermédiaire).
 *   3. Probe → batch_size dynamique selon le modèle local configuré
 *      (LlmModel.context_window + max_output_tokens du modèle).
 *   4. Loop : POST /api/anonymization/improve-pseudo par chunks de
 *      batch_size. Chaque chunk update pseudo_middle en BDD + refresh
 *      l'UI en temps réel.
 *   5. Sortir du modal (X / ESC / backdrop / Arrêter) → AbortController
 *      abort les fetches restants → break la boucle. Les chunks déjà
 *      persistés restent (résilience par chunk).
 *
 * Doctrine (miroir scan-progress.js, cohérent UX) :
 *
 * 1. **CSP-safe** : aucun ``onclick`` inline, ``addEventListener`` partout.
 * 2. **Anti-XSS** : textContent pour les valeurs user-controlled.
 * 3. **Taxonomie 4-cas erreurs** (axe 5 Komptia) :
 *    (a) métier prévue : LLM local non configuré (503) → message + lien
 *        /admin/ai-config
 *    (b) 4xx : message clair (rare car endpoint sans rate-limit côté nous)
 *    (c) 5xx : message + ``feedback-reporter.js`` Signaler (si disponible)
 *    (d) offline : navigator.onLine OR fetch reject → message clair.
 *        Retry manuel par l'user (fermer + re-cliquer "Améliorer") —
 *        idempotent par construction grâce au filtrage côté serveur sur
 *        pseudo_middle IS NULL. Pas de retry auto (les chunks déjà
 *        persistés sont préservés, l'user reprend là où il en était).
 * 4. **Cas vide géré IMMÉDIATEMENT** (fix #2) : si l'user clique sans
 *    terme éligible, message "Aucun terme à améliorer" + Fermer, ZÉRO
 *    appel LLM.
 * 5. **Provider-agnostic** : tous les messages parlent de "LLM local",
 *    jamais "Ollama" en dur.
 * 6. **Persistance par chunk** : chaque chunk persisté → résilience à
 *    une fermeture mid-flow.
 */
(function() {
    'use strict';

    function _attachBrowser() {
        if (typeof document === 'undefined') return;

        var state = {
            improveInFlight: false,
            controller: null,
            modalLastFocus: null,
            modalClosing: false,
            backdropHandler: null,
        };

        function $(id) { return document.getElementById(id); }
        function show(el) { if (el) el.hidden = false; }
        function hide(el) { if (el) el.hidden = true; }

        function _setModalVisible(modal, visible) {
            if (!modal) return;
            if (visible) {
                modal.classList.remove('hidden');
                modal.classList.add('flex');
                modal.setAttribute('aria-hidden', 'false');
                // Force display via inline (override le ``display:none`` que
                // ``_setModalVisible(false)`` a pu poser pour neutraliser le
                // ``display:flex`` initial). Bug 2026-05-20 (diagnostic user) :
                // sans ce force, la class .hidden Tailwind ne gagnait pas
                // contre le ``display:flex`` posé par le cssText à la création
                // → le modal restait visible (backdrop noir bloquant).
                modal.style.display = 'flex';
                modal.hidden = false;
            } else {
                modal.classList.add('hidden');
                modal.classList.remove('flex');
                modal.setAttribute('aria-hidden', 'true');
                // Force inline display:none — neutralise le ``display:flex``
                // que cssText a posé à la création. La class ``hidden`` seule
                // ne suffit pas car elle est dominée par l'inline style en
                // priorité CSS (sauf si Tailwind compile avec !important,
                // ce qui n'est pas garanti dans le bundle Komptia).
                modal.style.display = 'none';
                modal.hidden = true;
            }
        }

        function _onBackdropClick(ev) {
            var modal = $('modal-improve');
            if (!modal || ev.target !== modal) return;
            // Sortir = arrête le LLM (contrat V6 user 2026-05-19).
            // Pas de protection scanInFlight car ici c'est intentionnel :
            // l'user veut arrêter en cliquant en dehors.
            closeModal();
        }

        function _setProgressIndeterminate(on) {
            var fill = $('improve-progress-fill');
            if (!fill) return;
            if (on) {
                fill.style.width = '30%';
                fill.classList.add('improve-progress-indeterminate');
            } else {
                fill.classList.remove('improve-progress-indeterminate');
            }
            if (on && !document.getElementById('improve-indeterminate-style')) {
                // Lazy-load du fichier CSS externe (au lieu d'un <style>
                // inline injecté via textContent). Respecte une CSP stricte
                // ``style-src 'self'`` sans ``unsafe-inline``.
                var link = document.createElement('link');
                link.id = 'improve-indeterminate-style';
                link.rel = 'stylesheet';
                link.href = '/static/css/improve-pseudos.css';
                document.head.appendChild(link);
            }
        }

        /**
         * Crée à la volée le DOM ``#modal-improve`` si absent — permet
         * d'utiliser ``PrivacyImprovePseudos.openAndStartImprove()`` depuis
         * n'importe quelle page (privacy, iris, datastore, automations/edit),
         * pas seulement ``/data/privacy`` qui pose le markup via template.
         *
         * Styling inline (CSP-safe, indépendant de Tailwind) pour
         * fonctionner aussi sur les pages qui n'ont pas Tailwind chargé.
         * Tous les IDs préservent le contrat du template original
         * (``improve-status``, ``improve-progress-bar``, ``improve-progress-fill``,
         * ``improve-results``, ``modal-improve-cancel``, ``modal-improve-close``).
         */
        function _ensureModalDom() {
            if (typeof document === 'undefined') return null;
            var existing = document.getElementById('modal-improve');
            if (existing) return existing;

            var overlay = document.createElement('div');
            overlay.id = 'modal-improve';
            overlay.setAttribute('role', 'dialog');
            overlay.setAttribute('aria-modal', 'true');
            overlay.setAttribute('aria-labelledby', 'modal-improve-title');
            overlay.setAttribute('aria-hidden', 'true');
            overlay.hidden = true;
            overlay.classList.add('hidden');
            // z-index piloté par OverlayManager.open() — cf. openModal().
            // Ne PAS remettre une valeur en dur ici sinon elle reprend si
            // le panel est appelé sans passer par le manager (debug, fork).
            //
            // ``display:none`` initial (fix bug 2026-05-20 diagnostic user) :
            // avant on posait ``display:flex`` ici → la classe ``.hidden``
            // Tailwind était dominée par l'inline style → le modal restait
            // visuellement affiché en permanence après le 1er open/close
            // cycle (backdrop noir bloquant). Le ``_setModalVisible(true)``
            // pose désormais ``display:flex`` inline pour ouvrir.
            overlay.style.cssText =
                'position:fixed;inset:0;background:rgba(0,0,0,0.5);'
                + 'display:none;align-items:center;justify-content:center;';

            var dialog = document.createElement('div');
            dialog.style.cssText =
                'background:var(--bg-surface, #fff);color:var(--text-primary, #111827);'
                + 'border-radius:0.5rem;box-shadow:0 10px 40px rgba(0,0,0,0.2);'
                + 'border:1px solid var(--border, #e5e7eb);'
                + 'width:min(420px, 94vw);max-height:86vh;'
                + 'display:flex;flex-direction:column;overflow:hidden;';

            var header = document.createElement('div');
            header.style.cssText =
                'display:flex;align-items:center;justify-content:space-between;'
                + 'gap:0.75rem;padding:0.85rem 1.1rem;'
                + 'border-bottom:1px solid var(--border, #e5e7eb);';

            var titleEl = document.createElement('h3');
            titleEl.id = 'modal-improve-title';
            titleEl.textContent = 'Amélioration des pseudonymes';
            titleEl.style.cssText =
                'margin:0;font-size:0.95rem;font-weight:600;'
                + 'color:var(--text-primary, #111827);';

            var closeBtn = document.createElement('button');
            closeBtn.id = 'modal-improve-close';
            closeBtn.type = 'button';
            closeBtn.setAttribute('aria-label', 'Fermer');
            closeBtn.title = 'Fermer (arrête le LLM local)';
            closeBtn.textContent = '×';
            closeBtn.style.cssText =
                'background:transparent;border:0;font-size:1.4rem;line-height:1;'
                + 'color:var(--text-muted, #6b7280);cursor:pointer;padding:0 0.4rem;';
            closeBtn.addEventListener('click', closeModal);

            header.appendChild(titleEl);
            header.appendChild(closeBtn);

            var body = document.createElement('div');
            body.style.cssText =
                'flex:1;overflow-y:auto;padding:1rem 1.1rem;'
                + 'display:flex;flex-direction:column;gap:0.6rem;'
                + 'font-size:0.875rem;color:var(--text-primary, #111827);';

            var status = document.createElement('p');
            status.id = 'improve-status';
            status.setAttribute('aria-live', 'polite');
            status.style.cssText = 'margin:0;font-size:0.875rem;';
            status.textContent = 'Démarrage…';

            var progressWrap = document.createElement('div');
            progressWrap.id = 'improve-progress-bar';
            progressWrap.setAttribute('role', 'progressbar');
            progressWrap.setAttribute('aria-valuemin', '0');
            progressWrap.setAttribute('aria-valuemax', '100');
            progressWrap.setAttribute('aria-valuenow', '0');
            progressWrap.hidden = true;
            progressWrap.style.cssText =
                'width:100%;height:6px;background:var(--bg-surface-2, #e5e7eb);'
                + 'border-radius:9999px;overflow:hidden;';
            var progressFill = document.createElement('div');
            progressFill.id = 'improve-progress-fill';
            progressFill.style.cssText =
                'height:100%;width:0%;background:var(--brand, #2563eb);'
                + 'transition:width 0.3s;';
            progressWrap.appendChild(progressFill);

            var results = document.createElement('div');
            results.id = 'improve-results';
            results.hidden = true;
            results.style.cssText =
                'font-size:0.75rem;color:var(--text-muted, #6b7280);';

            body.appendChild(status);
            body.appendChild(progressWrap);
            body.appendChild(results);

            var footer = document.createElement('div');
            footer.style.cssText =
                'display:flex;align-items:center;justify-content:flex-end;'
                + 'gap:0.5rem;padding:0.85rem 1.1rem;'
                + 'border-top:1px solid var(--border, #e5e7eb);';

            var cancel = document.createElement('button');
            cancel.id = 'modal-improve-cancel';
            cancel.type = 'button';
            cancel.hidden = true;
            cancel.textContent = 'Arrêter';
            cancel.style.cssText =
                'padding:0.4rem 0.8rem;border:1px solid var(--border, #d1d5db);'
                + 'background:var(--bg-surface, #fff);color:var(--text-primary, #111827);'
                + 'border-radius:0.375rem;font-size:0.875rem;cursor:pointer;';
            footer.appendChild(cancel);

            dialog.appendChild(header);
            dialog.appendChild(body);
            dialog.appendChild(footer);
            overlay.appendChild(dialog);
            document.body.appendChild(overlay);
            return overlay;
        }

        function openModal() {
            var modal = _ensureModalDom();
            if (!modal) return;
            state.modalClosing = false;
            $('improve-status').textContent = 'Démarrage…';
            $('improve-results').innerHTML = '';
            hide($('improve-results'));
            hide($('improve-progress-bar'));
            $('improve-progress-fill').style.width = '0%';
            hide($('modal-improve-cancel'));
            state.modalLastFocus = document.activeElement;
            _setModalVisible(modal, true);
            if (state.backdropHandler) {
                modal.removeEventListener('click', state.backdropHandler);
            }
            state.backdropHandler = _onBackdropClick;
            modal.addEventListener('click', state.backdropHandler);
            if (window.OverlayManager) {
                window.OverlayManager.open(modal, {
                    layer: 'modal',
                    lockScroll: true,
                    trapFocus: true,
                    inertSiblings: true,
                    onClose: closeModal,
                });
            }
            var cancelBtn = $('modal-improve-cancel');
            if (cancelBtn) {
                try { cancelBtn.focus(); } catch (_e) { /* hidden au moment du focus initial */ }
            }
        }

        function closeModal() {
            if (state.modalClosing) return;
            state.modalClosing = true;
            // Abort tous les fetches en cours (chunks restants).
            if (state.improveInFlight && state.controller) {
                try { state.controller.abort(); } catch (_e) { /* déjà aborted */ }
            }
            state.improveInFlight = false;
            var modal = $('modal-improve');
            if (!modal) {
                state.modalClosing = false;
                return;
            }
            if (state.backdropHandler) {
                modal.removeEventListener('click', state.backdropHandler);
                state.backdropHandler = null;
            }
            if (window.OverlayManager) window.OverlayManager.close(modal);
            _setModalVisible(modal, false);
            _setProgressIndeterminate(false);
            if (state.modalLastFocus && typeof state.modalLastFocus.focus === 'function') {
                try { state.modalLastFocus.focus(); } catch (_e) { /* élément détaché */ }
            }
            state.modalClosing = false;
        }

        // ─── Flow principal : openAndStartImprove(deps) ─────────────────
        async function openAndStartImprove(deps) {
            if (state.improveInFlight) return;

            // Étape 1 — Ouvrir la modal immédiatement (feedback instantané).
            openModal();

            // Étape 2 — Cas vide (2026-05-19, fix David) : le bouton
            // « Améliorer l'anonymisation » ne doit JAMAIS refuser de
            // s'exécuter. On retire le early-return refus précédent qui
            // bloquait silencieusement quand l'user n'avait pas de termes
            // ``enabled=true && pseudo_middle IS NULL``. Désormais :
            //   - Si 0 termes ``enabled`` → message ACTIONNABLE (active
            //     des termes via le toggle de la liste), modal refermable.
            //   - Si au moins 1 terme ``enabled`` → on lance toujours le
            //     call backend. Le backend gère le scope (ré-amélioration
            //     des auto-générés ``LABEL_<hex>`` + préservation des vrais
            //     customs user-saisis).
            var eligibleTerms = (deps && typeof deps.getEligibleTerms === 'function')
                ? deps.getEligibleTerms() : [];
            if (!eligibleTerms || eligibleTerms.length === 0) {
                $('improve-status').textContent =
                    "Aucun terme activé pour l'instant. Active des termes "
                    + "via le bouton « Anonymiser » de la liste pour pouvoir "
                    + "améliorer leur pseudonyme.";
                hide($('improve-progress-bar'));
                show($('modal-improve-cancel'));
                $('modal-improve-cancel').textContent = 'Fermer';
                return;
            }

            // Étape 3 — Probe pour calibrer le batch_size.
            state.improveInFlight = true;
            state.controller = new AbortController();
            show($('modal-improve-cancel'));
            $('modal-improve-cancel').textContent = 'Arrêter';
            show($('improve-progress-bar'));
            // Le probe est instant (~15ms) — pas besoin d'un message d'attente
            // ici. Le vrai temps d'attente est dans la boucle chunk plus bas
            // (où on update le status à "LLM en cours de traitement…").
            $('improve-status').textContent = 'Préparation du LLM local…';
            _setProgressIndeterminate(true);

            var batchSize = 50;
            var modelName = '';
            try {
                var probeResp = await fetch('/api/anonymization/improve-pseudo/probe', {
                    method: 'POST',
                    headers: {
                        'X-Xsrftoken': deps.getXsrf(),
                        'X-Requested-With': 'XMLHttpRequest',
                    },
                    credentials: 'same-origin',
                    signal: state.controller.signal,
                });
                if (!probeResp.ok) {
                    _setProgressIndeterminate(false);
                    $('improve-progress-fill').style.width = '0%';
                    if (probeResp.status === 503) {
                        // Fix #3 (a) — métier prévue.
                        $('improve-status').textContent =
                            'LLM local non configuré. Va dans /admin/ai-config → Connexion et modèle → « LLM local » pour l\'activer.';
                    } else if (probeResp.status >= 500) {
                        // Fix #3 (c) — 5xx.
                        $('improve-status').textContent =
                            'Erreur serveur (' + probeResp.status + '). Réessaye plus tard ou signale le bug.';
                    } else if (probeResp.status === 401) {
                        $('improve-status').textContent = 'Session expirée. Reconnecte-toi.';
                    } else {
                        $('improve-status').textContent = 'Erreur (' + probeResp.status + ') au probe.';
                    }
                    state.improveInFlight = false;
                    hide($('modal-improve-cancel'));
                    return;
                }
                var probeData = await probeResp.json();
                if (typeof probeData.batch_size === 'number' && probeData.batch_size > 0) {
                    batchSize = probeData.batch_size;
                }
                if (typeof probeData.model_name === 'string') {
                    modelName = probeData.model_name;
                }
            } catch (err) {
                if (err && err.name === 'AbortError') {
                    // L'user a fermé la modal pendant le probe — comportement attendu.
                    return;
                }
                // Fix #3 (d) — offline / réseau.
                _setProgressIndeterminate(false);
                $('improve-progress-fill').style.width = '0%';
                $('improve-status').textContent =
                    (typeof navigator !== 'undefined' && navigator.onLine === false)
                        ? 'Hors-ligne. Réessaye une fois reconnecté.'
                        : 'Erreur réseau lors du probe LLM local.';
                state.improveInFlight = false;
                hide($('modal-improve-cancel'));
                return;
            }

            // Étape 4 — Loop chunks. Pas de cap total — l'user peut traiter
            // une liste de taille infinie (contrat V5+V6).
            var tokens = eligibleTerms.map(function(t) { return t.term; });
            var processed = 0;
            var totalUpdated = 0;
            var totalSkippedCustom = 0;
            var totalSkippedInvalid = 0;
            var totalSkippedNumeric = 0;
            var totalSkippedStateChanged = 0;
            // #97 — termes non traités (budget LLM local épuisé sur le chunk).
            // Sans ce compteur, le recap affichait « Terminé » alors que ces
            // termes restaient au libellé générique (données fausses).
            var totalUnprocessed = 0;
            $('improve-progress-bar').setAttribute('aria-valuenow', '0');

            // Modèle d'affichage : "Analyse de N termes via <model> | X/N traités, Y améliorés"
            function _renderStatus() {
                var pct = tokens.length > 0
                    ? Math.floor((100 * processed) / tokens.length)
                    : 0;
                $('improve-progress-fill').style.width = pct + '%';
                $('improve-progress-bar').setAttribute('aria-valuenow', String(pct));
                var modelSuffix = modelName ? (' via ' + modelName) : '';
                $('improve-status').textContent =
                    'Traité : ' + processed + '/' + tokens.length +
                    ' (' + totalUpdated + ' amélioré' + (totalUpdated > 1 ? 's' : '') +
                    ', ' + totalSkippedCustom + ' déjà personnalisé' + (totalSkippedCustom > 1 ? 's' : '') +
                    ', ' + totalSkippedInvalid + ' label rejeté' + (totalSkippedInvalid > 1 ? 's' : '') +
                    ')' + modelSuffix + '.';
            }

            for (var i = 0; i < tokens.length; i += batchSize) {
                if (!state.improveInFlight) break; // aborted
                var chunk = tokens.slice(i, i + batchSize);
                // Indique au user qu'on attend le LLM (durée réelle :
                // 30s-3min selon modèle/CPU). Fix UX 2026-05-20 : avant,
                // le statut restait sur "Connexion au LLM local…" pendant
                // toute l'attente, ce qui était trompeur (la connexion
                // est instant, c'est la GÉNÉRATION qui prend du temps).
                var chunkEnd = Math.min(i + chunk.length, tokens.length);
                var modelSuffixWait = modelName ? (' via ' + modelName) : '';
                $('improve-status').textContent =
                    'Analyse en cours' + modelSuffixWait + ' — termes '
                    + (i + 1) + '–' + chunkEnd + ' / ' + tokens.length
                    + ' (peut prendre 30s à 3 min sur CPU)…';
                try {
                    var resp = await fetch('/api/anonymization/improve-pseudo', {
                        method: 'POST',
                        headers: {
                            'X-Xsrftoken': deps.getXsrf(),
                            'Content-Type': 'application/json',
                            'X-Requested-With': 'XMLHttpRequest',
                        },
                        credentials: 'same-origin',
                        body: JSON.stringify({ tokens: chunk }),
                        signal: state.controller.signal,
                    });
                    if (!resp.ok) {
                        if (resp.status === 503) {
                            $('improve-status').textContent =
                                'LLM local indisponible pendant le traitement. Vérifie /admin/ai-config.';
                        } else if (resp.status >= 500) {
                            $('improve-status').textContent =
                                'Erreur serveur (' + resp.status + '). Arrêt du traitement.';
                        } else if (resp.status === 401) {
                            $('improve-status').textContent = 'Session expirée.';
                        } else {
                            $('improve-status').textContent =
                                'Erreur (' + resp.status + ') au chunk ' + (i / batchSize + 1) + '.';
                        }
                        break;
                    }
                    var data = await resp.json();
                    var updated = Array.isArray(data.updated) ? data.updated : [];
                    totalUpdated += updated.length;
                    totalSkippedCustom += Number(data.skipped_custom) || 0;
                    totalSkippedInvalid += Number(data.skipped_invalid_label) || 0;
                    totalSkippedNumeric += Number(data.skipped_numeric) || 0;
                    totalSkippedStateChanged += Number(data.skipped_state_changed) || 0;
                    totalUnprocessed += Number(data.skipped_unprocessed) || 0;
                    // Refresh UI en temps réel.
                    if (typeof deps.refreshTerm === 'function') {
                        for (var u = 0; u < updated.length; u++) {
                            deps.refreshTerm(updated[u].term, updated[u].new_pseudo_middle);
                        }
                    }
                    processed += chunk.length;
                    // À partir du 1er chunk reçu, bascule en progress déterminé.
                    _setProgressIndeterminate(false);
                    _renderStatus();
                    // Si le serveur renvoie un status != "ok" (timeout/error
                    // LLM), on continue avec les chunks suivants — best-effort.
                    // Le frontend log juste l'info pour observabilité.
                    if (data.status && data.status !== 'ok') {
                        // eslint-disable-next-line no-console
                        console.warn('[improve-pseudo] chunk status=' + data.status,
                            data.message || '');
                    }
                } catch (err2) {
                    if (err2 && err2.name === 'AbortError') {
                        // User a fermé la modal — sortie propre.
                        $('improve-status').textContent =
                            'Arrêté à ' + processed + '/' + tokens.length + ' (' + totalUpdated + ' amélioré(s)).';
                        break;
                    }
                    // Fix #3 (d) — offline / réseau.
                    $('improve-status').textContent =
                        (typeof navigator !== 'undefined' && navigator.onLine === false)
                            ? 'Hors-ligne — arrêt à ' + processed + '/' + tokens.length + '.'
                            : 'Erreur réseau au chunk ' + (i / batchSize + 1) + '.';
                    break;
                }
            }

            // Étape 5 — Cleanup + recap final.
            state.improveInFlight = false;
            _setProgressIndeterminate(false);
            hide($('modal-improve-cancel'));
            // Bouton "Fermer" final (re-label de #modal-improve-cancel).
            $('modal-improve-cancel').textContent = 'Fermer';
            show($('modal-improve-cancel'));
            if (processed >= tokens.length) {
                $('improve-progress-fill').style.width = '100%';
                // #97 — si des termes n'ont PAS pu être traités (budget LLM
                // local épuisé), ne PAS prétendre « Terminé » : la campagne est
                // partielle et un re-clic les complétera. Sinon l'user croit ces
                // termes finaux alors qu'ils sont restés au libellé générique.
                $('improve-status').textContent =
                    (totalUnprocessed > 0 ? 'Terminé (partiel) : ' : 'Terminé : ') +
                    totalUpdated + '/' + tokens.length +
                    ' pseudonyme(s) amélioré(s)' +
                    (totalSkippedCustom > 0 ? ' (' + totalSkippedCustom + ' déjà personnalisé(s) préservé(s))' : '') +
                    (totalSkippedInvalid > 0 ? ', ' + totalSkippedInvalid + ' label(s) rejeté(s) (fallback sémantique)' : '') +
                    (totalSkippedNumeric > 0 ? ', ' + totalSkippedNumeric + ' numérique(s) ignoré(s) (aucune sémantique à améliorer)' : '') +
                    (totalSkippedStateChanged > 0 ? ', ' + totalSkippedStateChanged + ' modifié(s) en parallèle par un autre onglet' : '') +
                    (totalUnprocessed > 0 ? ', ' + totalUnprocessed + ' non traité(s) (budget du modèle local atteint — relancez pour les compléter)' : '') +
                    '.';
            }
            if (typeof deps.onComplete === 'function') {
                try { deps.onComplete(); } catch (_e) { /* swallow */ }
            }
        }

        // Expose API publique.
        window.PrivacyImprovePseudos = {
            openAndStartImprove: openAndStartImprove,
            closeModal: closeModal,
            isImproving: function() { return state.improveInFlight; },
        };
    }

    _attachBrowser();

    // Exports Node (tests purs — pas de DOM requis).
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = {
            // Pas d'helpers purs exposés ici — le module est principalement
            // DOM-driven. Les tests utilisent un mock document/window.
        };
    }
})();
