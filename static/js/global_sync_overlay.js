/**
 * global_sync_overlay.js — Overlay global "Sync schéma en cours" branché
 * sur le SSE ``/api/system/events``. Inclus dans ``base.html`` pour tous
 * les utilisateurs authentifiés.
 *
 * Comportement :
 * - Au boot : (1) ``connect()`` SSE d'abord (subscribe au bus), puis
 *   (2) snapshot synchrone via ``GET /api/system/sync-status``. L'ordre
 *   compte — il évite la race "sync qui finit pile entre le fetch et le
 *   subscribe SSE" (sinon le client raterait le ``done`` event et
 *   afficherait un overlay infini avec un état périmé).
 * - L'event bus n'a pas de replay : un client qui se reconnecte après un
 *   event le rate. Le snapshot REST comble ce trou pour la phase
 *   ``view_mining`` (~14 s sans progress) et ``fts5_rebuild`` (long, peu
 *   d'events). Le serveur expose aussi ``just_completed`` pour replayer
 *   un ``done`` récent (<30 s).
 * - Sur ``schema_sync.started`` → afficher l'overlay (spinner, 0%) +
 *   reset du flag ``userDismissed`` (un nouveau sync re-affiche, même si
 *   l'utilisateur avait fermé l'overlay du sync précédent).
 * - Sur ``schema_sync.progress`` → mettre à jour barre + step + message.
 * - Sur ``schema_sync.done`` → swap spinner pour check vert, montrer
 *   "Fermer", auto-close 3s plus tard si user ne clique pas. Force
 *   ``show()`` au cas où l'overlay était caché (page rechargée pendant
 *   un sync long et silencieux). Si l'utilisateur a déjà cliqué "Fermer"
 *   pendant la sync (``userDismissed`` true), on respecte son choix —
 *   pas de réouverture forcée.
 *
 * Idempotent : si l'overlay est déjà visible (autre tab du même user, ou
 * recharge en plein milieu d'un sync), un nouvel event ``progress`` met
 * juste à jour. Pas de double-affichage.
 */
(function () {
    'use strict';

    var overlay = document.getElementById('globalSyncOverlay');
    if (!overlay) return;  // partial non inclus → no-op

    var spinner = document.getElementById('globalSyncSpinner');
    var doneIcon = document.getElementById('globalSyncDoneIcon');
    var msg = document.getElementById('globalSyncMessage');
    var stepEl = document.getElementById('globalSyncStep');
    var pctEl = document.getElementById('globalSyncPercent');
    var bar = document.getElementById('globalSyncBar');
    var closeBtn = document.getElementById('globalSyncCloseBtn');
    // Admin only : rendu côté SSR uniquement si ``current_user.role == admin``
    // (cf. partial). Côté JS on tolère l'absence → user non-admin, no-op.
    var cancelBtn = document.getElementById('globalSyncCancelBtn');
    // Zone de statut dédiée au cancel — sans elle, les messages d'erreur du
    // cancel sont écrasés en <1s par le prochain ``schema_sync.progress``
    // qui écrit dans ``globalSyncMessage`` (MOY-1 review).
    var cancelStatusEl = document.getElementById('globalSyncCancelStatus');

    // Flag : un event SSE a-t-il déjà été reçu depuis le boot ? Sert à
    // ignorer un snapshot REST qui arriverait APRÈS un event SSE déjà
    // appliqué (race init fetch vs SSE). On préfère toujours l'event live.
    var sseEventReceived = false;

    // Flag : l'utilisateur a-t-il cliqué "Fermer" pendant la sync en cours ?
    // Permet de respecter son choix sur les events suivants (notamment
    // ``done``). Reset à false au prochain ``started`` — un nouveau cycle
    // de sync mérite d'être affiché.
    var userDismissed = false;

    // ID du setTimeout d'auto-close — capturé pour pouvoir clearTimeout si
    // un nouveau ``started`` arrive avant l'expiration (cas pathologique :
    // 2 syncs rapprochés, le reset post-done écraserait le state du nouveau).
    var autoCloseTimerId = null;

    // Flag anti double-clic + état "cancel demandé". Reset à false au prochain
    // ``started`` (nouveau cycle de sync) OU au ``done`` (sync terminée). Tant
    // que ``cancelling`` est true on cache le bouton et on ignore les re-clics.
    var cancelling = false;

    function show() { overlay.classList.remove('hidden'); }
    function hide() { overlay.classList.add('hidden'); }

    function clampPercent(p) {
        // Défense en profondeur — si jamais le backend émet un percent
        // hors-bornes (corruption, bug futur), la bar visuelle reste sane.
        var n = Number(p);
        if (!isFinite(n)) return 0;
        if (n < 0) return 0;
        if (n > 100) return 100;
        return n;
    }

    function setProgress(step, percent, message) {
        var p = clampPercent(percent);
        if (stepEl) stepEl.textContent = String(step || '');
        if (pctEl) pctEl.textContent = String(Math.round(p)) + '%';
        if (bar) bar.style.width = p + '%';
        if (msg) msg.textContent = String(message || '');
    }

    function setCancelButtonState(state) {
        // state ∈ {'idle','pending','hidden'}. ``idle`` : bouton dispo
        // (sync active, admin peut cliquer). ``pending`` : cancel envoyé,
        // bouton désactivé visuellement, attend le ``done``. ``hidden`` :
        // pas de sync active OU sync terminée.
        if (!cancelBtn) return;
        if (state === 'hidden') {
            cancelBtn.classList.add('hidden');
            cancelBtn.disabled = false;
            cancelBtn.textContent = 'Annuler';
            return;
        }
        cancelBtn.classList.remove('hidden');
        if (state === 'pending') {
            cancelBtn.disabled = true;
            cancelBtn.textContent = 'Annulation…';
        } else {
            cancelBtn.disabled = false;
            cancelBtn.textContent = 'Annuler';
        }
    }

    function setCancelStatus(text) {
        // ``null``/``''`` → hide. Sinon écrit le message persistant dans la
        // zone dédiée — survivra au prochain ``progress`` (contrairement à
        // ``globalSyncMessage``).
        if (!cancelStatusEl) return;
        if (!text) {
            cancelStatusEl.textContent = '';
            cancelStatusEl.classList.add('hidden');
            return;
        }
        cancelStatusEl.textContent = String(text);
        cancelStatusEl.classList.remove('hidden');
    }

    // Petit helper interne — récupère le cookie XSRF de manière idempotente.
    // Le SSOT global est ``iris-common.js::getCookie`` mais il n'est pas
    // chargé sur toutes les pages (uniquement hors /iris). On évite une
    // dépendance fragile en réimplémentant inline (3 lignes).
    function getXsrfCookie() {
        var m = (document.cookie || '').match(/(?:^|;\s*)_xsrf=([^;]+)/);
        return m ? decodeURIComponent(m[1]) : '';
    }

    function cancelAutoClose() {
        if (autoCloseTimerId !== null) {
            clearTimeout(autoCloseTimerId);
            autoCloseTimerId = null;
        }
    }

    function showDone() {
        // Reset état cancel : le ``done`` event arrive après cancel ET après
        // succès — dans les 2 cas le sync n'est plus active, donc plus
        // d'action possible. Bouton caché + statut cancel effacé.
        cancelling = false;
        setCancelButtonState('hidden');
        setCancelStatus(null);
        // Respect du choix utilisateur : s'il a cliqué "Fermer" pendant la
        // sync, on ne le force pas à revoir l'overlay au done.
        if (userDismissed) return;
        // Garantit l'affichage : si la page a été chargée APRÈS le
        // ``schema_sync.started`` et qu'aucun progress n'est passé entre
        // temps (phase silencieuse), l'overlay était caché et le user
        // n'aurait jamais vu la complétion.
        show();
        if (spinner) spinner.classList.add('hidden');
        if (doneIcon) doneIcon.classList.remove('hidden');
        if (closeBtn) closeBtn.classList.remove('hidden');
        if (msg) msg.textContent = 'Synchronisation terminée';
        if (pctEl) pctEl.textContent = '100%';
        if (bar) bar.style.width = '100%';
        // Auto-fermeture 3s — user peut cliquer "Fermer" avant. On capture
        // l'ID pour pouvoir clear si un nouveau ``started`` arrive avant.
        cancelAutoClose();
        autoCloseTimerId = setTimeout(function () {
            // Garde anti-race (FAIBLE-2 review) : si ``cancelAutoClose()``
            // a été appelée entre le schedule et l'exec (race rare sur
            // certains browsers où clearTimeout perd contre une tick déjà
            // enqueuée), on no-op pour ne pas écraser l'état "started" du
            // sync suivant.
            if (autoCloseTimerId === null) return;
            autoCloseTimerId = null;
            hide();
            // Reset pour la prochaine fois.
            if (spinner) spinner.classList.remove('hidden');
            if (doneIcon) doneIcon.classList.add('hidden');
            if (closeBtn) closeBtn.classList.add('hidden');
            setProgress('start', 0, 'Initialisation...');
        }, 3000);
    }

    if (closeBtn) {
        closeBtn.addEventListener('click', function () {
            userDismissed = true;
            cancelAutoClose();
            hide();
            if (spinner) spinner.classList.remove('hidden');
            if (doneIcon) doneIcon.classList.add('hidden');
            closeBtn.classList.add('hidden');
            // Reset état cancel pour ne pas bloquer le bouton sur un futur
            // cycle dans des scénarios multi-tab/multi-action (MOY-3 review).
            cancelling = false;
            setCancelButtonState('hidden');
            setCancelStatus(null);
        });
    }

    // ── Bouton « Annuler » (admin only) ─────────────────────────────────
    // Le bouton n'existe dans le DOM que pour les admins (cf. partial
    // Jinja). Pour les non-admins, ``cancelBtn`` est null → no-op total.
    // Côté serveur l'endpoint est ``@admin_required`` → defense-in-depth.
    if (cancelBtn) {
        cancelBtn.addEventListener('click', function () {
            // Anti double-clic — un cancel en vol bloque les suivants.
            if (cancelling) return;
            cancelling = true;
            setCancelButtonState('pending');
            setCancelStatus(null);

            // ``fetch`` plutôt que XHR pour profiter du wrap network-status.js
            // (retry auto + détection 401 → redirect login). Headers XSRF
            // requis par Tornado pour les méthodes non-safe.
            var headers = {};
            var xsrf = getXsrfCookie();
            if (xsrf) headers['X-Xsrftoken'] = xsrf;

            // ``fetch`` peut throw SYNCHRONE (URL malformée, blocked by CSP,
            // browser shutdown). Sans ce ``try``, ``cancelling`` resterait à
            // ``true`` indéfiniment (jusqu'au prochain ``started``) — bouton
            // bloqué à "Annulation…" en permanence (MOY-2 review).
            var pending;
            try {
                pending = fetch('/api/ai/schema/sync', {
                    method: 'DELETE',
                    credentials: 'same-origin',
                    headers: headers
                });
            } catch (syncErr) {
                cancelling = false;
                setCancelButtonState('idle');
                setCancelStatus('Erreur d’envoi : ' + (syncErr && syncErr.message ? syncErr.message : 'requête bloquée'));
                return;
            }

            pending.then(function (r) {
                if (r.status === 204) {
                    // Cancel envoyé côté backend. Le service va vérifier
                    // ``_cancelled()`` au prochain check et stopper.
                    // On reste en état ``pending`` : c'est le ``schema_sync.done``
                    // event qui finalisera l'UI (showDone → bouton hidden).
                    setCancelStatus('Annulation envoyée — arrêt en cours…');
                    return;
                }
                if (r.status === 404) {
                    // Aucune sync active — soit le ``done`` est arrivé pile
                    // avant notre DELETE (race timing), soit l'état UI était
                    // stale. On réinitialise sans afficher d'erreur agressive.
                    cancelling = false;
                    setCancelButtonState('hidden');
                    return;
                }
                if (r.status === 401 || r.status === 403) {
                    // Session expirée ou rôle révoqué. ``session-status.js``
                    // intercepte normalement le 401 pour rediriger. Si pas
                    // chargé, on signale au user via la zone sticky.
                    cancelling = false;
                    setCancelButtonState('idle');
                    setCancelStatus('Session expirée — reconnectez-vous.');
                    return;
                }
                // 5xx ou autre : on rétablit le bouton pour permettre un
                // retry manuel. Le sync continue côté serveur. Message
                // sticky dans la zone dédiée (sinon écrasé < 1s par le
                // prochain ``progress`` event SSE — MOY-1 review).
                cancelling = false;
                setCancelButtonState('idle');
                setCancelStatus('Échec de l’annulation (' + r.status + '). Réessayez.');
            }).catch(function () {
                // Erreur réseau côté fetch — même politique que 5xx.
                cancelling = false;
                setCancelButtonState('idle');
                setCancelStatus('Connexion perdue — réessayez l’annulation.');
            });
        });
    }

    /**
     * Snapshot REST de l'état sync — appelé au boot pour rattraper une
     * sync en cours OU un sync tout juste terminé (``just_completed``
     * couvre la fenêtre de race "fetch arrive juste après le done").
     * Fail-silent : si l'endpoint répond 401/500 ou si le réseau est
     * down, on n'affiche rien et on laisse le SSE prendre le relais.
     */
    function loadInitialSnapshot() {
        if (typeof fetch !== 'function') return;
        fetch('/api/system/sync-status', {
            credentials: 'same-origin',
            headers: { 'Accept': 'application/json' }
        }).then(function (r) {
            if (!r || !r.ok) return null;
            return r.json();
        }).then(function (data) {
            // Si un event SSE est déjà arrivé entre temps, il fait foi.
            if (!data || sseEventReceived) return;
            if (data.active) {
                setProgress(data.step, data.percent, data.message);
                if (spinner) spinner.classList.remove('hidden');
                if (doneIcon) doneIcon.classList.add('hidden');
                if (closeBtn) closeBtn.classList.add('hidden');
                // Sync active découverte par snapshot → admin peut annuler.
                // ``cancelling`` n'est pas re-set ici : un refresh page perd
                // l'état UI précédent et démarre propre.
                cancelling = false;
                setCancelButtonState('idle');
                show();
            } else if (data.just_completed) {
                // Le ``done`` event est passé avant qu'on subscribe au bus —
                // on rejoue la complétion pour cohérence visuelle.
                showDone();
            }
        }).catch(function () { /* silent — fail-soft, SSE prendra le relais */ });
    }

    var es = null;
    function connect() {
        try {
            es = new EventSource('/api/system/events');
        } catch (e) {
            // EventSource pas supporté ou bloqué — silencieux.
            return;
        }
        es.onmessage = function (ev) {
            if (!ev || !ev.data) return;
            var payload;
            try { payload = JSON.parse(ev.data); } catch (e) { return; }
            if (!payload || !payload.type) return;
            sseEventReceived = true;
            switch (payload.type) {
                case 'schema_sync.started':
                    // Nouveau cycle → respecter aucun choix de fermeture
                    // précédent + cancel le reset planifié du done précédent
                    // (sinon la barre repasse à 0% pile pendant le started).
                    userDismissed = false;
                    cancelling = false;
                    cancelAutoClose();
                    setProgress('start', 0, 'Synchronisation démarrée...');
                    setCancelStatus(null);
                    if (spinner) spinner.classList.remove('hidden');
                    if (doneIcon) doneIcon.classList.add('hidden');
                    if (closeBtn) closeBtn.classList.add('hidden');
                    setCancelButtonState('idle');
                    show();
                    break;
                case 'schema_sync.progress':
                    var d = payload.data || {};
                    setProgress(d.step, d.percent, d.message);
                    // Sync active → bouton annuler dispo (sauf si déjà
                    // en cours d'annulation, on garde ``pending``).
                    if (!cancelling) setCancelButtonState('idle');
                    if (!userDismissed) {
                        show();  // au cas où le ``started`` a été manqué (recharge)
                    }
                    break;
                case 'schema_sync.done':
                    showDone();
                    break;
                default:
                    // Autres events système ignorés — extensible plus tard.
                    break;
            }
        };
        es.onerror = function () {
            // Le serveur a fait `retry: 5000` — le browser reconnecte tout
            // seul. On ferme juste pour libérer la connexion socket actuelle.
            if (es) {
                try { es.close(); } catch (e) { /* ignore */ }
                es = null;
            }
            setTimeout(connect, 5000);
        };
    }

    function boot() {
        // Ordre critique : SSE d'abord pour subscribe au bus, PUIS snapshot
        // REST. Inverser ferait rater un ``done`` qui survient pendant le
        // fetch (le client n'est pas encore subscribed → l'event est perdu).
        connect();
        loadInitialSnapshot();
    }

    // Cleanup explicite à la navigation : ferme l'EventSource pour libérer
    // immédiatement le slot HTTP/1.1 (limite browser : 6 connexions/domaine).
    // Sans ce cleanup, la SSE reste en "zombie" côté browser pendant que la
    // nouvelle page ouvre sa propre SSE → 2 slots consommés en parallèle
    // pendant le TCP timeout côté serveur, ralentissant tous les fetches
    // de la nouvelle page (filters, sync-status, etc.).
    //
    // ``pagehide`` couvre aussi le bfcache (Firefox/Safari mettent en cache
    // les pages — ``beforeunload`` ne se déclenche pas dans ce cas).
    function cleanup() {
        if (es) {
            try { es.close(); } catch (e) { /* ignore */ }
            es = null;
        }
    }
    window.addEventListener('pagehide', cleanup);
    window.addEventListener('beforeunload', cleanup);

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', boot);
    } else {
        boot();
    }
})();
