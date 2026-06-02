/* eslint-env browser */
/* global GridTabManager */
/**
 * Komptia — Preview d'étape sur /automations/N/edit
 *
 * Expose un bouton "▶ Apercu" dans le panel config de l'automation
 * editor : sur clic, exécute le step (et ses parents en cascade) via
 * la WebSocket /ws/automations/:id/preview, puis affiche le résultat
 * dans la zone du bas (#komptia-preview-area).
 *
 * Patterns repris de iris.js :
 *  - XSRF: token frais via GET /api/auth/xsrf, query-param `_xsrf`
 *  - Reconnexion exponential backoff
 *  - Codes 4001/4003 = fatals → reload une fois
 *
 * Pas de dépendance jQuery / framework. Pas de eval. Pas d'innerHTML
 * sur du contenu serveur — toujours textContent + DOM.
 */
(function () {
    'use strict';

    // A7-M14 : taille de l'échantillon preview. DOIT correspondre au texte du
    // hint « N lignes maximum » — sinon promesse non tenue (le hint annonçait
    // 100 mais le preview tirait jusqu'au cap admin, ex 10000+). Source unique.
    var PREVIEW_MAX_ROWS = 100;

    // window.komptiaCanvas expose une API plate (cf. automation-canvas.js
    // bloc "API publique") : getAutomationId, getStepById, setNodeStatus,
    // on, off. La variable est assignee par `setup()` (DOMContentLoaded
    // + event 'komptia-canvas-ready') car `initCanvas` est async — au
    // moment ou cette IIFE tourne, `window.komptiaCanvas` n'existe pas
    // encore meme sur la bonne page. Le rename "editor" → "canvas"
    // serait plus explicite mais multiplie le diff inutilement.
    var editor = null;

    // ── Helpers DOM / XSRF ───────────────────────────────────────

    function getCookie(name) {
        var value = '; ' + document.cookie;
        var parts = value.split('; ' + name + '=');
        if (parts.length === 2) return parts.pop().split(';').shift();
        return '';
    }

    /**
     * Conversion safe en string — on rebaptise l'ancien `escapeText` qui
     * faisait juste un cast (trompeur : un dev pouvait croire qu'il avait
     * échappé du HTML, et faire ensuite `innerHTML += toText(value)` =
     * XSS direct). Cette fonction NE FAIT PAS d'escape — on l'utilise
     * uniquement avec `el(..., { text: ... })` qui passe par textContent.
     */
    function toText(s) {
        if (s === null || s === undefined) return '';
        return String(s);
    }

    /**
     * Helper de création DOM. Volontairement SANS branche `html` (la
     * version précédente acceptait `{html: ...}` qui faisait `innerHTML =`
     * — anti-pattern : un dev pouvait laisser passer une variable au
     * lieu d'une string statique). Pour les icônes Bootstrap, créer un
     * sous-élément `<i class="bi bi-...">` séparé.
     */
    function el(tag, attrs, children) {
        var node = document.createElement(tag);
        if (attrs) {
            for (var k in attrs) {
                if (!Object.prototype.hasOwnProperty.call(attrs, k)) continue;
                if (k === 'class') node.className = attrs[k];
                else if (k === 'text') node.textContent = attrs[k];
                else if (
                    k.indexOf('data-') === 0
                    || k === 'role'
                    || k === 'aria-label'
                    || k === 'aria-live'
                    || k === 'aria-hidden'
                    || k === 'aria-expanded'
                ) {
                    node.setAttribute(k, attrs[k]);
                }
                else node[k] = attrs[k];
            }
        }
        if (children) {
            for (var i = 0; i < children.length; i += 1) {
                if (children[i] === null || children[i] === undefined) continue;
                if (typeof children[i] === 'string') node.appendChild(document.createTextNode(children[i]));
                else node.appendChild(children[i]);
            }
        }
        return node;
    }

    function bsIcon(name) {
        return el('i', { class: 'bi ' + name, 'aria-hidden': 'true' });
    }

    async function refreshXsrfToken() {
        try {
            var res = await fetch('/api/auth/xsrf', {
                method: 'GET',
                credentials: 'same-origin',
                headers: { 'X-Requested-With': 'XMLHttpRequest' },
            });
            if (!res.ok) return null;
            var data = await res.json();
            return data && data.token ? data.token : getCookie('_xsrf');
        } catch (_) {
            return getCookie('_xsrf');
        }
    }

    // ── State module ─────────────────────────────────────────────

    var state = {
        ws: null,
        wsConnecting: false,
        reconnectDelay: 1000,
        reconnectTimer: null,
        currentRunStepId: null,
        // step_id → derniers résultats reçus (pour ré-affichage si user
        // re-sélectionne un step déjà preview). Réinitialisé au reload.
        resultsByStep: Object.create(null),
        running: false,
        // step_id → status courant (running/success/failed/null)
        nodeStatuses: Object.create(null),
        wsFatal: false,  // 4001/4003 reçu → on n'essaie plus de reconnecter
        wsReconnectAttempts: 0,
        wsOfflineMode: false,  // après N échecs, on s'arrête et on attend un retry manuel
        // Cluster-P 2026-05-26 — Heartbeat (ping/pong) :
        // - `pingTimer` : interval ID qui send {action:'ping'} toutes les
        //   PING_INTERVAL_MS (25s) tant que la WS est OPEN.
        // - `lastPongAt` : timestamp du dernier pong reçu (ms epoch).
        //   Si > PONG_TIMEOUT_MS sans pong → WS zombie (proxy a coupé
        //   silencieusement), on force close + scheduleReconnect.
        // - `wasOffline` : flag pour afficher un toast au retour online
        //   (pas de notif inutile au premier open).
        pingTimer: null,
        lastPongAt: 0,
        wasOffline: false,
    };

    var MAX_WS_RECONNECT_ATTEMPTS = 5;
    // Cluster-P — Constantes heartbeat. Le défaut 25s est conservateur :
    // les proxies ALB AWS / Nginx default ont un idle timeout de 60s, et
    // CloudFlare WS default à 100s. 25s laisse une marge confortable et
    // limite la charge serveur (1 message/25s par client).
    var PING_INTERVAL_MS = 25000;
    // Si 2 pings d'affilée sans réponse (= 60s mort), on considère le WS
    // zombie. Plus court que reconnect-delay-max (30s) pour pousser la
    // détection plus tôt.
    var PONG_TIMEOUT_MS = 60000;

    // ── DOM refs (résolus au DOMContentLoaded) ───────────────────

    var dom = {};

    function bindDom() {
        dom.area = document.getElementById('komptia-preview-area');
        dom.body = document.getElementById('komptia-preview-body');
        dom.meta = document.getElementById('komptia-preview-meta');
        dom.collapseBtn = document.getElementById('komptia-preview-collapse-btn');
        dom.closeBtn = document.getElementById('komptia-preview-close-btn');
        dom.panelForm = document.getElementById('komptia-panel-form');
        dom.root = document.getElementById('komptia-edit-root');
    }

    function showArea() {
        if (!dom.area) return;
        dom.area.hidden = false;
        dom.area.classList.remove('komptia-preview-collapsed');
    }

    function collapseArea() {
        if (!dom.area) return;
        dom.area.classList.toggle('komptia-preview-collapsed');
    }

    function hideArea() {
        if (!dom.area) return;
        dom.area.hidden = true;
    }

    function setMeta(text) {
        if (dom.meta) dom.meta.textContent = text || '';
    }

    function clearBody() {
        if (dom.body) dom.body.innerHTML = '';
    }

    // ── WebSocket plomberie ──────────────────────────────────────

    async function connectWS() {
        if (state.wsFatal) return;
        if (state.wsConnecting || (state.ws && state.ws.readyState === 1)) return;
        state.wsConnecting = true;

        var automationId = editor.getAutomationId();
        if (!automationId) {
            state.wsConnecting = false;
            return;
        }

        var token = await refreshXsrfToken();
        if (!token) token = getCookie('_xsrf');

        var proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        var url = proto + '//' + window.location.host + '/ws/automations/' + automationId + '/preview';
        if (token) url += '?_xsrf=' + encodeURIComponent(token);

        try {
            state.ws = new WebSocket(url);
        } catch (_) {
            state.wsConnecting = false;
            scheduleReconnect();
            return;
        }

        state.ws.onopen = function () {
            state.wsConnecting = false;
            state.reconnectDelay = 1000;
            state.wsReconnectAttempts = 0;
            state.wsOfflineMode = false;
            // Cluster-P 2026-05-26 — Démarre le heartbeat ping/pong.
            // Sans ça, les proxies (ALB/Nginx) coupent la WS après 60-300s
            // d'inactivité → preview qui semble figé sans erreur.
            startHeartbeat();
            // Notif retour online uniquement si on a déjà été offline.
            if (state.wasOffline) {
                state.wasOffline = false;
                if (typeof window.showToast === 'function') {
                    window.showToast('Connexion preview rétablie', 'success');
                }
            }
        };
        state.ws.onmessage = function (ev) {
            var payload;
            try { payload = JSON.parse(ev.data); } catch (_) { return; }
            // Cluster-P — pong reçu = WS vivante, MAJ timestamp.
            if (payload && payload.type === 'pong') {
                state.lastPongAt = Date.now();
                return;
            }
            handleWsEvent(payload);
        };
        state.ws.onclose = function (ev) {
            state.wsConnecting = false;
            // Cluster-P — arrête le heartbeat (sinon il continue à tourner
            // sur un WS fermé, gaspille un setInterval handle par close).
            stopHeartbeat();
            if (ev.code === 4001 || ev.code === 4003) {
                state.wsFatal = true;
                renderError({
                    category: 'auth',
                    message: 'Session expirée. Rechargez la page pour continuer.',
                });
                return;
            }
            if (state.running) {
                renderError({
                    category: 'network',
                    message: 'Connexion WebSocket interrompue. Reconnexion en cours…',
                });
                state.running = false;
                applyStatus(state.currentRunStepId, 'failed');
            }
            // Cluster-P — flag pour notifier au retour online.
            state.wasOffline = true;
            scheduleReconnect();
        };
        state.ws.onerror = function () {
            // Les détails partent dans onclose ; ici on log simplement.
            try { console.warn('komptia preview ws: error event'); } catch (_) { /* ignore */ }
        };
    }

    function scheduleReconnect() {
        if (state.wsFatal || state.wsOfflineMode) return;
        if (state.reconnectTimer) clearTimeout(state.reconnectTimer);
        state.reconnectAttempts = (state.reconnectAttempts || 0) + 1;
        if (state.wsReconnectAttempts >= MAX_WS_RECONNECT_ATTEMPTS) {
            state.wsOfflineMode = true;
            renderOffline();
            return;
        }
        state.wsReconnectAttempts += 1;
        state.reconnectTimer = setTimeout(function () {
            state.reconnectDelay = Math.min(state.reconnectDelay * 2, 30000);
            connectWS();
        }, state.reconnectDelay);
    }

    function renderOffline() {
        showArea();
        clearBody();
        var msg = el('div', {
            text: 'Connexion impossible après plusieurs tentatives. Vérifiez votre réseau.',
        });
        var retry = el('button', { type: 'button', text: 'Réessayer' });
        retry.addEventListener('click', function () {
            state.wsOfflineMode = false;
            state.wsReconnectAttempts = 0;
            state.reconnectDelay = 1000;
            connectWS();
            renderLoading('Reconnexion…');
        });
        var actions = el('div', { class: 'komptia-preview-error-actions' }, [retry]);
        dom.body.appendChild(
            el('div', { class: 'komptia-preview-error', role: 'alert' }, [msg, actions])
        );
    }

    function sendWs(payload) {
        if (!state.ws || state.ws.readyState !== 1) return false;
        try {
            state.ws.send(JSON.stringify(payload));
            return true;
        } catch (_) {
            return false;
        }
    }

    // ── Cluster-P 2026-05-26 — Heartbeat ping/pong ────────────────
    // Send `{action:'ping'}` toutes les PING_INTERVAL_MS. Le serveur
    // répond `{type:'pong', ts}`. Si pas de pong depuis PONG_TIMEOUT_MS,
    // on force close → onclose déclenche scheduleReconnect. Évite le cas
    // « WS zombie » : TCP côté client encore ouvert mais le proxy ALB/Nginx
    // a déjà fermé sa moitié → write_message échoue silencieusement, le
    // user voit un preview qui ne répond plus mais aucune erreur dans
    // l'UI. Avec heartbeat, on détecte ça en < 60s.

    function startHeartbeat() {
        stopHeartbeat();  // safety : pas de double interval
        state.lastPongAt = Date.now();  // baseline init
        state.pingTimer = setInterval(function () {
            if (!state.ws || state.ws.readyState !== 1) {
                stopHeartbeat();
                return;
            }
            // Liveness check : pas de pong depuis trop longtemps =
            // zombie. On force close, onclose va scheduleReconnect.
            var sincePong = Date.now() - state.lastPongAt;
            if (sincePong > PONG_TIMEOUT_MS) {
                try { state.ws.close(4000, 'Heartbeat timeout'); } catch (_) {}
                return;
            }
            sendWs({ action: 'ping' });
        }, PING_INTERVAL_MS);
    }

    function stopHeartbeat() {
        if (state.pingTimer) {
            clearInterval(state.pingTimer);
            state.pingTimer = null;
        }
    }

    // ── Event router ──────────────────────────────────────────────

    function handleWsEvent(ev) {
        switch (ev.type) {
            case 'ready':
                return;
            case 'preview_start':
                state.running = true;
                state.currentRunStepId = ev.step_id;
                applyStatus(ev.step_id, 'running');
                renderLoading('Démarrage…');
                return;
            case 'preview_progress':
                applyStatus(ev.step_id, 'running');
                renderLoading(ev.message || 'En cours…');
                return;
            case 'preview_step_result':
                state.resultsByStep[ev.step_id] = ev;
                state.resultsByStepOrder = state.resultsByStepOrder || [];
                // LRU cap 10 — un user qui preview 50 noeuds différents
                // sans toucher la config sinon retiendrait 50 workbooks
                // en RAM (M8). On évince le plus ancien.
                var orderIdx = state.resultsByStepOrder.indexOf(ev.step_id);
                if (orderIdx >= 0) state.resultsByStepOrder.splice(orderIdx, 1);
                state.resultsByStepOrder.push(ev.step_id);
                while (state.resultsByStepOrder.length > 10) {
                    var oldId = state.resultsByStepOrder.shift();
                    delete state.resultsByStep[oldId];
                }
                // Pour les étapes intermédiaires (parents), on met success
                // mais on ne change pas la zone résultat (on attend la
                // step finale ciblée par le clic).
                applyStatus(ev.step_id, 'success');
                if (ev.step_id === state.currentRunStepId) {
                    renderResult(ev);
                }
                return;
            case 'preview_error':
                state.running = false;
                if (ev.step_id) applyStatus(ev.step_id, 'failed');
                renderError(ev);
                return;
            case 'preview_complete':
                state.running = false;
                return;
            default:
                return;
        }
    }

    function applyStatus(stepId, status) {
        if (!stepId && stepId !== 0) return;
        state.nodeStatuses[stepId] = status;
        editor.setNodeStatus(stepId, status);
    }

    // ── Rendu : empty / loading / error / result ─────────────────

    function renderLoading(message) {
        showArea();
        clearBody();
        var spinner = el('div', { class: 'komptia-spinner', 'aria-hidden': 'true' });
        var text = el('div', { text: message || 'En cours…', 'aria-live': 'polite' });
        dom.body.appendChild(el('div', { class: 'komptia-preview-loading' }, [spinner, text]));
    }

    function renderError(ev) {
        showArea();
        clearBody();
        var category = (ev && ev.category) || 'internal';
        var rawMsg = (ev && ev.message) || 'Erreur inconnue.';
        var classes = 'komptia-preview-error';
        if (category === 'validation') classes += ' komptia-preview-error-validation';

        var msgNode = el('div', { text: rawMsg });
        var children = [msgNode];

        if (category === 'anon_pending_review') {
            var link = el('a', {
                text: 'Confirmer dans Iris',
                href: '/iris',
                target: '_blank',
                rel: 'noopener',
            });
            link.className = 'underline text-blue-600';
            children.push(el('div', { class: 'komptia-preview-error-actions' }, [link]));
        } else if (category === 'sage_unavailable' || category === 'llm_error' || category === 'timeout' || category === 'internal') {
            var retryBtn = el('button', { type: 'button', text: 'Réessayer' });
            retryBtn.addEventListener('click', function () {
                // Le user re-clique ▶ : on relance le run sur le step ciblé.
                if (state.currentRunStepId !== null) {
                    triggerPreview(state.currentRunStepId);
                }
            });
            var actions = el('div', { class: 'komptia-preview-error-actions' }, [retryBtn]);

            // 5xx / internal : proposer "Signaler" si feedback-reporter existe.
            if (category === 'internal' && typeof window.komptiaReportFeedback === 'function') {
                var reportBtn = el('button', { type: 'button', text: 'Signaler' });
                reportBtn.addEventListener('click', function () {
                    try { window.komptiaReportFeedback({ context: 'automation_preview', message: rawMsg }); }
                    catch (_) { /* ignore */ }
                });
                actions.appendChild(reportBtn);
            }
            children.push(actions);
        }
        dom.body.appendChild(el('div', { class: classes, role: 'alert' }, children));
    }

    function renderResult(ev) {
        showArea();
        clearBody();
        var stepInfo = editor.getStepById(ev.step_id);
        var stepName = stepInfo ? stepInfo.name : ('Étape #' + ev.step_id);
        var stepType = ev.step_type || (stepInfo && stepInfo.step_type) || '';

        // Meta info en haut
        var meta = '« ' + stepName + ' » — ' + stepType;
        if (ev.from_cache) meta += ' (cache)';
        if (ev.duration_ms !== undefined && !ev.from_cache) {
            meta += ' — ' + Math.round(ev.duration_ms) + ' ms';
        }
        if (ev.rows_out !== undefined && ev.rows_out !== null) {
            meta += ' — ' + ev.rows_out + ' ligne(s)';
        }
        if (ev.truncated) meta += ' ⚠ tronqué';
        setMeta(meta);

        // Dispatch par catégorie d'output
        var extras = ev.extras || {};
        var kind = extras.output_kind || '';

        if (kind === 'email_dry_run' && extras.dry_run) {
            renderEmailDryRun(extras.dry_run);
            return;
        }
        if (kind === 'datastore_dry_run' && extras.dry_run) {
            renderDatastoreDryRun(extras.dry_run);
            return;
        }
        if ((kind === 'report' || kind === 'export') && ev.output_file_token && ev.output_filename) {
            renderFileResult(ev, kind);
            return;
        }
        // Default : workbook (sources + format)
        renderWorkbook(ev);
    }

    function renderWorkbook(ev) {
        var wb = ev.workbook;
        if (!wb || !wb.tabs || !wb.tabs.length) {
            dom.body.appendChild(el('div', {
                class: 'komptia-preview-empty',
                text: 'L\'étape n\'a pas produit de classeur.',
            }));
            return;
        }
        // Si GridTabManager n'est pas chargée (cas dégradé), fallback HTML simple
        if (typeof GridTabManager !== 'function') {
            renderWorkbookFallback(wb);
            return;
        }
        var card = el('div', { class: 'iris-sql-card' });
        dom.body.appendChild(card);
        try {
            var mgr = new GridTabManager(card);
            for (var i = 0; i < wb.tabs.length; i += 1) {
                var t = wb.tabs[i];
                mgr.addTab(
                    t.label || ('Onglet ' + (i + 1)),
                    t.columns || [],
                    t.rows || [],
                    t.sql || '',
                    typeof t.totalRowCount === 'number' ? t.totalRowCount : (t.rows || []).length,
                    null,
                    false
                );
            }
        } catch (e) {
            try { console.error('GridTabManager render fail', e); } catch (_) { /* ignore */ }
            renderWorkbookFallback(wb);
        }
    }

    function renderWorkbookFallback(wb) {
        var wrap = el('div', { class: 'komptia-preview-workbook-fallback' });
        for (var i = 0; i < wb.tabs.length; i += 1) {
            var t = wb.tabs[i];
            var label = el('h3', { text: t.label || ('Onglet ' + (i + 1)) });
            label.style.fontSize = '0.875rem';
            label.style.fontWeight = '600';
            label.style.margin = '0.5rem 0 0.25rem';
            wrap.appendChild(label);

            var table = el('table');
            table.style.fontSize = '0.75rem';
            table.style.borderCollapse = 'collapse';
            table.style.width = '100%';
            var thead = el('thead');
            var trh = el('tr');
            (t.columns || []).forEach(function (c) {
                var th = el('th', { text: toText(c) });
                th.style.padding = '4px 6px';
                th.style.borderBottom = '1px solid #e5e7eb';
                th.style.textAlign = 'left';
                trh.appendChild(th);
            });
            thead.appendChild(trh);
            table.appendChild(thead);
            var tbody = el('tbody');
            (t.rows || []).slice(0, 100).forEach(function (row) {
                var tr = el('tr');
                (t.columns || []).forEach(function (c) {
                    var td = el('td', { text: toText(row && row[c] !== undefined ? row[c] : '') });
                    td.style.padding = '3px 6px';
                    td.style.borderBottom = '1px solid #f3f4f6';
                    tr.appendChild(td);
                });
                tbody.appendChild(tr);
            });
            table.appendChild(tbody);
            wrap.appendChild(table);
        }
        dom.body.appendChild(wrap);
    }

    function renderFileResult(ev, kind) {
        var automationId = editor.getAutomationId();
        var url = '/automations/' + automationId
            + '/preview/output/' + ev.step_id
            + '/' + encodeURIComponent(ev.output_filename)
            + '?token=' + encodeURIComponent(ev.output_file_token)
            + (kind === 'report' ? '&inline=true' : '');

        var iconClass = kind === 'report'
            ? 'bi-file-earmark-pdf'
            : 'bi-file-earmark-spreadsheet';
        var label = kind === 'report' ? 'Ouvrir le PDF' : 'Télécharger le fichier';

        var primary = el('a', {
            href: url,
            target: '_blank',
            rel: 'noopener',
            'aria-label': label,
        }, [bsIcon(iconClass), el('span', { text: label })]);

        var actions = el('div', { class: 'komptia-preview-file-actions' }, [primary]);

        // Pour le PDF, on offre aussi "Télécharger" en secondaire
        // (target=_blank pour ne pas casser l'état de la page edit en
        // navigant ailleurs — finding F3).
        if (kind === 'report') {
            var dlUrl = '/automations/' + automationId
                + '/preview/output/' + ev.step_id
                + '/' + encodeURIComponent(ev.output_filename)
                + '?token=' + encodeURIComponent(ev.output_file_token);
            var secondary = el('a', {
                href: dlUrl,
                class: 'komptia-preview-file-secondary',
                text: 'Télécharger',
                target: '_blank',
                rel: 'noopener',
            });
            actions.appendChild(secondary);
        }

        var meta = el('div', {
            class: 'komptia-preview-file-meta',
            text: 'Fichier temporaire — disponible pendant quelques minutes.',
        });
        dom.body.appendChild(el('div', { class: 'komptia-preview-file' }, [meta, actions]));
    }

    function renderEmailDryRun(dry) {
        var wrap = el('div', { class: 'komptia-preview-email' });
        wrap.appendChild(el('div', {
            class: 'komptia-preview-email-banner',
            text: 'DRY-RUN : aucun email n\'est envoyé en mode aperçu. Les destinataires sont masqués.',
            role: 'status',
        }));

        function row(labelText, value) {
            return el('div', { class: 'komptia-preview-email-row' }, [
                el('strong', { text: labelText }),
                el('span', { class: 'komptia-preview-email-recipients', text: value }),
            ]);
        }

        // Le serveur masque les emails (cf. _mask_recipients) — on
        // affiche tel quel. Pas de PII en clair côté wire.
        var recip = dry.recipients || {};
        wrap.appendChild(row('À', (recip.to || []).join(', ') || '—'));
        if ((recip.cc || []).length) wrap.appendChild(row('Cc', recip.cc.join(', ')));
        if ((recip.bcc || []).length) wrap.appendChild(row('Bcc', recip.bcc.join(', ')));
        wrap.appendChild(row('Objet', dry.subject || ''));
        wrap.appendChild(row('Stratégie', dry.strategy || ''));
        var totalRecips = dry.total_recipients || 0;
        wrap.appendChild(row(
            'Total',
            totalRecips + ' destinataire(s) — ' + (dry.ticket_count || 0) + ' email(s) à envoyer'
        ));

        // Conversion implicite workbook → xlsx : si l'email a des ancetres
        // directs qui produisent des workbooks (Source/Format), le runtime
        // generera automatiquement un xlsx pour chacun et l'attachera.
        // L'utilisateur voit ici quelles pj seront produites — sans avoir
        // a inserer manuellement un step Export entre Format et Email.
        var implicitCount = dry.implicit_workbook_xlsx_count || 0;
        if (implicitCount > 0) {
            var implicitSteps = (dry.implicit_workbook_xlsx_steps || []).join(', ');
            wrap.appendChild(row(
                'PJ auto (xlsx)',
                implicitCount + ' classeur(s) seront convertis en Excel a l\'envoi : ' + implicitSteps
            ));
        }

        if (dry.body) {
            wrap.appendChild(el('div', { class: 'komptia-preview-email-body', text: dry.body }));
        }
        dom.body.appendChild(wrap);
    }

    function renderDatastoreDryRun(dry) {
        // Recap save_to_datastore (sink filesystem) : on n'ecrit pas
        // pendant la preview pour eviter de polluer le datastore. On
        // affiche le path resolu + metadonnees pour que l'utilisateur
        // valide ce qui SERAIT ecrit en execution reelle.
        var wrap = el('div', { class: 'komptia-preview-email' });
        wrap.appendChild(el('div', {
            class: 'komptia-preview-email-banner',
            text: 'DRY-RUN : aucun fichier n\'est ecrit en mode apercu. Voici ce qui serait sauvegarde a l\'execution.',
            role: 'status',
        }));

        function row(labelText, value) {
            return el('div', { class: 'komptia-preview-email-row' }, [
                el('strong', { text: labelText }),
                el('span', { class: 'komptia-preview-email-recipients', text: value }),
            ]);
        }

        wrap.appendChild(row('Chemin cible', '/datastore/' + (dry.target_path || '')));
        wrap.appendChild(row('Dossier', dry.folder_path || '(racine)'));
        wrap.appendChild(row('Nom du fichier', dry.filename || ''));
        // Mode : "serialize" (workbook → .afz.json) vs "copy" (PDF/Excel
        // archive du fichier amont). Le content_descr affiche le bon resume
        // selon le mode (cf. preview_service).
        wrap.appendChild(row(
            'Mode',
            dry.save_mode === 'copy'
                ? 'Archive du fichier amont (copy)'
                : 'Serialisation classeur Komptia (.afz.json)'
        ));
        wrap.appendChild(row('Contenu', dry.content_descr || ''));
        if (dry.save_mode === 'serialize') {
            var sizeKB = Math.round((dry.estimated_bytes || 0) / 1024);
            wrap.appendChild(row('Taille estimee', sizeKB + ' Ko (approximatif)'));
        }
        if (dry.collision_resolved) {
            wrap.appendChild(row(
                'Note',
                'Un fichier existe deja a ce nom — un suffixe numerique sera ajoute (overwrite=false).'
            ));
        } else if (dry.overwrite) {
            wrap.appendChild(row('Note', 'overwrite=true — un fichier existant sera remplace.'));
        }
        dom.body.appendChild(wrap);
    }

    // ── Bouton ▶ Apercu dans le panel config ─────────────────────

    function injectPreviewButton(stepId) {
        if (!dom.panelForm) return;
        // Évite les doublons : si un bouton est déjà là, on met juste à jour data-step-id
        var existing = document.getElementById('komptia-panel-preview-btn');
        if (existing) {
            existing.setAttribute('data-step-id', String(stepId));
            existing.disabled = state.running;
            return;
        }
        var wrap = el('div', { class: 'komptia-panel-preview-wrap' });
        wrap.style.marginTop = '0.75rem';
        wrap.style.paddingTop = '0.75rem';
        wrap.style.borderTop = '1px solid #e5e7eb';

        var btn = el('button', {
            type: 'button',
            id: 'komptia-panel-preview-btn',
            class: 'komptia-panel-preview-btn',
            'data-step-id': String(stepId),
            'aria-label': 'Exécuter cette étape en aperçu',
        }, [
            el('span', { class: 'komptia-preview-icon', 'aria-hidden': 'true', text: '▶' }),
            el('span', { text: 'Apercu' }),
        ]);
        btn.addEventListener('click', function () {
            var sid = parseInt(btn.getAttribute('data-step-id') || '', 10);
            if (Number.isFinite(sid)) triggerPreview(sid);
        });

        var hint = el('p', {
            text: 'Exécute l\'étape (et ses parents si besoin) sur ' + PREVIEW_MAX_ROWS
                + ' lignes maximum, sans envoi réel.',
        });
        hint.style.fontSize = '0.7rem';
        hint.style.color = '#6b7280';
        hint.style.marginTop = '0.4rem';

        wrap.appendChild(btn);
        wrap.appendChild(hint);
        dom.panelForm.appendChild(wrap);
    }

    function removePreviewButton() {
        var existing = document.getElementById('komptia-panel-preview-btn');
        if (!existing) return;
        // Le wrap parent est créé par injectPreviewButton (.komptia-panel-preview-wrap).
        // On remonte via closest pour ne pas dépendre d'un nombre de niveaux
        // qui pourrait varier si automation-canvas.js re-render le panel.
        var wrap = existing.closest('.komptia-panel-preview-wrap') || existing.parentElement;
        if (wrap && wrap.parentNode) {
            wrap.parentNode.removeChild(wrap);
        }
    }

    // ── Action : déclencher un preview ───────────────────────────

    function triggerPreview(stepId) {
        if (!Number.isFinite(stepId)) return;
        // Reset des statuts précédents (sauf running de cette nouvelle run)
        for (var sid in state.nodeStatuses) {
            if (Object.prototype.hasOwnProperty.call(state.nodeStatuses, sid)) {
                editor.setNodeStatus(parseInt(sid, 10), null);
            }
        }
        state.nodeStatuses = Object.create(null);
        state.currentRunStepId = stepId;
        applyStatus(stepId, 'running');

        renderLoading('Préparation…');

        // Si déjà un run en cours, le serveur cancel automatiquement et
        // démarre le nouveau (cf. handler ws). Mais si la WS n'est pas
        // ouverte, on essaie de connecter et on attend `onopen`.
        if (!state.ws || state.ws.readyState !== 1) {
            // Defense en profondeur : connectWS peut early-return undefined
            // (state.wsFatal, automationId null, new WebSocket throw). On
            // chaîne en safe-mode au lieu d'un .then naïf qui crashait.
            var promise;
            try { promise = connectWS(); } catch (_) { promise = null; }
            var sendWhenReady = function () {
                // 5 retries × 200ms = 1s max d'attente. Si la WS n'est
                // toujours pas en readyState=1, on affiche une erreur
                // plutôt qu'un loading silencieux.
                var tries = 0;
                var interval = setInterval(function () {
                    tries += 1;
                    if (state.ws && state.ws.readyState === 1) {
                        clearInterval(interval);
                        sendWs({ action: 'preview_step', step_id: stepId, max_rows: PREVIEW_MAX_ROWS });
                    } else if (tries >= 5) {
                        clearInterval(interval);
                        renderError({
                            category: 'network',
                            message: 'Impossible d\'établir la connexion. Vérifiez votre réseau puis réessayez.',
                            step_id: stepId,
                        });
                    }
                }, 200);
            };
            if (promise && typeof promise.then === 'function') {
                promise.then(sendWhenReady, sendWhenReady);
            } else {
                sendWhenReady();
            }
            return;
        }
        sendWs({ action: 'preview_step', step_id: stepId, max_rows: PREVIEW_MAX_ROWS });
    }

    function cancelPreview() {
        if (state.ws && state.ws.readyState === 1) {
            sendWs({ action: 'cancel' });
        }
        state.running = false;
    }

    // ── Subscription au bus du canvas editor ─────────────────────

    function setup() {
        bindDom();
        if (!dom.area) return;  // Pas la bonne page (zone preview absente)

        // `automation-canvas.js::initCanvas` est async — `window.komptiaCanvas`
        // peut ne pas etre cree au moment ou ce DOMContentLoaded handler tourne.
        // On checke maintenant ; si absent, on attend l'event 'komptia-canvas-ready'
        // dispatche par le canvas a la fin de son init.
        if (typeof window.komptiaCanvas !== 'undefined') {
            editor = window.komptiaCanvas;
            actualSetup();
        } else {
            window.addEventListener('komptia-canvas-ready', function (ev) {
                editor = (ev && ev.detail) || window.komptiaCanvas;
                if (!editor) return;
                actualSetup();
            }, { once: true });
        }
    }

    function actualSetup() {
        if (dom.collapseBtn) dom.collapseBtn.addEventListener('click', collapseArea);
        if (dom.closeBtn) dom.closeBtn.addEventListener('click', function () {
            cancelPreview();
            hideArea();
            // Cleanup statuts des nodes — sinon un node reste visuellement
            // "running" alors que l'aperçu est fermé (finding C6).
            for (var sid in state.nodeStatuses) {
                if (Object.prototype.hasOwnProperty.call(state.nodeStatuses, sid)) {
                    editor.setNodeStatus(parseInt(sid, 10), null);
                }
            }
            state.nodeStatuses = Object.create(null);
        });

        // Accessibilité : Escape ferme la zone (analogue aux modals existantes).
        document.addEventListener('keydown', function (e) {
            if (e.key !== 'Escape') return;
            if (!dom.area || dom.area.hidden) return;
            cancelPreview();
            hideArea();
        });

        // Cluster-Q 2026-05-26 — Stocker les listeners en const pour
        // pouvoir les `off()` au pagehide (bfcache safety + propre).
        var onStepSelected = function (payload) {
            // Le bus du canvas emet la cle `step_id` (snake_case) — on
            // lit les deux pour tolerer les eventuelles divergences de
            // convention futures.
            var stepId = payload && (payload.step_id != null ? payload.step_id : payload.stepId);
            if (typeof stepId !== 'number') return;
            injectPreviewButton(stepId);
            // Si on a un résultat caché pour ce step, on le réaffiche
            // (UX : cliquer sur un noeud déjà preview ne fait pas
            // disparaître le résultat).
            var cached = state.resultsByStep[stepId];
            if (cached) {
                state.currentRunStepId = stepId;
                renderResult(cached);
            }
        };
        var onStepDeselected = function () {
            removePreviewButton();
        };
        var onConfigChanged = function (payload) {
            // Invalide le résultat caché côté client : la config a changé,
            // le résultat n'est plus valide. Le cache serveur est invalidé
            // automatiquement via le hash de config.
            var stepId = payload && (payload.step_id != null ? payload.step_id : payload.stepId);
            if (typeof stepId === 'number') {
                delete state.resultsByStep[stepId];
                editor.setNodeStatus(stepId, null);
                if (state.currentRunStepId === stepId && dom.area && !dom.area.hidden) {
                    // Affiche un hint que l'aperçu est obsolète, sans
                    // re-run automatique (cher en LLM/SQL).
                    setMeta('Configuration modifiée — cliquez à nouveau sur Apercu.');
                }
            }
        };
        editor.on('step-selected', onStepSelected);
        editor.on('step-deselected', onStepDeselected);
        editor.on('config-changed', onConfigChanged);

        // Cleanup à la fermeture / navigation : ferme la WS proprement
        // (le serveur cancel les tasks pendantes), annule le reconnect
        // timer pour ne pas reconnecter pendant le teardown.
        window.addEventListener('pagehide', function () {
            // Cluster-Q — Unsubscribe les listeners bus pour éviter
            // un leak si bfcache restore la page (Safari/iOS).
            if (editor && typeof editor.off === 'function') {
                try { editor.off('step-selected', onStepSelected); } catch (_) { /* swallow */ }
                try { editor.off('step-deselected', onStepDeselected); } catch (_) { /* swallow */ }
                try { editor.off('config-changed', onConfigChanged); } catch (_) { /* swallow */ }
            }
            state.wsFatal = true;
            if (state.reconnectTimer) {
                clearTimeout(state.reconnectTimer);
                state.reconnectTimer = null;
            }
            // Cluster-P — Arrêter aussi le heartbeat (le close() ci-dessous
            // le déclenche normalement via onclose, mais defense-in-depth).
            if (typeof stopHeartbeat === 'function') {
                try { stopHeartbeat(); } catch (_) { /* swallow */ }
            }
            if (state.ws) {
                try { state.ws.close(1000, 'page unload'); } catch (_) { /* swallow */ }
            }
        });

        // #3 (2026-05-28) — Restauration bfcache (Safari/iOS bouton « précédent ») :
        // la page est réutilisée sans recharger, donc le connectWS() initial ne
        // re-tourne pas ET le pagehide a posé wsFatal=true + retiré les listeners
        // bus → la preview restait MORTE (aucune maj live, aucune réaction à la
        // sélection d'étape). On ré-abonne les listeners (symétrique du pagehide :
        // seulement si editor.off existe — donc s'ils ont bien été retirés, sinon
        // ils sont encore là et on éviterait un double-abonnement) puis on relance
        // la WS. addEventListener (CSP-safe).
        window.addEventListener('pageshow', function (evt) {
            if (!evt.persisted) return;  // uniquement la restauration bfcache
            if (editor && typeof editor.off === 'function' && typeof editor.on === 'function') {
                try { editor.on('step-selected', onStepSelected); } catch (_) { /* swallow */ }
                try { editor.on('step-deselected', onStepDeselected); } catch (_) { /* swallow */ }
                try { editor.on('config-changed', onConfigChanged); } catch (_) { /* swallow */ }
            }
            state.wsFatal = false;
            connectWS();
        });

        // Lance la connexion WS en background (ne bloque pas le mount)
        connectWS();
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', setup);
    } else {
        setup();
    }
})();
