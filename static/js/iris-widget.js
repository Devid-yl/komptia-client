/**
 * Iris Floating Widget — iris-widget.js
 * Self-contained IIFE. No dependency on iris.js.
 * Connects to /ws/iris, same auth (cookie-based).
 */
(function () {
    "use strict";

    // --- Skip on the full Iris page ---
    if (window.location.pathname.startsWith("/iris")) return;

    // --- Guard SSOT (task #14 adversarial #1 BLOCKING) ---
    // iris-common.js DOIT être chargé avant ce script (cf. base.html). Si
    // un futur template échappe au gate ``{% if current_user and not /iris %}``
    // ou si un proxy strip le tag, on fail-soft sans crash : log une erreur
    // que feedback-reporter capture (pour signalement automatique au support)
    // et abort le boot du widget. Sans ce guard, le 1er appel à un wrapper
    // (escapeHtml, sanitizeHtml…) lèverait un ReferenceError plusieurs
    // secondes après le boot, invisible côté user.
    if (typeof window.IrisCommon === "undefined") {
        try {
            console.error(
                "[iris-widget] IrisCommon non chargé — iris-common.js doit être chargé AVANT iris-widget.js (cf. base.html). Widget désactivé."
            );
        } catch (_) { /* defensive — console peut être absent */ }
        return;
    }

    // --- User scope (anti-cross-user-leak) ---
    // ``jw_open`` est persisté en localStorage. Sans scoping par user_id,
    // sur un poste partagé Alice ouvre le widget → Bob se login → voit le
    // widget ouvert (cf. mémoire `feedback_localstorage_cross_user_leak.md`
    // et pattern déjà appliqué à iris.js _getDraftKey + iris-grid.js).
    // Source : <meta name="komptia-user-id" content="..."> dans base.html.
    function _getCurrentUserId() {
        try {
            var meta = document.querySelector('meta[name="komptia-user-id"]');
            if (meta && meta.content) return String(meta.content);
        } catch (e) { /* defensive */ }
        return 'anon';
    }
    var _USER_ID = _getCurrentUserId();
    var _OPEN_STATE_KEY = 'jw_open_u' + _USER_ID;
    var _LEGACY_OPEN_KEY = 'jw_open';

    // --- State ---
    let ws = null;
    let conversationId = null;
    let isOpen = localStorage.getItem(_OPEN_STATE_KEY) === "1";
    let isStreaming = false;
    let currentStreamDiv = null;
    let reconnectDelay = 1000;
    let reconnectTimer = null;
    let unreadCount = 0;
    let hasMessages = false;
    let heartbeatTimer = null;
    let sessionInvalid = false; // 401 reçu — stop reconnect, attend reload
    // ── Hydratation overlay (2026-05-26) ────────────────────────────
    // ``_historyLoaded`` : marque la rehydratation terminée (au moins
    // une tentative). Évite N fetch redondants si l'user ouvre/ferme le
    // panel plusieurs fois sans refresh. Reset à false par
    // ``clearConversation`` (after clean) pour un retry possible.
    // ``_historyAbortCtrl`` : permet d'annuler la fetch si l'user
    // ferme le panel pendant le chargement (sinon on rendrait dans un
    // DOM potentiellement déjà reset par clearConversation — race
    // condition vécue avec fetchWelcomeSuggestions).
    let _historyLoaded = false;
    let _historyLoadInFlight = false;
    let _historyAbortCtrl = null;
    // Token de run incrémenté à chaque (re-)démarrage du fetch ET à
    // chaque invalidation. Le ``.then()`` du fetch compare son
    // ``currentToken`` à ``_historyRunToken`` au moment du render — si
    // différent, la microtask drop sans toucher au DOM. Couvre le cas
    // où ``AbortController.abort()`` ne stoppe PAS les microtasks
    // déjà queuées (réponse réseau arrivée mais .then pas encore exec).
    let _historyRunToken = 0;
    // Mode "plein écran" du panel — bascule via le bouton header (icône
    // flèches diagonales). Volontairement NON persisté en localStorage :
    // si l'user déclenche le fullscreen sur /reports puis navigue vers
    // /classeurs, le widget doit revenir à sa taille ancrée (sinon il
    // squatte tout l'écran de la page suivante sans signal). Réinitialisé
    // à chaque chargement de page.
    let isFullscreen = false;

    // Migration douce : si l'ancienne clé non-scopée existe, la purger
    // (elle peut appartenir à un autre user sur poste partagé). On ne la
    // migre PAS vers la clé scopée — préférable de partir d'un état clean
    // pour le user courant.
    try { localStorage.removeItem(_LEGACY_OPEN_KEY); } catch (e) { /* defensive */ }

    // --- Fullscreen icons (rendu initial + swap au toggle) ---
    // EXPAND = flèches vers les coins du SVG (pattern "agrandir / ouvrir").
    // COLLAPSE = flèches vers le centre (pattern "réduire / quitter le
    // plein écran"). Mêmes attributs viewBox/stroke que le reste des SVG
    // header pour rendu identique (taille 16×16 via .jw-header-btn svg).
    var JW_EXPAND_ICON =
        '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
        '<polyline points="15 3 21 3 21 9"/><polyline points="9 21 3 21 3 15"/>' +
        '<line x1="21" y1="3" x2="14" y2="10"/><line x1="3" y1="21" x2="10" y2="14"/>' +
        '</svg>';
    var JW_COLLAPSE_ICON =
        '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
        '<polyline points="4 14 10 14 10 20"/><polyline points="20 10 14 10 14 4"/>' +
        '<line x1="14" y1="10" x2="21" y2="3"/><line x1="3" y1="21" x2="10" y2="14"/>' +
        '</svg>';

    // --- Utility wrappers vers iris-common.js (SSOT — task #14) ---
    // Le bundle ``IrisCommon`` est chargé AVANT iris-widget.js dans
    // templates/base.html. Si non chargé, ces wrappers crashent — c'est
    // volontaire (fail-loud pour détecter une régression d'ordre).
    function escapeHtml(text) {
        return IrisCommon.escapeHtml(text);
    }
    function escapeAttr(text) {
        return IrisCommon.escapeAttr(text);
    }
    function sanitizeHtml(html) {
        return IrisCommon.sanitizeHtml(html);
    }
    function getCookie(name) {
        return IrisCommon.getCookie(name);
    }

    // --- Utility: basic markdown ---
    function formatMarkdown(text) {
        // Strip internal LLM tags before rendering
        text = text.replace(/\[THINKING\][\s\S]*?\[\/THINKING\]/gi, '');
        text = text.replace(/\[SUGGESTIONS\][\s\S]*?\[\/SUGGESTIONS\]/gi, '');
        text = text.replace(/\[ANALYSIS\][\s\S]*?\[\/ANALYSIS\]/gi, '');
        text = text.replace(/\[THINKING\][\s\S]*$/gi, '');
        text = text.replace(/\[SUGGESTIONS\][\s\S]*$/gi, '');
        text = text.replace(/\[ANALYSIS\][\s\S]*$/gi, '');
        text = text.replace(/\n{3,}/g, '\n\n');
        text = text.trim();
        if (!text) return '';
        // Escape HTML first to prevent XSS
        text = escapeHtml(text);
        // Code blocks (escaped content inside)
        text = text.replace(/```(\w*)\n?([\s\S]*?)```/g, function (_, lang, code) {
            return "<pre><code>" + code.trim() + "</code></pre>";
        });
        // Inline code
        text = text.replace(/`([^`]+)`/g, "<code>$1</code>");
        // Bold
        text = text.replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>");
        // Italic
        text = text.replace(/\*(.+?)\*/g, "<em>$1</em>");
        // Line breaks (but not inside pre)
        text = text.replace(/\n/g, "<br>");
        // Fix <br> inside <pre>
        text = text.replace(/<pre><code>([\s\S]*?)<\/code><\/pre>/g, function (_, code) {
            return "<pre><code>" + code.replace(/<br>/g, "\n") + "</code></pre>";
        });
        return text;
    }

    // --- Utility: build result table ---
    function buildResultTable(columns, rows, truncated) {
        const maxRows = 20;
        const display = rows.slice(0, maxRows);
        let html = '<div class="jw-sql-wrap"><table class="jw-sql-table"><thead><tr>';
        columns.forEach(function (col) {
            html += "<th>" + escapeHtml(String(col)) + "</th>";
        });
        html += "</tr></thead><tbody>";
        display.forEach(function (row) {
            html += "<tr>";
            columns.forEach(function (_, i) {
                const val = row[i] != null ? String(row[i]) : '<span style="color:#94a3b8">NULL</span>';
                html += "<td>" + (row[i] != null ? escapeHtml(val) : val) + "</td>";
            });
            html += "</tr>";
        });
        html += "</tbody></table></div>";
        if (rows.length > maxRows) {
            html +=
                '<div class="jw-sql-info">' +
                rows.length +
                " lignes au total (affichage limité à " +
                maxRows +
                ")</div>";
        }
        // #39 (A5-F4) — troncature SERVEUR (plafond admin ``max_rows``), distincte
        // du cap d'affichage local ci-dessus : le résultat lui-même est coupé en
        // amont. Cohérent avec le badge « ⚠ limité » de la page (iris-grid). Sans
        // ça, le widget montrait un résultat tronqué comme s'il était complet
        // (donnée fausse silencieuse — même classe que #53/#65).
        if (truncated) {
            html +=
                '<div class="jw-sql-info">⚠ Résultat limité : la requête a ' +
                "retourné plus de lignes que le plafond admin (toutes ne sont " +
                "pas incluses).</div>";
        }
        return html;
    }

    // --- Build DOM ---
    function buildWidget() {
        // FAB — aria-expanded reflète l'état (pattern WAI-ARIA disclosure).
        var fab = document.createElement("button");
        fab.className = "jw-fab";
        fab.id = "jw-fab";
        fab.setAttribute("aria-label", "Ouvrir Iris");
        fab.setAttribute("aria-expanded", isOpen ? "true" : "false");
        fab.setAttribute("aria-controls", "jw-panel");
        fab.innerHTML =
            '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
            '<path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>' +
            "</svg>" +
            '<span class="jw-badge" id="jw-badge">0</span>';

        // Panel — ``role=complementary`` (pas ``dialog``) car widget AMBIENT,
        // pas modal bloquant. WAI-ARIA Authoring Practices : ``role=dialog``
        // implique focus management (trap), inapproprié ici. ``complementary``
        // signale au SR « zone complémentaire à la page principale », ce qui
        // est exactement le statut du widget (adversarial #4).
        var panel = document.createElement("div");
        panel.className = "jw-panel";
        panel.id = "jw-panel";
        panel.setAttribute("role", "complementary");
        panel.setAttribute("aria-label", "Assistant Iris");
        panel.setAttribute("aria-labelledby", "jw-title");
        panel.innerHTML =
            // Header
            '<div class="jw-header">' +
            '  <div class="jw-header-left">' +
            '    <div class="jw-avatar" aria-hidden="true">I</div>' +
            "    <div>" +
            '      <div class="jw-title" id="jw-title">Iris</div>' +
            '      <div class="jw-status"><span class="jw-ws-dot" id="jw-ws-dot" aria-hidden="true"></span> <span id="jw-ws-label">Déconnecté</span></div>' +
            "    </div>" +
            "  </div>" +
            '  <div class="jw-header-actions">' +
            // aria-pressed reflète le mode plein écran (pattern WAI-ARIA
            // toggle-button). État initial = false (rendu en mode ancré).
            '    <button class="jw-header-btn" id="jw-fullscreen-btn" title="Plein écran" aria-label="Plein écran" aria-pressed="false">' +
            JW_EXPAND_ICON +
            "    </button>" +
            '    <button class="jw-header-btn" id="jw-clear-btn" title="Effacer la conversation" aria-label="Effacer la conversation">' +
            '      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
            '        <path d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/>' +
            "      </svg>" +
            "    </button>" +
            '    <button class="jw-header-btn" id="jw-close-btn" title="Fermer" aria-label="Fermer">' +
            '      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
            '        <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>' +
            "      </svg>" +
            "    </button>" +
            "  </div>" +
            "</div>" +
            // Messages — aria-live polite + atomic=false : SR annonce les
            // ajouts incrémentaux (chaque message), pas tout le bloc à chaque
            // mutation (chaque text_delta serait insupportable).
            '<div class="jw-messages" id="jw-messages" aria-live="polite" aria-atomic="false">' +
            '  <div class="jw-welcome" id="jw-welcome">' +
            '    <div class="jw-welcome-icon" aria-hidden="true">I</div>' +
            '    <div class="jw-welcome-title">Iris</div>' +
            '    <div class="jw-welcome-sub">Posez-moi une question sur Komptia, je suis là pour vous aider.</div>' +
            '    <div class="jw-welcome-chips" id="jw-welcome-chips"></div>' +
            "  </div>" +
            "</div>" +
            // Typing
            '<div class="jw-typing" id="jw-typing" aria-hidden="true">' +
            '  <span class="jw-typing-dot"></span><span class="jw-typing-dot"></span><span class="jw-typing-dot"></span>' +
            "</div>" +
            // Input — label visuellement caché (pas de label visible mais SR ok).
            '<div class="jw-input-area">' +
            '  <label for="jw-input" class="sr-only">Votre message à Iris</label>' +
            '  <div class="jw-input-wrap">' +
            '    <textarea class="jw-textarea" id="jw-input" rows="1" placeholder="Votre message..." maxlength="4000" aria-label="Votre message à Iris"></textarea>' +
            '    <button class="jw-send-btn" id="jw-send" title="Envoyer" aria-label="Envoyer">' +
            '      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
            '        <line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/>' +
            "      </svg>" +
            "    </button>" +
            "  </div>" +
            "</div>";

        document.body.appendChild(panel);
        document.body.appendChild(fab);
    }

    // --- DOM refs (populated after build) ---
    var els = {};
    function cacheElements() {
        els.fab = document.getElementById("jw-fab");
        els.badge = document.getElementById("jw-badge");
        els.panel = document.getElementById("jw-panel");
        els.messages = document.getElementById("jw-messages");
        els.welcome = document.getElementById("jw-welcome");
        els.welcomeChips = document.getElementById("jw-welcome-chips");
        els.typing = document.getElementById("jw-typing");
        els.input = document.getElementById("jw-input");
        els.sendBtn = document.getElementById("jw-send");
        els.wsDot = document.getElementById("jw-ws-dot");
        els.wsLabel = document.getElementById("jw-ws-label");
        els.closeBtn = document.getElementById("jw-close-btn");
        els.clearBtn = document.getElementById("jw-clear-btn");
        els.fullscreenBtn = document.getElementById("jw-fullscreen-btn");
    }

    // --- Welcome suggestions (task #11) ----------------------------
    // SSOT côté backend : ``GET /api/iris/welcome-suggestions`` qui réutilise
    // ``sync_svc.generate_welcome_suggestions(user_id)`` — exactement le même
    // service que ``IrisPageHandler._fetch_welcome_suggestions``. Zéro
    // hardcoded, zéro duplication : si Komptia raffine ses suggestions côté
    // sync LLM, le widget bénéficie automatiquement.
    var _MAX_CHIP_LABEL_CHARS = 80;  // anti layout overflow (adversarial #10)
    var _suggestionsFetchInFlight = false;
    var _suggestionsHaveData = false;
    var _suggestionsAbortCtrl = null;
    function _renderWelcomeChips(suggestions) {
        if (!els.welcomeChips) return;
        els.welcomeChips.innerHTML = "";
        if (!Array.isArray(suggestions) || suggestions.length === 0) return;
        suggestions.slice(0, 4).forEach(function (s) {
            // Format attendu : {label, prompt}. ``label`` = court (chip),
            // ``prompt`` = ce qui est envoyé en message si clic. Fallback :
            // si pas de ``prompt``, on utilise ``label``.
            var label = (s && typeof s.label === "string") ? s.label : "";
            var prompt = (s && typeof s.prompt === "string") ? s.prompt : label;
            if (!label) return;
            // Cap chars défensif (adversarial #10) — le backend cap déjà
            // à 80 chars mais on garde la garde front pour ne jamais
            // exploser le layout 400px du panel.
            label = label.slice(0, _MAX_CHIP_LABEL_CHARS);
            var chip = document.createElement("button");
            chip.type = "button";
            chip.className = "jw-suggestion-chip";
            chip.textContent = label;
            chip.setAttribute("aria-label", "Poser la question : " + label);
            chip.addEventListener("click", function () {
                els.input.value = prompt;
                els.input.focus();
                autoResizeInput();
            });
            els.welcomeChips.appendChild(chip);
        });
        _suggestionsHaveData = true;
    }
    function fetchWelcomeSuggestions() {
        // Distinction "fetch en cours" vs "fetch réussi avec data" :
        // - in-flight → anti-double-request
        // - have-data → cache local (pas de refetch tant qu'on a des chips)
        // Si la réponse est ``[]`` (cache LLM pas encore peuplé au 1er boot),
        // on NE met PAS ``_suggestionsHaveData=true`` → la prochaine
        // ouverture refetch et a une chance d'avoir le cache rempli
        // (adversarial #5).
        if (_suggestionsFetchInFlight || _suggestionsHaveData) return;
        _suggestionsFetchInFlight = true;
        // AbortController : si user ferme/clear le panel pendant la fetch,
        // on annule pour éviter d'écrire dans un noeud détaché (adversarial #6).
        _suggestionsAbortCtrl = new AbortController();
        fetch("/api/iris/welcome-suggestions", {
            credentials: "same-origin",
            signal: _suggestionsAbortCtrl.signal,
        })
            .then(function (res) {
                if (!res.ok) return null;
                return res.json();
            })
            .then(function (data) {
                _suggestionsFetchInFlight = false;
                if (!data) return;
                _renderWelcomeChips(data.suggestions || []);
                // Si liste vide → ne pas marquer have-data → refetch possible
                // à la prochaine ouverture (cache LLM peut s'être peuplé entre-temps).
            })
            .catch(function () {
                // Fail-safe (inclut AbortError sur close). Reset les flags
                // pour permettre un retry à la prochaine ouverture.
                _suggestionsFetchInFlight = false;
            });
    }

    // --- Hydratation overlay (2026-05-26) -----------------------------
    // Pendant côté API du ``_rehydrate_conversation`` SSR de la page /iris.
    // Le widget n'a pas de SSR : on fetch ``GET /api/iris/widget/conversation``
    // au boot (si panel ouvert) ou à la première ouverture (sinon),
    // puis on rejoue les messages dans le DOM. Sans cela, le widget
    // perdait son historique à chaque refresh — alors que les messages
    // étaient bien en BDD (le SSOT ``get_or_create_active_conversation``
    // continuait la même conv, mais le frontend ne la relisait pas).
    //
    // Replay strategy : on réutilise les renderers existants
    // (``addUserMessage`` pour user, bulle assistant inline ici,
    // ``buildResultTable`` pour SQL) — pas de nouveau pipeline de rendu
    // pour éviter une dérive de comportement vs streaming live.
    function _replayPersistedMessage(msg) {
        if (!msg || typeof msg !== "object") return;
        var role = msg.role;
        if (role === "user") {
            var content = typeof msg.content === "string" ? msg.content : "";
            if (!content) return;
            addUserMessage(content);
            return;
        }
        if (role === "assistant") {
            var text = typeof msg.content === "string" ? msg.content : "";
            if (!text) return;
            // Crée une bulle complète directement (pas de stream). Le
            // ``sanitizeHtml + formatMarkdown`` = parité avec
            // ``handleTextComplete`` (defense-in-depth XSS sur historique
            // déjà scrubbé côté serveur via _render_conversation_messages).
            hideWelcome();
            hasMessages = true;
            var wrap = document.createElement("div");
            wrap.className = "jw-msg jw-msg-assistant";
            var bubble = document.createElement("div");
            bubble.className = "jw-bubble jw-bubble-assistant";
            bubble.innerHTML = sanitizeHtml(formatMarkdown(text));
            wrap.appendChild(bubble);
            els.messages.appendChild(wrap);
            return;
        }
        if (role === "tool") {
            // ``ask_user_clarification`` outils : pas de chip dans le
            // widget live (cf. ``handleToolUse``), on les skip au
            // replay pour parité visuelle.
            if (msg.tool_name === "ask_user_clarification") return;
            // ``_render_tool_message`` côté backend pose éventuellement
            // ``sql_data`` (colonnes + rows) pour ``execute_sql``. On
            // réaffiche la grille — sans ça, l'historique perdrait la
            // lisibilité des résultats SQL au refresh.
            var sqlData = msg.sql_data;
            if (sqlData && Array.isArray(sqlData.columns) && Array.isArray(sqlData.rows)) {
                hideWelcome();
                hasMessages = true;
                var sqlWrap = document.createElement("div");
                sqlWrap.className = "jw-msg jw-msg-assistant";
                var sqlBubble = document.createElement("div");
                sqlBubble.className = "jw-bubble jw-bubble-assistant";
                sqlBubble.innerHTML = sanitizeHtml(
                    // #39 (A5-F4) — propager le flag de troncature serveur au
                    // restore (parité avec la page). Absent legacy → pas de notice.
                    buildResultTable(sqlData.columns, sqlData.rows, sqlData.truncated || false)
                );
                sqlWrap.appendChild(sqlBubble);
                els.messages.appendChild(sqlWrap);
                return;
            }
            // Autres outils : chip "outil" complétée (parité dégradée
            // avec le live — pas de payload sensible déroulé au refresh).
            // Le statut succès/échec vient du backend (champ ``success``
            // posé par ``_render_tool_message``) — sans ça on marquait
            // « done » même pour les échecs (MOYEN-3 adversarial).
            hideWelcome();
            hasMessages = true;
            var chip = document.createElement("div");
            var statusClass = msg.success === false ? "jw-tool-error" : "jw-tool-done";
            chip.className = "jw-tool " + statusClass;
            var icon = typeof msg.icon === "string" ? msg.icon : "";
            var label =
                typeof msg.label === "string"
                    ? msg.label
                    : typeof msg.tool_name === "string"
                        ? msg.tool_name
                        : "Outil";
            var iconHTML = icon ? escapeHtml(icon) : '<i class="bi bi-tools"></i>';
            chip.innerHTML = iconHTML + " " + escapeHtml(label);
            els.messages.appendChild(chip);
            return;
        }
        // Defense future-proof : si le backend ajoute un nouveau role
        // (system, etc.) sans coordonner avec le widget, on logge pour
        // détecter la dérive (MOYEN-2 adversarial).
        try {
            console.debug("[iris-widget] role inconnu, skip:", msg.role);
        } catch (_) { /* defensive */ }
    }

    function loadConversationHistory() {
        // Idempotence : un seul fetch par chargement de page. Si l'user
        // clear sa conv (``clearConversation``), ``_historyLoaded`` est
        // remis à false → un nouveau fetch est possible (mais inutile
        // car la conv vient d'être supprimée — c'est sécurisé : on
        // recevra ``conversation_id: null, messages: []``).
        if (_historyLoaded || _historyLoadInFlight) return Promise.resolve();
        if (sessionInvalid) return Promise.resolve();
        _historyLoadInFlight = true;
        // Token de run incrémental : permet de détecter au moment du
        // ``.then()`` qu'un abort/clear/send/close a eu lieu APRÈS
        // l'envoi du fetch mais AVANT la résolution. Sans ce token,
        // ``AbortController.abort()`` n'empêche PAS la microtask
        // ``.then(data => render(...))`` de s'exécuter si la réponse
        // réseau est déjà arrivée — d'où resurrection des messages
        // dans le DOM après un clear (adversarial CRITIQUE-1).
        _historyRunToken += 1;
        var currentToken = _historyRunToken;
        _historyAbortCtrl = new AbortController();
        return fetch("/api/iris/widget/conversation", {
            credentials: "same-origin",
            signal: _historyAbortCtrl.signal,
            // Cohérent avec les headers serveur (anti-bfcache + anti-CDN).
            cache: "no-store",
        })
            .then(function (res) {
                // Si un autre événement a invalidé ce run pendant le
                // round-trip réseau, on drop la réponse.
                if (currentToken !== _historyRunToken) return null;
                if (res.status === 401 || res.status === 403) {
                    // Session expirée → cohérent avec onclose WS auth.
                    sessionInvalid = true;
                    _showSessionExpiredHint();
                    return null;
                }
                if (!res.ok) return null;
                return res.json();
            })
            .then(function (data) {
                _historyLoadInFlight = false;
                _historyLoaded = true;
                // Defense contre resurrection — si clear/close/send a
                // invalidé ce run pendant que ``res.json()`` était en
                // cours, on NE rend PAS dans le DOM. Sans cette garde,
                // les messages historiques peuvent réapparaître après
                // un clic « Effacer » (cas vécu adversarial CRITIQUE-1).
                if (currentToken !== _historyRunToken) return;
                if (!data || data.success === false) return;
                var convId = data.conversation_id;
                if (Number.isInteger(convId)) {
                    conversationId = convId;
                }
                var messages = Array.isArray(data.messages) ? data.messages : [];
                if (messages.length === 0) return;
                for (var i = 0; i < messages.length; i++) {
                    _replayPersistedMessage(messages[i]);
                }
                if (hasMessages) {
                    forceScrollToBottom();
                }
            })
            .catch(function (err) {
                _historyLoadInFlight = false;
                // AbortError (close panel pendant fetch) → silencieux,
                // retry possible à la prochaine ouverture. Reset
                // ``_historyLoaded`` à false pour permettre ce retry.
                if (err && err.name === "AbortError") {
                    _historyLoaded = false;
                    return;
                }
                // Erreur réseau / 5xx → on marque ``_historyLoaded=true``
                // pour ne pas boucler (le widget doit rester sobre, pas
                // de toast tonitruant). L'user verra son welcome ; ses
                // messages reviendront au prochain refresh si le serveur
                // s'est rétabli. Le bug-report viendra si l'user signale
                // activement (taxonomie 4-cas Komptia : 5xx = signaler).
                _historyLoaded = true;
                try {
                    console.warn("[iris-widget] hydratation overlay KO", err);
                } catch (_) { /* defensive */ }
            });
    }

    /**
     * Invalide le run d'hydratation en cours — appelé par les actions
     * qui modifient le DOM ou la conv (close, clear, send, clarification).
     * L'incrément du token assure que les microtasks ``.then()`` déjà
     * en vol au moment de l'invalidation NE RENDENT PAS dans le DOM.
     *
     * Plus robuste que ``_historyAbortCtrl.abort()`` seul : abort() ne
     * bloque pas les microtasks post-network-resolve. Le couple
     * abort+token couvre tous les chemins (réseau lent : abort marche ;
     * réseau rapide : token marche).
     */
    function _invalidateHistoryRun() {
        _historyRunToken += 1;
        try {
            if (_historyAbortCtrl) { _historyAbortCtrl.abort(); }
        } catch (e) { /* defensive */ }
        _historyLoadInFlight = false;
    }

    // --- Toggle panel ---
    function openPanel() {
        isOpen = true;
        els.panel.classList.add("jw-visible");
        els.fab.classList.add("jw-open");
        els.fab.setAttribute("aria-expanded", "true");
        localStorage.setItem(_OPEN_STATE_KEY, "1");
        clearUnread();
        // Reset backoff à chaque ouverture : si user a laissé fermé 1h, on
        // veut une 1re tentative immédiate, pas attendre 30s (le backoff
        // exponentiel précédent restait à sa dernière valeur).
        reconnectDelay = 1000;
        if (reconnectTimer) { clearTimeout(reconnectTimer); reconnectTimer = null; }
        sessionInvalid = false;
        if (!ws || ws.readyState !== WebSocket.OPEN) {
            connectWebSocket();
        }
        // Suggestions d'accueil dynamiques (lazy : pas au boot pour ne pas
        // peser sur le first paint des pages où l'user n'ouvre jamais le
        // widget). Idempotent — ``_suggestionsLoaded`` évite les refetch.
        fetchWelcomeSuggestions();
        // Rehydratation de l'historique (idempotent via ``_historyLoaded``).
        // Lazy — pas appelé au boot global pour ne pas peser sur le first
        // paint des pages où le widget reste fermé. Si l'user ouvre le
        // panel pour la 1re fois → fetch + replay. Si déjà fait dans
        // cette session JS → no-op silencieux.
        loadConversationHistory();
        setTimeout(function () {
            els.input.focus();
        }, 300);
    }

    function closePanel() {
        // Si le panel est en plein écran, on quitte ce mode AVANT de fermer.
        // Sans ça, l'état (classe ``.jw-fullscreen`` + icône collapse + flag
        // isFullscreen) resterait positionné pendant le fade-out, et la
        // prochaine ouverture afficherait le panel directement en plein écran
        // sans signal explicite — déroutant pour l'user qui s'attend à
        // retrouver son widget ancré. ``toggleFullscreen`` est appelé tant
        // que ``isOpen`` est encore ``true`` (le guard fonctionne).
        if (isFullscreen) {
            toggleFullscreen();
        }
        isOpen = false;
        els.panel.classList.remove("jw-visible");
        els.fab.classList.remove("jw-open");
        els.fab.setAttribute("aria-expanded", "false");
        localStorage.setItem(_OPEN_STATE_KEY, "0");
        // Abort fetch suggestions en cours pour éviter d'écrire dans un
        // DOM potentiellement modifié au prochain open/clear (adversarial #6).
        try {
            if (_suggestionsAbortCtrl) { _suggestionsAbortCtrl.abort(); }
        } catch (e) { /* defensive */ }
        // Idem hydratation : si la fetch /widget/conversation est en
        // cours quand l'user ferme, on l'invalide pour éviter de rendre
        // l'historique dans un DOM que le prochain open recréera vide.
        // ``_invalidateHistoryRun`` incrémente le token + abort —
        // empêche AUSSI la microtask ``.then`` post-network-resolve
        // de rendre (CRITIQUE-1 adversarial 2026-05-26).
        _invalidateHistoryRun();
        // Cancel propre : si un stream LLM est en cours, on l'annule côté
        // serveur — sinon les tokens continuent à coûter en arrière-plan
        // sans aucune UI pour les afficher (gaspillage + badge unread
        // accumulant des deltas invisibles).
        try {
            if (isStreaming && ws && ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify({ action: "cancel" }));
            }
        } catch (e) { /* defensive */ }
    }

    function togglePanel() {
        if (isOpen) closePanel();
        else openPanel();
    }

    // --- Unread badge ---
    function addUnread() {
        if (isOpen) return;
        unreadCount++;
        els.badge.textContent = unreadCount > 9 ? "9+" : String(unreadCount);
        els.badge.classList.add("jw-visible");
    }
    function clearUnread() {
        unreadCount = 0;
        els.badge.classList.remove("jw-visible");
    }

    // --- Smart scroll ---
    var _userScrolledUp = false;

    function scrollToBottom() {
        if (_userScrolledUp) return;
        els.messages.scrollTop = els.messages.scrollHeight;
    }

    function forceScrollToBottom() {
        _userScrolledUp = false;
        els.messages.scrollTop = els.messages.scrollHeight;
    }

    // --- Hide welcome ---
    function hideWelcome() {
        if (els.welcome) {
            els.welcome.style.display = "none";
        }
    }

    // --- Add user message ---
    function addUserMessage(text) {
        hideWelcome();
        hasMessages = true;
        var wrap = document.createElement("div");
        wrap.className = "jw-msg jw-msg-user";
        var bubble = document.createElement("div");
        bubble.className = "jw-bubble jw-bubble-user";
        bubble.textContent = text;
        wrap.appendChild(bubble);
        els.messages.appendChild(wrap);
        forceScrollToBottom();
    }

    // --- Create assistant bubble ---
    function createAssistantBubble() {
        hideWelcome();
        hasMessages = true;
        var wrap = document.createElement("div");
        wrap.className = "jw-msg jw-msg-assistant";
        var bubble = document.createElement("div");
        bubble.className = "jw-bubble jw-bubble-assistant";
        wrap.appendChild(bubble);
        els.messages.appendChild(wrap);
        scrollToBottom();
        return bubble;
    }

    // --- Show typing ---
    function showTyping(visible) {
        els.typing.classList.toggle("jw-visible", visible);
    }

    // --- Set WS status ---
    function setWsStatus(state) {
        els.wsDot.className = "jw-ws-dot";
        if (state === "connected") {
            els.wsDot.classList.add("jw-connected");
            els.wsLabel.textContent = "Connecté";
        } else if (state === "error") {
            els.wsDot.classList.add("jw-error");
            els.wsLabel.textContent = "Déconnecté";
        } else {
            els.wsLabel.textContent = "Connexion...";
        }
    }

    // --- Enable/disable input ---
    function setInputEnabled(enabled) {
        els.input.disabled = !enabled;
        els.sendBtn.disabled = !enabled;
        var wrap = els.input.closest('.jw-input-wrap');
        if (wrap) {
            if (enabled) {
                wrap.classList.remove('jw-processing');
            } else {
                wrap.classList.add('jw-processing');
            }
        }
    }

    // --- WebSocket ---
    // ws close codes : 1000 normal, 1006 abnormal (réseau), 1008 policy
    // violation (auth standard). 4001 = ``_WS_CLOSE_AUTH_REQUIRED`` côté
    // backend (cf. ``app/handlers/iris.py`` même nom). ATTENTION : cette
    // constante DOIT rester alignée avec le backend ; un test de garde
    // ``test_iris_widget_p0_hardening::test_ws_auth_close_codes_align``
    // grep les deux fichiers pour empêcher la dérive (adversarial #1).
    var _WS_CLOSE_AUTH = [1008, 4001];
    var _HEARTBEAT_MS = 30000; // 30s — sous le timeout idle des proxys

    function _stopHeartbeat() {
        if (heartbeatTimer) { clearInterval(heartbeatTimer); heartbeatTimer = null; }
    }

    function _startHeartbeat() {
        _stopHeartbeat();
        heartbeatTimer = setInterval(function () {
            // Si l'user a fermé le panel, on stop le ping — la WS reste
            // ouverte mais inactive (réveillée à la prochaine ouverture).
            // Sans ça, N onglets idle × N users = bruit constant sur le
            // handler WS (adversarial #5 sur fix #7).
            if (!isOpen) {
                _stopHeartbeat();
                return;
            }
            if (!ws || ws.readyState !== WebSocket.OPEN) {
                _stopHeartbeat();
                return;
            }
            try { ws.send(JSON.stringify({ action: "ping" })); }
            catch (e) { /* la prochaine close gérera */ }
        }, _HEARTBEAT_MS);
    }

    function _showSessionExpiredHint() {
        // Affiche un toast/message court à l'utilisateur — sans bloquer.
        // Le client doit recharger pour ré-auth ; on reste simple, pas
        // de banner flashy (cohérent avec le ton sobre du widget).
        hideWelcome();
        var div = document.createElement("div");
        div.className = "jw-error";
        div.textContent =
            "Session expirée. Rechargez la page pour vous reconnecter.";
        els.messages.appendChild(div);
        scrollToBottom();
        setWsStatus("error");
        els.wsLabel.textContent = "Session expirée";
        setInputEnabled(false);
    }

    function connectWebSocket() {
        if (sessionInvalid) return; // stop hard tant que pas de reload
        if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) {
            return;
        }
        var protocol = location.protocol === "https:" ? "wss:" : "ws:";
        var xsrfToken = getCookie("_xsrf");
        var url =
            protocol +
            "//" +
            location.host +
            "/ws/iris?_xsrf=" +
            encodeURIComponent(xsrfToken);
        setWsStatus("connecting");

        ws = new WebSocket(url);

        ws.onopen = function () {
            setWsStatus("connected");
            reconnectDelay = 1000;
            _startHeartbeat();
        };

        ws.onclose = function (ev) {
            _stopHeartbeat();
            setWsStatus("error");
            ws = null;
            isStreaming = false;
            currentStreamDiv = null;
            setInputEnabled(true);
            setSendButtonMode("send");
            showTyping(false);
            // Auth perdue → on stoppe le reconnect (sinon boucle infinie
            // de 401 silencieux jusqu'à fermeture onglet). L'utilisateur
            // doit recharger pour se re-authentifier.
            var code = ev && typeof ev.code === 'number' ? ev.code : 0;
            if (_WS_CLOSE_AUTH.indexOf(code) !== -1) {
                sessionInvalid = true;
                _showSessionExpiredHint();
                return;
            }
            // P4.1 (audit 2026-05-26) — Avant : silent close, l'user voyait
            // juste le badge rouge sans aucune raison. Le serveur peut fermer
            // avec un ``reason`` explicite (RFC 6455 close code + reason),
            // typiquement « SQL timeout 30s », « Stream aborted », « Server
            // shutting down ». On affiche ce reason dans la conversation
            // pour que l'utilisateur sache si une reconnexion va l'aider.
            var reason = ev && typeof ev.reason === "string" ? ev.reason.trim() : "";
            if (reason && code !== 1000 && code !== 1001) {
                // Codes 1000 (normal closure) et 1001 (going away navigateur
                // reload) sont silencieux car attendus — pas la peine d'alarmer.
                handleError({
                    message: "Connexion interrompue : " + reason,
                    detail: "Code WebSocket : " + code,
                    category: "connection",
                });
            }
            scheduleReconnect();
        };

        ws.onerror = function (ev) {
            // L'event ``error`` ne porte pas de payload utile en WebSocket
            // (juste un Event opaque). Le vrai diagnostic est dans
            // ``ws.onclose`` ci-dessus qui lit ``ev.reason``. On reste
            // sur le simple badge ici pour ne pas dupliquer.
            setWsStatus("error");
        };

        ws.onmessage = function (event) {
            var data;
            try {
                data = JSON.parse(event.data);
            } catch (e) {
                return;
            }
            // Ignore les pongs serveur si jamais il en émet
            if (data && data.type === "pong") return;
            handleMessage(data);
        };
    }

    function scheduleReconnect() {
        if (!isOpen || sessionInvalid) return;
        if (reconnectTimer) clearTimeout(reconnectTimer);
        reconnectTimer = setTimeout(function () {
            reconnectTimer = null;
            reconnectDelay = Math.min(reconnectDelay * 2, 30000);
            if (isOpen && !sessionInvalid) connectWebSocket();
        }, reconnectDelay);
    }

    // --- Handle incoming messages ---
    function handleMessage(data) {
        switch (data.type) {
            case "text_delta":
                handleTextDelta(data);
                break;
            case "text_complete":
                handleTextComplete(data);
                break;
            case "sql_results":
                handleSqlResults(data);
                break;
            case "clarification":
                handleClarification(data);
                break;
            case "suggestions":
                handleSuggestions(data);
                break;
            case "tool_use":
                handleToolUse(data);
                break;
            case "tool_result":
                handleToolResult(data);
                break;
            case "error":
                handleError(data);
                break;
            case "done":
                handleDone(data);
                break;
            case "cancelled":
                handleCancelled(data);
                break;
            // Ignored: thinking, verification, rag_sources
        }
    }

    function handleTextDelta(data) {
        if (!isStreaming) {
            isStreaming = true;
            showTyping(false);
            currentStreamDiv = createAssistantBubble();
            currentStreamDiv._rawText = "";
        }
        currentStreamDiv._rawText += data.content || "";
        // During streaming, use escaped text only (cheap). Full markdown on text_complete.
        currentStreamDiv.textContent = currentStreamDiv._rawText;
        scrollToBottom();
        addUnread();
    }

    function handleTextComplete(data) {
        if (currentStreamDiv) {
            // sanitizeHtml = defense-in-depth XSS (parity iris.js:3200).
            // Si demain le markdown autorise un format plus riche, le
            // widget reste sûr sans nouvelle correction.
            currentStreamDiv.innerHTML = sanitizeHtml(
                formatMarkdown(data.content || currentStreamDiv._rawText || "")
            );
        }
        isStreaming = false;
        currentStreamDiv = null;
        scrollToBottom();
        addUnread();
    }

    function handleSqlResults(data) {
        hideWelcome();
        var wrap = document.createElement("div");
        wrap.className = "jw-msg jw-msg-assistant";
        var bubble = document.createElement("div");
        bubble.className = "jw-bubble jw-bubble-assistant";
        bubble.innerHTML = sanitizeHtml(
            // #39 (A5-F4) — flag de troncature serveur en live (parité page +
            // restore widget). Sans ça le widget montrait un résultat coupé
            // comme complet (donnée fausse silencieuse).
            buildResultTable(data.columns || [], data.rows || [], data.truncated || false)
        );
        wrap.appendChild(bubble);
        els.messages.appendChild(wrap);
        scrollToBottom();
        addUnread();
    }

    function handleClarification(data) {
        hideWelcome();
        var wrap = document.createElement("div");
        wrap.className = "jw-msg jw-msg-assistant";
        var bubble = document.createElement("div");
        bubble.className = "jw-bubble jw-bubble-assistant";
        var inner = '<div class="jw-clarification">';
        inner += '<div class="jw-clarification-q">' + escapeHtml(data.question || "") + "</div>";
        (data.options || []).forEach(function (opt) {
            inner += '<button class="jw-option-btn" data-option="' + escapeAttr(opt) + '">' + escapeHtml(opt) + "</button>";
        });
        inner += "</div>";
        bubble.innerHTML = sanitizeHtml(inner);
        wrap.appendChild(bubble);
        els.messages.appendChild(wrap);
        // Bind option click
        bubble.querySelectorAll(".jw-option-btn").forEach(function (btn) {
            btn.addEventListener("click", function () {
                var val = this.getAttribute("data-option");
                sendClarification(val);
                // Disable all option buttons
                bubble.querySelectorAll(".jw-option-btn").forEach(function (b) {
                    b.disabled = true;
                    b.style.opacity = "0.5";
                    b.style.cursor = "default";
                });
                this.style.opacity = "1";
                this.style.borderColor = "var(--brand, var(--brand))";
                this.style.background = "var(--brand-soft, rgb(var(--brand-rgb) / 0.12))";
            });
        });
        scrollToBottom();
        addUnread();
    }

    function handleSuggestions(data) {
        var container = document.createElement("div");
        container.className = "jw-suggestion-chips";
        (data.questions || []).forEach(function (q) {
            var chip = document.createElement("button");
            chip.className = "jw-suggestion-chip";
            chip.textContent = q;
            chip.addEventListener("click", function () {
                els.input.value = q;
                els.input.focus();
            });
            container.appendChild(chip);
        });
        els.messages.appendChild(container);
        scrollToBottom();
    }

    function handleToolUse(data) {
        // Pas de chip outil pour les clarifications
        if (data.tool === "ask_user_clarification") return;
        var chip = document.createElement("div");
        chip.className = "jw-tool";
        var icon = data.icon || "";
        var label = data.label || data.tool || "Outil";
        var iconHTML = icon ? escapeHtml(icon) : '<i class="bi bi-tools"></i>';
        chip.innerHTML = iconHTML + " " + escapeHtml(label);
        els.messages.appendChild(chip);
        showTyping(true);
        scrollToBottom();
    }

    function handleToolResult(data) {
        // Ignorer les tool_result pour les clarifications
        if (data.tool === "ask_user_clarification") return;
        var chips = els.messages.querySelectorAll(".jw-tool:not(.jw-tool-done):not(.jw-tool-error)");
        var chip = chips.length > 0 ? chips[chips.length - 1] : null;
        var result = data.result || {};
        var isSuccess = result.success === true;
        if (chip) {
            chip.classList.add(isSuccess ? "jw-tool-done" : "jw-tool-error");
        }
        // P4.1 (audit 2026-05-26) — Avant : juste une classe CSS rouge sans
        // détail. Maintenant : panel <details> expandable sous le chip avec
        // result.error / result.sql / result.next_actions / result.blocked_by
        // pour aligner sur la page /iris (iris.js:4326). Le user du widget
        // pouvait être bloqué sans aucun moyen de comprendre l'erreur SQL.
        if (!isSuccess && chip) {
            var errMsg = "";
            if (result.error) errMsg = String(result.error);
            else if (result.blocked_by) errMsg = String(result.blocked_by);
            else if (data.summary) errMsg = String(data.summary);
            if (errMsg) {
                var detailPanel = document.createElement("details");
                detailPanel.className = "jw-tool-error-detail";
                var summary = document.createElement("summary");
                summary.textContent = "Voir le détail de l'erreur";
                detailPanel.appendChild(summary);
                var errBody = document.createElement("div");
                errBody.className = "jw-tool-error-detail-body";
                var errLine = document.createElement("div");
                errLine.textContent = errMsg;
                errBody.appendChild(errLine);
                if (result.sql) {
                    var sqlBlock = document.createElement("pre");
                    sqlBlock.className = "jw-tool-error-sql";
                    sqlBlock.textContent = String(result.sql);
                    errBody.appendChild(sqlBlock);
                }
                if (result.next_actions && Array.isArray(result.next_actions) && result.next_actions.length) {
                    var actionsList = document.createElement("ul");
                    actionsList.className = "jw-tool-error-actions";
                    result.next_actions.forEach(function (a) {
                        var li = document.createElement("li");
                        li.textContent = String(a);
                        actionsList.appendChild(li);
                    });
                    errBody.appendChild(actionsList);
                }
                detailPanel.appendChild(errBody);
                chip.insertAdjacentElement("afterend", detailPanel);
            }
        }
        showTyping(false);
    }

    // Whitelist d'erreurs sur lesquelles le bouton "Signaler" est utile.
    // Conforme à la taxonomie 4-cas Komptia (cf. mémoire
    // ``feedback_error_taxonomy_4cases.md``) : seuls les 5xx / internal
    // méritent un report user (les 4xx / métier / réseau ont des UX dédiées
    // ou sont attendus). Adversarial #7 sur fix P1.
    var _REPORTABLE_ERROR_TYPES = ["5xx", "internal_error", "server_error"];
    function _isReportableError(data) {
        if (!data || typeof data !== "object") return false;
        if (data.type && _REPORTABLE_ERROR_TYPES.indexOf(String(data.type)) !== -1) return true;
        if (data.code && /^5\d\d$/.test(String(data.code))) return true;
        return false;
    }

    function handleError(data) {
        showTyping(false);
        isStreaming = false;
        currentStreamDiv = null;
        setInputEnabled(true);
        setSendButtonMode("send");
        // P4.1 (audit 2026-05-26) — Avant : ``data.message`` only → jetait
        // ``data.error`` / ``data.detail`` / ``data.sql`` quand le backend les
        // envoyait (cas SQL Server [42S22], [HYT00], etc.). Maintenant : chaîne
        // de fallback complète + panel <details> expandable pour le détail
        // technique (SQL fautif, SQLSTATE, stack).
        var msg = data.message || data.error || data.detail || "Une erreur est survenue.";
        var wrap = document.createElement("div");
        wrap.className = "jw-error";
        var text = document.createElement("span");
        text.textContent = msg;
        wrap.appendChild(text);
        // Panel détail expandable si le backend a fourni un raw detail / SQL
        var hasExtraDetail =
            (data.detail && data.detail !== msg) ||
            data.sql ||
            data.sqlstate ||
            data.category;
        if (hasExtraDetail) {
            var detailPanel = document.createElement("details");
            detailPanel.className = "jw-error-detail";
            var detailSummary = document.createElement("summary");
            detailSummary.textContent = "Voir le détail technique";
            detailPanel.appendChild(detailSummary);
            var detailBody = document.createElement("div");
            detailBody.className = "jw-error-detail-body";
            if (data.sqlstate || data.category) {
                var metaLine = document.createElement("div");
                metaLine.className = "jw-error-detail-meta";
                var parts = [];
                if (data.sqlstate) parts.push("SQLSTATE: " + data.sqlstate);
                if (data.category) parts.push("Catégorie: " + data.category);
                metaLine.textContent = parts.join(" — ");
                detailBody.appendChild(metaLine);
            }
            if (data.detail && data.detail !== msg) {
                var detailLine = document.createElement("div");
                detailLine.textContent = String(data.detail);
                detailBody.appendChild(detailLine);
            }
            if (data.sql) {
                var sqlBlock = document.createElement("pre");
                sqlBlock.className = "jw-error-sql";
                sqlBlock.textContent = String(data.sql);
                detailBody.appendChild(sqlBlock);
            }
            detailPanel.appendChild(detailBody);
            wrap.appendChild(detailPanel);
        }
        // Bouton "Signaler" — UNIQUEMENT pour les erreurs reportables
        // (5xx / internal). Une session expirée, rate-limit, erreur métier
        // n'a pas vocation à être signalée → l'user verrait un bouton qui
        // noierait le canal bug-report (adversarial #7).
        try {
            if (_isReportableError(data) && typeof window.komptiaReportFeedback === "function") {
                var btn = document.createElement("button");
                btn.type = "button";
                btn.className = "jw-error-report-btn";
                btn.textContent = "Signaler";
                btn.setAttribute("aria-label", "Signaler cette erreur au support");
                btn.addEventListener("click", function () {
                    try {
                        // Contexte enrichi pour rendre le bug report
                        // actionnable côté support (adversarial #8) :
                        // conv_id permet de retrouver le flow, timestamp +
                        // pathname situent l'incident, le type d'erreur
                        // côté serveur (si exposé) précise la cause.
                        window.komptiaReportFeedback({
                            context: "iris_widget",
                            message: msg,
                            conversation_id: conversationId || null,
                            timestamp: new Date().toISOString(),
                            page: window.location.pathname,
                            error_type: data.type || data.code || null,
                            request_id: data.request_id || null,
                        });
                    } catch (e) { /* defensive — reporter peut échouer silencieusement */ }
                });
                wrap.appendChild(btn);
            }
        } catch (_) { /* defensive */ }
        els.messages.appendChild(wrap);
        scrollToBottom();
        addUnread();
    }

    function handleDone(data) {
        showTyping(false);
        isStreaming = false;
        currentStreamDiv = null;
        setInputEnabled(true);
        setSendButtonMode("send");
        if (data.conversation_id && Number.isInteger(data.conversation_id)) {
            conversationId = data.conversation_id;
        }
    }

    function handleCancelled(data) {
        showTyping(false);
        isStreaming = false;
        currentStreamDiv = null;
        setInputEnabled(true);
        setSendButtonMode("send");
        var div = document.createElement("div");
        div.className = "jw-system-msg";
        div.textContent = data.message || "Génération interrompue.";
        els.messages.appendChild(div);
        scrollToBottom();
    }

    // --- Stop/Send button mode ---
    var SEND_ICON = '<svg width="14" height="14" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2.25"><path stroke-linecap="round" stroke-linejoin="round" d="M6 12L3.269 3.126A59.768 59.768 0 0121.485 12 59.77 59.77 0 013.27 20.876L5.999 12zm0 0h7.5"/></svg>';
    var STOP_ICON = '<svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor"><rect x="4" y="4" width="16" height="16" rx="2"/></svg>';

    function setSendButtonMode(mode) {
        if (!els.sendBtn) return;
        if (mode === "stop") {
            els.sendBtn.innerHTML = STOP_ICON;
            els.sendBtn.classList.add("jw-stop-mode");
            els.sendBtn.disabled = false;
        } else {
            els.sendBtn.innerHTML = SEND_ICON;
            els.sendBtn.classList.remove("jw-stop-mode");
        }
    }

    function stopGeneration() {
        if (!ws || ws.readyState !== WebSocket.OPEN) return;
        if (!els.sendBtn || !els.sendBtn.classList.contains("jw-stop-mode")) return;
        ws.send(JSON.stringify({ action: "cancel" }));
    }

    // --- Send message ---
    function sendMessage() {
        var text = els.input.value.trim();
        if (!text) return;
        if (!ws || ws.readyState !== WebSocket.OPEN) {
            connectWebSocket();
            return;
        }

        // Race condition : si l'hydratation overlay est encore en vol au
        // moment où l'user envoie un message, on invalide le run. Sinon
        // les messages historiques arriveraient APRÈS le message courant
        // (chronologie cassée à l'écran). Le prochain refresh re-fetchera
        // — au pire on perd l'historique de cette session JS, jamais
        // de la BDD. Le backend SSOT continue la même conv (pas de
        // duplicate) : envoyer ``conversation_id: null`` ici est safe
        // (cf. ``get_or_create_active_conversation`` qui SELECT-first).
        // ``_invalidateHistoryRun`` couvre le cas réseau-rapide (token
        // bump) ET réseau-lent (abort) — cf. CRITIQUE-1 adversarial.
        if (_historyLoadInFlight) {
            _invalidateHistoryRun();
            _historyLoaded = true;
        }

        addUserMessage(text);
        els.input.value = "";
        autoResizeInput();
        setInputEnabled(false);
        setSendButtonMode("stop");
        showTyping(true);

        // ``source: "widget"`` — discrimine du chat page ``/iris`` côté
        // backend (cf. ``ConversationSource`` enum). Sans ce champ, le
        // widget partageait la conv active de la page (bug 2026-05-21).
        ws.send(
            JSON.stringify({
                action: "send_message",
                conversation_id: conversationId,
                message: text,
                role: "iris",
                mode: "execution",
                source: "widget",
            })
        );
    }

    // --- Send clarification ---
    function sendClarification(response) {
        if (!ws || ws.readyState !== WebSocket.OPEN) return;
        // Race condition identique à sendMessage : si hydrate en vol,
        // on l'invalide pour préserver la chronologie d'affichage
        // (token bump + abort — cf. CRITIQUE-1 adversarial).
        if (_historyLoadInFlight) {
            _invalidateHistoryRun();
            _historyLoaded = true;
        }
        showTyping(true);
        setInputEnabled(false);
        setSendButtonMode("stop");
        ws.send(
            JSON.stringify({
                action: "clarification_response",
                conversation_id: conversationId,
                response: response,
                source: "widget",
            })
        );
    }

    // --- Clear conversation ---
    function clearConversation() {
        // Cancel propre : si un stream est en cours, on l'annule AVANT de
        // toucher au DOM/state. Sans ça, des ``text_delta`` post-clear
        // ressucitaient le contenu dans une nouvelle bubble — pour des
        // données comptables, « Effacer » qui ment est inacceptable.
        try {
            if (isStreaming && ws && ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify({ action: "cancel" }));
            }
        } catch (e) { /* defensive */ }
        // Reset streaming state BEFORE clearing DOM to avoid race condition
        isStreaming = false;
        currentStreamDiv = null;
        // Idem race condition pour l'hydratation : si fetch
        // /api/iris/widget/conversation est en vol au moment du clear,
        // sa résolution ressusciterait les messages dans le DOM qu'on
        // s'apprête à vider — invalidation immédiate (token bump + abort).
        // ``_invalidateHistoryRun`` bloque AUSSI la microtask ``.then``
        // post-network-resolve (CRITIQUE-1 adversarial 2026-05-26).
        _invalidateHistoryRun();

        // Call API to soft-delete, then reset UI
        function resetUI() {
            conversationId = null;
            hasMessages = false;
            els.messages.innerHTML = "";
            // Re-add welcome — **avec** le container chips (adversarial #1
            // critique : sans ce container, ``els.welcomeChips`` resterait
            // pointé vers un noeud orphelin détaché, et la feature #11
            // serait silencieusement cassée jusqu'au reload).
            var welcome = document.createElement("div");
            welcome.className = "jw-welcome";
            welcome.id = "jw-welcome";
            welcome.innerHTML =
                '<div class="jw-welcome-icon" aria-hidden="true">I</div>' +
                '<div class="jw-welcome-title">Iris</div>' +
                '<div class="jw-welcome-sub">Posez-moi une question sur Komptia, je suis là pour vous aider.</div>' +
                '<div class="jw-welcome-chips" id="jw-welcome-chips"></div>';
            els.messages.appendChild(welcome);
            els.welcome = welcome;
            // Ré-assigner la ref (l'ancienne pointait vers le noeud détaché).
            els.welcomeChips = welcome.querySelector("#jw-welcome-chips");
            // Reset les flags pour permettre un nouveau fetch — l'user
            // qui clear veut probablement repartir de zéro avec ses chips.
            _suggestionsHaveData = false;
            _suggestionsFetchInFlight = false;
            // Abort un fetch éventuellement en vol (pourrait écrire dans
            // l'ancien noeud chips détaché — race condition).
            try {
                if (_suggestionsAbortCtrl) { _suggestionsAbortCtrl.abort(); }
            } catch (e) { /* defensive */ }
            // Reset l'hydratation : la conv vient d'être supprimée côté
            // BDD. Si un autre onglet recrée une conv widget plus tard
            // (envoyant un msg), un retry de fetch ici la trouvera —
            // sinon l'user aurait vu un widget vide alors qu'une conv
            // existe en BDD. Idempotent : si rien n'existe → réponse
            // ``{conversation_id: null, messages: []}`` = no-op visible.
            _historyLoaded = false;
            _historyLoadInFlight = false;
            // Refetch immédiat pour repeupler les chips.
            fetchWelcomeSuggestions();
            setInputEnabled(true);
            showTyping(false);
            els.input.focus();
        }

        function showClearFailure() {
            // Le serveur a refusé : NE PAS resetUI (ce serait mentir à
            // l'user — sa conv reste en BDD). Affiche un message bref.
            hideWelcome();
            var div = document.createElement("div");
            div.className = "jw-error";
            div.textContent =
                "Impossible d'effacer la conversation (erreur serveur). Réessaie.";
            els.messages.appendChild(div);
            scrollToBottom();
            setInputEnabled(true);
        }

        if (!conversationId) {
            resetUI();
            return;
        }

        // Get XSRF token from cookie
        var xsrf = "";
        var parts = ("; " + document.cookie).split("; _xsrf=");
        if (parts.length === 2) xsrf = parts.pop().split(";").shift();

        // ``source: "widget"`` — clear scopé : ne touche PAS la conv de la
        // page ``/iris`` (cf. ``IrisClearAPIHandler`` côté backend).
        fetch("/api/iris/clear", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-Xsrftoken": xsrf,
            },
            body: JSON.stringify({ source: "widget" }),
        })
            .then(function (res) {
                if (!res.ok) {
                    // Le serveur n'a PAS effacé — surfacer l'erreur plutôt
                    // que faire passer pour OK (correctif adversarial #9
                    // sur fix #18).
                    showClearFailure();
                    return;
                }
                resetUI();
            })
            .catch(function (_err) {
                // Erreur réseau : pareil, ne PAS resetUI à l'aveugle.
                showClearFailure();
            });
    }

    // --- Fullscreen toggle ---
    // Bascule entre mode "panneau ancré" (400×560 en bas-droite via .jw-panel)
    // et mode "plein écran" (couvre tout le viewport via .jw-panel.jw-fullscreen).
    // **Ne navigue PAS vers /iris** — l'utilisateur garde sa conv active, son
    // input en cours, sa position de scroll, et la page sur laquelle il
    // travaille. C'est le comportement attendu : "ouvrir en grand", pas
    // "ouvrir ailleurs". La page /iris reste accessible via la sidebar pour
    // un workflow dédié (mode "expert").
    //
    // z-index = var(--z-iris-grid-fullscreen, 1900) — sous OverlayManager.modal
    // (2000), system-modal (9999), toast (10000) → confirmations, sync, bug
    // reports restent visibles au-dessus (cohérent avec iris-grid fullscreen).
    function toggleFullscreen() {
        // Guard défensif : le bouton n'est pas accessible quand le panel est
        // fermé (il est dans le header) mais on garde la garde au cas où un
        // futur shortcut clavier appellerait toggleFullscreen sans panel ouvert.
        if (!isOpen) return;
        isFullscreen = !isFullscreen;
        if (isFullscreen) {
            els.panel.classList.add("jw-fullscreen");
            els.fullscreenBtn.innerHTML = JW_COLLAPSE_ICON;
            els.fullscreenBtn.setAttribute("title", "Quitter le plein écran");
            els.fullscreenBtn.setAttribute("aria-label", "Quitter le plein écran");
            els.fullscreenBtn.setAttribute("aria-pressed", "true");
        } else {
            els.panel.classList.remove("jw-fullscreen");
            els.fullscreenBtn.innerHTML = JW_EXPAND_ICON;
            els.fullscreenBtn.setAttribute("title", "Plein écran");
            els.fullscreenBtn.setAttribute("aria-label", "Plein écran");
            els.fullscreenBtn.setAttribute("aria-pressed", "false");
        }
        // Focus management : on ancre le focus sur le bouton après toggle.
        // Sans ça, un utilisateur au clavier peut perdre la position de
        // focus lors du redimensionnement (focus reste sur l'élément qui a
        // déclenché, mais NVDA n'annonce pas toujours le changement
        // aria-pressed sans re-focus). Adversarial #3 a11y.
        try { els.fullscreenBtn.focus(); } catch (e) { /* defensive */ }
    }

    // --- Auto-resize textarea ---
    function autoResizeInput() {
        els.input.style.height = "auto";
        els.input.style.height = Math.min(els.input.scrollHeight, 80) + "px";
    }

    // --- Bind events ---
    function bindEvents() {
        els.fab.addEventListener("click", togglePanel);
        els.closeBtn.addEventListener("click", closePanel);
        els.clearBtn.addEventListener("click", clearConversation);
        els.fullscreenBtn.addEventListener("click", toggleFullscreen);

        // Smart scroll : tracker si l'utilisateur a scrollé vers le haut
        els.messages.addEventListener("scroll", function () {
            var threshold = 100;
            var atBottom = els.messages.scrollHeight - els.messages.scrollTop - els.messages.clientHeight < threshold;
            _userScrolledUp = !atBottom;
        });

        els.sendBtn.addEventListener("click", function () {
            if (els.sendBtn.classList.contains("jw-stop-mode")) {
                stopGeneration();
            } else {
                sendMessage();
            }
        });

        els.input.addEventListener("keydown", function (e) {
            if (e.key === "Enter" && !e.shiftKey) {
                e.preventDefault();
                sendMessage();
            }
        });

        els.input.addEventListener("input", autoResizeInput);

        // Escape — étapes successives (pattern aligné iris-grid.js
        // ``_handleEscape`` line 10600 sur /datastore) :
        //   1) Si plein écran → quitter le plein écran, garder le panel ouvert.
        //   2) Sinon, si le panel est ouvert → fermer le panel.
        // Cette progression évite que l'utilisateur en plein écran perde sa
        // conversation par un Escape involontaire (cas vécu sur les éditeurs
        // type VSCode/IntelliJ qui ont le même pattern).
        document.addEventListener("keydown", function (e) {
            if (e.key !== "Escape") return;
            if (isFullscreen) {
                toggleFullscreen();
            } else if (isOpen) {
                closePanel();
            }
        });
    }

    // --- Init ---
    function init() {
        buildWidget();
        cacheElements();
        bindEvents();

        // Restore open state
        if (isOpen) {
            // Pre-warm hydratation : on lance le fetch AVANT openPanel
            // pour minimiser le flash welcome → contenu historique. Le
            // openPanel re-appelle ``loadConversationHistory`` mais
            // c'est idempotent (``_historyLoadInFlight`` empêche le
            // double-fetch). Sans ce pre-warm, l'user voit ~50-200ms
            // de welcome avant que les messages apparaissent ; avec
            // pre-warm + animation du panel (300ms), c'est invisible
            // en pratique.
            loadConversationHistory();
            openPanel();
        }
    }

    // Wait for DOM
    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init);
    } else {
        init();
    }
})();
