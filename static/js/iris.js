/**
 * iris.js — Client WebSocket pour l'interface de chat de l'agent Komptia.
 *
 * Mode conversation unique : une seule conversation par utilisateur.
 * Gère : connexion WebSocket, envoi/réception de messages, streaming,
 * résultats SQL, clarifications, rendu Markdown basique.
 */

/* Debug helper (P5) — remplace console.log en prod. Activable via :
 *   - window.IRIS_DEBUG = true (depuis la console du navigateur, persisté)
 *   - localStorage.setItem('iris_debug', '1')
 * En prod sans flag : no-op. Pas de bruit dans DevTools des utilisateurs.
 * Note : console.warn/console.error restent actifs partout (signaux
 * légitimes que les ops doivent voir). */
function _irisDebug() {
    try {
        var on = (typeof window !== 'undefined' && window.IRIS_DEBUG === true) ||
                 (typeof localStorage !== 'undefined' && localStorage.getItem('iris_debug') === '1');
        if (on && typeof console !== 'undefined' && console.log) {
            console.log.apply(console, arguments);
        }
    } catch (e) { /* SSR / privacy mode */ }
}

// ──── State ────

/** @type {WebSocket|null} */
let ws = null;

/** @type {number|null} */
let currentConversationId = null;

/** @type {number} Dernière valeur ``_seq`` reçue d'un event WebSocket.
 * Task #15 (M2, 2026-05-22) — utilisée pour dedup et détection de trous.
 * Source de vérité backend : ``SequentialEventPersister._seq`` muté dans
 * ``event["_seq"]`` avant l'envoi WS. Monotone par conversation.
 * Reset à 0 quand on change de conversation (nouvelle conv = nouveau flux).
 * Pas reset sur reconnect WS : un reconnect dans la même conv DOIT voir
 * la continuité du seq (sinon faux warnings sur les premiers events). */
let lastEventSeq = 0;

/** @type {string} */
// Rôle auto-détecté par le backend (plus de sélection manuelle)

/** @type {boolean} */
let isStreaming = false;
// Mirroir global de ``isStreaming`` — lu par ``iris-grid.js`` dans le
// guard ``beforeunload`` pour ne déclencher l'avertissement
// "modifications non enregistrées" que si Iris streame réellement
// (sinon, un classeur transitoire affichait un warning trompeur après
// chaque résultat). Synchronisé à chaque changement de ``isStreaming``.
try { window.__irisStreamingActive = false; } catch (e) { /* SSR-safe */ }
// Note : __irisPipelineRunning a été retiré (refonte 2026-05-08). Le
// streaming pipeline passe désormais par le tour Iris classique, donc
// __irisStreamingActive couvre déjà le blocage messageInput pendant la
// durée de la pipeline.

/** @type {HTMLElement|null} */
let currentStreamDiv = null;

/** @type {HTMLElement|null} Dernière bulle assistant (pour feedback) */
let lastAssistantBubble = null;

/** @type {number} Délai de reconnexion en ms (backoff exponentiel capé à 30s) */
let reconnectDelay = 1000;

/** @type {number|null} */
let reconnectTimer = null;

/**
 * @type {number} Compteur de tentatives de reconnexion consécutives.
 * Reset à 0 dès qu'un onopen réussit. Atteindre MAX_RECONNECT_ATTEMPTS
 * stoppe le retry automatique et propose une reconnexion manuelle
 * (finding M1 audit /iris 2026-05-20 — anti-spam logs + UX explicite).
 */
let reconnectAttempts = 0;

/**
 * @type {number} Plafond dur de tentatives consécutives avant abandon.
 * Avec backoff 1s → 30s + jitter, 30 tentatives ≈ ~12-15 min de retries.
 * Au-delà : on suppose un problème serveur durable, l'utilisateur doit
 * réessayer manuellement (UX explicite > drain CPU silencieux).
 */
const MAX_RECONNECT_ATTEMPTS = 30;

/** @type {string} Current mode: 'execution' or 'explanation' */
let currentMode = 'execution';

/** @type {Array<{question: string, options: string[]}>} Buffer de clarifications pour groupement */
let pendingClarifications = [];

/** @type {number} Compteur de grilles SQL pour persistence localStorage */
let _gridCounter = 0;

/**
 * Registre `search_id -> SqlResultGrid` pour le flow de consent.
 *
 * Quand Iris yielde un event ``sql_results`` (cf. ``agent_service.py:6080``),
 * le frontend rend une grille via ``renderSQLResults`` et capture son
 * instance ici, indexée par le ``search_id`` du tool_result. Quand l'event
 * ``data_read_consent_request`` arrive juste après (même ``search_id``,
 * ligne ``agent_service.py:6367``), le bouton « Configurer l'anonymisation »
 * récupère la grille et appelle son ``_openAnonymizationPanel()`` —
 * c'est le MÊME modal que le bouton cadenas du classeur, pas un panel
 * détaché dupliqué.
 *
 * Cycle de vie : reset au changement de conversation (cf. ``_resetGridState``).
 * Pas de WeakMap : ``search_id`` est un nombre, pas un objet.
 *
 * **LRU cap (todo #22)** : ``Map`` au lieu de ``Object.create(null)`` pour
 * garantir l'ordre d'insertion et permettre l'éviction FIFO de la plus
 * ancienne grille quand on dépasse ``_GRIDS_MAX``. Sans ce cap, une session
 * Iris longue (100+ requêtes SQL dans une conv) accumulait toutes les
 * grilles + leur DOM + données → memory leak frontend lent. 20 entrées
 * couvrent largement le consent flow (qui regarde uniquement la grille
 * du dernier ``execute_sql``) avec une marge confortable pour les
 * accès rétroactifs (re-clic sur une grille précédente du chat).
 *
 * @type {Map<number, Object>}  // search_id -> SqlResultGrid
 */
const _GRIDS_MAX = 20;
let _gridsBySearchId = new Map();

/**
 * Dernier ``search_id`` indexé dans ``_gridsBySearchId`` (par ordre
 * d'insertion dans ``renderSQLResults``). Utilisé comme fallback EXPLICITE
 * du flow consent uniquement quand le backend a omis ``search_id`` dans
 * l'event ``data_read_consent_request`` (rétrocompat, ne devrait pas
 * arriver en pratique).
 *
 * Pourquoi un tracker dédié plutôt que ``Math.max(...Object.keys(...))`` :
 * (1) ne dépend pas de l'ordre d'iteration des keys (la spec ES garantit
 * l'ordre pour les integer-like keys mais le code reste plus lisible avec
 * un tracker explicite) ; (2) survit à un changement vers search_id non
 * numérique ; (3) O(1) au lieu de O(N). Cf. adversarial review MEDIUM
 * 2026-05-20.
 *
 * @type {number|null}
 */
let _lastIndexedSearchId = null;

// ──── DOM Elements ────

const messagesArea = document.getElementById('messagesArea');
const welcomeState = document.getElementById('welcomeState');
const messageInput = document.getElementById('messageInput');
const sendBtn = document.getElementById('sendBtn');
const typingIndicator = document.getElementById('typingIndicator');
// roleSelector supprimé — auto-détection côté backend

// ──── Utilities ────

/**
 * Append à messagesArea en maintenant l'invariant : le typingIndicator
 * (logo Iris + 3 dots animés) reste TOUJOURS le dernier enfant de la zone.
 *
 * Sans ce wrapper, un appendChild brut place le nouvel élément APRÈS le
 * typingIndicator (qui est le lastChild initial du HTML), donc le logo
 * remonte visuellement au-dessus des nouveaux contenus — bug typique vu
 * en streaming quand des thinking blocks / tool indicators / etc.
 * apparaissent pendant qu'Iris « réfléchit ».
 *
 * Tous les rendus dans messagesArea DOIVENT passer par ce helper (sauf
 * le typingIndicator lui-même).
 */
function appendToMessages(el) {
    if (!messagesArea || !el) return;
    messagesArea.appendChild(el);
    _ensureTypingIndicatorLast();
}

function _ensureTypingIndicatorLast() {
    if (
        typingIndicator
        && typingIndicator.parentNode === messagesArea
        && messagesArea.lastChild !== typingIndicator
    ) {
        messagesArea.appendChild(typingIndicator);
    }
}

// ──── Auto-save du draft (anti-perte au refresh) ────
//
// Stocke le texte en cours de saisie dans localStorage. Au reload de la page,
// on restaure dans ``messageInput`` pour que l'user retrouve sa réponse même
// après un refresh accidentel ou un crash navigateur. Cf. incident 2026-05-09
// (David a perdu une longue réponse à une clarification après un retour-arrière
// non voulu).
//
// La clé est scopée par user (cf. feedback_localstorage_cross_user_leak.md) :
// l'ancienne clé globale 'iris.draft.text' fuitait le brouillon d'un user vers
// le suivant sur un navigateur partagé (poste comptable, démo client). Le scope
// par username — déjà disponible côté template via IRIS_CONFIG.currentUser —
// garantit qu'un draft reste lié au compte qui l'a tapé.
var _IRIS_DRAFT_DEBOUNCE_MS = 400;
var _draftSaveTimer = null;

function _getDraftKey() {
    // Lit window.IRIS_CONFIG.currentUser (username, injecté par
    // templates/iris.html). Fallback 'anon' si IRIS_CONFIG pas encore
    // initialisé : ce script est chargé APRÈS l'injection donc improbable,
    // mais defensive au cas où un futur refactor changerait l'ordre.
    var who = '';
    try {
        if (window.IRIS_CONFIG && typeof window.IRIS_CONFIG.currentUser === 'string') {
            who = window.IRIS_CONFIG.currentUser;
        }
    } catch (e) { who = ''; }
    return 'iris.draft.text.' + (who || 'anon');
}

/**
 * Récupère le username scopé pour les clés localStorage (Mo3 — anti
 * pollution cross-user sur poste partagé). Réutilise la même source que
 * ``_getDraftKey`` pour cohérence. Filtre les caractères non-alnum pour
 * éviter les collisions de séparateur ``-`` dans la clé composite
 * ``grid-{user}-conv{N}-{idx}``.
 * @returns {string}
 */
function _getPersistUsername() {
    var who = '';
    try {
        if (window.IRIS_CONFIG && typeof window.IRIS_CONFIG.currentUser === 'string') {
            who = window.IRIS_CONFIG.currentUser;
        }
    } catch (e) { who = ''; }
    // Sanitize : seulement [a-zA-Z0-9_], remplacer le reste par '_'.
    // Évite qu'un username contenant '-' ne casse le parsing de la clé
    // (ex: clé 'grid-jean-dupont-conv5-1' → ambiguïté avec conv-id).
    return (who || 'anon').replace(/[^a-zA-Z0-9_]/g, '_');
}

// One-shot migration : purger l'ancienne clé globale 'iris.draft.text' qui
// fuitait entre comptes. Tournera UNE FOIS par navigateur (puis la clé
// n'existe plus). On préfère perdre l'éventuel draft non envoyé plutôt que
// le laisser leaker au prochain user qui se connectera.
try { localStorage.removeItem('iris.draft.text'); }
catch (e) { /* localStorage indispo : silencieux */ }

function _saveDraft(text) {
    if (_draftSaveTimer) clearTimeout(_draftSaveTimer);
    _draftSaveTimer = setTimeout(function() {
        try {
            var key = _getDraftKey();
            if (text && text.trim()) {
                localStorage.setItem(key, text);
            } else {
                localStorage.removeItem(key);
            }
        } catch (e) { /* localStorage plein / indispo : silencieux */ }
    }, _IRIS_DRAFT_DEBOUNCE_MS);
}

function _loadDraft() {
    try { return localStorage.getItem(_getDraftKey()) || ''; }
    catch (e) { return ''; }
}

function _clearDraft() {
    if (_draftSaveTimer) { clearTimeout(_draftSaveTimer); _draftSaveTimer = null; }
    try { localStorage.removeItem(_getDraftKey()); }
    catch (e) { /* idem */ }
}

// ──── Todo #36 — Récupération automatique d'un message perdu sur coupure WS ────
//
// Si l'utilisateur clique « Envoyer » au moment exact où la WS coupe
// (réseau lâche, serveur redémarre, etc.), l'ancienne implémentation
// affichait juste "Connexion au serveur perdue" et le message tapé
// disparaissait — l'user devait retaper. Désormais : on stocke le
// message dans localStorage (clé scopée user comme ``_saveDraft``),
// et à la prochaine ``ws.onopen`` on le rejoue automatiquement.
//
// Cohérent avec le pattern _saveDraft : 1 clé par user via
// ``_getPersistUsername``, fail-safe sur localStorage indispo.
function _getPendingMessageKey() {
    return 'iris.pending.msg.' + _getPersistUsername();
}

function _savePendingMessage(text) {
    if (!text || !text.trim()) return;
    try { localStorage.setItem(_getPendingMessageKey(), text); }
    catch (e) { /* localStorage indispo / plein : silencieux */ }
}

function _loadPendingMessage() {
    try { return localStorage.getItem(_getPendingMessageKey()) || ''; }
    catch (e) { return ''; }
}

function _clearPendingMessage() {
    try { localStorage.removeItem(_getPendingMessageKey()); }
    catch (e) { /* idem */ }
}

/**
 * Échappe les caractères HTML pour éviter les injections XSS.
 * @param {*} text
 * @returns {string}
 */
// Wrappers vers iris-common.js (SSOT — task #14). Le bundle ``IrisCommon``
// est chargé AVANT iris.js dans templates/iris.html. Si non chargé, ces
// wrappers crashent immédiatement — c'est volontaire (fail-loud pour
// détecter une régression d'ordre de chargement plutôt que running
// silencieusement avec des copies stale).
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

/**
 * Convertit du Markdown basique en HTML.
 * Supporte : **gras**, *italique*, `code inline`, ```blocs de code```,
 * listes (- / * / 1.), headers (#-###), sauts de ligne.
 * @param {string} text
 * @returns {string}
 */
function formatMarkdown(text) {
    if (!text) return '';

    // 0. Supprimer les tags internes du LLM (pas destinés à l'affichage)
    // Tolérant à la casse ET aux espaces internes pour matcher le parser
    // backend tolérant (C20). Accepte [THINKING], [ thinking ], [Suggestions],
    // etc. Singulier/pluriel accepté pour SUGGESTION(S).
    text = text.replace(/\[\s*THINKING\s*\][\s\S]*?\[\s*\/\s*THINKING\s*\]/gi, '');
    text = text.replace(/\[\s*SUGGESTIONS?\s*\][\s\S]*?\[\s*\/\s*SUGGESTIONS?\s*\]/gi, '');
    text = text.replace(/\[\s*ANALYSIS\s*\][\s\S]*?\[\s*\/\s*ANALYSIS\s*\]/gi, '');
    // Nettoyer les tags orphelins (streaming partiel — le tag fermant n'est pas encore arrivé)
    text = text.replace(/\[\s*THINKING\s*\][\s\S]*$/gi, '');
    text = text.replace(/\[\s*SUGGESTIONS?\s*\][\s\S]*$/gi, '');
    text = text.replace(/\[\s*ANALYSIS\s*\][\s\S]*$/gi, '');
    // Supprimer les lignes vides multiples résultantes
    text = text.replace(/\n{3,}/g, '\n\n');
    text = text.trim();
    if (!text) return '';

    // 1. Extraire les blocs de code pour les protéger
    var codeBlocks = [];
    var withPlaceholders = text.replace(/```([\s\S]*?)```/g, function(_, code) {
        var idx = codeBlocks.length;
        codeBlocks.push(code.trim());
        return '\x00CODEBLOCK' + idx + '\x00';
    });

    // 2. Escape le HTML (hors blocs de code)
    var html = escapeHtml(withPlaceholders);

    // 3. Restaurer les blocs de code (déjà escapés par escapeHtml dans le contenu)
    html = html.replace(/\x00CODEBLOCK(\d+)\x00/g, function(_, idx) {
        return '<pre class="iris-code-block"><code>' + escapeHtml(codeBlocks[parseInt(idx)]) + '</code></pre>';
    });

    // 4. Code inline (`...`) — avant gras pour ne pas interférer
    html = html.replace(/`([^`]+)`/g, '<code class="iris-inline-code">$1</code>');

    // 5. Gras (**...**) et italique (*...*)
    html = html.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
    html = html.replace(/(?<!\*)\*([^*]+)\*(?!\*)/g, '<em>$1</em>');

    // 5b. Séparateurs horizontaux (--- ou ***)
    html = html.replace(/^-{3,}$/gm, '<hr class="iris-md-hr">');
    html = html.replace(/^\*{3,}$/gm, '<hr class="iris-md-hr">');

    // 6. Headers (# à ###) — en début de ligne
    html = html.replace(/^### (.+)$/gm, '<strong style="font-size:0.95em">$1</strong>');
    html = html.replace(/^## (.+)$/gm, '<strong style="font-size:1.05em">$1</strong>');
    html = html.replace(/^# (.+)$/gm, '<strong style="font-size:1.15em">$1</strong>');

    // 7. Listes à puces (- ou *) — convertir en <ul><li>
    html = html.replace(/((?:^|\n)(?:[-*] .+(?:\n|$))+)/g, function(block) {
        var items = block.trim().split('\n');
        var lis = items.map(function(item) {
            return '<li>' + item.replace(/^[-*] /, '') + '</li>';
        }).join('');
        return '<ul class="iris-md-list">' + lis + '</ul>';
    });

    // 8. Listes numérotées (1. 2. etc.)
    html = html.replace(/((?:^|\n)\d+\. .+(?:\n|$))+/g, function(block) {
        var items = block.trim().split('\n');
        var lis = items.map(function(item) {
            return '<li>' + item.replace(/^\d+\. /, '') + '</li>';
        }).join('');
        return '<ol class="iris-md-list">' + lis + '</ol>';
    });

    // 9. Tableaux Markdown (approche line-by-line — le regex `(^|\n)...(\n|$)`
    // consommait le `\n` séparateur et ne matchait qu'une ligne à la fois, ce qui
    // faisait rater la détection de bloc multi-lignes — donc les pipes restaient
    // en texte brut à l'écran).
    function _isPipeRow_(l) {
        var t = l.trim();
        return t.length >= 2 && t.charAt(0) === '|' && t.charAt(t.length - 1) === '|';
    }
    function _isSepRow_(l) {
        var t = l.trim();
        if (!_isPipeRow_(t)) return false;
        var inner = t.slice(1, -1);
        var cells = inner.split('|');
        if (cells.length === 0) return false;
        return cells.every(function(cell) {
            var c = cell.trim();
            return c.length > 0 && /^:?-+:?$/.test(c);
        });
    }
    function _parseCells_(l) {
        return l.trim().replace(/^\|/, '').replace(/\|$/, '')
            .split('|').map(function(c) { return c.trim(); });
    }
    function _parseAlign_(l) {
        return _parseCells_(l).map(function(c) {
            var left = c.charAt(0) === ':';
            var right = c.charAt(c.length - 1) === ':';
            if (left && right) return 'center';
            if (right) return 'right';
            if (left) return 'left';
            return null;
        });
    }
    function _renderTable_(blockLines) {
        var hasHeader = blockLines.length >= 2 && _isSepRow_(blockLines[1]);
        var aligns = hasHeader ? _parseAlign_(blockLines[1]) : [];
        function cellAttr(i) {
            var a = aligns[i];
            return a ? ' style="text-align:' + a + '"' : '';
        }
        var out = '<div class="iris-md-table-wrap"><table class="iris-md-table">';
        if (hasHeader) {
            var headers = _parseCells_(blockLines[0]);
            out += '<thead><tr>' + headers.map(function(h, i) {
                return '<th' + cellAttr(i) + '>' + h + '</th>';
            }).join('') + '</tr></thead><tbody>';
            for (var j = 2; j < blockLines.length; j++) {
                if (_isSepRow_(blockLines[j])) continue;
                var cells = _parseCells_(blockLines[j]);
                out += '<tr>' + cells.map(function(c, i) {
                    return '<td' + cellAttr(i) + '>' + c + '</td>';
                }).join('') + '</tr>';
            }
            out += '</tbody>';
        } else {
            out += '<tbody>';
            for (var k = 0; k < blockLines.length; k++) {
                if (_isSepRow_(blockLines[k])) continue;
                var cells2 = _parseCells_(blockLines[k]);
                out += '<tr>' + cells2.map(function(c) {
                    return '<td>' + c + '</td>';
                }).join('') + '</tr>';
            }
            out += '</tbody>';
        }
        out += '</table></div>';
        return out;
    }
    (function _parseAllTables_() {
        var lines = html.split('\n');
        var out = [];
        var i = 0;
        while (i < lines.length) {
            if (_isPipeRow_(lines[i])) {
                var block = [];
                while (i < lines.length && _isPipeRow_(lines[i])) {
                    block.push(lines[i]);
                    i++;
                }
                // Au moins 2 lignes contiguës pour faire un tableau visuel
                if (block.length >= 2) {
                    out.push(_renderTable_(block));
                } else {
                    out.push.apply(out, block);
                }
            } else {
                out.push(lines[i]);
                i++;
            }
        }
        html = out.join('\n');
    })();

    // 10. Sauts de ligne (sauf à l'intérieur des <pre>, <ul>, <ol>, <table>)
    html = html.replace(/\n/g, '<br>');
    // Nettoyer les <br> inutiles autour des blocs (`(?:<br>\s*)+` = 1 ou plus,
    // pour couvrir les doubles sauts de ligne avant/après un bloc Markdown)
    html = html.replace(/(?:<br>\s*)+(<\/?(?:pre|ul|ol|li|hr|table|thead|tbody|tr|th|td|div class="iris-md-table-wrap"))/g, '$1');
    html = html.replace(/(<\/(?:pre|ul|ol|li|table|thead|tbody|tr|th|td|div)>)(?:\s*<br>)+/g, '$1');
    html = html.replace(/(<hr[^>]*>)(?:\s*<br>)+/g, '$1');

    return html;
}

// ──── Indicateur de remplissage context-window ────
//
// Source de vérité : `/admin/ai-config` (via IRIS_CONFIG.contextWindow et le
// done event qui porte `last_input_tokens` + `context_window` à chaque tour).
// Le numérateur reflète la TAILLE DU CONTEXTE envoyée au LLM au dernier tour
// (input + cache pour Anthropic) — donc chute après un compact, ce qui rend
// les compacts observables visuellement. Le total dépend du modèle actif :
// si l'admin change de modèle, le `done` event suivant met à jour le total.
// Single source of truth : window.KomptiaFormat (format-helpers.js).
// Le helper est chargé en <head> par base.html — toujours disponible ici.
function _formatTokenCount(value) {
    return window.KomptiaFormat.tokenCount(value);
}

// Format compact « 313k/1m » : 1234 → "1.2k", 1500000 → "1.5m". Plus lisible
// qu'un grand nombre formaté avec des espaces dans une pilule étroite.
function _formatCompact(n) {
    return window.KomptiaFormat.compactNumber(n);
}

function _formatPct(used, total) {
    return window.KomptiaFormat.percent(used, total);
}

function _zoneClassForPct(pct) {
    if (pct >= 95) return 'cw-critical';
    if (pct >= 80) return 'cw-high';
    if (pct >= 60) return 'cw-med';
    return 'cw-low';
}

// Barre HTML/CSS classique : un wrapper `.iris-cw-bar` avec un `.iris-cw-fill`
// dont on pilote la `width` en pourcentage. Plus net que des glyphes braille
// (qui rendent moche en UI web : trop fins, espacés, varient selon la fonte).

// Refs DOM mises en cache au premier appel (le DOM est prêt avant le 1er
// appel grâce au DOMContentLoaded init). Évite N×getElementById à chaque
// turn — et permet de logger UN warning si le template a divergé (rename
// d'un id, suppression d'un sub-élément). Sans ça, un changement de template
// silencieux casserait le bar SANS aucun signal côté ops (anti-pattern
// flaggé par la doctrine Komptia : « pas de données fausses silencieuses »).
var _cwRefs = null;
var _cwLastUsed = 0;          // mémoire pour skipper les payloads `last_input_tokens=0`
var _cwMissingWarned = false; // ne logger qu'une fois

// ── Estimation live entre 2 valeurs autoritatives du serveur ──
//
// Le serveur n'émet ``context_progress`` qu'après CHAQUE appel LLM. Pour un
// turn typique (1 LLM call avec tool_use + 1 LLM call final), l'utilisateur
// voit le compteur figé pendant que les tool_use/tool_result défilent.
// L'estimation locale comble le trou : chaque event qui sera renvoyé au
// LLM au prochain tour (text assistant streamé, tool_use, tool_result,
// message user) incrémente ``_cwEstimatedDelta`` en ``chars/_CW_CHARS_PER_TOKEN``.
// Quand le serveur renvoie un ``context_progress`` (autoritative), on
// reset le delta et on cale ``_cwLastUsed`` sur la vraie valeur.
//
// Ratio 4 chars/token : approximation safe pour Claude (réel ≈ 3.5-4).
// L'estimation sous-estime légèrement — le ``context_progress`` recale.
// Cap par event évite qu'un gros tool_result SQL fasse exploser l'UI.
var _cwEstimatedDelta = 0;
var _cwTotal = null;
var _cwModelDisplay = null;
var _cwRecomputeRaf = null;
var _CW_CHARS_PER_TOKEN = 4;
var _CW_PER_EVENT_CHAR_CAP = 80000;

function _cwAddEstimatedChars(chars) {
    if (window.__irisReplayMode) return;
    if (_cwTotal == null) return;
    if (!chars || !Number.isFinite(chars) || chars <= 0) return;
    var capped = Math.min(chars, _CW_PER_EVENT_CHAR_CAP);
    _cwEstimatedDelta += capped / _CW_CHARS_PER_TOKEN;
    _cwScheduleRecompute();
}

function _cwScheduleRecompute() {
    if (_cwRecomputeRaf != null) return;
    if (typeof requestAnimationFrame === 'undefined') {
        // Fallback (env tests sans rAF) : render synchrone.
        _cwApplyEstimationRender();
        return;
    }
    _cwRecomputeRaf = requestAnimationFrame(function() {
        _cwRecomputeRaf = null;
        _cwApplyEstimationRender();
    });
}

function _cwApplyEstimationRender() {
    if (_cwTotal == null) return;
    var used = _cwLastUsed + Math.round(_cwEstimatedDelta);
    if (used > _cwTotal) used = _cwTotal;
    _cwRenderToDOM(used, _cwTotal, _cwModelDisplay);
}

function _cwResolveRefs() {
    if (_cwRefs) return _cwRefs;
    var root = document.getElementById('contextWindowIndicator');
    if (!root) return null;
    _cwRefs = {
        root: root,
        progress: document.getElementById('cwProgress'),
        value: document.getElementById('cwValue')
    };
    return _cwRefs;
}

/**
 * Met à jour l'indicateur de remplissage de la fenêtre de contexte du LLM.
 * @param {Object} opts
 * @param {number|null} opts.usedTokens   Tokens d'entrée du dernier tour
 *   (= taille de contexte envoyée). 0 = conversation vierge.
 * @param {number|null} opts.contextWindow Capacité maximale du modèle actif
 *   (depuis le registre BDD). null = aucun provider configuré → indicateur masqué.
 * @param {string|null} [opts.modelDisplay] Nom lisible du modèle, pour le tooltip.
 * @param {boolean} [opts.animate] Si vrai, animation de chute (post-compact).
 * @param {boolean} [opts.skipIfZeroAfterPositive] Si vrai et usedTokens=0
 *   alors qu'on avait déjà reporté une valeur > 0, on garde la valeur
 *   précédente (cas : un run sort sans appel LLM → done event renvoie 0,
 *   on ne veut pas que la barre tombe trompeusement à 0%).
 */
// Rendu DOM pur — pas d'effet de bord sur l'état (``_cwLastUsed``, etc.).
// Appelé à la fois par ``updateContextWindow`` (autoritative serveur) et
// ``_cwApplyEstimationRender`` (tick estimation locale).
function _cwRenderToDOM(used, total, modelDisplay) {
    var refs = _cwResolveRefs();
    if (!refs) return;
    refs.root.removeAttribute('hidden');
    var pct = (used / total) * 100;
    if (!Number.isFinite(pct) || pct < 0) pct = 0;
    var modelTxt = modelDisplay ? ' (' + modelDisplay + ')' : '';
    if (refs.value) {
        refs.value.textContent = _formatCompact(used) + '/' + _formatCompact(total);
    }
    if (refs.progress) {
        refs.progress.style.width = pct.toFixed(2) + '%';
    }
    refs.root.classList.remove('cw-med', 'cw-high', 'cw-critical');
    var zone = _zoneClassForPct(pct);
    if (zone !== 'cw-low') refs.root.classList.add(zone);
    refs.root.setAttribute(
        'title',
        'Contexte LLM' + modelTxt + ' : ' + _formatTokenCount(used) + ' / ' +
        _formatTokenCount(total) + ' tokens (' + _formatPct(used, total) + ')'
    );
}

function updateContextWindow(opts) {
    var refs = _cwResolveRefs();
    if (!refs) return;
    var total = (opts && opts.contextWindow != null) ? Number(opts.contextWindow) : null;
    if (!Number.isFinite(total) || total <= 0) {
        refs.root.setAttribute('hidden', '');
        return;
    }
    var used = (opts && opts.usedTokens != null) ? Number(opts.usedTokens) : 0;
    if (!Number.isFinite(used) || used < 0) used = 0;
    if (opts && opts.skipIfZeroAfterPositive && used === 0 && _cwLastUsed > 0) {
        return;
    }
    if (used > total) used = total;
    // Valeur autoritative reçue → on recale l'état + reset l'estimation
    // locale (le delta accumulé est désormais inclus dans ``used``).
    _cwLastUsed = used;
    _cwTotal = total;
    if (opts && opts.modelDisplay) _cwModelDisplay = opts.modelDisplay;
    _cwEstimatedDelta = 0;
    if (_cwRecomputeRaf != null) {
        if (typeof cancelAnimationFrame !== 'undefined') {
            cancelAnimationFrame(_cwRecomputeRaf);
        }
        _cwRecomputeRaf = null;
    }
    _cwRenderToDOM(used, total, _cwModelDisplay);
}

// ──── Smart scroll — ne pas forcer le scroll si l'utilisateur a scrollé vers le haut ────
var _userScrolledUp = false;

/**
 * Fait défiler #messagesArea vers le bas de façon fluide.
 * Ne scroll que si l'utilisateur est déjà en bas (pas scrollé vers le haut).
 *
 * Pendant le replay (refresh DOM-IDENTIQUE), on no-op : un seul scroll
 * final est fait par ``replayConversationEvents`` à la fin pour éviter
 * 100 scroll smooth × 100 events.
 */
function scrollToBottom() {
    if (_userScrolledUp || !messagesArea) return;
    if (window.__irisReplayMode) return;
    messagesArea.scrollTo({ top: messagesArea.scrollHeight, behavior: 'smooth' });
}

/**
 * Force le scroll vers le bas (pour les actions utilisateur : envoi message, clear, etc.)
 */
function forceScrollToBottom() {
    _userScrolledUp = false;
    if (messagesArea) {
        messagesArea.scrollTo({ top: messagesArea.scrollHeight, behavior: 'smooth' });
    }
}

// ──── SQL Results Jump Banner ────

/**
 * Affiche un bandeau "Résultats SQL" si des cartes SQL existent mais sont scrollées hors de vue.
 * Le bandeau apparaît en bas de la zone de messages et permet de scroller vers les résultats.
 */
function showSqlResultsBannerIfNeeded() {
    // Remove any existing banner
    var existing = document.getElementById('sqlJumpBanner');
    if (existing) existing.remove();

    // Find the LAST sql results card in the chat
    var allCards = messagesArea.querySelectorAll('.iris-sql-card');
    if (allCards.length === 0) return;
    var lastCard = allCards[allCards.length - 1];

    // Check if the card is scrolled out of view
    var areaRect = messagesArea.getBoundingClientRect();
    var cardRect = lastCard.getBoundingClientRect();
    var isVisible = cardRect.top >= areaRect.top && cardRect.bottom <= areaRect.bottom;
    if (isVisible) return;

    // Create a sticky banner
    var banner = document.createElement('div');
    banner.id = 'sqlJumpBanner';
    banner.className = 'iris-sql-jump-banner';
    var rowCount = lastCard.querySelector('.iris-sql-card-header');
    var rowText = rowCount ? rowCount.textContent.trim() : 'Résultats SQL';
    banner.innerHTML = '<span>' + escapeHtml(rowText) + '</span>'
        + '<button type="button" class="iris-sql-jump-btn">Voir les données ↑</button>';

    // Insert banner at end of messages area (above the input area)
    appendToMessages(banner);

    // Auto-remove banner when user scrolls to the card
    var scrollHandler = function() {
        var cr = lastCard.getBoundingClientRect();
        var ar = messagesArea.getBoundingClientRect();
        if (cr.top >= ar.top && cr.bottom <= ar.bottom + 50) {
            banner.remove();
            messagesArea.removeEventListener('scroll', scrollHandler);
        }
    };
    messagesArea.addEventListener('scroll', scrollHandler);

    // Handle click
    banner.querySelector('.iris-sql-jump-btn').addEventListener('click', function() {
        lastCard.scrollIntoView({ behavior: 'smooth', block: 'start' });
        // Highlight briefly
        lastCard.classList.add('iris-sql-card-highlight');
        setTimeout(function() { lastCard.classList.remove('iris-sql-card-highlight'); }, 2000);
        banner.remove();
        messagesArea.removeEventListener('scroll', scrollHandler);
    });

    // Auto-remove after 15 seconds
    setTimeout(function() {
        if (banner.parentNode) banner.remove();
        messagesArea.removeEventListener('scroll', scrollHandler);
    }, 15000);
}

// ──── Feedback row (helper partagé live + restore) ────

/**
 * Construit une rangée de feedback (thumbs-up / refresh / thumbs-down) en SVG, compacte et discrète.
 * Le CSS contrôle l'apparition au hover sur la bulle.
 * @param {string} [selectedFeedback] - 'positive' | 'adjust' | 'negative' | undefined
 * @returns {HTMLElement}
 */
function _buildFeedbackRow(selectedFeedback) {
    // Icônes SVG (Lucide-style, 14px) — rendu cohérent cross-platform
    var ICON_UP = '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M7 10v12"/><path d="M15 5.88 14 10h5.83a2 2 0 0 1 1.92 2.56l-2.33 8A2 2 0 0 1 17.5 22H7V10l4.34-8.68a1 1 0 0 1 1.66.26z"/></svg>';
    var ICON_ADJUST = '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12a9 9 0 0 1 14.83-6.9L21 8"/><path d="M21 3v5h-5"/><path d="M21 12a9 9 0 0 1-14.83 6.9L3 16"/><path d="M3 21v-5h5"/></svg>';
    var ICON_DOWN = '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 14V2"/><path d="M9 18.12 10 14H4.17a2 2 0 0 1-1.92-2.56l2.33-8A2 2 0 0 1 6.5 2H17v12l-4.34 8.68a1 1 0 0 1-1.66-.26z"/></svg>';

    var row = document.createElement('div');
    row.className = 'iris-feedback-row';
    row.innerHTML =
        '<button type="button" class="iris-feedback-btn" data-feedback="positive" title="Bonne réponse" aria-label="Bonne réponse">' + ICON_UP + '</button>' +
        '<button type="button" class="iris-feedback-btn iris-feedback-btn--adjust" data-feedback="adjust" title="Presque, à ajuster" aria-label="Presque, à ajuster">' + ICON_ADJUST + '</button>' +
        '<button type="button" class="iris-feedback-btn" data-feedback="negative" title="Mauvaise réponse" aria-label="Mauvaise réponse">' + ICON_DOWN + '</button>';
    if (selectedFeedback) {
        var selEl = row.querySelector('[data-feedback="' + selectedFeedback + '"]');
        if (selEl) selEl.classList.add('selected');
        // Cohérence live/refresh : après vote les boutons sont disabled (pas de
        // re-clic possible). Si l'user veut changer d'avis, il reposte la question.
        row.querySelectorAll('.iris-feedback-btn').forEach(function(b) { b.disabled = true; });
        // Flag pour garder la row visible sans dépendre de :has() (pas supporté
        // sur certains vieux navigateurs)
        row.classList.add('voted');
    }
    return row;
}

// ──── Rendering — Messages ────

/**
 * Ajoute une bulle de message utilisateur (alignée à droite).
 * @param {string} text
 */
function addUserMessage(text) {
    const row = document.createElement('div');
    row.className = 'iris-message-row user';

    const bubble = document.createElement('div');
    bubble.className = 'iris-bubble';
    // Preserve line breaks in user messages
    bubble.innerHTML = escapeHtml(text).replace(/\n/g, '<br>');

    const avatar = document.createElement('div');
    avatar.className = 'iris-avatar user-avatar';
    avatar.title = 'Vous';
    avatar.innerHTML = '<svg width="14" height="14" fill="none" stroke="white" viewBox="0 0 24 24" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M15.75 6a3.75 3.75 0 11-7.5 0 3.75 3.75 0 017.5 0zM4.501 20.118a7.5 7.5 0 0114.998 0"/></svg>';

    row.appendChild(bubble);
    row.appendChild(avatar);
    appendToMessages(row);
    // Garder le typingIndicator toujours en dernier enfant
    if (typingIndicator && typingIndicator.parentNode === messagesArea) {
        messagesArea.appendChild(typingIndicator);
    }
    forceScrollToBottom();
}

/**
 * Crée une bulle vide pour l'assistant (alignée à gauche), l'ajoute au DOM et la retourne.
 * Utilisée pour le streaming : le texte est injecté progressivement dedans.
 * @returns {HTMLElement} Le div de contenu dans la bulle (cible du streaming)
 */
function createAssistantBubble() {
    const row = document.createElement('div');
    row.className = 'iris-message-row assistant';

    const avatar = document.createElement('div');
    avatar.className = 'iris-avatar assistant-avatar';
    avatar.title = 'Iris';
    avatar.innerHTML = '<svg width="14" height="14" viewBox="0 0 100 100"><g transform="translate(0,100) scale(0.1,-0.1)" stroke="none"><path d="M325 804 l-169 -174 344 0 344 0 -169 174 c-94 95 -172 173 -175 173 -3 0 -81 -78 -175 -173z" fill="#fff"/><path d="M25 500 c-18 -20 -18 -21 5 -45 23 -24 29 -25 144 -25 l120 0 -57 -58 c-31 -32 -57 -62 -57 -67 0 -5 12 -22 27 -37 l27 -28 63 62 63 62 0 -125 0 -125 45 -44 45 -44 0 247 0 247 -203 0 c-192 0 -205 -1 -222 -20z" fill="rgba(255,255,255,0.6)"/><path d="M555 275 l0 -246 124 128 c69 70 168 172 220 225 94 96 95 97 76 118 -17 19 -29 20 -219 20 l-201 0 0 -245z" fill="var(--brand-light)"/></g></svg>';

    const bubble = document.createElement('div');
    bubble.className = 'iris-bubble';

    const content = document.createElement('div');
    content.className = 'iris-bubble-content';

    bubble.appendChild(content);
    row.appendChild(avatar);
    row.appendChild(bubble);
    appendToMessages(row);
    lastAssistantBubble = bubble;
    scrollToBottom();

    return content;
}

/** Compteur d'étapes outils pour la session de réponse courante */
let toolStepCount = 0;
let _currentElementGroup = null;  // Active element group element
let _currentSQLBuildGroup = null; // Active SQL build group element
// Flag tour-en-cours : si execute_sql a réussi avec des lignes ET que le LLM
// n'a pas pensé à appeler ask_user_clarification, le frontend affiche
// automatiquement une card feedback au 'done' — garantit que l'utilisateur
// peut toujours valider/corriger, indépendamment du bon vouloir du modèle.
var _pendingExecuteSqlFeedback = false;

/**
 * Returns the container where tool lines should be appended
 * (element group body, SQL build body, or messagesArea as fallback).
 */
function _getToolContainer() {
    if (_currentElementGroup) {
        var body = _currentElementGroup.querySelector('.iris-element-group-body');
        if (body) return body;
    }
    if (_currentSQLBuildGroup) {
        var body2 = _currentSQLBuildGroup.querySelector('.iris-element-group-body');
        if (body2) return body2;
    }
    return messagesArea;
}

/**
 * Opens a collapsible element group section.
 */
function handleElementStart(element, index, total) {
    // Close any previous element group that wasn't closed
    if (_currentElementGroup) {
        _currentElementGroup.classList.add('collapsed');
        _currentElementGroup = null;
    }

    const group = document.createElement('div');
    group.className = 'iris-element-group';
    group.dataset.element = element;
    group.innerHTML =
        '<div class="iris-element-group-header">' +
            '<span class="iris-element-group-chevron">▼</span>' +
            '<span class="iris-element-group-name">' + escapeHtml(element) + '</span>' +
            '<span class="iris-element-group-result"></span>' +
            '<span class="iris-element-group-status">' +
                '<span class="iris-tool-spinner"></span>' +
            '</span>' +
        '</div>' +
        '<div class="iris-element-group-body"></div>';

    // Toggle collapse on header click
    group.querySelector('.iris-element-group-header').addEventListener('click', function() {
        group.classList.toggle('collapsed');
    });

    // Track start time for total elapsed display
    group._startTime = Date.now();

    appendToMessages(group);
    _currentElementGroup = group;
    scrollToBottom();
}

/**
 * Closes the current element group with a result summary.
 */
function handleElementEnd(element, success, sqlFragment) {
    var group = _currentElementGroup;
    if (!group) {
        // Try to find by data attribute (e.g., on restore)
        var all = messagesArea.querySelectorAll('.iris-element-group[data-element="' + CSS.escape(element) + '"]');
        if (all.length > 0) group = all[all.length - 1];
    }
    if (!group) return;

    // En replay, _startTime a été posé au moment du refresh (microsecondes
    // plus tôt) → elapsed bidon. On masque la durée pour ne pas afficher
    // "0ms" partout. Cf. review BLOCKING #7. Dette : persister elapsed_ms
    // côté backend pour avoir la vraie durée du live.
    var elapsed = (group._startTime && !window.__irisReplayMode)
        ? Date.now() - group._startTime
        : null;
    var timeStr = elapsed === null ? '' : (
        elapsed >= 60000
            ? Math.floor(elapsed / 60000) + 'min ' + Math.round((elapsed % 60000) / 1000) + 's'
            : elapsed >= 1000
                ? (elapsed / 1000).toFixed(1) + 's'
                : elapsed + 'ms'
    );

    // Update result on header
    var resultEl = group.querySelector('.iris-element-group-result');
    if (resultEl && sqlFragment) {
        resultEl.textContent = '✓ Localisé';
    }

    // Update status
    var statusEl = group.querySelector('.iris-element-group-status');
    if (statusEl) {
        if (success) {
            statusEl.innerHTML = '<span style="color:var(--status-success,#22c55e);font-weight:600;">✓</span> ' + escapeHtml(timeStr);
        } else {
            statusEl.innerHTML = '<span style="color:var(--status-error,#ef4444);font-weight:600;">✗</span> ' + escapeHtml(timeStr);
        }
    }

    // Apply found/not-found styling
    group.classList.add(success ? 'element-found' : 'element-not-found');

    // Clear reference BEFORE scheduling collapse (prevents race with next element_start)
    _currentElementGroup = null;

    // Auto-collapse after a short delay for visual feedback
    setTimeout(function() { group.classList.add('collapsed'); }, 400);
}

/**
 * Affiche la progression de la recherche 4D.
 */
function handleAlignmentSearch(event) {
    var container = document.createElement('div');
    container.className = 'iris-alignment-progress';
    container.innerHTML = '<span class="iris-tool-spinner"></span> ' +
        '<span class="search-count">Recherche dans la BDD…</span>';
    appendToMessages(container);
    scrollToBottom();
}

/**
 * Affiche une question d'alignement.
 */
function handleAlignmentQuestion(event) {
    var question = event.question || 'Question de clarification';
    var row = document.createElement('div');
    row.className = 'iris-message-row assistant';

    var avatar = document.createElement('div');
    avatar.className = 'iris-avatar assistant-avatar';
    avatar.title = 'Iris';
    avatar.innerHTML = '<svg width="14" height="14" viewBox="0 0 100 100"><g transform="translate(0,100) scale(0.1,-0.1)" stroke="none"><path d="M325 804 l-169 -174 344 0 344 0 -169 174 c-94 95 -172 173 -175 173 -3 0 -81 -78 -175 -173z" fill="#fff"/><path d="M25 500 c-18 -20 -18 -21 5 -45 23 -24 29 -25 144 -25 l120 0 -57 -58 c-31 -32 -57 -62 -57 -67 0 -5 12 -22 27 -37 l27 -28 63 62 63 62 0 -125 0 -125 45 -44 45 -44 0 247 0 247 -203 0 c-192 0 -205 -1 -222 -20z" fill="rgba(255,255,255,0.6)"/><path d="M555 275 l0 -246 124 128 c69 70 168 172 220 225 94 96 95 97 76 118 -17 19 -29 20 -219 20 l-201 0 0 -245z" fill="var(--brand-light)"/></g></svg>';

    var bubble = document.createElement('div');
    bubble.className = 'iris-bubble';
    bubble.innerHTML = '<div class="iris-alignment-question">' + escapeHtml(question) + '</div>';

    row.appendChild(avatar);
    row.appendChild(bubble);
    appendToMessages(row);
    scrollToBottom();
}

/**
 * Affiche un résumé d'alignement.
 */
function handleAlignmentComplete(event) {
    var container = document.createElement('div');
    container.className = 'iris-alignment-summary';
    var summary = '<strong>✓ Alignement confirmé</strong> — ';
    summary += (event.element_count || 0) + ' éléments trouvés';
    container.innerHTML = summary;
    appendToMessages(container);
    scrollToBottom();
}

/**
 * Opens the SQL build group.
 */
function handleSQLBuildStart() {
    if (_currentSQLBuildGroup) return;

    var group = document.createElement('div');
    group.className = 'iris-sql-build-group';
    group.innerHTML =
        '<div class="iris-concept-group-header">' +
            '<span class="iris-concept-group-chevron">▼</span>' +
            '<span class="iris-concept-group-name">Construction de la requête SQL</span>' +
            '<span class="iris-concept-group-result"></span>' +
            '<span class="iris-concept-group-status">' +
                '<span class="iris-tool-spinner"></span>' +
            '</span>' +
        '</div>' +
        '<div class="iris-concept-group-body"></div>';

    group.querySelector('.iris-concept-group-header').addEventListener('click', function() {
        group.classList.toggle('collapsed');
    });

    group._startTime = Date.now();
    appendToMessages(group);
    _currentSQLBuildGroup = group;
    scrollToBottom();
}

/**
 * Closes the SQL build group.
 */
function handleSQLBuildEnd(success, reason) {
    var group = _currentSQLBuildGroup;
    if (!group) return;

    // Idem handleElementEnd : masque la durée en replay pour éviter "0ms".
    var elapsed = (group._startTime && !window.__irisReplayMode)
        ? Date.now() - group._startTime
        : null;
    var timeStr = elapsed === null ? '' : (
        elapsed >= 60000
            ? Math.floor(elapsed / 60000) + 'min ' + Math.round((elapsed % 60000) / 1000) + 's'
            : elapsed >= 1000
                ? (elapsed / 1000).toFixed(1) + 's'
                : elapsed + 'ms'
    );

    var resultEl = group.querySelector('.iris-concept-group-result');
    if (resultEl && !success && reason) {
        resultEl.textContent = '→ ' + reason;
        resultEl.style.color = 'var(--status-error, #ef4444)';
    }

    var statusEl = group.querySelector('.iris-concept-group-status');
    if (statusEl) {
        if (success) {
            statusEl.innerHTML = '<span style="color:var(--status-success,#22c55e);font-weight:600;">✓</span> ' + escapeHtml(timeStr);
        } else {
            statusEl.innerHTML = '<span style="color:var(--status-error,#ef4444);font-weight:600;">✗</span> ' + escapeHtml(timeStr);
        }
    }

    group.classList.add(success ? 'sql-success' : 'sql-failed');
    if (success) {
        setTimeout(function() { group.classList.add('collapsed'); }, 300);
    }

    _currentSQLBuildGroup = null;
}

// ──── Exploration group (guard phases timeline) ────

// Référence du bloc exploration courant (une session à la fois).
// Reset par cleanupExploration() ou renderExplorationGroup() d'une nouvelle question.
var _currentExplorationGroup = null;

/**
 * Labels/icônes par phase de l'exploration guard.
 * Les textes sont en français, respect du pattern existant.
 */
var EXPLORATION_STEP_DEFS = {
    catalog:        { icon: '<i class="bi bi-book"></i>', label: 'Catalogue du schéma' },
    selection:      { icon: '<i class="bi bi-bullseye"></i>', label: 'Sélection des tables' },
    fk:             { icon: '<i class="bi bi-link-45deg"></i>', label: 'Expansion FK' },
    batch:          { icon: '<i class="bi bi-calculator"></i>', label: 'Analyse des colonnes' },
    complementary:  { icon: '<i class="bi bi-search"></i>', label: 'Recherche complémentaire' },
    complete:       { icon: '<i class="bi bi-check-circle-fill"></i>', label: 'Exploration terminée' },
};

/**
 * Ouvre un nouveau bloc exploration dans la bulle assistant courante.
 *
 * Placement : à l'INTÉRIEUR de la bulle assistant, sous `iris-bubble-content`.
 * Ainsi, quand le texte de l'assistant stream dans `currentStreamDiv`, il
 * apparaît AU-DESSUS de la timeline — ordre de lecture chronologique naturel :
 * [message d'Iris] → [détail des outils qu'il a utilisés].
 *
 * Si aucune bulle n'existe encore (exploration démarre avant le 1er text_delta),
 * on en crée une vide pour garantir la même structure.
 *
 * @returns {HTMLElement} la ref du bloc créé
 */
function renderExplorationGroup() {
    // Si un bloc précédent existe encore (ex: question enchaînée sans refresh),
    // le fermer proprement avant d'en ouvrir un nouveau.
    if (_currentExplorationGroup) {
        _currentExplorationGroup.classList.add('collapsed');
    }

    var group = document.createElement('div');
    group.className = 'iris-exploration-group';
    group.innerHTML =
        '<div class="iris-exploration-group-header">' +
            '<span class="iris-exploration-group-chevron">▼</span>' +
            '<span class="iris-exploration-group-icon"><i class="bi bi-search"></i></span>' +
            '<span class="iris-exploration-group-name">Exploration du schéma</span>' +
            '<span class="iris-exploration-group-status">' +
                '<span class="iris-tool-spinner"></span>' +
            '</span>' +
        '</div>' +
        '<div class="iris-exploration-group-body"></div>';

    var header = group.querySelector('.iris-exploration-group-header');
    header.addEventListener('click', function() {
        group.classList.toggle('collapsed');
    });
    group._startTime = Date.now();

    // Créer la bulle assistant tôt si elle n'existe pas encore, pour pouvoir
    // positionner le groupe d'exploration EN DESSOUS du texte (qui arrivera
    // plus tard via text_delta). Le typing indicator générique devient
    // redondant — on le masque puisque la timeline sert d'indicateur riche.
    if (!currentStreamDiv) {
        if (typingIndicator) {
            typingIndicator.style.display = 'none';
        }
        currentStreamDiv = createAssistantBubble();
        currentStreamDiv._rawText = '';
        currentStreamDiv._renderedAnalysis = new Set();
    }

    // Append INSIDE the bubble (sibling of iris-bubble-content, after it).
    // Le text_delta ultérieur écrira dans `currentStreamDiv.innerHTML`
    // (= iris-bubble-content) — notre groupe, frère suivant, n'est pas affecté.
    var bubbleEl = currentStreamDiv.parentElement;
    if (bubbleEl) {
        bubbleEl.appendChild(group);
    } else {
        // Fallback défensif si la structure attendue n'est pas là
        appendToMessages(group);
    }
    _currentExplorationGroup = group;
    scrollToBottom();
    return group;
}

/**
 * Ajoute OU met à jour une ligne d'étape dans le bloc exploration courant.
 * - step : 'catalog'|'selection'|'fk'|'batch'|'complementary'|'complete'
 * - state : 'active'|'done'|'error'
 * - meta  : objet dépendant de l'étape (counts, tables, etc.)
 *
 * Si une ligne avec le même `step` existe déjà, elle est remplacée (idempotent).
 */
function updateExplorationStep(step, state, meta) {
    if (!_currentExplorationGroup) return;
    var body = _currentExplorationGroup.querySelector('.iris-exploration-group-body');
    if (!body) return;

    var def = EXPLORATION_STEP_DEFS[step] || { icon: '•', label: step };
    var detail = _formatExplorationDetail(step, meta);

    // Retire une ligne existante pour le même step (update)
    var existing = body.querySelector('.iris-exploration-step[data-step="' + step + '"]');
    if (existing) existing.remove();

    var line = document.createElement('div');
    line.className = 'iris-exploration-step' + (state || 'active');
    line.dataset.step = step;

    line.innerHTML =
        '<span class="iris-exploration-step-dot"></span>' +
        '<span class="iris-exploration-step-label">' +
            def.icon + ' ' + escapeHtml(def.label) +
        '</span>' +
        '<span class="iris-exploration-step-detail">' + detail + '</span>';

    body.appendChild(line);
    scrollToBottom();
}

/**
 * Construit le détail textuel/HTML d'une étape à partir de son payload.
 * Respect confidentialité : counts + table names uniquement.
 */
function _formatExplorationDetail(step, meta) {
    meta = meta || {};
    if (step === 'catalog') {
        var tot = (meta.total_tables || 0) + (meta.total_views || 0);
        return escapeHtml(tot + ' éléments (' + (meta.total_tables || 0) + ' tables, ' + (meta.total_views || 0) + ' vues)');
    }
    if (step === 'selection') {
        var count = meta.count || 0;
        if (count === 0) return '<span style="color:var(--status-error,#ef4444);">aucune table retenue — élargissement…</span>';
        var tables = (meta.tables || []).slice(0, 8);
        var chipsHtml = tables.map(function(t) {
            return '<span class="iris-exploration-step-chip">' + escapeHtml(t) + '</span>';
        }).join('');
        var more = count > tables.length ? ' <span style="color:var(--text-faint,#94a3b8);">+' + (count - tables.length) + '</span>' : '';
        return escapeHtml('(' + count + ') ') + chipsHtml + more;
    }
    if (step === 'fk') {
        var added = meta.added || 0;
        if (added === 0) {
            return '<span style="color:var(--text-faint,#94a3b8);">aucun voisin FK ajouté</span>';
        }
        var at = (meta.added_tables || []).slice(0, 5);
        var chips = at.map(function(t) {
            return '<span class="iris-exploration-step-chip">' + escapeHtml(t) + '</span>';
        }).join('');
        return escapeHtml('+' + added + ' tables ') + chips;
    }
    if (step === 'batch') {
        return escapeHtml('lot ' + (meta.current || 0) + '/' + (meta.total || 0) +
            ' · ' + (meta.tables_in_batch || 0) + ' tables, ' +
            (meta.columns_in_batch || 0) + ' colonnes');
    }
    if (step === 'complementary') {
        if (meta.has_findings) {
            return escapeHtml((meta.new_findings_count || 0) + ' élément(s) supplémentaire(s) trouvé(s)');
        }
        return '<span style="color:var(--text-faint,#94a3b8);">rien de nouveau</span>';
    }
    if (step === 'complete') {
        if (meta.aborted) {
            // exploration interrompue (aucune table retenue, cancel, exception…)
            // — on le signale visuellement pour que le bloc ne reste pas "silencieux"
            return '<span style="color:var(--status-warn,#f59e0b);">exploration interrompue (sélection insuffisante ou annulée)</span>';
        }
        var parts = [(meta.table_count || 0) + ' tables explorées'];
        if (meta.business_rules_injected) {
            parts.push(meta.business_rules_injected + ' règle(s) métier injectée(s)');
        }
        return escapeHtml(parts.join(' · '));
    }
    return '';
}

/**
 * Finalise le bloc exploration courant (appel au 'exploration_complete' event).
 * Affiche le temps total + status ✓ et auto-collapse après 800ms.
 */
function finalizeExplorationGroup(success, meta) {
    if (!_currentExplorationGroup) return;
    var group = _currentExplorationGroup;

    // Mo1 — Priorité au duration_ms persisté côté serveur (event.duration_ms).
    // Source de vérité : le serveur a mesuré le vrai elapsed entre
    // ``exploration_start`` et ``exploration_complete`` au moment du LIVE.
    // Au replay, cette valeur est restituée telle quelle → durée correcte
    // au refresh (avant Mo1, on masquait via _skipTimer faute de meilleur).
    //
    // Fallback : si ``duration_ms`` absent (event yieldé sans cette clé,
    // conv legacy pré-Mo1, ou path B replay sans server timing), on retombe
    // sur l'ancien comportement : calcul live OK, replay masqué.
    var elapsed;
    if (meta && typeof meta.duration_ms === 'number' && meta.duration_ms >= 0) {
        elapsed = meta.duration_ms;
    } else {
        var skipTimer = !!(meta && meta._skipTimer);
        elapsed = skipTimer ? null : (group._startTime ? Date.now() - group._startTime : 0);
    }
    var timeStr = '';
    if (elapsed != null) {
        timeStr = elapsed >= 60000
            ? Math.floor(elapsed / 60000) + 'min ' + Math.round((elapsed % 60000) / 1000) + 's'
            : elapsed >= 1000
                ? (elapsed / 1000).toFixed(1) + 's'
                : elapsed + 'ms';
    }

    var statusEl = group.querySelector('.iris-exploration-group-status');
    if (statusEl) {
        var color = success ? '#22c55e' : '#ef4444';
        var mark = success ? '✓' : '✗';
        statusEl.innerHTML = '<span style="color:' + color + ';font-weight:600;">' + mark + '</span>'
            + (timeStr ? ' <span>' + escapeHtml(timeStr) + '</span>' : '');
    }
    group.classList.add(success ? 'exploration-done' : 'exploration-error');

    // Compacter le header avec un résumé (table_count, règles injectées)
    if (success && meta) {
        var nameEl = group.querySelector('.iris-exploration-group-name');
        if (nameEl) {
            var brief = 'Schéma exploré · ' + (meta.table_count || 0) + ' tables';
            if (meta.business_rules_injected) {
                brief += ' · ' + meta.business_rules_injected + ' règle(s) métier';
            }
            nameEl.textContent = brief;
        }
    }

    // Auto-collapse après un court délai
    setTimeout(function() {
        if (group && group.classList) group.classList.add('collapsed');
    }, 800);

    _currentExplorationGroup = null;
}

/**
 * Nettoie le bloc exploration si interrompu (cancel/error/done sans complete).
 */
function cleanupExploration() {
    if (_currentExplorationGroup) {
        _currentExplorationGroup.classList.add('collapsed');
        var statusEl = _currentExplorationGroup.querySelector('.iris-exploration-group-status');
        if (statusEl) {
            statusEl.innerHTML = '<span style="color:var(--text-faint,#94a3b8);">interrompu</span>';
        }
        _currentExplorationGroup = null;
    }
}

// ──── Plan structuré (plan_add / plan_update / plan_list) ────
//
// Référence du bloc plan courant (un seul par turn assistant). Reset par
// ``startNewConversation`` / ``loadConversationHistory`` (nouveau turn) ou
// par ``applyPlanUpdate`` quand un nouvel assistant bubble apparaît.
var _currentPlanGroup = null;

var PLAN_STATUS_DEFS = {
    pending:     { marker: '○', label: 'À faire',   shortLabel: 'restant' },
    in_progress: { marker: '◐', label: 'En cours',  shortLabel: 'en cours' },
    completed:   { marker: '✓', label: 'Fait',      shortLabel: 'fait' },
    cancelled:   { marker: '✗', label: 'Annulé',    shortLabel: 'annulé' }
};
var PLAN_STATUS_ORDER = ['pending', 'in_progress', 'completed', 'cancelled'];
var PLAN_MAX_RENDER_TASKS = 50;  // mirror MAX_PLAN_TASKS côté Python

/**
 * Crée ou met à jour le widget plan dans le turn courant (idempotent).
 * Reçoit un snapshot complet de la liste des tasks (jamais des deltas).
 *
 * @param {Array<{id:number,subject:string,status:string,description?:string,updated_at?:number}>} plan
 */
function applyPlanUpdate(plan) {
    if (!Array.isArray(plan)) return;

    // Snapshot vide = soit pas de plan posé (cas normal au début), soit
    // tous les outils sont en cours sans plan : on ne crée pas de widget
    // pour rien. Si un widget existait déjà (cas théorique), on le laisse
    // tel quel — ne JAMAIS supprimer un widget qui contenait des tasks
    // avant (l'utilisateur perdrait l'historique de ce qui a été planifié).
    if (plan.length === 0) {
        return;
    }

    // Cap défensif côté UI au cas où le snapshot dépasserait. Tronque les
    // tasks au-delà de PLAN_MAX_RENDER_TASKS pour ne pas exploser le DOM,
    // mais on affiche un footer explicite pour ne PAS masquer silencieusement
    // (cf. règle « pas de données fausses silencieusement »). Si MAX_PLAN_TASKS
    // côté Python (plan_tools_core.py) augmente sans bump ici, l'utilisateur
    // voit explicitement « + N tasks tronquées » au lieu d'une liste tronquée
    // sans signal.
    var truncatedCount = Math.max(0, plan.length - PLAN_MAX_RENDER_TASKS);
    var safePlan = truncatedCount > 0
        ? plan.slice(0, PLAN_MAX_RENDER_TASKS)
        : plan;

    var group = _currentPlanGroup;
    if (!group || !group.isConnected) {
        group = _createPlanGroup();
        _currentPlanGroup = group;
    }

    _renderPlanTasks(group, safePlan, truncatedCount);
    _updatePlanGroupStatus(group, safePlan);
    _ensureTypingIndicatorLast();
    scrollToBottom();
}

function _createPlanGroup() {
    var group = document.createElement('div');
    group.className = 'iris-plan-group';

    var header = document.createElement('div');
    header.className = 'iris-plan-group-header';

    var chev = document.createElement('span');
    chev.className = 'iris-plan-group-chevron';
    chev.textContent = '▼';
    header.appendChild(chev);

    var icon = document.createElement('span');
    icon.className = 'iris-plan-group-icon';
    icon.innerHTML = '<i class="bi bi-list-check" aria-hidden="true"></i>';
    header.appendChild(icon);

    var name = document.createElement('span');
    name.className = 'iris-plan-group-name';
    name.textContent = 'Plan structuré';
    header.appendChild(name);

    var status = document.createElement('span');
    status.className = 'iris-plan-group-status';
    header.appendChild(status);

    header.addEventListener('click', function() {
        group.classList.toggle('collapsed');
    });

    var body = document.createElement('div');
    body.className = 'iris-plan-group-body';

    group.appendChild(header);
    group.appendChild(body);

    // Append au niveau de ``messagesArea`` (pas dans une bulle assistant),
    // pour la même raison que ``addToolIndicator`` ne s'attache pas à
    // ``currentStreamDiv`` : entre deux ``plan_update``, un ``tool_use``
    // remet ``currentStreamDiv = null`` (iris.js case ``tool_use``), et
    // s'attacher à la bulle créerait un widget orphelin dans une bulle
    // qui n'aurait que ça dedans. Le widget est conceptuellement au
    // niveau du tour, pas du segment de texte — il vit donc au niveau
    // de la conversation, comme les ``.iris-tool-line`` standalone.
    appendToMessages(group);

    return group;
}

function _renderPlanTasks(group, plan, truncatedCount) {
    var body = group.querySelector('.iris-plan-group-body');
    if (!body) return;

    // Re-render complet : le snapshot est la source de vérité. On vide et
    // on reconstruit — moins de bugs qu'un patch incrémental, perf
    // négligeable pour plans ≤ 50 tasks.
    body.textContent = '';

    for (var i = 0; i < plan.length; i++) {
        var task = plan[i];
        if (!task || typeof task !== 'object') continue;

        var statusKey = (typeof task.status === 'string' && PLAN_STATUS_DEFS[task.status])
            ? task.status
            : 'pending';
        var def = PLAN_STATUS_DEFS[statusKey];

        var line = document.createElement('div');
        line.className = 'iris-plan-task status-' + statusKey;

        var marker = document.createElement('span');
        marker.className = 'iris-plan-task-marker';
        marker.textContent = def.marker;
        marker.setAttribute('aria-label', def.label);
        line.appendChild(marker);

        var taskBody = document.createElement('div');
        taskBody.className = 'iris-plan-task-body';

        var subj = document.createElement('div');
        subj.className = 'iris-plan-task-subject';
        // textContent = XSS safe (le subject vient du LLM)
        subj.textContent = (typeof task.subject === 'string' ? task.subject : '');
        taskBody.appendChild(subj);

        if (typeof task.description === 'string' && task.description.trim()) {
            var desc = document.createElement('div');
            desc.className = 'iris-plan-task-desc';
            desc.textContent = task.description;
            taskBody.appendChild(desc);
        }

        line.appendChild(taskBody);

        var idChip = document.createElement('span');
        idChip.className = 'iris-plan-task-id';
        idChip.textContent = '#' + (Number.isFinite(task.id) ? task.id : '?');
        line.appendChild(idChip);

        body.appendChild(line);
    }

    // Footer "+ N tasks tronquées" si le serveur a dépassé le cap UI. Pas
    // de masquage silencieux : l'utilisateur sait que la liste affichée
    // est partielle.
    if (typeof truncatedCount === 'number' && truncatedCount > 0) {
        var footer = document.createElement('div');
        footer.className = 'iris-plan-task iris-plan-task-truncated';
        var msg = document.createElement('div');
        msg.className = 'iris-plan-task-body';
        msg.textContent = '+ ' + truncatedCount + ' tasks tronquées (affichage limité à '
            + PLAN_MAX_RENDER_TASKS + ' tasks).';
        footer.appendChild(msg);
        body.appendChild(footer);
    }
}

function _updatePlanGroupStatus(group, plan) {
    var counts = { pending: 0, in_progress: 0, completed: 0, cancelled: 0 };
    for (var i = 0; i < plan.length; i++) {
        var s = plan[i] && plan[i].status;
        if (s && Object.prototype.hasOwnProperty.call(counts, s)) {
            counts[s] += 1;
        } else {
            counts.pending += 1;
        }
    }

    // Sémantique de couleur du bandeau :
    // - plan-done : tout completed/cancelled (pending+in_progress = 0)
    // - plan-stalled : aucune task in_progress mais des pending → l'agent
    //   a posé un plan mais ne l'exécute pas activement (purement visuel)
    // - default (ambre) : au moins une in_progress
    group.classList.remove('plan-done', 'plan-stalled');
    var activeOrPending = counts.pending + counts.in_progress;
    if (activeOrPending === 0 && plan.length > 0) {
        group.classList.add('plan-done');
    } else if (counts.in_progress === 0 && counts.pending > 0) {
        group.classList.add('plan-stalled');
    }

    var statusEl = group.querySelector('.iris-plan-group-status');
    if (statusEl) {
        statusEl.textContent = '';
        var parts = [];
        for (var k = 0; k < PLAN_STATUS_ORDER.length; k++) {
            var key = PLAN_STATUS_ORDER[k];
            var c = counts[key];
            if (c > 0) {
                parts.push(c + ' ' + PLAN_STATUS_DEFS[key].shortLabel);
            }
        }
        statusEl.textContent = parts.join(' · ');
    }

    // Auto-collapse quand le plan est entièrement terminé pour ne pas
    // encombrer la conversation. Auto-expand si une task est in_progress.
    // L'utilisateur peut toujours toggler à la main.
    if (group.classList.contains('plan-done')) {
        // Ne collapse PAS si l'user vient juste de l'ouvrir manuellement
        // (heuristique : si group n'a JAMAIS été collapsé en auto, on le fait
        // une fois ; sinon on respecte l'état utilisateur).
        if (!group._autoCollapsedOnce) {
            group.classList.add('collapsed');
            group._autoCollapsedOnce = true;
        }
    } else if (counts.in_progress > 0) {
        group.classList.remove('collapsed');
    }
}

/**
 * Reset le state du plan widget — appelé quand on quitte la conversation,
 * démarre un nouveau message user, ou recharge l'historique.
 */
function resetPlanGroup() {
    _currentPlanGroup = null;
}

/**
 * Affiche un avertissement "tool bloqué par un garde".
 * Distinct des erreurs SQL : c'est un refus programmatique (règle interne),
 * pas une erreur de la BDD.
 */
// Map reason codes → short user-facing labels.
// The raw `message` from the guard is written FOR THE LLM (imperative "Tu DOIS…")
// and must NOT be shown to the end user.
var _BLOCKED_REASON_LABELS = {
    'structural_question': 'question structurelle autonome',
    'missing_filters_no_where': 'filtres manquants',
    'explanation_mode': 'mode explication',
    'no_confirmation': 'confirmation requise',
    'analysis_required': 'analyse [ANALYSIS] requise',
    'test_sql_required': 'test préalable requis',
    'column_validation': 'colonnes invalides',
};

function renderToolBlocked(tool, reason, _rawMessage) {
    // _rawMessage est ignoré côté UI : il contient des instructions adressées
    // au LLM (impératif "Tu DOIS…") et polluerait l'interface utilisateur.
    // L'utilisateur voit seulement : outil + raison courte + "Iris adapte sa stratégie".
    var label = _BLOCKED_REASON_LABELS[reason] || reason || 'règle interne';
    var block = document.createElement('div');
    block.className = 'iris-tool-blocked';
    block.innerHTML =
        '<span class="iris-tool-blocked-icon"><i class="bi bi-slash-circle"></i></span>' +
        '<div class="iris-tool-blocked-content">' +
            '<span class="iris-tool-blocked-tool">' + escapeHtml(tool || 'tool') +
            ' bloqué</span>' +
            ' <span style="color:var(--text-muted,#64748b);font-size:0.72rem;">· ' +
            escapeHtml(label) + '</span>' +
            '<div class="iris-tool-blocked-reason">Iris adapte sa stratégie…</div>' +
        '</div>';
    var container = _getToolContainer();
    container.appendChild(block);
    scrollToBottom();
}

// Tick global qui rafraîchit ``.iris-tool-line-time`` des lignes pending.
// Démarré paresseusement par addToolIndicator lors du premier tool_use et
// auto-arrêté quand aucune ligne pending n'a de ``data-start-ts`` (= toutes
// résolues ou aucune en cours). Singleton — pas de timer par-ligne, donc
// pas de leak si la conversation est clear ou la page rechargée. Tick à
// 250 ms : compromis entre fluidité visuelle et coût CPU (un querySelectorAll
// sur ~10-50 nœuds).
var _irisToolLineLiveTimerId = null;
function _formatToolElapsedMs(elapsedMs) {
    if (elapsedMs >= 60000) {
        var mins = Math.floor(elapsedMs / 60000);
        var secs = Math.round((elapsedMs % 60000) / 1000);
        return mins + 'min ' + secs + 's';
    }
    if (elapsedMs >= 1000) return (elapsedMs / 1000).toFixed(1) + 's';
    return elapsedMs + 'ms';
}
function _tickToolLineLiveTimers() {
    var lines = document.querySelectorAll(
        '.iris-tool-line:not(.tool-resolved)[data-start-ts]'
    );
    if (lines.length === 0) {
        if (_irisToolLineLiveTimerId) {
            clearInterval(_irisToolLineLiveTimerId);
            _irisToolLineLiveTimerId = null;
        }
        return;
    }
    var now = Date.now();
    for (var i = 0; i < lines.length; i++) {
        var ln = lines[i];
        var startTs = parseInt(ln.dataset.startTs, 10);
        if (!isFinite(startTs)) continue;
        var timeEl = ln.querySelector('.iris-tool-line-time');
        if (!timeEl) continue;
        timeEl.textContent = _formatToolElapsedMs(now - startTs);
    }
}
function _ensureToolLineLiveTimer() {
    if (_irisToolLineLiveTimerId) return;
    _irisToolLineLiveTimerId = setInterval(_tickToolLineLiveTimers, 250);
}

/**
 * Compact tool line (Claude Code style) — replaces the old card.
 * @param {string} toolName Tool technical name
 * @param {string} [icon] Emoji icon
 * @param {string} [label] Human label
 * @param {string} [description] Human-readable description
 * @param {boolean} [resolved] Already completed (for history restore)
 * @param {number} [startTs] Epoch ms de début (pour live timer). Si omis,
 *                            ``Date.now()`` est utilisé en fallback.
 * @returns {HTMLElement}
 */
function addToolIndicator(toolName, icon, label, description, resolved, startTs) {
    toolStepCount++;
    var isSqlTool = (toolName === 'execute_sql' || toolName === 'test_sql');

    // Wrapper holds the line + an expandable panel for SQL tools
    var wrapper = document.createElement('div');
    wrapper.className = 'iris-tool-wrap';
    wrapper.dataset.tool = toolName;
    wrapper.dataset.step = toolStepCount;

    var line = document.createElement('div');
    line.className = 'iris-tool-line'
        + (isSqlTool ? ' iris-tool-line-expandable' : '')
        + (resolved ? ' tool-resolved' : '');
    line.dataset.tool = toolName;
    line.dataset.step = toolStepCount;

    // Timer live : pose ``data-start-ts`` (epoch ms) sur la ligne pour
    // qu'un tick global (cf. _ensureToolLineLiveTimer) rafraîchisse
    // ``.iris-tool-line-time`` toutes les ~250 ms tant que la ligne n'est
    // pas ``tool-resolved``. Sans ça, ``.iris-tool-line-time`` restait vide
    // jusqu'au tool_result puis affichait soit la valeur correcte, soit
    // "0ms" si le backend n'avait pas propagé ``duration_seconds`` (cas
    // pipeline_phase_X avant 2026-05-20). Le replay (__irisReplayMode)
    // n'arme pas le live timer — c'est le restore qui pose la valeur finale.
    if (!resolved && !window.__irisReplayMode) {
        var effectiveStart = (typeof startTs === 'number' && isFinite(startTs))
            ? startTs
            : Date.now();
        line.dataset.startTs = String(effectiveStart);
        _ensureToolLineLiveTimer();
    }

    var iconStr = _emojiToBootstrapIcon(icon) || (icon ? escapeHtml(icon) : '<i class="bi bi-tools"></i>');
    var labelText = escapeHtml(label || toolName);
    var dotClass = resolved ? 'iris-tool-line-dot' : 'iris-tool-line-dot dot-active';

    if (isSqlTool) {
        line.setAttribute('role', 'button');
        line.setAttribute('tabindex', '0');
        line.setAttribute('aria-expanded', 'false');
        // Store full SQL on the line for later retrieval / copy
        line.dataset.sql = description || '';
        // Short single-line preview (truncated via CSS ellipsis); expanded view shows full SQL
        var previewText = (description || '').replace(/\s+/g, ' ').trim();
        var previewHtml = previewText
            ? ' <span class="iris-tool-line-desc">— ' + escapeHtml(previewText) + '</span>'
            : '';
        line.innerHTML =
            '<span class="iris-tool-line-chevron" aria-hidden="true">▸</span>' +
            '<span class="' + dotClass + '"></span>' +
            '<span class="iris-tool-line-icon">' + iconStr + '</span>' +
            '<span class="iris-tool-line-label">' + labelText + '</span>' +
            previewHtml +
            '<span class="iris-tool-line-time"></span>';
    } else {
        var descHtml = description
            ? ' <span class="iris-tool-line-desc">— ' + escapeHtml(description) + '</span>'
            : '';
        line.innerHTML =
            '<span class="' + dotClass + '"></span>' +
            '<span class="iris-tool-line-icon">' + iconStr + '</span>' +
            '<span class="iris-tool-line-label">' + labelText + '</span>' +
            descHtml +
            '<span class="iris-tool-line-time"></span>';
    }

    wrapper.appendChild(line);

    if (isSqlTool) {
        var panel = document.createElement('div');
        panel.className = 'iris-tool-expanded-panel';
        panel.innerHTML =
            '<div class="iris-tool-expanded-header">' +
                '<span class="iris-tool-expanded-title">Requête SQL</span>' +
                '<button type="button" class="iris-tool-expanded-copy" title="Copier la requête">Copier</button>' +
            '</div>' +
            '<pre class="iris-tool-expanded-sql"></pre>' +
            '<div class="iris-tool-expanded-error" hidden></div>';
        var preEl = panel.querySelector('.iris-tool-expanded-sql');
        if (preEl) {
            if (description) {
                preEl.textContent = description;
            } else {
                preEl.style.display = 'none';
            }
        }
        wrapper.appendChild(panel);

        var togglePanel = function() {
            var opened = wrapper.classList.toggle('iris-tool-wrap-open');
            line.setAttribute('aria-expanded', opened ? 'true' : 'false');
        };
        line.addEventListener('click', function(e) {
            // Ignore clicks on buttons / text selection drags
            if (e.target && e.target.closest('button')) return;
            togglePanel();
        });
        line.addEventListener('keydown', function(e) {
            if (e.key === 'Enter' || e.key === ' ') {
                if (e.target && e.target.closest('button')) return;
                e.preventDefault();
                togglePanel();
            }
        });

        var copyBtn = panel.querySelector('.iris-tool-expanded-copy');
        if (copyBtn) {
            copyBtn.addEventListener('click', function(e) {
                e.stopPropagation();
                var sql = line.dataset.sql || '';
                if (!sql) return;
                var done = function(ok) {
                    copyBtn.textContent = ok ? 'Copié ✓' : 'Erreur';
                    setTimeout(function() { copyBtn.textContent = 'Copier'; }, 1500);
                };
                if (navigator.clipboard && navigator.clipboard.writeText) {
                    navigator.clipboard.writeText(sql).then(function() { done(true); })
                        .catch(function() { done(false); });
                } else {
                    done(false);
                }
            });
        }
    }

    var container = _getToolContainer();
    container.appendChild(wrapper);
    scrollToBottom();
    return line;
}

// ──── Rendering — SQL Results ────

/**
 * Construit un tableau HTML à partir de colonnes et lignes.
 * @param {string[]} columns
 * @param {Object[]} rows
 * @returns {string} HTML du tableau
 */
function buildResultTable(columns, rows) {
    if (!rows || rows.length === 0) {
        return '<div class="iris-no-results">Aucun résultat retourné.</div>';
    }

    // Déterminer les colonnes : priorité au paramètre, puis keys du premier row
    let cols = columns && columns.length > 0 ? columns : null;
    if (!cols) {
        const firstRow = rows[0];
        if (firstRow && typeof firstRow === 'object' && !Array.isArray(firstRow)) {
            cols = Object.keys(firstRow);
        }
    }
    if (!cols || cols.length === 0) {
        console.warn('[Iris SQL] Aucune colonne détectable. columns:', columns, 'rows[0]:', rows[0]);
        return '<div class="iris-no-results">Erreur : impossible de détecter les colonnes.</div>';
    }

    // Détecter le format des rows : array ou dict
    const firstRow = rows[0];
    const isArrayFormat = Array.isArray(firstRow);

    let html = '<table class="iris-sql-table">';

    // En-tête
    html += '<thead><tr>';
    for (const col of cols) {
        html += `<th>${escapeHtml(col)}</th>`;
    }
    html += '</tr></thead>';

    // Corps — supporte rows en format dict {col: val} ou array [val1, val2, ...]
    html += '<tbody>';
    for (let i = 0; i < rows.length; i++) {
        const row = rows[i];
        html += `<tr class="${i % 2 === 0 ? 'row-even' : 'row-odd'}">`;
        for (let j = 0; j < cols.length; j++) {
            const value = isArrayFormat ? row[j] : row[cols[j]];
            if (value == null) {
                html += '<td class="cell-null">null</td>';
            } else {
                const escaped = escapeHtml(value);
                html += `<td title="${escapeAttr(value)}">${escaped}</td>`;
            }
        }
        html += '</tr>';
    }
    html += '</tbody></table>';
    return html;
}

/**
 * Insère un tableau de résultats SQL + bloc SQL repliable dans le chat.
 * @param {string[]} columns
 * @param {Object[]} rows
 * @param {string} [sql]
 * @param {number} [totalRowCount]
 * @param {boolean} [truncated]
 * @param {number} [searchId] - ``search_id`` du tool_result execute_sql.
 *   Quand défini, l'instance ``SqlResultGrid`` créée est indexée dans
 *   ``_gridsBySearchId`` pour que le flow de consent (cf. event
 *   ``data_read_consent_request``) puisse retrouver la bonne grille
 *   et ouvrir son ``_openAnonymizationPanel`` — le MÊME modal que le
 *   cadenas du classeur. Omis sur les restaurations (turn_events,
 *   msg.sql_data) car ces grilles n'ont jamais de gate de consent
 *   en attente — la conv est déjà marquée consented ou refusée.
 */
function renderSQLResults(columns, rows, sql, totalRowCount, truncated, searchId) {
    const card = document.createElement('div');
    card.className = 'iris-sql-card';

    try {
        var count = totalRowCount || (rows ? rows.length : 0);
        var label = 'Résultat' + (count ? ' (' + count + ')' : '');
        var tabMgr = new GridTabManager(card);
        var tabInfo = tabMgr.addTab(label, columns, rows, sql, totalRowCount, null, false);
        if (truncated && tabInfo && tabInfo.grid) {
            tabInfo.grid._truncated = true;
            tabInfo.grid._updateHeaderInfo();
        }
        // Persistence localStorage : identifiant unique par grille dans la conversation,
        // SCOPÉ PAR USER pour éviter la pollution cross-user sur poste partagé
        // (cf. finding Mo3 audit /iris 2026-05-20). Le username vient de
        // ``window.IRIS_CONFIG.currentUser`` (même source que le draft, ligne 164).
        var convId = currentConversationId || 0;
        var _safeUser = _getPersistUsername();
        _gridCounter++;
        tabMgr.setPersistId('grid-' + _safeUser + '-conv' + convId + '-' + _gridCounter);

        // Indexe la grille pour le flow consent (cf. JSDoc ci-dessus).
        // ``searchId`` peut être 0 (premier search_id de la conv) — comparer
        // strictement à null/undefined, pas via falsy. Le backend envoie
        // un int (cf. ``agent_tools.py:_handle_execute_sql`` ligne 4093+).
        if (searchId !== undefined && searchId !== null && tabInfo && tabInfo.grid) {
            // LRU cap : évincer la plus ancienne entrée si on dépasse la
            // limite. Map garde l'ordre d'insertion (ES2015+), donc
            // ``keys().next().value`` est la plus ancienne. Skip eviction
            // si le ``searchId`` est déjà présent (re-index du même).
            if (_gridsBySearchId.size >= _GRIDS_MAX && !_gridsBySearchId.has(searchId)) {
                const oldestKey = _gridsBySearchId.keys().next().value;
                _gridsBySearchId.delete(oldestKey);
            }
            _gridsBySearchId.set(searchId, tabInfo.grid);
            _lastIndexedSearchId = searchId;
        }
    } catch (err) {
        console.error('[Iris SQL] Erreur SqlResultGrid:', err);
        card.innerHTML = '<div class="iris-sql-card-header">Erreur d\'affichage</div>'
            + '<div class="iris-no-results">Impossible de construire la grille de résultats.</div>';
    }

    appendToMessages(card);
    scrollToBottom();
}

// ──── Rendering — Report Ready ────

/**
 * Affiche une carte de rapport généré avec lien de téléchargement.
 * @param {{ title: string, filename: string, format: string, row_count: number, download_url?: string, error?: string }} event
 */
function renderReportReady(event) {
    var card = document.createElement('div');
    card.className = 'iris-file-card';

    if (event.error) {
        card.innerHTML = '<div class="iris-file-card-header iris-file-card-error">'
            + '<span>&#x26A0;</span> Erreur rapport : ' + escapeHtml(event.title)
            + '</div>'
            + '<div class="iris-file-card-body">' + escapeHtml(event.error) + '</div>';
    } else {
        var formatLabel = (event.format || 'pdf').toUpperCase();
        // Validate download URL (must start with /api/reports/ to prevent injection)
        var safeUrl = '';
        if (event.download_url && /^\/api\/reports\/\d+\/download$/.test(event.download_url)) {
            safeUrl = event.download_url;
        }
        card.innerHTML = '<div class="iris-file-card-header">'
            + '<span><i class="bi bi-file-earmark-text"></i></span> Rapport g\u00e9n\u00e9r\u00e9 : <strong>' + escapeHtml(event.title) + '</strong>'
            + '</div>'
            + '<div class="iris-file-card-body">'
            + '<span class="iris-file-badge">' + escapeHtml(formatLabel) + '</span>'
            + ' ' + (event.row_count || 0) + ' ligne(s)'
            + (safeUrl
                ? ' &mdash; <a href="' + safeUrl
                  + '" class="iris-file-link" target="_blank">T\u00e9l\u00e9charger</a>'
                : '')
            + '</div>'
            + '<div class="iris-file-card-hint">Visible sur la page <a href="/reports">Rapports</a></div>';
    }

    appendToMessages(card);
    scrollToBottom();
}

// ──── Rendering — Datastore Saved ────

/**
 * Affiche une carte de confirmation de sauvegarde dans le datastore.
 * @param {{ filename: string, format?: string, row_count: number, error?: string }} event
 */
function renderDatastoreSaved(event) {
    var card = document.createElement('div');
    card.className = 'iris-file-card';

    if (event.error) {
        card.innerHTML = '<div class="iris-file-card-header iris-file-card-error">'
            + '<span>&#x26A0;</span> Erreur sauvegarde : ' + escapeHtml(event.filename)
            + '</div>'
            + '<div class="iris-file-card-body">' + escapeHtml(event.error) + '</div>';
    } else {
        var formatLabel = (event.format || '').toUpperCase();
        card.innerHTML = '<div class="iris-file-card-header iris-file-card-success">'
            + '<span><i class="bi bi-floppy"></i></span> Fichier sauvegard\u00e9 : <strong>' + escapeHtml(event.filename) + '</strong>'
            + '</div>'
            + '<div class="iris-file-card-body">'
            + (formatLabel ? '<span class="iris-file-badge">' + escapeHtml(formatLabel) + '</span> ' : '')
            + (event.row_count || 0) + ' ligne(s)'
            + '</div>'
            + '<div class="iris-file-card-hint">Visible sur la page <a href="/datastore">Datastore</a></div>';
    }

    appendToMessages(card);
    scrollToBottom();
}

// \u2500\u2500\u2500\u2500 Rendering enrichi quick_overview_workbook (P1.2.2 task #20, 2026-05-26)
//
// Attach\u00e9 en sub-element sous la iris-tool-line quand un tool_result
// quick_overview_workbook arrive avec succ\u00e8s. Affiche : nom du fichier,
// row/col counts, pills des colonnes avec type/null, mini-table 3 rows.
// Multi-sheet : note explicite.
//
// XSS-safe : tous les textes passent par textContent ou escapeHtml (le DOM
// est construit via createElement, pas innerHTML, sauf pour la pill class
// qui est sanitiz\u00e9e).
//
// Idempotent : si l'extras a d\u00e9j\u00e0 \u00e9t\u00e9 ins\u00e9r\u00e9 pour cette tool-line (cas
// du replay au refresh), on skip pour \u00e9viter de dupliquer.
function renderWorkbookOverview(targetLine, event) {
    if (!targetLine || !event || !event.result) return;
    var result = event.result;
    var tabs = result.tabs;
    if (!Array.isArray(tabs) || tabs.length === 0) return;
    var tab = tabs[0];
    if (!tab || !tab.stats_available) return;

    // Idempotence \u2014 pas de double rendering sur replay
    var wrap = targetLine.closest('.iris-tool-wrap') || targetLine.parentNode;
    if (!wrap) return;
    if (wrap.querySelector('.iris-tool-workbook-extras')) return;

    var extras = document.createElement('div');
    extras.className = 'iris-tool-workbook-extras';

    // Header : filename \u2014 counts
    var header = document.createElement('div');
    header.className = 'iris-tool-workbook-header';
    var title = result.filename || tab.label || 'Classeur';
    header.textContent = title + ' \u2014 ' + (tab.row_count || 0)
        + ' ligne(s), ' + (tab.column_count || 0) + ' colonne(s)';
    extras.appendChild(header);

    // Pills colonnes avec type + null_count si > 0
    var cols = Array.isArray(tab.columns_summary) ? tab.columns_summary : [];
    if (cols.length > 0) {
        var colsList = document.createElement('div');
        colsList.className = 'iris-tool-workbook-cols';
        cols.forEach(function(c) {
            if (!c || typeof c !== 'object') return;
            var pill = document.createElement('span');
            // Classe sanitiz\u00e9e pour type-hint (variation visuelle)
            var typeClass = String(c.type_hint || 'unknown')
                .replace(/[^a-z0-9]/gi, '-').toLowerCase();
            pill.className = 'iris-tool-workbook-col-pill iris-tool-workbook-col-type-' + typeClass;
            var text = (c.name || '?') + ' \u00b7 ' + (c.type_hint || '?');
            if (typeof c.null_count === 'number' && c.null_count > 0) {
                text += ' \u00b7 ' + c.null_count + ' null';
            }
            // Indication overflow unique
            if (c.unique_overflow) {
                text += ' \u00b7 >' + (c.unique_count_capped || 0) + ' uniques';
            }
            pill.textContent = text;
            colsList.appendChild(pill);
        });
        extras.appendChild(colsList);
    }

    // Sample rows (max 3 \u2014 ne pas surcharger la chat zone)
    var samples = Array.isArray(tab.sample_rows) ? tab.sample_rows.slice(0, 3) : [];
    if (samples.length > 0 && cols.length > 0) {
        var sampleTable = document.createElement('table');
        sampleTable.className = 'iris-tool-workbook-sample';
        var thead = document.createElement('thead');
        var hrow = document.createElement('tr');
        cols.forEach(function(c) {
            var th = document.createElement('th');
            th.textContent = c.name || '';
            hrow.appendChild(th);
        });
        thead.appendChild(hrow);
        sampleTable.appendChild(thead);
        var tbody = document.createElement('tbody');
        samples.forEach(function(row) {
            if (!row || typeof row !== 'object') return;
            var tr = document.createElement('tr');
            cols.forEach(function(c) {
                var td = document.createElement('td');
                var val = row[c.name];
                if (val === null || val === undefined) {
                    td.textContent = '\u2014';
                    td.className = 'iris-tool-workbook-sample-null';
                } else {
                    td.textContent = String(val);
                }
                tr.appendChild(td);
            });
            tbody.appendChild(tr);
        });
        sampleTable.appendChild(tbody);
        extras.appendChild(sampleTable);
    }

    // Multi-sheet note
    if (typeof result.tab_count === 'number' && result.tab_count > 1) {
        var note = document.createElement('div');
        note.className = 'iris-tool-workbook-note';
        note.textContent = result.tab_count
            + ' onglets au total (d\u00e9tails sur \u00ab ' + (tab.label || 'le 1er') + ' \u00bb)';
        extras.appendChild(note);
    }

    wrap.appendChild(extras);
}

// ──── Rendering enrichi read_workbook_rows (P1.2.3 task #21, 2026-05-26)
//
// Reconstruit une mini-table HTML depuis les cells sparse retournées par
// _read_tab_rows_core. Format : header `# col1 col2 ...` + jusqu'à 10 rows
// affichées (le tool cap déjà à 60 — au-delà : note pagination). Réutilise
// les classes CSS .iris-tool-workbook-* du quick_overview (#20).
//
// XSS-safe (textContent partout), idempotent (skip si extras déjà inséré),
// fail-safe (try/catch au call site).
function renderWorkbookRowsTable(targetLine, event) {
    if (!targetLine || !event || !event.result) return;
    var result = event.result;
    var cells = Array.isArray(result.cells) ? result.cells : [];
    if (cells.length === 0) return;

    var wrap = targetLine.closest('.iris-tool-wrap') || targetLine.parentNode;
    if (!wrap) return;
    if (wrap.querySelector('.iris-tool-workbook-extras')) return;

    // Pivot sparse → dense : rowMap[row_idx][col_name] = value
    var rowMap = {};
    var colsSeen = []; // ordre d'apparition (préserve l'ordre du backend)
    var colsSet = {};
    cells.forEach(function(c) {
        if (!c || typeof c.row !== 'number') return;
        var col = c.col;
        if (col === undefined || col === null) return;
        if (!rowMap[c.row]) rowMap[c.row] = {};
        rowMap[c.row][col] = c.value;
        if (!colsSet[col]) {
            colsSet[col] = true;
            colsSeen.push(col);
        }
    });
    if (colsSeen.length === 0) return;
    var rowKeys = Object.keys(rowMap).map(Number).sort(function(a, b) {
        return a - b;
    });
    if (rowKeys.length === 0) return;

    var extras = document.createElement('div');
    extras.className = 'iris-tool-workbook-extras';

    // Header — label de l'onglet + range lu
    var header = document.createElement('div');
    header.className = 'iris-tool-workbook-header';
    var totalRows = result.row_count_total;
    var range = '';
    if (typeof result.row_start_0based === 'number'
        && typeof result.row_end_0based === 'number') {
        range = ' (rows ' + result.row_start_0based
            + '-' + result.row_end_0based + ')';
    }
    var headerTxt = (result.label || 'Onglet')
        + ' — ' + rowKeys.length + ' ligne(s) lue(s)';
    if (totalRows) headerTxt += ' sur ' + totalRows;
    headerTxt += range;
    header.textContent = headerTxt;
    extras.appendChild(header);

    // Mini-table (cap 10 rows pour rester compact dans le chat)
    var MAX_DISPLAY = 10;
    var displayKeys = rowKeys.slice(0, MAX_DISPLAY);
    var table = document.createElement('table');
    table.className = 'iris-tool-workbook-sample';
    // Thead avec colonne # (row index 0-based) + colonnes data
    var thead = document.createElement('thead');
    var hrow = document.createElement('tr');
    var thIdx = document.createElement('th');
    thIdx.textContent = '#';
    thIdx.className = 'iris-tool-workbook-sample-rowidx';
    hrow.appendChild(thIdx);
    colsSeen.forEach(function(col) {
        var th = document.createElement('th');
        th.textContent = String(col);
        hrow.appendChild(th);
    });
    thead.appendChild(hrow);
    table.appendChild(thead);
    // Tbody
    var tbody = document.createElement('tbody');
    displayKeys.forEach(function(rk) {
        var tr = document.createElement('tr');
        var idxTd = document.createElement('td');
        idxTd.textContent = String(rk);
        idxTd.className = 'iris-tool-workbook-sample-rowidx';
        tr.appendChild(idxTd);
        colsSeen.forEach(function(col) {
            var td = document.createElement('td');
            var val = rowMap[rk][col];
            if (val === null || val === undefined) {
                td.textContent = '—';
                td.className = 'iris-tool-workbook-sample-null';
            } else {
                td.textContent = String(val);
            }
            tr.appendChild(td);
        });
        tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    extras.appendChild(table);

    // Note pagination si plus de rows que MAX_DISPLAY
    if (rowKeys.length > MAX_DISPLAY) {
        var note = document.createElement('div');
        note.className = 'iris-tool-workbook-note';
        note.textContent = '... ' + (rowKeys.length - MAX_DISPLAY)
            + ' ligne(s) supplémentaires lues — pagine avec '
            + '`row_start` pour en voir plus.';
        extras.appendChild(note);
    }

    wrap.appendChild(extras);
}

// ──── Mapping centralisé emoji → Bootstrap Icon ────
//
// Couvre :
//  1. Les icons d'outils envoyés par le backend (event.icon défini dans
//     app/services/ai/agent_service.py — ~30 emojis fixes).
//  2. Les emojis que le LLM peut placer en tête d'options
//     ask_user_clarification ("✅ C'est bon !" → bi-check-circle-fill).
//
// Toute valeur non mappée tombe en fallback escapeHtml — donc XSS-safe.
// Étendre librement quand de nouveaux emojis apparaissent côté backend
// ou dans les conventions LLM.
var EMOJI_TO_BI = {
    '✅': 'bi-check-circle-fill',
    '❌': 'bi-x-circle-fill',
    '🔄': 'bi-arrow-repeat',
    '⚠': 'bi-exclamation-triangle',
    '❓': 'bi-question-circle',
    '💡': 'bi-lightbulb',
    '🔍': 'bi-search',
    '🔎': 'bi-zoom-in',
    '📊': 'bi-bar-chart',
    '📈': 'bi-graph-up',
    '📁': 'bi-folder',
    '📂': 'bi-folder2-open',
    '📄': 'bi-file-earmark-text',
    '📅': 'bi-calendar-event',
    '📋': 'bi-clipboard',
    '📎': 'bi-paperclip',
    '📚': 'bi-book',
    '📧': 'bi-envelope',
    '💾': 'bi-floppy',
    '🔗': 'bi-link-45deg',
    '🔧': 'bi-tools',
    '🎯': 'bi-bullseye',
    '🤖': 'bi-robot',
    '🚫': 'bi-slash-circle',
    '🚨': 'bi-exclamation-octagon',
    '🧮': 'bi-calculator',
    '🧠': 'bi-cpu',
    '🧪': 'bi-eyedropper',
    '🧭': 'bi-compass',
    '🩺': 'bi-heart-pulse',
    '🗂': 'bi-folder2-open',
    '👁': 'bi-eye',
    '👍': 'bi-hand-thumbs-up',
    '👎': 'bi-hand-thumbs-down',
    '👥': 'bi-people',
    '👤': 'bi-person',
    '⚙': 'bi-gear',
    '⚡': 'bi-lightning',
    '⏳': 'bi-hourglass-split',
    '✨': 'bi-stars',
    '🔀': 'bi-shuffle',
    '🔬': 'bi-eyedropper',
    '⚖': 'bi-arrow-left-right',
    '🧩': 'bi-puzzle'
};

/**
 * Convertit un emoji en HTML Bootstrap Icon. Retourne null si non mappé.
 * Tolère les variation selectors (U+FE0F) qui suivent certains emojis.
 * @param {string} emoji
 * @returns {string|null}
 */
function _emojiToBootstrapIcon(emoji) {
    if (!emoji) return null;
    var key = String(emoji).replace(/️/g, '').trim();
    return EMOJI_TO_BI[key] ? '<i class="bi ' + EMOJI_TO_BI[key] + '"></i>' : null;
}

/**
 * Rend une option de clarification en HTML safe : si l'option commence
 * par un emoji mappé, remplace par une bi-icon ; sinon escapeHtml.
 * Garantit l'absence d'emoji visible dans les boutons.
 * @param {string} opt
 * @returns {string} HTML safe
 */
function _renderClarifOption(opt) {
    if (!opt) return '';
    var s = String(opt);
    var match = s.match(/^([\u{1F000}-\u{1FFFF}\u{2300}-\u{27BF}\u{2B00}-\u{2BFF}]️?)\s*(.*)$/u);
    if (match) {
        var bi = _emojiToBootstrapIcon(match[1]);
        if (bi) return bi + ' ' + escapeHtml(match[2]);
    }
    return escapeHtml(s);
}

// ──── Rendering — Clarification ────

/**
 * Normalise les options de clarification : garantit un Array<string>.
 * Défensif contre le LLM qui peut envoyer une string au lieu d'un array.
 * @param {*} options
 * @returns {string[]}
 */
function _normalizeClarificationOptions(options) {
    if (!options) return [];
    if (Array.isArray(options)) {
        // Défensif : le LLM peut envoyer ["opt1 | opt2 | opt3"] (1 élément avec pipes)
        // au lieu de ["opt1", "opt2", "opt3"]. Éclater chaque élément contenant des pipes.
        var expanded = [];
        for (var k = 0; k < options.length; k++) {
            var item = options[k];
            if (typeof item !== 'string') {
                expanded.push(item != null ? String(item) : '');
                continue;
            }
            if (item.indexOf(' | ') !== -1) {
                item.split(' | ').forEach(function(s) {
                    var cleaned = s.trim().replace(/^\[/, '').replace(/\]$/, '').trim();
                    if (cleaned) expanded.push(cleaned);
                });
            } else {
                expanded.push(item);
            }
        }
        return expanded.filter(Boolean);
    }
    if (typeof options !== 'string') return [];
    var text = options.trim();
    if (!text) return [];
    // Essayer de découper par retours ligne, tirets ou pipes
    if (text.indexOf('\n') !== -1) {
        return text.split(/\n/).map(function(s) {
            return s.replace(/^[\s\-*•]+/, '').trim();
        }).filter(Boolean);
    }
    if (text.indexOf(' - ') !== -1 && text.split(' - ').length >= 2) {
        return text.split(' - ').map(function(s) { return s.trim(); }).filter(Boolean);
    }
    if (text.indexOf(' | ') !== -1) {
        return text.split(' | ').map(function(s) { return s.trim(); }).filter(Boolean);
    }
    return [text];
}

/**
 * Buffer une clarification pour groupement. Le rendu est déclenché par flushPendingClarifications().
 * @param {string} question
 * @param {string[]|string} options
 */
function bufferClarification(question, options) {
    pendingClarifications.push({ question: question, options: _normalizeClarificationOptions(options) });
}

// ── Consentement lecture résultats SQL par Iris ─────────────────────────
//
// Doctrine : avant qu'Iris n'envoie au LLM cloud des valeurs lues sur la BDD
// source (SQL Server), le backend yielde un event 'data_read_consent_request'
// et bloque jusqu'à notre réponse via la WS action 'data_read_consent_response'.
// Périmètre piloté par CONSENT_REQUIRED_TOOLS côté backend — aujourd'hui
// execute_sql + peek_table_data. Le ``tool_name`` est porté par l'event pour
// adapter le copy (titre/body) au cas précis.
//
// Flow utilisateur :
//   mode='ask'                → modal OUI / Configurer (NON ouvre panel)
//   mode='always_show_panel'  → panel directement (skip modal OUI/NON)
//
// Configurer l'anonymisation : nécessite une SqlResultGrid côté frontend
// (indexée par search_id). Pour les tools qui n'émettent pas d'event
// 'sql_results' (ex: peek_table_data), le bouton est masqué et l'user n'a
// que OUI / Esc(=abandon).
//
// État local pour orchestrer le cycle prompt ↔ panel sur le même request.
var _consentRequestState = null;  // { conversationId, sampleValues, rowCount, toolName, searchId, dontAskAgainChecked }

/**
 * Copy adapté à l'outil qui déclenche le consent. Le titre et le body
 * doivent refléter ce qu'Iris veut faire (lire une requête vs consulter
 * un aperçu de table) pour que l'user comprenne ce qu'il autorise.
 *
 * ``mode`` (pref user) + ``canConfigure`` (search_id présent) déterminent
 * si on doit ajouter un disclaimer expliquant pourquoi le panel
 * d'anonymisation n'est pas accessible pour ce tool (cas
 * ``peek_table_data`` qui n'émet pas d'event ``sql_results``). Sans ce
 * disclaimer, l'utilisateur qui a choisi « Toujours ouvrir le panneau »
 * voit le prompt OUI/NON sans comprendre pourquoi sa pref n'est pas
 * honorée — exactement le scénario du bug 2026-05-22.
 *
 * @param {string} toolName
 * @param {number} rowCount
 * @param {string} mode  Pref user ('ask' | 'always_show_panel').
 * @param {boolean} canConfigure  ``true`` si search_id présent (panel possible).
 * @returns {{title: string, body: string}}
 */
function _consentCopyForTool(toolName, rowCount, mode, canConfigure) {
    var label = rowCount > 0 ? rowCount + ' ligne(s)' : 'des données';
    var commonHint =
        ' Si tu refuses, tu pourras configurer au préalable les termes ' +
        'que tu souhaites anonymiser avant qu\'Iris ne les voie.';
    // Si l'utilisateur a explicitement choisi « Toujours ouvrir le panneau »
    // mais qu'on est obligé de fallback sur le prompt OUI/NON (parce que
    // ce tool n'expose pas de SqlResultGrid à laquelle brancher le panel),
    // on lui dit clairement pourquoi — sinon il a l'impression que sa pref
    // est ignorée silencieusement.
    var prefMismatchNote = '';
    if (mode === 'always_show_panel' && !canConfigure) {
        prefMismatchNote =
            ' Ta préférence est « Toujours ouvrir le panneau », mais cet ' +
            'outil ne te permet pas de configurer l\'anonymisation cellule ' +
            'par cellule (pas d\'aperçu interactif). Tu peux autoriser ou ' +
            'refuser globalement.';
    }
    if (toolName === 'peek_table_data') {
        return {
            title: 'Iris peut-il consulter un aperçu de cette table ?',
            body:
                'Iris veut lire ' + label + ' d\'aperçu pour comprendre la ' +
                'structure de la table et orienter sa réponse.' + commonHint +
                prefMismatchNote,
        };
    }
    // execute_sql (défaut) + tout nouveau tool dont le copy n'est pas
    // spécifié : message générique. À étendre quand on ajoute un tool
    // à CONSENT_REQUIRED_TOOLS côté backend.
    return {
        title: 'Iris peut-il lire les résultats de cette requête ?',
        body:
            'La requête a retourné ' + label + '. Iris doit les analyser ' +
            'pour répondre à ta demande.' + commonHint +
            prefMismatchNote,
    };
}

function handleDataReadConsentRequest(event) {
    var conversationId = parseInt(event.conversation_id, 10);
    if (!Number.isFinite(conversationId)) {
        console.warn('data_read_consent_request: conversation_id invalide', event);
        return;
    }
    // Race state global single-slot : si un consent request est déjà en
    // cours (modal/panel ouvert pas encore résolu), on refuse le 2e
    // pour ne pas écraser silencieusement le choix de l'user (notamment
    // la checkbox « ne plus me redemander » qu'il aurait cochée).
    // Le backend a déjà la garde « Future en attente écrasé » (warning),
    // mais le frontend ne peut pas reset l'état mid-flow sans trahir
    // l'intention de l'utilisateur. Adversarial review CRITICAL #3.
    if (_consentRequestState) {
        console.warn(
            'data_read_consent_request: un consent est déjà en cours pour '
            + 'la conversation ' + _consentRequestState.conversationId
            + ' — le nouveau request (' + conversationId + ') est refusé '
            + 'localement (abandon) pour préserver le choix utilisateur en cours.'
        );
        // Réponse immédiate "abandoned" au backend pour libérer son Future
        // au lieu de le laisser bloqué jusqu'au timeout (5min).
        try {
            ws.send(JSON.stringify({
                action: 'data_read_consent_response',
                conversation_id: conversationId,
                approved: false,
                abandoned: true,
                dont_ask_again: false
            }));
        } catch (e) { /* WS down — backend libérera au timeout. */ }
        return;
    }
    var mode = event.mode === 'always_show_panel' ? 'always_show_panel' : 'ask';
    // Diagnostic 2026-05-22 : si l'user voit un prompt malgré une pref
    // ``always_allow`` en BDD, ce log expose exactement ce que le backend
    // a envoyé. Niveau ``info`` pour rester visible sans configurer le
    // log level. À retirer une fois la cause racine identifiée.
    console.info(
        '[iris-consent] data_read_consent_request reçu — '
        + 'tool=' + event.tool_name + ' conv=' + conversationId
        + ' mode=' + event.mode + ' (normalisé en ' + mode + ')'
        + ' search_id=' + event.search_id + ' row_count=' + event.row_count
    );
    // ``search_id`` permet de retrouver la grille rendue par l'event
    // ``sql_results`` précédent (yieldé juste avant par agent_service.py).
    // Peut être ``null``/``undefined`` si backend très ancien — fallback
    // gracieux dans openConsentAnonymizationPanel.
    var searchId = event.search_id;
    if (searchId !== undefined && searchId !== null) {
        var asNum = Number(searchId);
        searchId = Number.isFinite(asNum) ? asNum : null;
    } else {
        searchId = null;
    }
    _consentRequestState = {
        conversationId: conversationId,
        sampleValues: Array.isArray(event.sample_values) ? event.sample_values.slice() : [],
        rowCount: Number(event.row_count) || 0,
        toolName: String(event.tool_name || 'execute_sql'),
        searchId: searchId,
        // Conservé pour ``_consentCopyForTool`` afin d'adapter le copy
        // au cas où la pref user (``always_show_panel``) ne peut pas
        // s'appliquer sur ce tool (pas de search_id → pas de panel).
        mode: mode,
        dontAskAgainChecked: false
    };
    // Mode ``always_show_panel`` : ouvre le panel d'anonymisation directement
    // — mais UNIQUEMENT s'il y a une SqlResultGrid à brancher. Pour les
    // tools sans grille (ex: peek_table_data qui n'émet pas d'event
    // ``sql_results``), fallback gracieux sur le modal OUI/NON, sinon
    // ``openConsentAnonymizationPanel`` ferait un abandon par défaut
    // silencieux et l'utilisateur ne saurait pas pourquoi sa requête est
    // refusée. Sa pref reste respectée pour les tools avec grille.
    var canConfigure = (searchId !== null && searchId !== undefined);
    if (mode === 'always_show_panel' && canConfigure) {
        openConsentAnonymizationPanel();
    } else {
        openConsentPromptModal();
    }
}

function _sendConsentResponse(approved, abandoned) {
    if (!_consentRequestState) return;
    var payload = {
        action: 'data_read_consent_response',
        conversation_id: _consentRequestState.conversationId,
        approved: !!approved,
        abandoned: !!abandoned,
        dont_ask_again: !!_consentRequestState.dontAskAgainChecked
    };
    try {
        ws.send(JSON.stringify(payload));
    } catch (e) {
        console.warn('data_read_consent_response: send failed', e);
    }
    // ``approved=false && abandoned=false`` (= "Configurer") n'est PAS
    // une réponse finale — le backend ignore et continue d'attendre. On
    // garde _consentRequestState pour l'ouverture du panel.
    if (approved || abandoned) {
        _consentRequestState = null;
    }
}

function openConsentPromptModal() {
    if (!_consentRequestState) return;
    // Évite double-ouverture si le user clique vite.
    if (document.getElementById('iris-consent-prompt-modal')) return;

    var state = _consentRequestState;
    var overlay = document.createElement('div');
    overlay.id = 'iris-consent-prompt-modal';
    overlay.setAttribute('role', 'dialog');
    overlay.setAttribute('aria-modal', 'true');
    overlay.setAttribute('aria-labelledby', 'iris-consent-prompt-title');
    // z-index délégué à OverlayManager (layer='system-modal' = 9999+N×10) :
    // consentement = blocant cross-page, donc layer system-modal (au-dessus
    // de tout modal métier).
    overlay.style.cssText =
        'position:fixed;inset:0;background:rgba(0,0,0,0.5);' +
        'display:flex;align-items:center;justify-content:center;';

    var card = document.createElement('div');
    card.style.cssText =
        'background:var(--bg-surface, #fff);color:var(--text-primary, #111827);' +
        'border:1px solid var(--border, #e5e7eb);border-radius:0.5rem;' +
        'box-shadow:0 10px 40px rgba(0,0,0,0.2);' +
        'width:min(520px, 94vw);padding:1.25rem;' +
        'display:flex;flex-direction:column;gap:0.85rem;';

    // Title/body adaptés au tool_name pour rester précis sur ce qu'Iris
    // veut lire. Le bouton « Configurer l'anonymisation » dépend de la
    // présence d'une SqlResultGrid : pour ``peek_table_data`` il n'y a pas
    // de search_id (pas d'event ``sql_results`` yieldé en amont), donc on
    // masque le bouton — l'user n'a que OUI/Esc.
    var canConfigureAnonymization = (state.searchId !== null && state.searchId !== undefined);
    var copy = _consentCopyForTool(
        state.toolName, state.rowCount, state.mode, canConfigureAnonymization
    );

    var title = document.createElement('h2');
    title.id = 'iris-consent-prompt-title';
    title.textContent = copy.title;
    title.style.cssText = 'margin:0;font-size:1rem;font-weight:600;';

    var body = document.createElement('p');
    body.style.cssText = 'margin:0;font-size:0.875rem;color:var(--text-secondary, #374151);line-height:1.45;';
    body.textContent = copy.body;

    var dontAskRow = document.createElement('label');
    dontAskRow.style.cssText =
        'display:flex;align-items:center;gap:0.5rem;font-size:0.8125rem;' +
        'color:var(--text-secondary, #374151);cursor:pointer;user-select:none;';
    var dontAskCheckbox = document.createElement('input');
    dontAskCheckbox.type = 'checkbox';
    dontAskCheckbox.id = 'iris-consent-dont-ask';
    dontAskCheckbox.addEventListener('change', function() {
        if (_consentRequestState) {
            _consentRequestState.dontAskAgainChecked = dontAskCheckbox.checked;
        }
    });
    var dontAskLabel = document.createElement('span');
    dontAskLabel.textContent =
        'Ne plus me redemander (modifiable depuis ' +
        'Paramètres → Confidentialité Iris).';
    dontAskRow.appendChild(dontAskCheckbox);
    dontAskRow.appendChild(dontAskLabel);

    var actions = document.createElement('div');
    actions.style.cssText =
        'display:flex;justify-content:flex-end;gap:0.5rem;flex-wrap:wrap;';

    // Bouton « Configurer l'anonymisation » : affiché UNIQUEMENT si une
    // SqlResultGrid existe pour ce request (search_id fourni par le
    // backend). Pour les tools sans grille (peek_table_data n'émet pas
    // d'event ``sql_results``), ouvrir le panel ferait un abandon par
    // défaut côté ``openConsentAnonymizationPanel`` — on évite cette
    // surprise UX en masquant directement le bouton.
    var btnConfigure = null;
    if (canConfigureAnonymization) {
        btnConfigure = document.createElement('button');
        btnConfigure.type = 'button';
        btnConfigure.textContent = 'Configurer l\'anonymisation';
        btnConfigure.style.cssText =
            'padding:0.5rem 0.9rem;border:1px solid var(--border, #d1d5db);' +
            'background:var(--bg-surface, #fff);color:var(--text-primary, #111827);' +
            'border-radius:0.375rem;font-size:0.8125rem;cursor:pointer;';
        btnConfigure.addEventListener('click', function() {
            _closeConsentPromptModal();
            // Réponse intermédiaire "Configurer" : approved=false abandoned=false.
            // Le backend l'ignore, on ouvre le panel localement et on rappellera
            // avec approved=true (save) ou abandoned=true (fermeture totale).
            openConsentAnonymizationPanel();
        });
    }

    // Bouton « Refuser la lecture » explicite — affiché UNIQUEMENT quand
    // l'user a choisi ``always_show_panel`` mais qu'on est obligé de
    // fallback sur ce prompt (pas de panel possible). Sinon, le focus
    // par défaut sur « Autoriser la lecture » trahit l'intent user
    // (« je veux toujours arbitrer ») — un Enter accidentel autoriserait
    // la lecture sans choix conscient. Adversarial review BLOCKING #2 :
    // fail-closed pour respecter la pref max-safety de l'utilisateur.
    // Pour le mode ``ask``, le comportement historique reste : Esc/X
    // ferme le modal et abandon (déjà géré par OverlayManager onClose).
    var btnRefuse = null;
    if (state.mode === 'always_show_panel' && !canConfigureAnonymization) {
        btnRefuse = document.createElement('button');
        btnRefuse.type = 'button';
        btnRefuse.textContent = 'Refuser la lecture';
        btnRefuse.style.cssText =
            'padding:0.5rem 0.9rem;border:1px solid var(--border, #d1d5db);' +
            'background:var(--bg-surface, #fff);color:var(--text-primary, #111827);' +
            'border-radius:0.375rem;font-size:0.8125rem;cursor:pointer;';
        btnRefuse.addEventListener('click', function() {
            _closeConsentPromptModal();
            _sendConsentResponse(false, true);
        });
    }

    var btnAllow = document.createElement('button');
    btnAllow.type = 'button';
    btnAllow.textContent = 'Autoriser la lecture';
    btnAllow.style.cssText =
        'padding:0.5rem 0.9rem;border:1px solid var(--brand, #2563eb);' +
        'background:var(--brand, #2563eb);color:#fff;' +
        'border-radius:0.375rem;font-size:0.8125rem;font-weight:500;cursor:pointer;';
    btnAllow.addEventListener('click', function() {
        _closeConsentPromptModal();
        _sendConsentResponse(true, false);
    });

    if (btnConfigure) {
        actions.appendChild(btnConfigure);
    }
    if (btnRefuse) {
        actions.appendChild(btnRefuse);
    }
    actions.appendChild(btnAllow);

    card.appendChild(title);
    card.appendChild(body);
    card.appendChild(dontAskRow);
    card.appendChild(actions);
    overlay.appendChild(card);
    document.body.appendChild(overlay);
    // Esc/backdrop = abandon total. Le manager gère Escape LIFO ; on
    // intercepte via onClose pour propager la sémantique métier
    // (envoyer un consentement "abandoned").
    if (window.OverlayManager && typeof window.OverlayManager.open === 'function') {
        window.OverlayManager.open(overlay, {
            layer: 'system-modal',
            lockScroll: true,
            onClose: function() {
                // Si fermeture déclenchée par le manager (Esc), traiter
                // comme abandon. Garde : si déjà fermé via bouton, c'est
                // le _closeConsentPromptModal qui aura retiré l'overlay
                // → ce onClose est no-op cohérent.
                if (document.getElementById('iris-consent-prompt-modal')) {
                    _closeConsentPromptModal();
                    _sendConsentResponse(false, true);
                }
            },
        });
    }

    // Clic en dehors de la card = abandon (même sémantique qu'Esc).
    overlay.addEventListener('click', function(ev) {
        if (ev.target === overlay) {
            _closeConsentPromptModal();
            _sendConsentResponse(false, true);
        }
    });

    // Focus initial : ``Refuser`` quand l'user a choisi ``always_show_panel``
    // (fail-closed — un Enter accidentel doit ne PAS lire les données),
    // ``Configurer`` quand le panel est possible (chemin recommandé),
    // ``Autoriser`` sinon (mode ``ask`` — comportement historique).
    // Adversarial review BLOCKING #2.
    var initialFocus = btnAllow;
    if (btnRefuse) {
        initialFocus = btnRefuse;
    } else if (btnConfigure) {
        initialFocus = btnConfigure;
    }
    setTimeout(function() { initialFocus.focus(); }, 0);
}

function _closeConsentPromptModal() {
    var existing = document.getElementById('iris-consent-prompt-modal');
    if (existing && existing.parentNode) {
        // ORDRE IMPORTANT (bug 2026-05-20) : retirer du DOM AVANT de notifier
        // le manager. ``OverlayManager.close(el)`` invoque systématiquement
        // le callback ``onClose`` enregistré à ``open()``. Or ce callback
        // (cf. ``openConsentPromptModal``) ré-interroge le DOM via
        // ``getElementById('iris-consent-prompt-modal')`` pour décider s'il
        // s'agit d'une fermeture non-intentionnelle (Esc/backdrop) à traiter
        // comme abandon. Si on appelle ``close()`` AVANT ``removeChild()``,
        // l'élément est encore dans le DOM → ``onClose`` envoie un consent
        // ``abandoned=true`` qui reset ``_consentRequestState=null`` → quand
        // le caller enchaîne ``openConsentAnonymizationPanel()`` (= bouton
        // « Configurer l'anonymisation »), le panel ne s'ouvre PAS (return
        // early silencieux ligne 1992). En inversant l'ordre, ``onClose``
        // ne trouve plus l'overlay et no-op, comme attendu pour une
        // fermeture programmatique.
        existing.parentNode.removeChild(existing);
        if (window.OverlayManager && typeof window.OverlayManager.close === 'function') {
            try { window.OverlayManager.close(existing); } catch (e) {}
        }
    }
}

function openConsentAnonymizationPanel() {
    if (!_consentRequestState) return;
    var state = _consentRequestState;

    // Récupère la SqlResultGrid rendue par l'event ``sql_results`` qui a
    // précédé ce ``data_read_consent_request`` (cf. ``renderSQLResults``
    // ligne ~1548 qui index par ``search_id`` dans ``_gridsBySearchId``).
    //
    // Le but de ce refactor : ouvrir EXACTEMENT le même modal
    // "Confidentialité — termes à anonymiser" que le bouton cadenas du
    // classeur — pas un panel détaché dupliqué et appauvri. Stats, filtres,
    // recherche, bulk actions, bouton "Améliorer l'anonymisation",
    // liste complète des termes user — tout fonctionne tel quel parce qu'on
    // appelle la méthode native de la grille.
    var grid = null;
    var searchIdProvided = (state.searchId !== null && state.searchId !== undefined);

    if (searchIdProvided) {
        grid = _gridsBySearchId.get(state.searchId) || null;
        // ⚠️ Si search_id était fourni mais introuvable dans le registre
        // (ex: renderSQLResults a throw et le try/catch a swallow l'erreur
        // sans indexer la grille, OU grille évincée par le cap LRU si la
        // conv est très longue), ON NE FALLBACK PAS sur une autre grille
        // — risque cross-classeur silencieux (l'user éditerait les termes
        // du classeur N-1 pour autoriser la lecture du classeur N).
        // Adversarial review MEDIUM 2026-05-20.
        if (!grid) {
            console.error(
                'openConsentAnonymizationPanel: search_id=' + state.searchId
                + ' fourni par le backend mais absent du registre '
                + '(registre size=' + _gridsBySearchId.size
                + '). renderSQLResults a probablement échoué silencieusement, '
                + 'ou la grille a été évincée par le cap LRU. '
                + 'Abandon par défaut (refus du gate) au lieu de fallback sur '
                + 'une autre grille — protège la confidentialité cross-classeur.'
            );
            _sendConsentResponse(false, true);
            return;
        }
    } else if (_lastIndexedSearchId !== null) {
        // Fallback uniquement si backend n'a PAS fourni search_id (cas
        // rétrocompat backend ancien). Le tracker ``_lastIndexedSearchId``
        // pointe la dernière grille indexée — c'est le best-effort
        // raisonnable dans ce cas (équivalent à l'ancien comportement
        // du panel détaché qui n'avait pas non plus de search_id).
        grid = _gridsBySearchId.get(_lastIndexedSearchId) || null;
    }

    // Pas de grille trouvée du tout (cas backend ancien sans search_id +
    // aucune grille jamais indexée dans cette conv). Abandon gracieux —
    // le gate backend recevra abandoned=true → Iris reçoit "lecture
    // refusée", l'user devra réessayer. Log pour observabilité.
    if (!grid || typeof grid._openAnonymizationPanel !== 'function') {
        console.error(
            'openConsentAnonymizationPanel: aucune SqlResultGrid disponible '
            + '(searchIdProvided=' + searchIdProvided + ', registre size='
            + _gridsBySearchId.size + ') — abandon par défaut.'
        );
        _sendConsentResponse(false, true);
        return;
    }

    // Ouvre le panneau natif de la grille avec callbacks consent.
    // Le contrat ``opts.consentCallbacks`` est implémenté dans iris-grid.js
    // (cf. ``_openAnonymizationPanel`` ligne 5569+). Si l'user clique
    // Enregistrer → ``onSave`` → ``approved=true``. Annuler → ``onCancel`` →
    // retour au prompt. Esc/backdrop → ``onAbandon`` → refus définitif.
    grid._openAnonymizationPanel({
        reason: 'consent',
        consentCallbacks: {
            onSave: function() {
                // Termes sauvegardés. Iris peut lire — les nouveaux termes
                // sont tokenisés par le pseudonymizer au prochain anonymize.
                _sendConsentResponse(true, false);
            },
            onCancel: function() {
                // Retour au prompt initial (cycle prompt ↔ panel).
                openConsentPromptModal();
            },
            onAbandon: function() {
                // Esc/X sans avoir cliqué Annuler explicitement = refus.
                _sendConsentResponse(false, true);
            }
        }
    });
}


/**
 * Vide le buffer de clarifications et les rend en un seul formulaire groupé.
 * Si une seule question : comportement classique (clic = envoi immédiat).
 * Si plusieurs : formulaire multi-questions avec bouton "Valider".
 */
function flushPendingClarifications() {
    if (pendingClarifications.length === 0) return;

    var items = pendingClarifications.slice();
    pendingClarifications = [];

    if (items.length === 1) {
        // Une seule question : rendu classique
        renderSingleClarification(items[0].question, items[0].options);
    } else {
        // Plusieurs questions : formulaire groupé
        renderClarificationGroup(items);
    }
}

/**
 * Affiche UNE question de clarification avec envoi immédiat au clic.
 * @param {string} question
 * @param {string[]} options
 */
/**
 * Détecte si une option nécessite une saisie libre de l'utilisateur.
 * @param {string} text
 * @returns {boolean}
 */
function _isOpenEndedOption(text) {
    var lower = text.toLowerCase();
    return /\bpréciser\b|\bautre\b|\bà préciser\b|\bspécifier\b|\bindiquer\b/.test(lower);
}

/**
 * Crée un champ de saisie libre inline pour les options ouvertes.
 * @param {string} optionLabel - Le label de l'option cliquée (ex: "Préciser la période")
 * @param {function} onSubmit - Callback(text) quand l'utilisateur valide
 * @returns {HTMLElement}
 */
function _createFreeTextInput(optionLabel, onSubmit) {
    var wrapper = document.createElement('div');
    wrapper.className = 'iris-clarif-freetext';

    var input = document.createElement('input');
    input.type = 'text';
    input.className = 'iris-clarif-freetext-input';
    input.placeholder = optionLabel + '…';
    wrapper.appendChild(input);

    var sendBtn = document.createElement('button');
    sendBtn.type = 'button';
    sendBtn.className = 'iris-clarif-freetext-send';
    sendBtn.textContent = 'Envoyer';
    sendBtn.disabled = true;
    wrapper.appendChild(sendBtn);

    input.addEventListener('input', function() {
        sendBtn.disabled = !input.value.trim();
        // Auto-save : draft preservé si refresh accidentel pendant la saisie
        // d'une réponse "Autre combinaison" à une clarification.
        _saveDraft(input.value);
    });

    function submit() {
        var val = input.value.trim();
        if (!val) return;
        input.disabled = true;
        sendBtn.disabled = true;
        sendBtn.textContent = '✓';
        _clearDraft();
        onSubmit(val);
    }

    sendBtn.addEventListener('click', submit);
    input.addEventListener('keydown', function(e) {
        if (e.key === 'Enter') { e.preventDefault(); submit(); }
    });

    // Focus automatique
    requestAnimationFrame(function() { input.focus(); });

    return wrapper;
}

function renderSingleClarification(question, options) {
    options = _normalizeClarificationOptions(options);
    var card = document.createElement('div');
    card.className = 'iris-clarification';

    var questionEl = document.createElement('p');
    questionEl.className = 'iris-clarification-question';
    questionEl.textContent = question;
    card.appendChild(questionEl);

    if (options && options.length > 0) {
        var btnRow = document.createElement('div');
        btnRow.className = 'iris-clarification-options';
        for (var i = 0; i < options.length; i++) {
            (function(opt) {
                var btn = document.createElement('button');
                btn.type = 'button';
                btn.className = 'iris-clarif-btn';
                btn.innerHTML = _renderClarifOption(opt);
                btn.addEventListener('click', function() {
                    if (_isOpenEndedOption(opt)) {
                        // Marquer le bouton sélectionné, désactiver les autres
                        card.querySelectorAll('.iris-clarif-btn').forEach(function(b) {
                            b.disabled = true;
                        });
                        btn.classList.add('selected');
                        // Retirer un éventuel champ libre précédent
                        var prev = card.querySelector('.iris-clarif-freetext');
                        if (prev) prev.remove();
                        // Afficher le champ de saisie libre
                        var freeText = _createFreeTextInput(opt, function(val) {
                            sendClarificationResponse(val);
                        });
                        card.appendChild(freeText);
                        scrollToBottom();
                    } else {
                        sendClarificationResponse(opt);
                        card.querySelectorAll('.iris-clarif-btn').forEach(function(b) {
                            b.disabled = true;
                        });
                        btn.classList.add('selected');
                    }
                });
                btnRow.appendChild(btn);
            })(options[i]);
        }
        card.appendChild(btnRow);
    }

    appendToMessages(card);
    scrollToBottom();
}

/**
 * Affiche un formulaire groupé pour plusieurs questions de clarification.
 * L'utilisateur sélectionne une réponse par question, puis clique "Valider".
 * @param {Array<{question: string, options: string[]}>} items
 */
function renderClarificationGroup(items) {
    var container = document.createElement('div');
    container.className = 'iris-clarification-group';

    var answers = {};

    for (var q = 0; q < items.length; q++) {
        (function(idx, item) {
            var section = document.createElement('div');
            section.className = 'iris-clarification';

            var questionEl = document.createElement('p');
            questionEl.className = 'iris-clarification-question';
            questionEl.textContent = item.question;
            section.appendChild(questionEl);

            if (item.options && item.options.length > 0) {
                var btnRow = document.createElement('div');
                btnRow.className = 'iris-clarification-options';
                for (var j = 0; j < item.options.length; j++) {
                    (function(opt) {
                        var btn = document.createElement('button');
                        btn.type = 'button';
                        btn.className = 'iris-clarif-btn';
                        btn.innerHTML = _renderClarifOption(opt);
                        btn.addEventListener('click', function() {
                            // Désélectionner les autres options de cette question
                            btnRow.querySelectorAll('.iris-clarif-btn').forEach(function(b) {
                                b.classList.remove('selected');
                            });
                            btn.classList.add('selected');
                            // Retirer un éventuel champ libre précédent
                            var prevFt = section.querySelector('.iris-clarif-freetext');
                            if (prevFt) prevFt.remove();

                            if (_isOpenEndedOption(opt)) {
                                // Afficher un champ de saisie libre
                                var ft = _createFreeTextInput(opt, function(val) {
                                    answers[idx] = val;
                                    if (Object.keys(answers).length === items.length && submitBtn) {
                                        submitBtn.disabled = false;
                                    }
                                    // Désactiver le champ après saisie
                                    ft.querySelector('input').disabled = true;
                                    ft.querySelector('button').disabled = true;
                                    ft.querySelector('button').textContent = '✓';
                                });
                                section.appendChild(ft);
                                scrollToBottom();
                            } else {
                                answers[idx] = opt;
                            }
                            // Activer le bouton valider si toutes les questions ont une réponse
                            if (Object.keys(answers).length === items.length && submitBtn) {
                                submitBtn.disabled = false;
                            }
                        });
                        btnRow.appendChild(btn);
                    })(item.options[j]);
                }
                section.appendChild(btnRow);
            }

            container.appendChild(section);
        })(q, items[q]);
    }

    // Bouton "Valider mes réponses"
    var submitBtn = document.createElement('button');
    submitBtn.type = 'button';
    submitBtn.className = 'iris-clarif-submit';
    submitBtn.textContent = 'Valider mes réponses';
    submitBtn.disabled = true;
    submitBtn.addEventListener('click', function() {
        // Construire la réponse combinée (format lisible par le LLM)
        var parts = [];
        for (var k = 0; k < items.length; k++) {
            var ans = answers[k] || '(non répondu)';
            parts.push((k + 1) + '. ' + items[k].question + ' → ' + ans);
        }
        var combined = 'Voici mes réponses :\n' + parts.join('\n');
        sendClarificationResponse(combined);
        // Désactiver tout le formulaire
        container.querySelectorAll('.iris-clarif-btn').forEach(function(b) {
            b.disabled = true;
        });
        submitBtn.disabled = true;
        submitBtn.textContent = '✓ Réponses envoyées';
    });
    container.appendChild(submitBtn);

    appendToMessages(container);
    scrollToBottom();
}

/**
 * Affiche une question de clarification restaurée (déjà répondue — boutons désactivés).
 * @param {string} question
 * @param {string[]} options
 */
function renderRestoredClarification(question, options) {
    options = _normalizeClarificationOptions(options);
    var card = document.createElement('div');
    card.className = 'iris-clarification';

    var questionEl = document.createElement('p');
    questionEl.className = 'iris-clarification-question';
    questionEl.textContent = question;
    card.appendChild(questionEl);

    if (options && options.length > 0) {
        var btnRow = document.createElement('div');
        btnRow.className = 'iris-clarification-options';
        for (var i = 0; i < options.length; i++) {
            var btn = document.createElement('button');
            btn.type = 'button';
            btn.className = 'iris-clarif-btn';
            btn.innerHTML = _renderClarifOption(options[i]);
            btn.disabled = true;
            btnRow.appendChild(btn);
        }
        card.appendChild(btnRow);
    }

    appendToMessages(card);
    scrollToBottom();
}

/**
 * Affiche un message d'erreur dans le chat.
 * @param {string} message
 */
function addErrorMessage(message) {
    const el = document.createElement('div');
    el.className = 'iris-error-message';
    // Task #19 — annoncer aux lecteurs d'écran. role='alert' implique
    // aria-live='assertive' (urgent : interrompt la lecture en cours).
    el.setAttribute('role', 'alert');
    el.setAttribute('aria-atomic', 'true');
    el.innerHTML = `⚠️ ${escapeHtml(message)}`;
    appendToMessages(el);
    scrollToBottom();
}

/**
 * Task #15 — Affiche un message d'erreur d'upload + bouton « Signaler »
 * inline si le contexte suggère un incident à remonter au support.
 *
 * Cohérent avec la **taxonomie 4-cas Komptia** (CLAUDE.md axe #5) :
 * - (a) métier prévue : message clair sans Signaler (validation client
 *   pré-fetch — extension, taille — passe par ``addErrorMessage``).
 * - (b) 4xx serveur : message backend si fourni, sans Signaler (l'user
 *   peut généralement corriger en re-uploadant).
 * - (c) 5xx serveur : Signaler activé (réutilise ``window.komptiaReportFeedback``,
 *   SSoT existante de ``feedback-reporter.js`` chargé via ``base.html``).
 * - (d) réseau (fetch TypeError, status absent) : Signaler activé.
 *
 * @param {Error&{status?: number}} err - exception levée dans le catch upload.
 * @param {string} fileName - nom du fichier concerné (pour le rapport).
 * @param {string} contextKey - identifiant context pour ``komptiaReportFeedback``
 *   (ex: ``'iris_upload_pc'``, ``'iris_upload_datastore'``).
 */
function _addUploadErrorWithReport(err, fileName, contextKey) {
    var status = (err && typeof err.status === 'number') ? err.status : 0;
    var isReportable = !status || status >= 500;
    var msgText = "Échec de l'envoi du fichier.";
    if (status && status < 500 && err && err.message && typeof err.message === 'string') {
        // Erreur 4xx avec message backend explicite → l'afficher tel quel
        // (ex: 'Extension non supportée', 'Fichier trop volumineux').
        msgText = err.message;
    }

    var el = document.createElement('div');
    el.className = 'iris-error-message';
    // Task #19 — accessibilité : annonce l'erreur aux lecteurs d'écran.
    el.setAttribute('role', 'alert');
    el.setAttribute('aria-atomic', 'true');

    var msgSpan = document.createElement('span');
    msgSpan.className = 'iris-error-message-text';
    msgSpan.textContent = '⚠️ ' + msgText;
    el.appendChild(msgSpan);

    if (isReportable && typeof window.komptiaReportFeedback === 'function') {
        var btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'iris-error-report-btn';
        btn.textContent = 'Signaler';
        btn.title = 'Signaler cet incident au support Komptia';
        btn.setAttribute('aria-label', 'Signaler cet incident au support Komptia');
        btn.addEventListener('click', function() {
            try {
                window.komptiaReportFeedback({
                    context: contextKey || 'iris_upload',
                    message: 'Iris upload error: ' + (err && err.message ? err.message : 'erreur inconnue')
                        + ' (status=' + (status || 'network')
                        + ', file=' + (fileName || '?') + ')',
                });
            } catch (_) {
                // feedback-reporter peut échouer silencieusement (jamais
                // chargé, CSP bloque, etc.). On dégrade gracieusement.
            }
        });
        el.appendChild(btn);
    }

    appendToMessages(el);
    scrollToBottom();
}

function addSystemMessage(message) {
    const el = document.createElement('div');
    el.className = 'iris-system-message';
    el.innerHTML = `⏹ ${escapeHtml(message)}`;
    appendToMessages(el);
    scrollToBottom();
}

/**
 * Affiche un bandeau d'information non-alarmant dans le flux de messages
 * (distinct de ``addSystemMessage`` qui utilise ``⏹`` pour les interruptions
 * et de ``addErrorMessage`` qui utilise ``⚠️`` pour les erreurs).
 *
 * Cas d'usage : signaler un mode dégradé / compatibilité que l'utilisateur
 * doit connaître mais qui n'est pas une erreur (ex: replay path B legacy
 * sans events bruts → certains détails visuels manquent).
 *
 * @param {string} message
 */
function addInfoBanner(message) {
    const el = document.createElement('div');
    el.className = 'iris-system-message iris-info-banner';
    el.innerHTML = `ℹ️ ${escapeHtml(message)}`;
    appendToMessages(el);
    scrollToBottom();
}

// ──── Rendering — Suggestions ────

/**
 * Affiche des chips de suggestion de questions follow-up.
 * @param {string[]} questions
 */
function renderSuggestions(questions) {
    if (!questions || questions.length === 0) return;

    const container = document.createElement('div');
    container.className = 'iris-suggestions';

    const label = document.createElement('span');
    label.className = 'iris-suggestions-label';
    label.textContent = 'Vous pourriez aussi demander :';
    container.appendChild(label);

    const chips = document.createElement('div');
    chips.className = 'iris-suggestions-chips';
    for (const q of questions) {
        const chip = document.createElement('button');
        chip.type = 'button';
        chip.className = 'iris-suggestion-chip';
        chip.textContent = q;
        chip.addEventListener('click', function() {
            if (messageInput) {
                messageInput.value = q;
                sendMessage();
            }
        });
        chips.appendChild(chip);
    }
    container.appendChild(chips);
    appendToMessages(container);
    scrollToBottom();
}

// ──── Rendering — RAG Sources ────

/**
 * Affiche les sources RAG utilisées dans une section repliable.
 * @param {{ type: string, name: string, score: number }[]} sources
 */
function renderRAGSources(sources) {
    if (!sources || sources.length === 0) return;

    const details = document.createElement('details');
    details.className = 'iris-rag-sources';

    const summary = document.createElement('summary');
    summary.innerHTML = `<i class="bi bi-book"></i> Sources utilisées (${sources.length})`;
    details.appendChild(summary);

    const list = document.createElement('ul');
    list.className = 'iris-rag-list';
    for (const src of sources) {
        const li = document.createElement('li');
        const scorePercent = Math.round((src.score || 0) * 100);
        li.innerHTML = `<span class="iris-rag-type">${escapeHtml(src.type || 'doc')}</span> `
            + `<span class="iris-rag-name">${escapeHtml(src.name)}</span> `
            + `<span class="iris-rag-score">${scorePercent}%</span>`;
        list.appendChild(li);
    }
    details.appendChild(list);
    appendToMessages(details);
    scrollToBottom();
}

/**
 * Rend le récap final structuré produit par la pipeline (todo #17).
 *
 * Le payload provient de ``build_pipeline_recap_payload`` côté backend
 * — single source of truth visible à l'utilisatrice. Sections :
 *   - Interprétations (concept → table.colonne + confiance)
 *   - Agrégations (concept → fonction FR)
 *   - Hypothèses tranchées par Iris en phases parallèles
 *   - Réponses utilisateur préservées (audit + dialog)
 *
 * Compact par défaut (<details>), expansif au clic. Pas d'emoji décoratif
 * (préférence Komptia). escapeHtml systématique — le payload contient
 * des chaînes user-controlled via Phase 1.1.
 *
 * @param {Object} payload — { version, interpretations, aggregations,
 *                              auto_assumptions, user_answers }
 */
function renderPipelineRecap(payload) {
    if (!payload || typeof payload !== 'object') return;
    var interpretations = Array.isArray(payload.interpretations) ? payload.interpretations : [];
    var aggregations = Array.isArray(payload.aggregations) ? payload.aggregations : [];
    var autoAssumptions = Array.isArray(payload.auto_assumptions) ? payload.auto_assumptions : [];
    var userAnswers = Array.isArray(payload.user_answers) ? payload.user_answers : [];

    // Si le payload est vide (sections toutes vides), ne rien rendre :
    // le LLM Iris est libre de rédiger un récap textuel sans qu'un
    // composant vide pollue l'UI.
    if (interpretations.length === 0
        && aggregations.length === 0
        && autoAssumptions.length === 0
        && userAnswers.length === 0) {
        return;
    }

    var totalItems = interpretations.length + aggregations.length
        + autoAssumptions.length + userAnswers.length;

    var details = document.createElement('details');
    details.className = 'iris-pipeline-recap';

    var summary = document.createElement('summary');
    summary.className = 'iris-pipeline-recap-summary';
    summary.textContent = 'Comment Iris a interprété ta demande (' + totalItems + ')';
    details.appendChild(summary);

    var body = document.createElement('div');
    body.className = 'iris-pipeline-recap-body';

    // ── Interprétations ─────────────────────────────────────────────
    if (interpretations.length > 0) {
        var section = document.createElement('section');
        section.className = 'iris-recap-section';
        var heading = document.createElement('h4');
        heading.className = 'iris-recap-heading';
        heading.textContent = 'Termes interprétés (' + interpretations.length + ')';
        section.appendChild(heading);

        var ul = document.createElement('ul');
        ul.className = 'iris-recap-list';
        interpretations.forEach(function(item) {
            if (!item || typeof item !== 'object') return;
            var li = document.createElement('li');
            li.className = 'iris-recap-item';

            // Concept (terme métier de la question user)
            var concept = document.createElement('span');
            concept.className = 'iris-recap-concept';
            concept.textContent = '« ' + (item.concept || '?') + ' »';
            li.appendChild(concept);

            // Mapping table.colonne (technique mais nécessaire)
            if (item.table || item.col) {
                var arrow = document.createElement('span');
                arrow.className = 'iris-recap-arrow';
                arrow.textContent = ' → ';
                li.appendChild(arrow);
                var target = document.createElement('span');
                target.className = 'iris-recap-target';
                var t = item.table || '?';
                var c = item.col || '?';
                target.textContent = t + '.' + c;
                li.appendChild(target);
            }

            // Badge de confiance (forte / moyenne / faible)
            var badge = document.createElement('span');
            badge.className = 'iris-recap-badge';
            if (item.requires_disambiguation || item.low_confidence) {
                badge.classList.add('iris-recap-badge-low');
                badge.textContent = 'confiance faible';
            } else if (typeof item.confidence_score === 'number'
                       && item.confidence_score >= 80) {
                badge.classList.add('iris-recap-badge-high');
                badge.textContent = 'confiance forte';
            } else {
                badge.classList.add('iris-recap-badge-mid');
                badge.textContent = 'confiance moyenne';
            }
            li.appendChild(badge);

            // Méthode + score (si dispo)
            if (item.evidence_method) {
                var method = document.createElement('div');
                method.className = 'iris-recap-method';
                var methodLabel = _humanizeEvidenceMethod(item.evidence_method);
                var methodText = methodLabel;
                if (typeof item.evidence_score === 'number') {
                    var pct = Math.round(item.evidence_score * 100);
                    methodText += ' (' + pct + '%)';
                }
                method.textContent = methodText;
                li.appendChild(method);
            }

            ul.appendChild(li);
        });
        section.appendChild(ul);
        body.appendChild(section);
    }

    // ── Agrégations ────────────────────────────────────────────────
    if (aggregations.length > 0) {
        var sectionAgg = document.createElement('section');
        sectionAgg.className = 'iris-recap-section';
        var headingAgg = document.createElement('h4');
        headingAgg.className = 'iris-recap-heading';
        headingAgg.textContent = 'Fonctions de calcul (' + aggregations.length + ')';
        sectionAgg.appendChild(headingAgg);

        var ulAgg = document.createElement('ul');
        ulAgg.className = 'iris-recap-list';
        aggregations.forEach(function(agg) {
            if (!agg || typeof agg !== 'object') return;
            var li = document.createElement('li');
            li.className = 'iris-recap-item';
            var conceptSpan = document.createElement('span');
            conceptSpan.className = 'iris-recap-concept';
            conceptSpan.textContent = '« ' + (agg.concept || '?') + ' »';
            li.appendChild(conceptSpan);
            var arrow = document.createElement('span');
            arrow.className = 'iris-recap-arrow';
            arrow.textContent = ' → ';
            li.appendChild(arrow);
            var fn = document.createElement('span');
            fn.className = 'iris-recap-function';
            fn.textContent = agg.function_label_fr || agg.function || '?';
            li.appendChild(fn);
            ulAgg.appendChild(li);
        });
        sectionAgg.appendChild(ulAgg);
        body.appendChild(sectionAgg);
    }

    // ── Hypothèses tranchées par Iris ──────────────────────────────
    if (autoAssumptions.length > 0) {
        var sectionAA = document.createElement('section');
        sectionAA.className = 'iris-recap-section';
        var headingAA = document.createElement('h4');
        headingAA.className = 'iris-recap-heading';
        headingAA.textContent = 'Choix automatiques d’Iris (' + autoAssumptions.length + ')';
        sectionAA.appendChild(headingAA);
        var pSubAA = document.createElement('p');
        pSubAA.className = 'iris-recap-subtitle';
        pSubAA.textContent = 'Questions auxquelles tu n’as pas répondu — Iris a choisi par défaut. Dis-moi si une réponse ne correspond pas.';
        sectionAA.appendChild(pSubAA);
        var ulAA = document.createElement('ul');
        ulAA.className = 'iris-recap-list';
        autoAssumptions.forEach(function(aa) {
            if (!aa || typeof aa !== 'object') return;
            var li = document.createElement('li');
            li.className = 'iris-recap-item';
            if (aa.concept) {
                var conceptSpan = document.createElement('span');
                conceptSpan.className = 'iris-recap-concept';
                conceptSpan.textContent = 'Sur « ' + aa.concept + ' » : ';
                li.appendChild(conceptSpan);
            }
            var q = document.createElement('span');
            q.className = 'iris-recap-question';
            q.textContent = aa.question || '';
            li.appendChild(q);
            ulAA.appendChild(li);
        });
        sectionAA.appendChild(ulAA);
        body.appendChild(sectionAA);
    }

    // ── Réponses utilisateur préservées ────────────────────────────
    if (userAnswers.length > 0) {
        var sectionUA = document.createElement('section');
        sectionUA.className = 'iris-recap-section';
        var headingUA = document.createElement('h4');
        headingUA.className = 'iris-recap-heading';
        headingUA.textContent = 'Tes réponses prises en compte (' + userAnswers.length + ')';
        sectionUA.appendChild(headingUA);
        var ulUA = document.createElement('ul');
        ulUA.className = 'iris-recap-list';
        userAnswers.forEach(function(ua) {
            if (!ua || typeof ua !== 'object') return;
            var li = document.createElement('li');
            li.className = 'iris-recap-item';
            if (ua.concept) {
                var conceptSpan = document.createElement('span');
                conceptSpan.className = 'iris-recap-concept';
                conceptSpan.textContent = 'Sur « ' + ua.concept + ' » : ';
                li.appendChild(conceptSpan);
            }
            var qa = document.createElement('span');
            qa.className = 'iris-recap-qa';
            qa.textContent = (ua.question || '') + ' → ' + (ua.answer || '');
            li.appendChild(qa);
            ulUA.appendChild(li);
        });
        sectionUA.appendChild(ulUA);
        body.appendChild(sectionUA);
    }

    details.appendChild(body);
    appendToMessages(details);
    scrollToBottom();
}

/**
 * Traduit l'``evidence_method`` (raw backend) en libellé FR pour le récap.
 * Fallback gracieux sur le raw si méthode unknown — pas un mapping
 * exhaustif (le backend peut introduire de nouvelles méthodes sans casser
 * le front).
 *
 * @param {string} method
 * @returns {string}
 */
function _humanizeEvidenceMethod(method) {
    if (!method) return '';
    var map = {
        'value_match_exact': 'correspondance exacte sur les valeurs',
        'value_match': 'correspondance sur les valeurs',
        'textual_token': 'correspondance sur des termes textuels',
        'temporal': 'correspondance temporelle',
        'name_match': 'correspondance sur le nom de colonne',
        'identifier_code': 'correspondance sur un code identifiant',
        'numeric_range': 'correspondance sur une plage numérique'
    };
    return map[method] || method;
}

// ──── Rendering — Chain-of-thought (GitHub Copilot style) ────

/**
 * Affiche le raisonnement de l'agent.
 * Comportement : s'ouvre automatiquement avec animation shimmer,
 * puis se ferme quand la réponse texte commence (text_delta).
 * L'utilisateur peut rouvrir manuellement en cliquant.
 * @param {string} thinking
 */
function renderThinking(thinking) {
    if (!thinking) return;

    const container = document.createElement('div');
    // Start expanded + live animation
    container.className = 'iris-thinking-block expanded thinking-live';

    // Header cliquable
    const header = document.createElement('button');
    header.type = 'button';
    header.className = 'iris-thinking-header';
    header.innerHTML = '<span class="iris-thinking-icon">'
        + '<svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor">'
        + '<path d="M8 1.5a6.5 6.5 0 100 13 6.5 6.5 0 000-13zM0 8a8 8 0 1116 0A8 8 0 010 8z"/>'
        + '<path d="M6.5 7.75A.75.75 0 017.25 7h1a.75.75 0 01.75.75v2.75h.25a.75.75 0 010 1.5h-2a.75.75 0 010-1.5h.25v-2h-.25a.75.75 0 01-.75-.75zM8 6a1 1 0 100-2 1 1 0 000 2z"/>'
        + '</svg></span>'
        + '<span class="iris-thinking-label">Raisonnement en cours…</span>'
        + '<span class="iris-thinking-chevron" title="Cliquer pour développer / réduire">'
        + '<svg width="12" height="12" viewBox="0 0 16 16" fill="currentColor">'
        + '<path fill-rule="evenodd" d="M4.22 6.22a.75.75 0 011.06 0L8 8.94l2.72-2.72a.75.75 0 111.06 1.06l-3.25 3.25a.75.75 0 01-1.06 0L4.22 7.28a.75.75 0 010-1.06z"/>'
        + '</svg></span>';
    container.appendChild(header);

    // Contenu (visible immédiatement grâce à expanded)
    const content = document.createElement('div');
    content.className = 'iris-thinking-content';
    content.innerHTML = sanitizeHtml(formatMarkdown(thinking));
    container.appendChild(content);

    // Toggle expand/collapse avec accessibilité
    header.setAttribute('aria-expanded', 'true');
    header.addEventListener('click', function() {
        var isExpanded = container.classList.toggle('expanded');
        header.setAttribute('aria-expanded', isExpanded ? 'true' : 'false');
    });

    appendToMessages(container);
    scrollToBottom();
}

/**
 * Affiche un bloc de thinking déjà terminé (pour la restauration d'historique).
 * Le bloc est fermé par défaut, l'utilisateur peut l'ouvrir en cliquant.
 * @param {string} thinking
 */
function renderThinkingCollapsed(thinking) {
    if (!thinking) return;

    const container = document.createElement('div');
    container.className = 'iris-thinking-block';

    const header = document.createElement('button');
    header.type = 'button';
    header.className = 'iris-thinking-header';
    header.innerHTML = '<span class="iris-thinking-icon">'
        + '<svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor">'
        + '<path d="M8 1.5a6.5 6.5 0 100 13 6.5 6.5 0 000-13zM0 8a8 8 0 1116 0A8 8 0 010 8z"/>'
        + '<path d="M6.5 7.75A.75.75 0 017.25 7h1a.75.75 0 01.75.75v2.75h.25a.75.75 0 010 1.5h-2a.75.75 0 010-1.5h.25v-2h-.25a.75.75 0 01-.75-.75zM8 6a1 1 0 100-2 1 1 0 000 2z"/>'
        + '</svg></span>'
        + '<span class="iris-thinking-label">Raisonnement terminé</span>'
        + '<span class="iris-thinking-chevron" title="Cliquer pour développer / réduire">'
        + '<svg width="12" height="12" viewBox="0 0 16 16" fill="currentColor">'
        + '<path fill-rule="evenodd" d="M4.22 6.22a.75.75 0 011.06 0L8 8.94l2.72-2.72a.75.75 0 111.06 1.06l-3.25 3.25a.75.75 0 01-1.06 0L4.22 7.28a.75.75 0 010-1.06z"/>'
        + '</svg></span>';
    container.appendChild(header);

    const content = document.createElement('div');
    content.className = 'iris-thinking-content';
    content.innerHTML = sanitizeHtml(formatMarkdown(thinking));
    container.appendChild(content);

    header.setAttribute('aria-expanded', 'false');
    header.addEventListener('click', function() {
        var isExpanded = container.classList.toggle('expanded');
        header.setAttribute('aria-expanded', isExpanded ? 'true' : 'false');
    });

    appendToMessages(container);
}

/**
 * Auto-ferme tous les blocs de thinking encore en mode "live".
 * Appelé quand la réponse texte commence à arriver.
 */
function collapseThinkingBlocks() {
    var liveBlocks = messagesArea.querySelectorAll('.iris-thinking-block.thinking-live');
    for (var i = 0; i < liveBlocks.length; i++) {
        var block = liveBlocks[i];
        block.classList.remove('thinking-live', 'expanded');
        var hdr = block.querySelector('.iris-thinking-header');
        if (hdr) hdr.setAttribute('aria-expanded', 'false');
        // Update label to show thinking is done
        var label = block.querySelector('.iris-thinking-label');
        if (label) label.textContent = 'Raisonnement terminé';
    }
}

// ──── Rendering — Analysis ────

/**
 * Affiche un bloc d'analyse (similaire au thinking, en ambre).
 * S'ouvre automatiquement avec animation shimmer live.
 * @param {string} analysis
 */
function renderAnalysis(analysis) {
    if (!analysis) return;

    const container = document.createElement('div');
    container.className = 'iris-analysis-block expanded analysis-live';

    const header = document.createElement('button');
    header.type = 'button';
    header.className = 'iris-analysis-header';
    header.innerHTML = '<span class="iris-analysis-icon">'
        + '<svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor">'
        + '<path d="M8 2a1.5 1.5 0 100 3 1.5 1.5 0 000-3zM6.5 3.5a2.5 2.5 0 115 0 2.5 2.5 0 01-5 0zM2.5 8a.5.5 0 01.5-.5h10a.5.5 0 010 1H3a.5.5 0 01-.5-.5zM4 11a1 1 0 011-1h6a1 1 0 110 2H5a1 1 0 01-1-1zM5.5 13.5a.5.5 0 000 1h5a.5.5 0 000-1h-5z"/>'
        + '</svg></span>'
        + '<span class="iris-analysis-label">Analyse en cours…</span>'
        + '<span class="iris-analysis-chevron" title="Cliquer pour développer / réduire">'
        + '<svg width="12" height="12" viewBox="0 0 16 16" fill="currentColor">'
        + '<path fill-rule="evenodd" d="M4.22 6.22a.75.75 0 011.06 0L8 8.94l2.72-2.72a.75.75 0 111.06 1.06l-3.25 3.25a.75.75 0 01-1.06 0L4.22 7.28a.75.75 0 010-1.06z"/>'
        + '</svg></span>';
    container.appendChild(header);

    const content = document.createElement('div');
    content.className = 'iris-analysis-content';
    content.innerHTML = sanitizeHtml(formatMarkdown(analysis));
    container.appendChild(content);

    header.setAttribute('aria-expanded', 'true');
    header.addEventListener('click', function() {
        var isExpanded = container.classList.toggle('expanded');
        header.setAttribute('aria-expanded', isExpanded ? 'true' : 'false');
    });

    appendToMessages(container);
    scrollToBottom();
}

/**
 * Affiche un bloc d'analyse déjà terminé (restauration d'historique).
 * Fermé par défaut.
 * @param {string} analysis
 */
function renderAnalysisCollapsed(analysis) {
    if (!analysis) return;

    const container = document.createElement('div');
    container.className = 'iris-analysis-block';

    const header = document.createElement('button');
    header.type = 'button';
    header.className = 'iris-analysis-header';
    header.innerHTML = '<span class="iris-analysis-icon">'
        + '<svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor">'
        + '<path d="M8 2a1.5 1.5 0 100 3 1.5 1.5 0 000-3zM6.5 3.5a2.5 2.5 0 115 0 2.5 2.5 0 01-5 0zM2.5 8a.5.5 0 01.5-.5h10a.5.5 0 010 1H3a.5.5 0 01-.5-.5zM4 11a1 1 0 011-1h6a1 1 0 110 2H5a1 1 0 01-1-1zM5.5 13.5a.5.5 0 000 1h5a.5.5 0 000-1h-5z"/>'
        + '</svg></span>'
        + '<span class="iris-analysis-label">Analyse terminée</span>'
        + '<span class="iris-analysis-chevron" title="Cliquer pour développer / réduire">'
        + '<svg width="12" height="12" viewBox="0 0 16 16" fill="currentColor">'
        + '<path fill-rule="evenodd" d="M4.22 6.22a.75.75 0 011.06 0L8 8.94l2.72-2.72a.75.75 0 111.06 1.06l-3.25 3.25a.75.75 0 01-1.06 0L4.22 7.28a.75.75 0 010-1.06z"/>'
        + '</svg></span>';
    container.appendChild(header);

    const content = document.createElement('div');
    content.className = 'iris-analysis-content';
    content.innerHTML = sanitizeHtml(formatMarkdown(analysis));
    container.appendChild(content);

    header.setAttribute('aria-expanded', 'false');
    header.addEventListener('click', function() {
        var isExpanded = container.classList.toggle('expanded');
        header.setAttribute('aria-expanded', isExpanded ? 'true' : 'false');
    });

    appendToMessages(container);
}

/**
 * Auto-ferme tous les blocs d'analyse live.
 */
function collapseAnalysisBlocks() {
    var liveBlocks = messagesArea.querySelectorAll('.iris-analysis-block.analysis-live');
    for (var i = 0; i < liveBlocks.length; i++) {
        var block = liveBlocks[i];
        block.classList.remove('analysis-live', 'expanded');
        var hdr = block.querySelector('.iris-analysis-header');
        if (hdr) hdr.setAttribute('aria-expanded', 'false');
        var label = block.querySelector('.iris-analysis-label');
        if (label) label.textContent = 'Analyse terminée';
    }
}

// ──── Rendering — Verification ────

/**
 * Affiche un indicateur de vérification en cours.
 * @param {string} status - 'start' ou 'complete'
 * @param {string} [message]
 */
function renderVerification(status, message) {
    if (status === 'start') {
        const indicator = document.createElement('div');
        indicator.className = 'iris-verification';
        indicator.id = 'irisVerification';
        indicator.innerHTML = '<span class="iris-verification-spinner"></span> '
            + escapeHtml(message || 'Vérification en cours…');
        appendToMessages(indicator);
        scrollToBottom();
    } else if (status === 'complete') {
        const el = document.getElementById('irisVerification');
        if (el) {
            el.className = 'iris-verification complete';
            el.innerHTML = '✓ ' + escapeHtml(message || 'Vérification terminée');
        }
    }
}

/**
 * Affiche un indicateur d'activité simple (style Claude Code).
 * Une seule ligne : dot pulsant + texte statut + timer.
 * @param {number} phase - Numéro de phase courante (0-5)
 * @param {string} status - Message de statut humainement lisible
 * @param {Object} [opts] - Options supplémentaires
 * @param {number} [opts.sub_current] - Sous-étape courante (ex: concept 2/5)
 * @param {number} [opts.sub_total] - Nombre total de sous-étapes
 */
var _activityStartTime = null;
var _activityTimerInterval = null;
var _currentPhase = -1;

function renderActivityStatus(phase, status, opts) {
    opts = opts || {};

    // Reset timer on phase change
    if (phase !== _currentPhase) {
        _currentPhase = phase;
        _activityStartTime = Date.now();
    }

    // Ensure only one timer interval runs.
    // Pas de setInterval en mode replay : sinon le timer leak après le replay
    // (cleanupActivity n'est pas appelé) et tick avec un _activityStartTime
    // posé au moment du refresh → durée bidon affichée. Cf. review BLOCKING #8.
    if (_activityTimerInterval) clearInterval(_activityTimerInterval);
    if (!window.__irisReplayMode) {
        _activityTimerInterval = setInterval(_updateActivityTimer, 1000);
    }

    // Reuse existing indicator or create new one
    var indicator = document.getElementById('irisActivityStatus');
    if (!indicator) {
        indicator = document.createElement('div');
        indicator.className = 'iris-activity-indicator';
        indicator.id = 'irisActivityStatus';
        appendToMessages(indicator);
    }

    // Build status text
    var textHtml = '';
    if (opts.sub_current && opts.sub_total) {
        textHtml += '<strong>(' + opts.sub_current + '/' + opts.sub_total + ')</strong> ';
    }
    textHtml += escapeHtml(status);

    indicator.innerHTML = '<span class="iris-activity-dot"></span>'
        + '<span class="iris-activity-text">' + textHtml + '</span>'
        + '<span class="iris-activity-timer" id="irisActivityTimer"></span>';

    _updateActivityTimer();

    // Update processing overlay text
    var safeStatus = status.replace(/'/g, "\\'");
    var wrapper = document.querySelector('.iris-input-wrapper');
    if (wrapper) {
        wrapper.style.setProperty('--processing-text', "'" + safeStatus + "'");
    }

    scrollToBottom();
}

function _updateActivityTimer() {
    var timerEl = document.getElementById('irisActivityTimer');
    if (!timerEl || !_activityStartTime) return;
    var elapsed = Math.floor((Date.now() - _activityStartTime) / 1000);
    if (elapsed < 1) return;
    var min = Math.floor(elapsed / 60);
    var sec = elapsed % 60;
    timerEl.textContent = min > 0
        ? min + 'm' + (sec < 10 ? '0' : '') + sec + 's'
        : sec + 's';
}

function cleanupActivity() {
    var indicator = document.getElementById('irisActivityStatus');
    if (indicator) indicator.remove();
    if (_activityTimerInterval) {
        clearInterval(_activityTimerInterval);
        _activityTimerInterval = null;
    }
    _currentPhase = -1;
    _activityStartTime = null;
    var wrapper = document.querySelector('.iris-input-wrapper');
    if (wrapper) wrapper.style.removeProperty('--processing-text');
}

// ──── WebSocket ────

/**
 * Récupère un token XSRF FRAIS via ``GET /api/auth/xsrf``.
 *
 * L'appel HTTP a deux effets :
 *   1. Le serveur (via ``BaseHandler.prepare``) ré-émet le cookie
 *      ``_xsrf`` -- garantit qu'au prochain handshake WS, le cookie
 *      envoyé par le navigateur est aligné avec ce qu'on va mettre
 *      dans l'URL.
 *   2. Retourne le token courant pour qu'on n'ait pas à le relire
 *      via ``getCookie`` (qui peut planter si jamais le cookie était
 *      ``HttpOnly`` un jour).
 *
 * Fallback en cascade : si ``/api/auth/xsrf`` est down ou renvoie 401
 * (anonyme), on retombe sur ``getCookie('_xsrf')`` puis sur
 * ``IRIS_CONFIG.xsrfToken``. Cas d'usage : 1ʳᵉ connexion juste après
 * login dans un autre onglet -- avant ce fix, on tournait en boucle
 * sur l'ancien token de la page, maintenant on récupère le frais.
 *
 * @returns {Promise<string>} token XSRF (string vide si tout fail).
 */
async function fetchFreshXsrfToken() {
    try {
        const r = await fetch('/api/auth/xsrf', {
            credentials: 'same-origin',
            cache: 'no-store',
        });
        if (r.ok) {
            const data = await r.json();
            if (data && typeof data.token === 'string' && data.token) {
                return data.token;
            }
        }
    } catch (e) { /* network down, fall through to fallback */ }
    // Fallbacks : cookie courant > IRIS_CONFIG (figé au render) > vide.
    return getCookie('_xsrf') || (window.IRIS_CONFIG && window.IRIS_CONFIG.xsrfToken) || '';
}

/**
 * Todo #37 — Affiche un banner persistant "offline réseau" quand le
 * navigateur perd le réseau (event ``offline`` sur ``window`` ou
 * ``navigator.onLine === false``).
 *
 * Distingue cet état d'une simple coupure serveur (gérée par le
 * backoff WS) : le banner explique à l'user qu'il doit se reconnecter
 * (pas attendre). Sans cette distinction, le message "Reconnexion en
 * cours…" trompe sur la cause réelle.
 */
function _showOfflineBanner() {
    var banner = document.getElementById('irisOfflineBanner');
    if (!banner) {
        banner = document.createElement('div');
        banner.id = 'irisOfflineBanner';
        banner.className = 'iris-offline-banner';
        banner.setAttribute('role', 'status');
        banner.setAttribute('aria-live', 'polite');
        banner.textContent = 'Tu es hors ligne — on reprend dès que le réseau revient.';
        document.body.appendChild(banner);
    }
    banner.style.display = 'block';
}

function _hideOfflineBanner() {
    var banner = document.getElementById('irisOfflineBanner');
    if (banner) banner.style.display = 'none';
}

function _handleNetworkOffline() {
    _showOfflineBanner();
    _irisDebug('[Iris] Network offline detected');
}

function _handleNetworkOnline() {
    _hideOfflineBanner();
    _irisDebug('[Iris] Network online detected — force reconnect WS');
    // Si la WS est down (ou en backoff long), force reconnect immédiat
    // sans attendre le prochain tick du retry exponentiel. Sans ce
    // reset, le navigateur revient online mais le WS attend potentielle-
    // ment ~30s avant de retenter (cas backoff max). Reset propre :
    // delay=1s + attempts=0 puis kick connectWebSocket().
    if (!ws || ws.readyState !== WebSocket.OPEN) {
        reconnectDelay = 1000;
        reconnectAttempts = 0;
        connectWebSocket();
    }
}

/**
 * Connecte le WebSocket à /ws/iris.
 * Configure les handlers et la reconnexion automatique avec backoff exponentiel.
 *
 * Note : la fonction est ``async`` car on pré-fetch le token XSRF avant
 * la handshake (cf. ``fetchFreshXsrfToken``). Les appelants existants
 * peuvent l'invoquer comme une fonction normale -- la promesse retournée
 * peut être ignorée (fire-and-forget), le WS sera créé en arrière-plan
 * dès que le token est prêt.
 */
async function connectWebSocket() {
    if (ws && ws.readyState === WebSocket.OPEN) {
        return;
    }
    // Close any stale CONNECTING socket before creating a new one
    if (ws && ws.readyState === WebSocket.CONNECTING) {
        ws.close();
        ws = null;
    }

    // Pré-fetch un token frais ET force l'émission du cookie _xsrf.
    // C'est la correction de la cause racine du bug "XSRF validation
    // failed" en boucle : sans cet appel, l'URL pouvait pointer un
    // ancien token alors que le cookie envoyé par le navigateur avait
    // été régénéré (ex: après login dans un autre onglet).
    const xsrfToken = await fetchFreshXsrfToken();
    const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
    const url = `${protocol}//${location.host}/ws/iris?_xsrf=${encodeURIComponent(xsrfToken)}`;

    ws = new WebSocket(url);

    ws.onopen = function() {
        _irisDebug('[Iris] WebSocket connecté');
        reconnectDelay = 1000; // Réinitialiser le délai de backoff
        reconnectAttempts = 0; // Reset compteur tentatives (M1)
        // Reset le flag "fatal reload deja fait" -- une session qui
        // tourne longtemps puis qui se fait fermer en 4003 (XSRF expire)
        // doit pouvoir reload UNE fois meme si on a deja reload tot
        // dans la session. Sans ce reset, le flag persiste a vie.
        try { sessionStorage.removeItem('iris.ws.fatalReload'); } catch (e) {}
        if (sendBtn) sendBtn.disabled = false;
        const dot = document.querySelector('.iris-ws-dot');
        if (dot) {
            dot.classList.add('connected');
            dot.title = 'Connecté au serveur';
        }

        // Todo #36 — Replay automatique d'un message stocké en pending
        // pendant que la WS était down. On consomme la clé (clear AVANT
        // sendMessage pour éviter une boucle si sendMessage re-trigger
        // la déconnexion). Le sendMessage met le texte dans l'input
        // puis appelle la logique normale (afficher user message,
        // typing indicator, envoyer au backend).
        var pending = _loadPendingMessage();
        if (pending && pending.trim() && messageInput) {
            _clearPendingMessage();
            messageInput.value = pending;
            try { messageInput.dispatchEvent(new Event('input')); } catch (e) {}
            // Léger délai pour laisser le frontend stabiliser son état
            // après la reconnexion (autres handlers onopen, dot.title, etc.)
            // avant de re-trigger la machinerie sendMessage.
            setTimeout(function() {
                if (ws && ws.readyState === WebSocket.OPEN) {
                    addSystemMessage('Message renvoyé après reconnexion.');
                    sendMessage();
                }
            }, 100);
        }
    };

    ws.onmessage = function(event) {
        let data;
        try {
            data = JSON.parse(event.data);
        } catch (e) {
            console.error('[Iris] Message WebSocket non-JSON :', event.data);
            return;
        }
        // Task #15 (M2) — dedup + détection trous via ``_seq`` muté par
        // ``SequentialEventPersister.persist()``. Events sans ``_seq``
        // (events non-persistés comme ``cancelled``) passent en clair.
        //
        // **Fix CRITICAL #2 adversarial session 19** : la garde
        // `lastEventSeq > 0` masquait des gaps réels au 1er event si
        // `_seq > 1`. Sémantique correcte : si on n'a JAMAIS vu d'event
        // (lastEventSeq=0) et qu'un `_seq` arrive, c'est la baseline.
        // Logger en info pour audit + dériver le gap depuis 0 si _seq > 1
        // (signal de BDD trash / state perdu côté serveur).
        if (data && typeof data._seq === 'number') {
            if (data._seq <= 0) {
                console.warn('[Iris] event _seq invalide (' + data._seq
                    + ') type=' + data.type + ' — skip');
                return;
            }
            if (lastEventSeq === 0) {
                // Baseline : 1er event de la session JS. Si _seq > 1, le
                // serveur a sauté des events (peut-être OK si reload mid-stream
                // ou multi-onglets) — info log pour traçabilité.
                if (data._seq > 1) {
                    console.info('[Iris] baseline _seq=' + data._seq
                        + ' type=' + data.type
                        + ' (events antérieurs non vus par cette session JS)');
                }
            } else if (data._seq <= lastEventSeq) {
                console.warn('[Iris] event _seq=' + data._seq
                    + ' déjà reçu (dernier=' + lastEventSeq
                    + ', type=' + data.type + ') — skip dup');
                return;
            } else {
                const gap = data._seq - lastEventSeq - 1;
                if (gap > 0) {
                    console.warn('[Iris] event _seq=' + data._seq
                        + ' avec gap=' + gap
                        + ' (attendu ' + (lastEventSeq + 1)
                        + ', type=' + data.type
                        + ') — events manquants entre les deux');
                }
            }
            lastEventSeq = data._seq;
        }
        handleWebSocketEvent(data);
    };

    ws.onclose = function(event) {
        console.warn('[Iris] WebSocket fermé :', event.code, event.reason);
        ws = null;
        const dot = document.querySelector('.iris-ws-dot');
        if (dot) {
            dot.classList.remove('connected');
            dot.title = 'Déconnecté — reconnexion en cours...';
        }
        // Réactiver l'input si la connexion coupe pendant une réponse
        if (typingIndicator) typingIndicator.style.display = 'none';
        cleanupActivity();
        resetAfterResponse();

        // ── Codes serveur fatals : ne PAS reconnecter en boucle ──
        // Le backend ferme avec 4001 (auth) ou 4003 (XSRF) quand il a
        // une raison structurelle de refuser. Reconnecter immediatement
        // = boucle infinie de logs server-side + drain CPU client.
        //
        // Au lieu d'insister, on essaie UNE fois un reload de la page
        // pour recharger le cookie XSRF / la session. Garde anti-boucle
        // via sessionStorage : si le reload n'aide pas, on s'arrete et
        // on affiche un message clair a l'utilisateur (qui pourra alors
        // re-login manuellement).
        //
        // M1 — Tout code applicatif 4xxx non listé est aussi considéré
        // comme un refus structurel : on stoppe le retry (fallback message
        // générique). Évite de spammer le serveur sur 4002/4005/etc. qui
        // seraient ajoutés à l'avenir sans mise à jour côté client.
        var FATAL_CODES = { 4001: 'Authentification requise', 4003: 'Jeton de sécurité expiré' };
        var isApplicativeReject = event.code >= 4000 && event.code < 4100;
        if (FATAL_CODES.hasOwnProperty(event.code)) {
            var reloadKey = 'iris.ws.fatalReload';
            var alreadyReloaded = false;
            try { alreadyReloaded = sessionStorage.getItem(reloadKey) === '1'; } catch (e) {}
            if (!alreadyReloaded) {
                try { sessionStorage.setItem(reloadKey, '1'); } catch (e) {}
                console.warn('[Iris] Reload page apres close ' + event.code +
                    ' (' + FATAL_CODES[event.code] + ') -- une seule tentative');
                // Petit delai pour laisser le log s'imprimer cote client.
                setTimeout(function() { location.reload(); }, 100);
                return;
            }
            // Deja reloade une fois et le close fatal persiste : il y a
            // un vrai probleme cote serveur (cookie HttpOnly, session
            // expiree definitivement, etc.). On stoppe et on previent.
            try {
                var msgBox = document.querySelector('.iris-input-wrapper') || document.body;
                if (msgBox && typeof addErrorMessage === 'function') {
                    addErrorMessage(
                        FATAL_CODES[event.code] + '. Veuillez vous reconnecter (deconnexion / reconnexion).'
                    );
                }
            } catch (e) {}
            if (dot) dot.title = FATAL_CODES[event.code] + ' -- reconnexion manuelle requise';
            // Pas de scheduleReconnect : on arrete net.
            return;
        }

        // M1 — Code applicatif 4xxx NON listé (4002, 4004, 4010, etc.) :
        // le serveur a refusé pour une raison structurelle qu'on ne
        // connaît pas. On ne reload PAS automatiquement (la cause peut
        // ne pas être un cookie/XSRF expiré) mais on stoppe le retry
        // pour ne pas spammer le serveur. L'utilisateur peut F5
        // manuellement pour réessayer.
        if (isApplicativeReject) {
            console.warn('[Iris] Close applicatif 4xxx non listé (' + event.code +
                ') -- pas de reconnexion auto. Reason=' + (event.reason || 'n/a'));
            try {
                if (typeof addErrorMessage === 'function') {
                    addErrorMessage(
                        'Connexion refusée par le serveur (code ' + event.code + '). ' +
                        'Rechargez la page pour réessayer.'
                    );
                }
            } catch (e) {}
            if (dot) dot.title = 'Refus serveur (code ' + event.code + ') -- F5 pour réessayer';
            return;
        }

        // Close OK ou erreur reseau : on a ete connecte au moins une fois,
        // donc on reset le flag de reload (au cas ou un futur close fatal
        // arrive plus tard apres une periode de fonctionnement normal).
        try { sessionStorage.removeItem('iris.ws.fatalReload'); } catch (e) {}
        scheduleReconnect();
    };

    ws.onerror = function(error) {
        console.error('[Iris] Erreur WebSocket :', error);
    };
}

/**
 * Planifie une tentative de reconnexion avec backoff exponentiel (max 30s)
 * + jitter ±20% + cap dur sur le nombre de tentatives (M1).
 *
 * - Backoff : 1s → 2s → 4s → 8s → 16s → 30s → 30s → ...
 * - Jitter ±20% : casse la synchronisation "thundering herd" si N clients
 *   perdent la connexion en même temps (déploiement, restart Tornado).
 *   Sans jitter, tous les clients tapent à t=1s, t=2s, ... simultanément
 *   au redémarrage du serveur — pic de charge artificiel.
 * - Cap MAX_RECONNECT_ATTEMPTS : au-delà, on abandonne et on demande à
 *   l'utilisateur de réessayer manuellement. Évite un drain CPU silencieux
 *   indéfini si le serveur reste down longtemps.
 */
function scheduleReconnect() {
    if (reconnectTimer) return;

    // Cap : si on a déjà essayé MAX fois sans succès, on abandonne.
    if (reconnectAttempts >= MAX_RECONNECT_ATTEMPTS) {
        console.warn(
            '[Iris] Abandon reconnexion après ' + reconnectAttempts +
            ' tentatives. Le serveur reste injoignable.'
        );
        try {
            var dot = document.querySelector('.iris-ws-dot');
            if (dot) dot.title = 'Serveur injoignable -- rechargez la page (F5) pour réessayer';
            if (typeof addErrorMessage === 'function') {
                addErrorMessage(
                    'Reconnexion abandonnée après ' + MAX_RECONNECT_ATTEMPTS +
                    ' tentatives. Rechargez la page (F5) pour réessayer.'
                );
            }
        } catch (e) {}
        return;
    }

    // Jitter ±20% : Math.random() ∈ [0,1[ → factor ∈ [0.8, 1.2]
    var jitterFactor = 0.8 + (Math.random() * 0.4);
    var actualDelay = Math.round(reconnectDelay * jitterFactor);

    reconnectAttempts++;
    reconnectTimer = setTimeout(function() {
        reconnectTimer = null;
        _irisDebug('[Iris] Tentative reconnexion #' + reconnectAttempts +
            '/' + MAX_RECONNECT_ATTEMPTS + ' (délai : ' + actualDelay + 'ms)');
        connectWebSocket();
        // Backoff exponentiel sur la base sans jitter (le jitter est appliqué
        // au planning, pas accumulé dans la base — sinon dérive aléatoire).
        reconnectDelay = Math.min(reconnectDelay * 2, 30000);
    }, actualDelay);
}

/**
 * Dispatche les événements WebSocket reçus vers le bon handler.
 * @param {{ type: string, [key: string]: any }} event
 */
function handleWebSocketEvent(event) {
    // Auto-resolve any pending verification indicators when new content arrives.
    // Skip en mode replay : ce flow dépend du timing réel (verif est marquée
    // complete quand un autre event arrive ensuite). Au replay, tous les events
    // sont rejoués séquentiellement et instantanément → divergence DOM possible
    // (verif marquée complete alors qu'au moment du refresh elle était encore
    // active). Au replay, on respecte l'état persisté des cards verification :
    // un event ``verification`` complete est forcément persisté quand la
    // résolution a vraiment eu lieu en live. Cf. adversarial review BLOCKING #4.
    if (event.type !== 'verification' && !window.__irisReplayMode) {
        const pendingVerif = document.getElementById('irisVerification');
        if (pendingVerif && !pendingVerif.classList.contains('complete')) {
            pendingVerif.className = 'iris-verification complete';
            pendingVerif.innerHTML = '✓ ' + (pendingVerif.textContent || 'Terminé');
            pendingVerif.removeAttribute('id');
        }
    }

    switch (event.type) {
        case 'user_message':
            // Bulle USER. En LIVE, jamais émis : ``sendMessage()`` rend déjà
            // localement via ``addUserMessage()`` AVANT l'envoi WS, et le
            // backend ne pousse pas ce type via la WS (uniquement persisté
            // en BDD comme WAL). En REPLAY, c'est ce qui restitue les
            // messages user persistés (cf. ``iris.py:_run_agent`` WAL).
            addUserMessage(event.content || '');
            break;
        case 'text_delta':
            // Texte partiel en streaming — crée la bulle si elle n'existe pas encore
            if (!currentStreamDiv) {
                if (typingIndicator) {
                    typingIndicator.style.display = 'none';
                    var st = typingIndicator.querySelector('.iris-typing-text');
                    if (st) st.textContent = '';
                }
                // Auto-fermer le thinking quand la réponse texte arrive
                collapseThinkingBlocks();
                collapseAnalysisBlocks();
                currentStreamDiv = createAssistantBubble();
                currentStreamDiv._rawText = '';
                currentStreamDiv._renderedAnalysis = new Set(); // track processed blocks by content
                isStreaming = true;
                try { window.__irisStreamingActive = true; } catch (e) { /* defensive */ }
            }
            currentStreamDiv._rawText += (event.content || '');
            // Estimation live context-window : ce texte assistant sera dans
            // l'historique au prochain appel LLM.
            _cwAddEstimatedChars((event.content || '').length);

            // Extract and render NEW complete [ANALYSIS] blocks (Set-based dedup)
            var analysisMatches = currentStreamDiv._rawText.match(/\[ANALYSIS\][\s\S]*?\[\/ANALYSIS\]/gi) || [];
            for (var ai = 0; ai < analysisMatches.length; ai++) {
                var fullMatch = analysisMatches[ai];
                if (currentStreamDiv._renderedAnalysis.has(fullMatch)) continue;
                currentStreamDiv._renderedAnalysis.add(fullMatch);
                var innerContent = fullMatch.replace(/^\[ANALYSIS\]/i, '').replace(/\[\/ANALYSIS\]$/i, '').trim();
                if (innerContent) {
                    renderAnalysis(innerContent);
                }
            }

            currentStreamDiv.innerHTML = sanitizeHtml(formatMarkdown(currentStreamDiv._rawText));
            scrollToBottom();
            break;

        case 'text_complete': {
            // Finalise le dernier message assistant — ajoute les boutons de feedback
            // Ne PAS écraser le contenu (il est déjà rendu via text_delta)
            const target = currentStreamDiv ? currentStreamDiv.parentElement : lastAssistantBubble;
            if (target) {
                target.appendChild(_buildFeedbackRow());
                scrollToBottom();
            }
            currentStreamDiv = null;
            isStreaming = false;
            try { window.__irisStreamingActive = false; } catch (e) { /* defensive */ }
            break;
        }

        case 'exploration_start':
            // Ouvre un nouveau bloc timeline d'exploration dans le chat.
            // Ferme typing indicator + thinking block en cours pour éviter
            // le chevauchement visuel.
            if (typingIndicator) {
                var et = typingIndicator.querySelector('.iris-typing-text');
                if (et) et.textContent = 'Exploration…';
            }
            renderExplorationGroup();
            break;

        case 'plan_update':
            // Snapshot complet du plan (jamais des deltas). Le widget se
            // crée à la première update qui apporte ≥ 1 task et se rafraîchit
            // idempotamment ensuite. Cf. ``applyPlanUpdate`` pour la sémantique
            // (auto-expand sur in_progress, auto-collapse une fois tout fait).
            try {
                applyPlanUpdate(event.plan);
            } catch (planErr) {
                console.warn('[Iris] applyPlanUpdate failed:', planErr);
            }
            break;

        case 'exploration_catalog':
            updateExplorationStep('catalog', 'done', event);
            break;

        case 'exploration_tables_selected':
            updateExplorationStep('selection', (event.count > 0 ? 'done' : 'error'), event);
            break;

        case 'exploration_fk_expanded':
            updateExplorationStep('fk', 'done', event);
            break;

        case 'exploration_batch_progress':
            // Pour les batches, on affiche UNE ligne qui se met à jour au fur
            // et à mesure (current/total). Le helper remplace la ligne existante.
            var batchState = (event.current >= event.total) ? 'done' : 'active';
            updateExplorationStep('batch', batchState, event);
            break;

        case 'exploration_complementary':
            updateExplorationStep('complementary', 'done', event);
            break;

        case 'exploration_complete':
            // aborted=true quand l'exploration n'a pas pu se dérouler complètement
            // (0 tables retenues, cancel, exception) → on ferme le bloc en état
            // d'erreur/warning au lieu de succès, pour éviter un spinner infini
            // ou une clôture trompeuse en vert.
            var okExplore = !event.aborted;
            updateExplorationStep('complete', okExplore ? 'done' : 'error', event);
            finalizeExplorationGroup(okExplore, event);
            break;

        case 'tool_blocked':
            renderToolBlocked(
                event.tool,
                event.reason,
                event.message,
            );
            break;

        case 'alignment_search':
            handleAlignmentSearch(event);
            break;

        case 'alignment_question':
            handleAlignmentQuestion(event);
            break;

        case 'alignment_complete':
            handleAlignmentComplete(event);
            break;

        case 'element_start':
            collapseThinkingBlocks();
            collapseAnalysisBlocks();
            currentStreamDiv = null;
            handleElementStart(event.element || '', event.index || 0, event.total || 0);
            break;

        case 'element_end':
            handleElementEnd(event.element || '', !!event.success, event.location || event.sql_fragment || '');
            break;

        case 'sql_build_start':
            collapseThinkingBlocks();
            collapseAnalysisBlocks();
            currentStreamDiv = null;
            handleSQLBuildStart();
            break;

        case 'sql_build_end':
            handleSQLBuildEnd(!!event.success, event.reason || '');
            break;

        case 'tool_use':
            // Finaliser la bulle de texte en cours avant l'outil
            collapseThinkingBlocks();
            collapseAnalysisBlocks();
            currentStreamDiv = null;

            // Pas de card outil pour les clarifications
            if (event.tool === 'ask_user_clarification') {
                // Le LLM pose sa propre question → plus besoin du fallback auto
                _pendingExecuteSqlFeedback = false;
                break;
            }

            // started_at (ISO 8601 UTC, propagé depuis le backend pour
            // pipeline_phase_X) → epoch ms pour le live timer. Date.parse
            // retourne NaN sur input invalide ; addToolIndicator fallback
            // alors à Date.now() local (acceptable car l'event vient de
            // tomber via WS → écart < 100 ms).
            var startTsLive;
            if (event.started_at) {
                var parsed = Date.parse(event.started_at);
                if (isFinite(parsed)) startTsLive = parsed;
            }

            // Compact tool line (Claude Code style)
            addToolIndicator(
                event.tool || 'outil',
                event.icon,
                event.label,
                event.description,
                false,
                startTsLive
            );
            // Estimation live context-window : le tool_use sera envoyé au
            // LLM dans le contexte du prochain tour. Approxime tool name +
            // label + description (input n'est pas dans cet event ; le
            // ``context_progress`` post-appel recalibrera).
            _cwAddEstimatedChars(
                ((event.tool || '').length)
                + ((event.label || '').length)
                + ((event.description || '').length)
            );
            break;

        case 'tool_result': {
            // Ignorer les tool_result pour ask_user_clarification
            if (event.tool === 'ask_user_clarification') break;

            // Estimation live context-window : le tool_result sera renvoyé
            // au LLM au prochain tour. JSON.stringify avec try/catch pour
            // les structures circulaires (rares mais possible).
            try {
                var resultPayload = event.result != null
                    ? JSON.stringify(event.result)
                    : '';
                _cwAddEstimatedChars(resultPayload.length);
            } catch (e) { /* structure circulaire — skip estimation */ }

            // Note (refonte UX 2026-05-08) : plus d'auto-open d'un panneau
            // séparé pour run_pipeline. Le serveur stream désormais les
            // events des phases directement dans le chat Iris sous forme
            // de tool_use/tool_result standards (tool="pipeline_phase_X"),
            // rendus par les renderers existants. Le messageInput est
            // bloqué via __irisStreamingActive (le tour Iris reste actif
            // pendant toute la durée de la pipeline — pas de flag dédié).

            // Flag feedback automatique : execute_sql réussi avec des lignes
            // réelles → on prévoit une card succès/itération/échec au 'done' si le LLM
            // n'a pas posé de question lui-même.
            if (event.tool === 'execute_sql' && event.result &&
                event.result.success === true) {
                var rc = event.result.row_count;
                var rowsLen = (event.result.rows && event.result.rows.length) || 0;
                if ((typeof rc === 'number' && rc > 0) || rowsLen > 0) {
                    _pendingExecuteSqlFeedback = true;
                }
            }

            // Find the last unresolved tool line for this tool
            var toolName = event.tool || '';
            var container = _getToolContainer();
            // Search in current group first, then fallback to messagesArea
            var searchRoot = (container !== messagesArea) ? container : messagesArea;
            var allLines = searchRoot.querySelectorAll(
                '.iris-tool-line:not(.tool-resolved)'
            );
            if (allLines.length === 0 && searchRoot !== messagesArea) {
                allLines = messagesArea.querySelectorAll('.iris-tool-line:not(.tool-resolved)');
            }
            var targetLine = null;
            for (var ti = allLines.length - 1; ti >= 0; ti--) {
                if (!toolName || allLines[ti].dataset.tool === toolName) {
                    targetLine = allLines[ti];
                    break;
                }
            }
            if (!targetLine && allLines.length > 0) {
                targetLine = allLines[allLines.length - 1];
            }
            if (targetLine) {
                targetLine.classList.add('tool-resolved');

                // Stop the dot animation
                var dot = targetLine.querySelector('.iris-tool-line-dot');
                if (dot) dot.classList.remove('dot-active');

                // Cleanup live timer : la classe ``tool-resolved`` court-circuite
                // déjà le tick global, mais on retire aussi ``data-start-ts``
                // pour que le ``querySelectorAll(...[data-start-ts])`` n'itère
                // plus dessus (perf, et évite un dernier tick stale juste avant
                // le clearInterval auto).
                if (targetLine.dataset.startTs) delete targetLine.dataset.startTs;

                // Pour les phases pipeline_phase_*, la description "Exécution
                // en cours…" posée au tool_use est devenue mensongère après
                // tool_result (phase terminée). On la retire — pour les SQL
                // tools la description = la requête (à garder visible).
                if (toolName.indexOf('pipeline_phase_') === 0) {
                    var phaseDescEl = targetLine.querySelector('.iris-tool-line-desc');
                    if (phaseDescEl) phaseDescEl.remove();
                }

                // Show elapsed time
                var timeEl = targetLine.querySelector('.iris-tool-line-time');
                var success = event.result && event.result.success === true;
                var elapsed = event.elapsed_ms;
                var timeStr = '';
                if (elapsed != null) {
                    timeStr = _formatToolElapsedMs(elapsed);
                }

                if (timeEl) {
                    if (success) {
                        timeEl.textContent = timeStr;
                    } else {
                        timeEl.innerHTML = '<span class="iris-tool-line-err">✗</span> ' + escapeHtml(timeStr);
                    }
                }

                if (!success) {
                    targetLine.classList.add('iris-tool-line-hasError');
                }

                var isExpandableLine = targetLine.classList.contains('iris-tool-line-expandable');

                // On failure for expandable SQL tools: just show a compact "Erreur" badge;
                // the full error goes into the expanded panel (no verbose inline redundancy).
                if (!success && isExpandableLine) {
                    var existingDesc = targetLine.querySelector('.iris-tool-line-desc');
                    var errBadge = document.createElement('span');
                    errBadge.className = 'iris-tool-line-err-badge';
                    errBadge.textContent = 'Erreur';
                    if (existingDesc) existingDesc.after(errBadge);
                    else {
                        var labelEl = targetLine.querySelector('.iris-tool-line-label');
                        if (labelEl) labelEl.after(errBadge);
                    }
                } else if (event.summary) {
                    // Success or non-expandable tool: show summary inline (capped by CSS max-width)
                    var existingDesc2 = targetLine.querySelector('.iris-tool-line-desc');
                    var summarySpan = document.createElement('span');
                    summarySpan.className = 'iris-tool-line-summary' + (success ? '' : ' iris-tool-line-summary-err');
                    summarySpan.textContent = '→ ' + event.summary;
                    if (existingDesc2) {
                        existingDesc2.after(summarySpan);
                    } else {
                        var labelEl2 = targetLine.querySelector('.iris-tool-line-label');
                        if (labelEl2) labelEl2.after(summarySpan);
                    }
                }

                // For expandable SQL tools, surface the full error in the expanded panel
                var toolWrap = targetLine.closest('.iris-tool-wrap');
                if (toolWrap && targetLine.classList.contains('iris-tool-line-expandable') && !success) {
                    var errEl = toolWrap.querySelector('.iris-tool-expanded-error');
                    if (errEl) {
                        var errMsg = '';
                        var r = event.result || {};
                        if (r.error) errMsg = String(r.error);
                        else if (r.blocked_by) errMsg = String(r.blocked_by);
                        else if (event.summary) errMsg = String(event.summary);
                        else errMsg = 'Erreur inconnue';
                        // P5.4 (audit 2026-05-26) — Avant : on ignorait r.detail,
                        // r.sqlstate, r.position (les détails techniques ODBC).
                        // Maintenant : on les concatène pour qu'un user senior
                        // puisse voir la cause précise (ligne SQL fautive,
                        // SQLSTATE pour grep documentation MSDN, etc.).
                        var techParts = [];
                        if (r.sqlstate) techParts.push('SQLSTATE: ' + String(r.sqlstate));
                        if (r.category) techParts.push('Catégorie: ' + String(r.category));
                        if (r.position) techParts.push('Position: ' + String(r.position));
                        if (r.detail && String(r.detail) !== errMsg) {
                            techParts.push('Détail: ' + String(r.detail));
                        }
                        // C24: si le guard fournit next_actions, les lister
                        // sous l'erreur — même plan de déblocage que celui vu
                        // par le LLM.
                        var nextActs = Array.isArray(r.next_actions) ? r.next_actions : null;
                        errEl.hidden = false;
                        errEl.innerHTML = '<span class="iris-tool-expanded-error-icon">⚠</span>'
                            + '<span class="iris-tool-expanded-error-text"></span>';
                        errEl.querySelector('.iris-tool-expanded-error-text').textContent = errMsg;
                        // P5.4 — bloc technique détaillé (collapsé visuel via
                        // CSS hint si déjà long ; le user senior peut copier).
                        if (techParts.length > 0) {
                            var techBox = document.createElement('div');
                            techBox.className = 'iris-tool-error-tech';
                            techBox.textContent = techParts.join(' · ');
                            errEl.appendChild(techBox);
                        }
                        // P5.4 — bloc SQL fautif en <pre> monospace si fourni
                        if (r.sql) {
                            var sqlBox = document.createElement('pre');
                            sqlBox.className = 'iris-tool-error-sql';
                            sqlBox.textContent = String(r.sql);
                            errEl.appendChild(sqlBox);
                        }
                        if (nextActs && nextActs.length > 0) {
                            var actionsBox = document.createElement('div');
                            actionsBox.className = 'iris-tool-next-actions';
                            var actionsTitle = document.createElement('div');
                            actionsTitle.className = 'iris-tool-next-actions-title';
                            actionsTitle.textContent = 'Pistes pour débloquer :';
                            actionsBox.appendChild(actionsTitle);
                            var ul = document.createElement('ul');
                            ul.className = 'iris-tool-next-actions-list';
                            nextActs.forEach(function(a) {
                                if (typeof a !== 'string' || !a.trim()) return;
                                var li = document.createElement('li');
                                li.textContent = a;
                                ul.appendChild(li);
                            });
                            actionsBox.appendChild(ul);
                            errEl.appendChild(actionsBox);
                        }
                        // Panel stays collapsed by default — user clicks to expand (like thinking blocks).
                    }
                }

                // P1.2.2 (task #20, 2026-05-26) — Rendering enrichi pour
                // quick_overview_workbook : sub-element compact avec liste
                // colonnes (type + nulls) + mini-table sample 3 rows.
                // Aucune dégradation si result mal formé (renderWorkbookOverview
                // skip silencieusement).
                if (success && event.tool === 'quick_overview_workbook') {
                    try {
                        renderWorkbookOverview(targetLine, event);
                    } catch (_renderErr) {
                        // Pas de console.error pour ne pas polluer le bug-report
                        // côté user — le tool_result reste affiché en mode summary.
                    }
                }
                // P1.2.3 (task #21, 2026-05-26) — Rendering enrichi pour
                // read_workbook_rows : mini-table HTML reconstruite depuis
                // les cells sparse. Cap à 10 rows affichées + note pagination.
                else if (success && event.tool === 'read_workbook_rows') {
                    try {
                        renderWorkbookRowsTable(targetLine, event);
                    } catch (_renderErr2) {
                        /* Fail-safe : summary inline reste affiché */
                    }
                }

                // C26 : si une auto-correction SQL a été appliquée, l'exposer
                // à l'utilisateur (sinon la correction est silencieuse et le
                // user croit avoir reçu sa SQL brute alors qu'elle a été réécrite).
                var rOk = event.result || {};
                var autoCorrections = Array.isArray(rOk.auto_corrected) ? rOk.auto_corrected : null;
                if (success && autoCorrections && autoCorrections.length > 0) {
                    var labelEl3 = targetLine.querySelector('.iris-tool-line-label');
                    var correctedBadge = document.createElement('span');
                    correctedBadge.className = 'iris-tool-line-autocorrected-badge';
                    correctedBadge.textContent = 'Auto-corrigé';
                    correctedBadge.title = autoCorrections.map(function(c) {
                        return (c.category || '?') + ' — ' + (c.description || '');
                    }).join('\n');
                    if (labelEl3) labelEl3.after(correctedBadge);
                }
            }
            break;
        }

        case 'sql_results':
            // Tableau de données SQL. ``search_id`` est passé en 6e arg pour
            // que le flow consent (event ``data_read_consent_request`` qui
            // suit) retrouve cette grille via ``_gridsBySearchId`` et ouvre
            // son ``_openAnonymizationPanel`` au lieu d'un panel détaché
            // dupliqué.
            renderSQLResults(
                event.columns || [],
                event.rows || [],
                event.sql,
                event.row_count || 0,
                event.truncated || false,
                event.search_id
            );
            break;

        case 'report_ready':
            // Rapport généré et sauvegardé — afficher un lien de téléchargement
            renderReportReady(event);
            break;

        case 'datastore_saved':
            // Fichier sauvegardé dans le datastore — afficher une confirmation
            renderDatastoreSaved(event);
            break;

        // Task #20 — Les 5 interactions question/réponse passent toutes par
        // ``renderInteraction(event)`` (taxonomie unifiée). Chaque cas garde
        // son ``case`` pour rétro-compat avec le switch et lisibilité, mais
        // délègue au dispatcher central — plus de duplication des contrats
        // (4 renderers historiques restent les helpers du dispatcher).

        case 'clarification':
            // kind = clarify_with_options. Buffer puis rendu groupé au 'done'.
            renderInteraction(event);
            break;

        case 'pipeline_ask_user':
            // kind = open_question. Fix 2026-05-20 : la pipeline elle-même
            // pose une question (cf. ``AskUserBridge.ask`` côté Phase 4) —
            // architecturalement distinct du ``clarification`` qui vient du
            // LLM Iris via le tool ``ask_user_clarification``. Ici on bypass
            // complètement le LLM — la pipeline await directement la réponse
            // et reprend SANS crasher. Affichage immédiat (pas de buffering
            // vers 'done' — la pipeline tourne déjà sans 'done' final tant
            // que la question n'est pas répondue).
            renderInteraction(event);
            break;

        case 'data_read_consent_request':
            // kind = consent. Iris s'apprête à lire les résultats d'un
            // execute_sql / run_pipeline. Selon la pref user, on ouvre soit
            // un prompt OUI/NON (mode='ask'), soit directement le panneau
            // Confidentialité pré-rempli (mode='always_show_panel'). Le
            // backend bloque jusqu'à notre réponse via la WS action
            // 'data_read_consent_response'.
            renderInteraction(event);
            break;

        case 'suggestions':
            // kind = suggestions.
            renderInteraction(event);
            break;

        case 'rag_sources':
            renderRAGSources(event.sources || []);
            break;

        case 'pipeline_recap':
            // Todo #17 — Composant UI dédié pour le récap structuré
            // produit par la pipeline (cf. ``build_pipeline_recap_payload``
            // backend). Single source of truth visible — la promesse de
            // traçabilité Komptia tient indépendamment du markdown que
            // le LLM Iris produira ensuite. Persisté + replay au refresh
            // via le même dispatcher (DOM identique).
            renderPipelineRecap(event.payload || {});
            break;

        case 'thinking':
            // Thinking complet (fallback ancien format)
            renderThinking(event.content || '');
            break;

        case 'thinking_start':
            // Créer le bloc thinking vide pour le streaming temps réel
            (function() {
                var container = document.createElement('div');
                container.className = 'iris-thinking-block expanded thinking-live';
                var header = document.createElement('button');
                header.type = 'button';
                header.className = 'iris-thinking-header';
                header.innerHTML = '<span class="iris-thinking-icon">'
                    + '<svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor">'
                    + '<path d="M8 1.5a6.5 6.5 0 100 13 6.5 6.5 0 000-13zM0 8a8 8 0 1116 0A8 8 0 010 8z"/>'
                    + '<path d="M6.5 7.75A.75.75 0 017.25 7h1a.75.75 0 01.75.75v2.75h.25a.75.75 0 010 1.5h-2a.75.75 0 010-1.5h.25v-2h-.25a.75.75 0 01-.75-.75zM8 6a1 1 0 100-2 1 1 0 000 2z"/>'
                    + '</svg></span>'
                    + '<span class="iris-thinking-label">Raisonnement en cours\u2026</span>'
                    + '<span class="iris-thinking-chevron" title="Cliquer pour développer / réduire">'
                    + '<svg width="12" height="12" viewBox="0 0 16 16" fill="currentColor">'
                    + '<path fill-rule="evenodd" d="M4.22 6.22a.75.75 0 011.06 0L8 8.94l2.72-2.72a.75.75 0 111.06 1.06l-3.25 3.25a.75.75 0 01-1.06 0L4.22 7.28a.75.75 0 010-1.06z"/>'
                    + '</svg></span>';
                header.setAttribute('aria-expanded', 'true');
                header.addEventListener('click', function() {
                    var isExpanded = container.classList.toggle('expanded');
                    header.setAttribute('aria-expanded', isExpanded ? 'true' : 'false');
                });
                container.appendChild(header);
                var content = document.createElement('div');
                content.className = 'iris-thinking-content';
                container.appendChild(content);
                appendToMessages(container);
                scrollToBottom();
            })();
            break;

        case 'thinking_delta':
            (function() {
                var liveBlock = messagesArea.querySelector('.iris-thinking-block.thinking-live');
                if (liveBlock) {
                    var contentEl = liveBlock.querySelector('.iris-thinking-content');
                    if (contentEl) {
                        contentEl.textContent += (event.content || '');
                        scrollToBottom();
                    }
                }
            })();
            break;

        case 'thinking_end':
            // Appliquer le markdown sur le texte brut puis fermer
            (function() {
                var liveBlock = messagesArea.querySelector('.iris-thinking-block.thinking-live');
                if (liveBlock) {
                    var contentEl = liveBlock.querySelector('.iris-thinking-content');
                    if (contentEl && contentEl.textContent) {
                        contentEl.innerHTML = sanitizeHtml(formatMarkdown(contentEl.textContent));
                    }
                }
                collapseThinkingBlocks();
            })();
            break;

        case 'verification':
            renderVerification(event.status || 'start', event.message);
            break;

        case 'phase_progress':
            renderActivityStatus(event.phase, event.status || '', {
                sub_current: event.sub_current || 0,
                sub_total: event.sub_total || 0,
            });
            break;

        case 'error':
            // Flush les clarifications bufferisées avant l'erreur
            flushPendingClarifications();
            // Annuler un éventuel feedback auto en attente (pas pertinent si erreur)
            _pendingExecuteSqlFeedback = false;
            addErrorMessage(event.message || 'Une erreur est survenue.');
            collapseThinkingBlocks();
            collapseAnalysisBlocks();
            cleanupActivity();
            cleanupExploration();
            if (typingIndicator) typingIndicator.style.display = 'none';
            resetAfterResponse();
            break;

        case 'sync_requested':
            _startSyncInChat();
            break;

        case 'done':
            // Flush les clarifications bufferisées (rendu groupé)
            flushPendingClarifications();
            // Fallback feedback : si execute_sql a rendu des lignes mais que
            // le LLM n'a pas appelé ask_user_clarification, on injecte nous
            // une card succès/itération/échec. Garantit que l'utilisateur peut toujours
            // valider ou signaler que la requête n'est pas bonne — sans
            // dépendre du fait que le LLM pense à demander.
            // Task #20 — Route via le dispatcher unifié (kind=feedback) pour
            // que les 5 familles d'interactions question/réponse passent
            // toutes par le même point d'entrée.
            if (_pendingExecuteSqlFeedback) {
                renderInteraction({ interaction_kind: 'feedback' });
                _pendingExecuteSqlFeedback = false;
            }
            // Réponse complète — réactiver l'UI
            collapseThinkingBlocks();
            collapseAnalysisBlocks();
            cleanupActivity();
            cleanupExploration();
            if (typingIndicator) typingIndicator.style.display = 'none';
            resetAfterResponse();

            // Mise à jour de l'ID conversation (critique pour le feedback)
            if (event.conversation_id != null) {
                currentConversationId = event.conversation_id;
                // Synchronise IRIS_CONFIG.conversationId pour que les
                // composants externes (iris-grid._detectScanContext) puissent
                // lire la valeur courante sans dépendre d'une var globale
                // privée du closure iris.js. Cf. mai 2026 — propagation
                // ``source_ref="iris:<conv>"`` dans /data/privacy.
                if (window.IRIS_CONFIG) {
                    window.IRIS_CONFIG.conversationId = currentConversationId;
                }
            }

            // Mise à jour de l'indicateur context-window. La valeur source
            // est `last_input_tokens` (= taille de contexte envoyée au DERNIER
            // tour, cache inclus pour Anthropic) — c'est elle qui chute après
            // un compact. `tokens_used` (cumul) est conservé pour compat
            // mais n'est pas affiché. Si le backend ne renvoie pas encore les
            // nouveaux champs (rolling deploy), on garde l'ancien état UI.
            // skipIfZeroAfterPositive: cas où le run sort sans appeler le LLM
            // (cold-start sync, exploration guard sans appel) — last_input_tokens
            // = 0 trompeusement, on garde la valeur précédente.
            if (event.context_window != null) {
                updateContextWindow({
                    usedTokens: event.last_input_tokens != null
                        ? event.last_input_tokens
                        : 0,
                    contextWindow: event.context_window,
                    modelDisplay: event.model_display || null,
                    skipIfZeroAfterPositive: true
                });
            }

            // Show jump-to-data banner if SQL results exist but are scrolled out of view
            showSqlResultsBannerIfNeeded();
            break;

        case 'context_progress':
            // Progression dynamique du remplissage de la context window —
            // émis APRÈS chaque tour LLM par agent_service.py (pas seulement
            // à 'done'). Permet à la barre #contextWindowIndicator d'avancer
            // pendant qu'Iris fait des tool-calls successifs (search_schema,
            // execute_sql, search_codebase, etc.) et de CHUTER visiblement
            // après une compaction mid-loop.
            if (event.context_window != null) {
                updateContextWindow({
                    usedTokens: event.last_input_tokens != null
                        ? event.last_input_tokens
                        : 0,
                    contextWindow: event.context_window,
                    skipIfZeroAfterPositive: true
                });
            }
            break;

        case 'status':
            // Status de l'exploration guard (progression)
            if (typingIndicator) {
                typingIndicator.style.display = '';
                var statusText = typingIndicator.querySelector('.iris-typing-text');
                if (statusText) statusText.textContent = event.message || '';
            }
            break;

        case 'cancelled':
            // Génération interrompue par l'utilisateur
            collapseThinkingBlocks();
            collapseAnalysisBlocks();
            cleanupActivity();
            cleanupExploration();
            if (typingIndicator) typingIndicator.style.display = 'none';
            addSystemMessage(event.message || 'Génération interrompue.');
            resetAfterResponse();
            break;

        default:
            console.warn('[Iris] Événement WebSocket inconnu :', event.type);
    }
}

// ──── Stop / Reset helpers ────

const SEND_ICON_SVG = '<svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2.25"><path stroke-linecap="round" stroke-linejoin="round" d="M6 12L3.269 3.126A59.768 59.768 0 0121.485 12 59.77 59.77 0 013.27 20.876L5.999 12zm0 0h7.5"/></svg>';
const STOP_ICON_SVG = '<svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><rect x="4" y="4" width="16" height="16" rx="2"/></svg>';

// Task #12 — Tracker des uploads en cours. Quand au moins un fetch
// d'upload (PC ou datastore) est en vol, ``_uploadInFlight = true``
// désactive ``sendBtn`` (mode send seulement, le mode stop reste
// fonctionnel pour annuler un message déjà en traitement). Évite la
// race condition F6 du brainstorm initial : user clique Envoyer
// pendant que l'upload est encore en fetch → message partait sans le
// file_id (pas encore setté dans ``dataset.fileId``).
var _uploadInFlight = false;

function _setUploadInFlight(flag) {
    _uploadInFlight = !!flag;
    if (!sendBtn) return;
    // Ne JAMAIS interférer avec le mode 'stop' (agent en cours de
    // traitement). L'upload se fait alors en background, le bouton
    // reste fonctionnel pour annuler le tour Iris en cours.
    if (sendBtn.classList.contains('stop-mode')) return;
    sendBtn.disabled = _uploadInFlight;
}

function setSendButtonMode(mode) {
    if (!sendBtn) return;
    if (mode === 'stop') {
        sendBtn.innerHTML = STOP_ICON_SVG;
        sendBtn.classList.add('stop-mode');
        sendBtn.disabled = false;
        sendBtn.setAttribute('aria-label', 'Arrêter');
    } else {
        sendBtn.innerHTML = SEND_ICON_SVG;
        sendBtn.classList.remove('stop-mode');
        sendBtn.setAttribute('aria-label', 'Envoyer');
        // Task #12 — si un upload est encore en vol au moment du retour
        // en mode send (ex: réponse Iris reçue mais l'user a empilé un
        // nouvel upload), respecte l'état upload pour ne pas permettre
        // un envoi prématuré.
        sendBtn.disabled = _uploadInFlight;
    }
}

function resetAfterResponse() {
    currentStreamDiv = null;
    isStreaming = false;
    try { window.__irisStreamingActive = false; } catch (e) { /* defensive */ }
    // Le widget plan_update est scopé au turn courant — null la référence
    // pour que le prochain turn créé un widget neuf dans sa propre bulle
    // assistant. Le DOM du widget précédent reste visible dans la
    // conversation (l'utilisateur peut scroller pour le revoir).
    resetPlanGroup();
    const inputWrapper = document.querySelector('.iris-input-wrapper');
    if (inputWrapper) inputWrapper.classList.remove('processing');
    setSendButtonMode('send');
    // Task #12 — respecte l'état upload : si un fichier est en cours
    // d'upload pendant le retour de réponse, le bouton reste disabled
    // jusqu'à la fin du fetch. setSendButtonMode('send') applique déjà
    // cette logique mais on garde le pattern d'origine en explicite.
    if (sendBtn) sendBtn.disabled = _uploadInFlight;
    if (messageInput) {
        messageInput.disabled = false;
        messageInput.focus();
    }
}

/**
 * Affiche la progression du sync schéma directement dans le chat.
 * Désactive l'input pendant le sync, affiche une barre de progression
 * avec estimation du temps et bouton annuler.
 */
/** @type {EventSource|null} SSE connexion pour le sync en cours */
var _syncSSE = null;

/**
 * Ouvre le picker de fichiers du datastore.
 * Charge la liste via /api/datastore et affiche les fichiers compatibles.
 */
var _datastoreCurrentPath = '';

// Task #14 — Datastore picker = vrai modal a11y.
// _openDatastorePicker / _closeDatastorePicker délèguent à OverlayManager
// (chargé via base.html) qui fournit Escape, focus trap, et restoration
// du focus à l'opener. Le click outside est géré séparément (handler
// mousedown qui ferme si le clic est hors du picker ET hors du bouton
// trombone qui l'a ouvert).
function _closeDatastorePicker() {
    var picker = document.getElementById('datastorePicker');
    if (!picker) return;
    picker.style.display = 'none';
    if (window.OverlayManager && typeof window.OverlayManager.close === 'function') {
        try { window.OverlayManager.close(picker); } catch (_) { /* defensive */ }
    }
}

async function _openDatastorePicker(path) {
    var picker = document.getElementById('datastorePicker');
    var list = document.getElementById('datastorePickerList');
    if (!picker || !list) return;

    picker.style.display = 'block';
    _datastoreCurrentPath = path || '';
    list.innerHTML = '<p class="text-xs text-gray-400 p-3 dark:text-gray-500">Chargement...</p>';

    // Task #14 — Délègue à OverlayManager pour Escape + focus trap +
    // restoration du focus à l'opener (le bouton trombone). Sans ce
    // helper, le picker était un div statique sans aucun comportement
    // modal — l'user clavier ne pouvait ni naviguer correctement, ni
    // revenir au bouton trombone après fermeture.
    if (window.OverlayManager && typeof window.OverlayManager.open === 'function') {
        try {
            window.OverlayManager.open(picker, {
                layer: 'modal',
                lockScroll: false,  // picker compact, pas besoin de lock du scroll de la page
                trapFocus: true,
                inertSiblings: false,
                onClose: function() { picker.style.display = 'none'; },
            });
        } catch (_) { /* defensive — OverlayManager peut ne pas être prêt */ }
    }

    try {
        var url = '/api/datastore';
        if (_datastoreCurrentPath) url += '?path=' + encodeURIComponent(_datastoreCurrentPath);
        var res = await fetch(url, {
            headers: { 'X-Xsrftoken': getCookie('_xsrf') }
        });
        var data = await res.json();
        if (!data.success || !data.items) {
            list.innerHTML = '<p class="text-xs text-gray-400 p-3 dark:text-gray-500">Aucun fichier</p>';
            return;
        }

        // SSoT — Task #11 : extensions autorisées dérivées du backend via
        // IRIS_CONFIG.uploadConfig (injecté par IrisPageHandler). Si la
        // config est absente (cas dégradé/rendering partiel), on bascule
        // sur un tableau vide qui désactive tout filtrage JS — le backend
        // reste de toute façon la dernière garde via _UploadValidator.
        var _ucfg = (window.IRIS_CONFIG && window.IRIS_CONFIG.uploadConfig) || null;
        var allowed = (_ucfg && Array.isArray(_ucfg.extensions)) ? _ucfg.extensions : [];
        if (!_ucfg) {
            console.warn('[Iris] IRIS_CONFIG.uploadConfig absent — filtrage datastore désactivé, le backend valide quand même.');
        }
        list.innerHTML = '';

        // Bouton retour si on est dans un sous-dossier
        if (_datastoreCurrentPath) {
            var backBtn = document.createElement('button');
            backBtn.className = 'iris-datastore-file';
            backBtn.innerHTML = '<span>⬅ ..</span>';
            backBtn.addEventListener('click', function() {
                var parent = _datastoreCurrentPath.split('/').slice(0, -1).join('/');
                _openDatastorePicker(parent);
            });
            list.appendChild(backBtn);
        }

        // Afficher dossiers puis fichiers
        data.items.forEach(function(f) {
            if (f.is_dir) {
                var dirBtn = document.createElement('button');
                dirBtn.className = 'iris-datastore-file';
                dirBtn.innerHTML = '<span><i class="bi bi-folder"></i> ' + escapeHtml(f.name) + '</span>';
                dirBtn.addEventListener('click', function() {
                    _openDatastorePicker(f.path || f.name);
                });
                list.appendChild(dirBtn);
            } else {
                var ext = (f.name || '').toLowerCase();
                var isAllowed = allowed.some(function(e) { return ext.endsWith(e); });
                if (!isAllowed) return;

                var fileBtn = document.createElement('button');
                fileBtn.className = 'iris-datastore-file';
                var sizeKb = f.size ? Math.round(f.size / 1024) : 0;
                fileBtn.innerHTML = '<span>' + escapeHtml(f.name) + '</span><span class="size">' + sizeKb + ' Ko</span>';
                fileBtn.addEventListener('click', function() {
                    _selectDatastoreFile(f.path || f.name, f.name);
                    picker.style.display = 'none';
                });
                list.appendChild(fileBtn);
            }
        });

        if (list.children.length === 0 || (list.children.length === 1 && _datastoreCurrentPath)) {
            var empty = document.createElement('p');
            empty.className = 'text-xs text-gray-400 p-3';
            empty.textContent = 'Aucun fichier compatible dans ce dossier';
            list.appendChild(empty);
        }
    } catch (err) {
        list.innerHTML = '<p class="text-xs text-red-400 p-3">Erreur de chargement</p>';
    }
}

// ─────────────────────────────────────────────────────────────────────
// Task #10 — Helpers d'attachement de fichier
// ─────────────────────────────────────────────────────────────────────
// Centralise la création + le rendu de l'``uploadIndicator`` (avec son
// bouton croix de retrait) pour les deux flows : upload PC (création
// dynamique appendée aux messages) ET upload depuis le datastore
// (remplit le div ``#uploadPreview`` statique sous la textarea). Sans
// ces helpers, chaque flow re-définissait son innerHTML à la main et
// le bouton ``.iris-upload-remove`` (CSS présent) n'était jamais branché.

/**
 * Remplit ``container`` avec un indicateur d'attachement complet :
 * icône trombone, label fichier + statut, bouton croix de retrait.
 *
 * Reset entièrement le contenu du container et ses classes status.
 * Le bouton croix appelle ``_clearAttachment(container)`` au clic.
 *
 * @param {HTMLElement} container - l'élément hôte (div existant).
 * @param {string} fileName - nom du fichier à afficher.
 * @param {string} statusText - texte de statut ("envoi en cours…", "✓ prêt", "✗ erreur").
 * @param {?string} statusClass - classe optionnelle: "success" | "error" | null.
 */
function _renderUploadIndicatorInto(container, fileName, statusText, statusClass) {
    if (!container) return;
    while (container.firstChild) container.removeChild(container.firstChild);
    container.className = 'iris-upload-indicator' + (statusClass ? ' ' + statusClass : '');
    container.style.display = 'flex';

    // Task #19 — accessibilité lecteurs d'écran : annonce les
    // changements de statut (envoi en cours / prêt / erreur). On
    // choisit dynamiquement :
    // - role="alert" + aria-live="assertive" pour les erreurs (urgent,
    //   interrompt la lecture en cours).
    // - role="status" + aria-live="polite" pour loading / success
    //   (informatif, attendre une pause naturelle).
    // ``aria-atomic="true"`` indique que le contenu doit être lu
    // complètement à chaque changement (pas juste le delta).
    var isError = statusClass === 'error';
    container.setAttribute('role', isError ? 'alert' : 'status');
    container.setAttribute('aria-live', isError ? 'assertive' : 'polite');
    container.setAttribute('aria-atomic', 'true');

    var icon = document.createElement('i');
    icon.className = 'bi bi-paperclip';
    icon.setAttribute('aria-hidden', 'true');  // décoratif, redondant avec le label
    container.appendChild(icon);

    var label = document.createElement('span');
    label.className = 'iris-upload-label';
    label.textContent = fileName + ' — ' + statusText;
    container.appendChild(label);

    var removeBtn = document.createElement('button');
    removeBtn.type = 'button';
    removeBtn.className = 'iris-upload-remove';
    removeBtn.title = 'Retirer le fichier';
    removeBtn.setAttribute('aria-label', 'Retirer le fichier joint');
    removeBtn.textContent = '✕';  // ✕
    removeBtn.addEventListener('click', function(e) {
        e.stopPropagation();
        // MED-8 — notifie le backend pour supprimer le fichier disque
        // immédiatement. L'utilisateur abandonne — pas besoin d'attendre
        // le TTL 30j pour libérer l'espace.
        _clearAttachment(container, { notifyBackend: true });
    });
    container.appendChild(removeBtn);
}

// ─────────────────────────────────────────────────────────────────────
// Task #33 / #8 Phase 1 — Affichage CSV en grille inline iris-sql-card
// ─────────────────────────────────────────────────────────────────────
// Parsing CSV côté navigateur (RFC 4180 + auto-détection du séparateur
// pour cabinets français Excel = ``;``). Le résultat est rendu via
// ``GridTabManager.addTab`` exactement comme une grille de résultats
// SQL — l'utilisateur voit son CSV en triable, filtrable, exportable.
// Cf. brainstorm review F26 : avant ce fix, seuls les .afz.json
// avaient ce traitement, les CSV n'étaient qu'un texte « ✓ prêt ».

/**
 * Détecte le séparateur de champs d'un CSV en analysant la première
 * ligne (par fréquence). Couvre les 3 séparateurs réels :
 * - ``,`` : standard international
 * - ``;`` : standard Excel sur OS Windows en locale FR (cabinets français)
 * - ``\t`` : TSV
 *
 * Le test se fait sur les 16 premières lignes pour limiter les fausses
 * détections sur un CSV qui contient des virgules dans le titre.
 *
 * @param {string} text - le contenu CSV.
 * @returns {string} le séparateur le plus fréquent (défaut ``,``).
 */
function _detectCsvSeparator(text) {
    if (!text) return ',';
    // Échantillon : 16 premières lignes ou 8 Ko, plus court des deux
    var sample = text.slice(0, Math.min(text.length, 8 * 1024));
    var lines = sample.split(/\r?\n/).slice(0, 16);
    var counts = { ',': 0, ';': 0, '\t': 0 };
    // On compte les occurrences en moyenne par ligne (les séparateurs
    // doivent être répétés ~constant par ligne, contrairement à des
    // virgules accidentelles dans un titre)
    var nonEmpty = 0;
    for (var i = 0; i < lines.length; i++) {
        if (!lines[i]) continue;
        nonEmpty++;
        for (var sep in counts) {
            if (Object.prototype.hasOwnProperty.call(counts, sep)) {
                // Approche simple : on compte hors quotes pour éviter de
                // confondre une virgule dans un champ ``"a,b"``.
                var inQuotes = false;
                for (var j = 0; j < lines[i].length; j++) {
                    var c = lines[i][j];
                    if (c === '"') inQuotes = !inQuotes;
                    else if (!inQuotes && c === sep) counts[sep]++;
                }
            }
        }
    }
    // Retourne le séparateur le plus fréquent (>= 1 par ligne en moyenne)
    var best = ',';
    var bestCount = 0;
    for (var s in counts) {
        if (Object.prototype.hasOwnProperty.call(counts, s) && counts[s] > bestCount) {
            bestCount = counts[s];
            best = s;
        }
    }
    // Si aucun séparateur trouvé en quantité raisonnable, défaut ``,``
    return bestCount >= Math.max(1, nonEmpty - 1) ? best : ',';
}

/**
 * Parse un CSV RFC 4180 en JS natif. Gère :
 * - Quotes doubles (``"a,b"`` → champ contenant ``a,b``)
 * - Quote escape (``"a""b"`` → ``a"b``)
 * - Newlines dans les champs entre quotes (multi-line cells)
 * - ``\r\n`` et ``\n`` comme line endings
 *
 * @param {string} text - le contenu CSV.
 * @param {?string} separator - séparateur explicite (auto-détecté si null).
 * @returns {{columns: string[], rows: any[][], separator: string}}
 */
function _parseCsv(text, separator) {
    var sep = separator || _detectCsvSeparator(text);
    var rows = [];
    var currentRow = [];
    var currentField = '';
    var inQuotes = false;
    var i = 0;
    var len = text.length;

    while (i < len) {
        var c = text[i];
        if (inQuotes) {
            if (c === '"') {
                if (i + 1 < len && text[i + 1] === '"') {
                    // Quote échappée
                    currentField += '"';
                    i += 2;
                    continue;
                }
                inQuotes = false;
                i++;
                continue;
            }
            currentField += c;
            i++;
        } else {
            if (c === '"') {
                // Quote ouvrante : commence un champ quoté (on accepte
                // aussi les quotes en milieu de champ pour tolérance)
                inQuotes = true;
                i++;
            } else if (c === sep) {
                currentRow.push(currentField);
                currentField = '';
                i++;
            } else if (c === '\n') {
                currentRow.push(currentField);
                rows.push(currentRow);
                currentField = '';
                currentRow = [];
                i++;
            } else if (c === '\r') {
                // Skip standalone \r (ou partie de \r\n traité au \n suivant)
                i++;
            } else {
                currentField += c;
                i++;
            }
        }
    }
    // Dernier champ + dernière ligne (si pas de newline final)
    if (currentField !== '' || currentRow.length > 0) {
        currentRow.push(currentField);
        rows.push(currentRow);
    }

    // 1ère ligne = headers. Si rows est vide après filtrage, columns vide.
    var columns = [];
    var dataRows = [];
    if (rows.length > 0) {
        columns = rows[0].map(function(c) { return String(c || ''); });
        dataRows = rows.slice(1);
    }
    return { columns: columns, rows: dataRows, separator: sep };
}

/**
 * Affiche un fichier CSV dans une carte iris-sql-card inline (parity
 * avec le pattern .afz.json). Lit le fichier via FileReader, parse via
 * ``_parseCsv``, crée une grille interactive via ``GridTabManager``.
 *
 * **Encoding** : FileReader.readAsText utilise UTF-8 par défaut. Pour
 * un cabinet français exportant depuis Excel Windows (cp1252), les
 * accents passeront mal — la grille affichera ``Fran?ois`` côté UI.
 * Le fix complet d'encoding (Task #25) couvre la lecture côté backend
 * (analyze_attachment) mais pas FileReader côté navigateur ; la
 * détection cp1252 navigateur nécessite TextDecoder + ArrayBuffer.
 * Reportée en backlog du fait que la majorité des exports modernes
 * (Excel macOS, Google Sheets, exports SaaS) sont en UTF-8.
 *
 * @param {File} file - le fichier CSV à afficher.
 * @returns {Promise<void>}
 */
async function _displayXlsxInGrid(fileId, fileName) {
    // Task #34 / #8 Phase 2 — Affichage XLSX/XLS inline via endpoint
    // backend pandas (alternative à SheetJS ~500 KB côté client).
    //
    // Appelé APRÈS upload success (file_id obtenu). Le backend charge
    // le fichier depuis _UPLOAD_DIR, parse via pandas multi-sheets et
    // retourne {tabs: [{name, columns, rows, row_count, truncated_rows,
    // truncated_cols}]}. Chaque onglet pandas devient un tab de
    // GridTabManager (cohérent avec le pattern .afz.json multi-tabs).
    //
    // Best-effort : si l'endpoint échoue (5xx, fichier corrompu),
    // on log un warning et on continue — l'user verra juste « ✓ prêt »
    // comme avant Task #34, pas de régression.
    if (typeof GridTabManager === 'undefined') {
        console.warn('[Iris] GridTabManager indisponible, skip XLSX inline render.');
        return;
    }
    var response;
    try {
        response = await fetch('/api/iris/parse-attachment', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Xsrftoken': getCookie('_xsrf'),
            },
            body: JSON.stringify({ file_id: fileId }),
        });
    } catch (netErr) {
        console.warn('[Iris] /api/iris/parse-attachment network error:', netErr);
        return;
    }
    if (!response.ok) {
        console.warn(
            '[Iris] /api/iris/parse-attachment status=' + response.status
            + ' fileId=' + fileId
        );
        return;
    }
    var data;
    try {
        data = await response.json();
    } catch (jsonErr) {
        console.warn('[Iris] parse-attachment JSON invalide:', jsonErr);
        return;
    }
    if (!data || !data.success || !Array.isArray(data.tabs) || data.tabs.length === 0) {
        console.warn(
            '[Iris] parse-attachment vide ou échoué :',
            data && data.error ? data.error : '(no data)'
        );
        return;
    }

    var card = document.createElement('div');
    card.className = 'iris-sql-card';
    var tabMgr = new GridTabManager(card);
    for (var i = 0; i < data.tabs.length; i++) {
        var tab = data.tabs[i];
        // Sanitize defensif — robustesse à un payload partiel
        var label = (typeof tab.name === 'string' && tab.name)
            ? tab.name
            : (fileName + ' — onglet ' + (i + 1));
        var cols = Array.isArray(tab.columns) ? tab.columns : [];
        var rows = Array.isArray(tab.rows) ? tab.rows : [];
        var rowCount = (typeof tab.row_count === 'number') ? tab.row_count : rows.length;
        // 1er tab non-closable (au moins 1 tab toujours présent)
        tabMgr.addTab(label, cols, rows, null, rowCount, null, i > 0);
    }
    appendToMessages(card);
    scrollToBottom();
}


function _displayCsvInGrid(file) {
    return new Promise(function(resolve) {
        if (typeof GridTabManager === 'undefined') {
            console.warn('[Iris] GridTabManager indisponible, skip rendu CSV inline.');
            resolve();
            return;
        }
        var reader = new FileReader();
        reader.onload = function(ev) {
            try {
                var text = ev.target.result || '';
                var parsed = _parseCsv(text);
                if (parsed.columns.length === 0 && parsed.rows.length === 0) {
                    console.warn('[Iris] CSV vide ou non-parseable, skip rendu.');
                    resolve();
                    return;
                }
                // Si les rows ont moins de cellules que les columns
                // (ligne tronquée), pad avec ''. Si plus, addTab gère.
                var nCols = parsed.columns.length;
                var paddedRows = parsed.rows.map(function(r) {
                    if (r.length === nCols) return r;
                    if (r.length < nCols) {
                        var padded = r.slice();
                        while (padded.length < nCols) padded.push('');
                        return padded;
                    }
                    return r.slice(0, nCols);  // truncate si plus long
                });

                var card = document.createElement('div');
                card.className = 'iris-sql-card';
                var tabMgr = new GridTabManager(card);
                tabMgr.addTab(
                    file.name,           // label = nom du fichier
                    parsed.columns,      // columns string[]
                    paddedRows,          // rows array of arrays
                    null,                // sql (pas de SQL pour CSV)
                    paddedRows.length,   // rowCount
                    null,                // metadata
                    false                // closable=false (1er tab non fermable)
                );
                appendToMessages(card);
                scrollToBottom();

                // Task #42a (cycle #29) — calcule les stats agrégées
                // depuis le navigateur (building block pour la bascule
                // éphémère future #42b/#42c). Stocké sur le card pour
                // que le flow upload puisse les passer au backend en
                // tant que metadata enrichie quand le flag IRIS_EPHEMERAL_MODE
                // sera activé. Pour l'instant : log debug only.
                try {
                    if (window.IrisStatsAggregator) {
                        var _stats = window.IrisStatsAggregator.aggregate({
                            columns: parsed.columns,
                            rows: paddedRows,
                        });
                        card.dataset.statsPayload = JSON.stringify(_stats);
                        if (window.IRIS_DEBUG) {
                            console.debug('[Iris #42a] Stats CSV agrégées', _stats);
                        }
                    }
                } catch (statsErr) {
                    // Best-effort — un échec de stats ne casse pas l'UX
                    console.warn('[Iris #42a] Stats aggregation failed', statsErr);
                }
            } catch (err) {
                console.error('[Iris] CSV parse error:', err);
                addErrorMessage('Erreur de lecture du CSV : ' + (err.message || err));
            }
            resolve();
        };
        reader.onerror = function() {
            console.error('[Iris] FileReader error pour CSV', file.name);
            resolve();
        };
        reader.readAsText(file, 'utf-8');
    });
}


/**
 * Task #23 — Upload XHR avec progress reporting.
 *
 * ``fetch()`` ne supporte pas nativement le progress côté upload (sauf
 * via ``ReadableStream`` complexe). On utilise XHR pour pouvoir afficher
 * un pourcentage pendant les gros uploads (Excel 5+ Mo qui prennent du
 * temps sur connexions lentes).
 *
 * Préserve l'interface du fetch d'origine :
 * - POST /api/iris/upload avec FormData
 * - XSRF header (X-Xsrftoken)
 * - Status >= 400 → Error avec .status et .message (compat _addUploadErrorWithReport)
 *
 * @param {File} file - fichier à uploader
 * @param {?function} onProgress - callback(fraction 0..1) appelé périodiquement
 * @returns {Promise<{success: boolean, file_id?: string, ...}>}
 */
function _uploadFileToBackend(file, onProgress) {
    return new Promise(function(resolve, reject) {
        var xhr = new XMLHttpRequest();
        // Progress côté upload (l'event ``progress`` global de XHR
        // concerne le download — c'est ``xhr.upload.onprogress`` pour
        // l'upload côté navigateur → serveur).
        if (typeof onProgress === 'function' && xhr.upload) {
            xhr.upload.onprogress = function(e) {
                if (e && e.lengthComputable && e.total > 0) {
                    var frac = e.loaded / e.total;
                    // Clamp défensif [0, 1] (certains navigateurs ont
                    // des micro-overshoots à 1.001 sur le dernier event)
                    if (frac < 0) frac = 0;
                    if (frac > 1) frac = 1;
                    try { onProgress(frac); } catch (_) { /* defensive */ }
                }
            };
        }
        xhr.onload = function() {
            // Parse JSON best-effort (le backend retourne TOUJOURS du
            // JSON, mais on tolère un body non-JSON pour ne pas crash).
            var bodyText = xhr.responseText || '';
            var bodyData = null;
            try { bodyData = JSON.parse(bodyText); } catch (_) { bodyData = null; }

            if (xhr.status >= 200 && xhr.status < 300) {
                resolve(bodyData || {});
            } else {
                // Compat _addUploadErrorWithReport (Task #15) :
                // err.status pour distinguer 4xx vs 5xx, err.message
                // pour afficher le message backend si fourni.
                var httpErr = new Error('Upload failed');
                httpErr.status = xhr.status;
                if (bodyData && typeof bodyData.error === 'string') {
                    httpErr.message = bodyData.error;
                }
                reject(httpErr);
            }
        };
        xhr.onerror = function() {
            // Erreur réseau (offline, CORS, etc.) — pas de status HTTP
            // disponible, _addUploadErrorWithReport classera comme
            // network-failure → Signaler activé.
            var netErr = new Error('Network error');
            netErr.status = 0;
            reject(netErr);
        };
        xhr.ontimeout = function() {
            var toErr = new Error('Upload timeout');
            toErr.status = 0;
            reject(toErr);
        };

        xhr.open('POST', '/api/iris/upload');
        xhr.setRequestHeader('X-Xsrftoken', getCookie('_xsrf'));
        // Pas de Content-Type — laisser le navigateur le setter avec
        // la boundary multipart correcte pour FormData.

        var formData = new FormData();
        formData.append('file', file);
        xhr.send(formData);
    });
}


/**
 * Crée un nouvel élément ``div.iris-upload-indicator`` autonome (pour
 * le flow PC upload qui appende le node à ``appendToMessages``).
 */
function _createUploadIndicator(fileName, statusText, statusClass) {
    var div = document.createElement('div');
    _renderUploadIndicatorInto(div, fileName, statusText, statusClass);
    return div;
}

/**
 * Trouve l'indicateur d'attachement actif (le plus récent avec un
 * ``dataset.fileId`` rempli). Couvre les deux flows :
 * - PC upload : ``.iris-upload-indicator`` créé par ``_createUploadIndicator``
 *   et appended aux messages.
 * - Datastore : ``#uploadPreview`` transformé en ``.iris-upload-indicator``
 *   par ``_renderUploadIndicatorInto``.
 *
 * **Fix critique Task #13** — l'ancien code lisait
 * ``getElementById('uploadIndicator')`` (3 occurrences) qui retournait
 * TOUJOURS null car aucun élément ne portait cet id (le static est
 * ``#uploadPreview``, les dynamiques n'avaient pas d'id). Conséquence :
 * ``payload.file_id`` n'arrivait JAMAIS au backend → toute la feature
 * trombone était cassée à la racine. Vérifié par grep négatif :
 * ``id="uploadIndicator"`` n'apparaît nulle part dans le template ni
 * dans le JS au moment du fix.
 */
function _getActiveAttachmentIndicator() {
    var candidates = document.querySelectorAll('.iris-upload-indicator');
    for (var i = candidates.length - 1; i >= 0; i--) {
        var c = candidates[i];
        if (c && c.dataset && c.dataset.fileId) {
            return c;
        }
    }
    return null;
}

/**
 * Task #42c (cycle #31) — récupère le dernier ``iris-sql-card`` avec un
 * ``statsPayload`` pré-calculé par ``_displayCsvInGrid`` (#42a).
 *
 * Symétrique de ``_getActiveAttachmentIndicator`` mais pour la bascule
 * éphémère : on cherche la grille la plus récente qui contient les
 * stats agrégées, prêtes à être envoyées via WS au backend (#42b).
 *
 * Returns:
 *   HTMLElement|null - le ``.iris-sql-card`` avec ``dataset.statsPayload``,
 *   ou null si aucun.
 */
function _findStatsPayloadCard() {
    var cards = document.querySelectorAll('.iris-sql-card');
    for (var i = cards.length - 1; i >= 0; i--) {
        var c = cards[i];
        if (c && c.dataset && c.dataset.statsPayload) {
            return c;
        }
    }
    return null;
}

/**
 * Retire l'attachement courant : reset ``dataset.fileId``, vide le
 * messageInput si auto-rempli avec « Analyse ce fichier : … », reset
 * ``fileInput.value`` pour permettre de re-uploader le même fichier,
 * et retire/cache l'indicateur du DOM (cache si #uploadPreview statique,
 * remove sinon).
 */
function _clearAttachment(indicator, options) {
    if (!indicator) return;
    // MED-8 fix 2026-05-26 — notifyBackend (option) supprime le fichier
    // côté serveur si l'user abandonne avant d'envoyer. Par défaut faux
    // car appelé aussi APRÈS envoi (le LLM doit pouvoir lire le fichier).
    var opts = options || {};
    var notifyBackend = !!opts.notifyBackend;
    var fileId = indicator.dataset && indicator.dataset.fileId;
    if (notifyBackend && fileId && /^[0-9a-f-]{36}$/.test(fileId)) {
        // Best-effort — on n'attend pas le résultat. Si le call échoue
        // (5xx, réseau down, etc.), le TTL nettoiera plus tard.
        try {
            var csrfToken = (typeof getCookie === 'function')
                ? getCookie('_xsrf') : '';
            fetch('/api/iris/upload/cancel', {
                method: 'POST',
                credentials: 'same-origin',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Xsrftoken': csrfToken || ''
                },
                body: JSON.stringify({ file_id: fileId })
            }).catch(function() { /* silent best-effort */ });
        } catch (e) { /* silent */ }
    }
    indicator.dataset.fileId = '';
    var msgInput = document.getElementById('messageInput');
    if (msgInput && /^Analyse ce fichier\s*:/.test(msgInput.value)) {
        msgInput.value = '';
        // Trigger input event pour que tout listener de validation
        // (longueur min, bouton Envoyer disabled, etc.) se re-évalue.
        msgInput.dispatchEvent(new Event('input', { bubbles: true }));
    }
    var fileInput = document.getElementById('fileInput');
    if (fileInput) fileInput.value = '';
    // #uploadPreview est un div statique du template qu'on cache au lieu de remove.
    // Les indicateurs créés dynamiquement (PC upload appendToMessages) sont removed.
    if (indicator.id === 'uploadPreview') {
        indicator.style.display = 'none';
        while (indicator.firstChild) indicator.removeChild(indicator.firstChild);
    } else if (indicator.parentNode) {
        indicator.parentNode.removeChild(indicator);
    }
}


/**
 * Sélectionne un fichier du datastore : le copie vers les uploads puis l'attache au message.
 */
async function _selectDatastoreFile(filePath, fileName) {
    // Le datastore picker remplit le div statique ``#uploadPreview`` du
    // template. (L'ancien fallback ``getElementById('uploadIndicator')``
    // était mort car aucun élément n'a jamais porté cet id — cf. fix
    // Task #13 et helper ``_getActiveAttachmentIndicator``.)
    var uploadIndicator = document.getElementById('uploadPreview');
    if (uploadIndicator) {
        _renderUploadIndicatorInto(uploadIndicator, fileName, 'chargement...', null);
    }
    // Task #12 — bloque sendBtn pendant le double fetch (download
    // datastore puis upload Iris). Sans ça, l'user pourrait cliquer
    // Envoyer avant que dataset.fileId soit setté → file_id manquant.
    _setUploadInFlight(true);

    try {
        // Télécharger le fichier depuis le datastore
        var dlRes = await fetch('/api/datastore/download?path=' + encodeURIComponent(filePath), {
            headers: { 'X-Xsrftoken': getCookie('_xsrf') }
        });
        if (!dlRes.ok) throw new Error('Téléchargement échoué');

        var blob = await dlRes.blob();
        var formData = new FormData();
        formData.append('file', blob, fileName);

        // Re-uploader vers l'endpoint iris upload pour obtenir un file_id
        var upRes = await fetch('/api/iris/upload', {
            method: 'POST',
            headers: { 'X-Xsrftoken': getCookie('_xsrf') },
            body: formData,
        });
        var data = await upRes.json();

        if (data.success && data.file_id) {
            if (uploadIndicator) {
                _renderUploadIndicatorInto(uploadIndicator, fileName, '✓ prêt', 'success');
                uploadIndicator.dataset.fileId = data.file_id;
            }
            if (messageInput && !messageInput.value.trim()) {
                messageInput.value = 'Analyse ce fichier : ' + fileName;
            }
            messageInput.focus();
        } else {
            throw new Error(data.error || 'Upload échoué');
        }
    } catch (err) {
        if (uploadIndicator) {
            _renderUploadIndicatorInto(uploadIndicator, fileName, '✗ erreur', 'error');
        }
        // Task #15 — message + Signaler conditionnel (5xx/réseau).
        // Le flow datastore fait 2 fetches (download + upload), donc
        // l'erreur peut venir de l'une ou l'autre — on remonte le tout.
        _addUploadErrorWithReport(err, fileName, 'iris_upload_datastore');
    } finally {
        // Task #12 — réactive sendBtn quoi qu'il arrive (success,
        // erreur download, erreur upload, exception parsing). Garantit
        // qu'un échec datastore ne laisse pas le bouton bloqué.
        _setUploadInFlight(false);
    }
}

function _startSyncInChat() {
    // Désactiver l'input
    if (messageInput) messageInput.disabled = true;
    if (sendBtn) sendBtn.disabled = true;

    // Créer la bulle de progression dans le chat
    var row = document.createElement('div');
    row.className = 'iris-message-row assistant';
    row.innerHTML =
        '<div class="iris-avatar">' +
            '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4"/></svg>' +
        '</div>' +
        '<div class="iris-message assistant" id="syncChatBubble">' +
            '<div style="min-width:320px">' +
                '<div class="flex items-center gap-2 mb-2">' +
                    '<svg class="w-4 h-4 text-brand-600 animate-spin" id="syncChatSpinner" fill="none" viewBox="0 0 24 24">' +
                        '<circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"/>' +
                        '<path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/>' +
                    '</svg>' +
                    '<span class="text-sm font-medium text-gray-900 dark:text-gray-100" id="syncChatTitle">Synchronisation du schéma</span>' +
                '</div>' +
                '<p class="text-sm text-gray-600 mb-2 dark:text-gray-400" id="syncChatMsg">Connexion à SQL Server...</p>' +
                '<div class="w-full bg-gray-200 rounded-full h-2 mb-1">' +
                    '<div id="syncChatBar" class="bg-brand-600 h-2 rounded-full transition-all duration-500" style="width:0%"></div>' +
                '</div>' +
                '<div class="flex items-center justify-between">' +
                    '<span class="text-xs text-gray-400 dark:text-gray-500" id="syncChatEta">~10 secondes</span>' +
                    '<button id="syncChatCancel" class="text-xs text-red-500 hover:text-red-700 font-medium dark:text-red-400">Annuler</button>' +
                '</div>' +
            '</div>' +
        '</div>';

    var area = document.getElementById('messagesArea');
    if (area) {
        area.appendChild(row);
        scrollToBottom();
    }

    var barEl = document.getElementById('syncChatBar');
    var msgEl = document.getElementById('syncChatMsg');
    var etaEl = document.getElementById('syncChatEta');
    var cancelEl = document.getElementById('syncChatCancel');
    var spinnerEl = document.getElementById('syncChatSpinner');
    var titleEl = document.getElementById('syncChatTitle');
    var startTime = Date.now();
    _syncSSE = new EventSource('/api/ai/schema/sync/stream');

    function formatDuration(seconds) {
        // Single source of truth : window.KomptiaFormat.durationSeconds.
        return window.KomptiaFormat.durationSeconds(seconds);
    }

    function updateEta(pct) {
        if (pct <= 5) return;
        var elapsed = (Date.now() - startTime) / 1000;
        var remaining = Math.max(0, (elapsed / pct) * (100 - pct));
        etaEl.textContent = formatDuration(remaining);
    }

    function finish(success, text) {
        if (_syncSSE) { _syncSSE.close(); _syncSSE = null; }
        if (spinnerEl) spinnerEl.classList.add('hidden');
        if (cancelEl) cancelEl.classList.add('hidden');
        if (barEl) barEl.style.width = '100%';
        if (etaEl) etaEl.textContent = '';
        if (titleEl) titleEl.textContent = success ? 'Synchronisation terminée' : 'Synchronisation échouée';
        if (msgEl) msgEl.textContent = text;
        if (!success && barEl) {
            barEl.classList.remove('bg-brand-600');
            barEl.classList.add('bg-red-500');
        }
        // Réactiver l'input
        if (messageInput) { messageInput.disabled = false; messageInput.focus(); }
        if (sendBtn) sendBtn.disabled = false;
    }

    _syncSSE.onmessage = function(e) {
        try {
            var d = JSON.parse(e.data);
            if (d.step === 'complete') {
                var r = d.result || {};
                var tables = r.tables_count || r.tables_synced || 0;
                var dur = (r.duration || 0).toFixed(1);
                finish(r.success !== false, tables + ' tables synchronisées en ' + dur + 's');
                return;
            }
            if (d.step === 'error') {
                finish(false, d.message || 'Erreur');
                return;
            }
            var pct = d.percent || 0;
            if (barEl) barEl.style.width = pct + '%';
            if (msgEl && d.message) msgEl.textContent = d.message;
            updateEta(pct);
        } catch(ex) {}
    };

    _syncSSE.onerror = function() {
        if (_syncSSE) { _syncSSE.close(); _syncSSE = null; }
        finish(false, 'Connexion perdue');
    };

    if (cancelEl) {
        cancelEl.addEventListener('click', function() {
            if (_syncSSE) { _syncSSE.close(); _syncSSE = null; }
            finish(false, 'Synchronisation annulée');
        });
    }
}

// Todo #38 — BroadcastChannel pour signaler le cancel aux autres onglets
// de la même conv (frontend MVP). Le vrai cross-WS cancel (un onglet
// cancel l'agent qui run sur la WS d'un autre onglet) demande un
// refactor backend (cancel_event partagé par conv_id, pas par WS) —
// out of scope MVP. Le BroadcastChannel ici garantit AU MOINS que
// l'UI des autres onglets reflète l'intention "cancel" (chaque onglet
// envoie cancel sur SA WS locale).
//
// API ES2015+ (Chrome 54+, FF 38+, Safari 15.4+) — fallback silencieux
// si non supporté (vieux navigateur).
var _irisCancelBus = null;
try {
    if (typeof BroadcastChannel !== 'undefined') {
        _irisCancelBus = new BroadcastChannel('iris-cancel-bus');
        _irisCancelBus.onmessage = function(event) {
            var data = event && event.data;
            if (!data || data.type !== 'iris-cancel') return;
            // Filtre par conversation : un cancel sur une autre conv ne
            // doit PAS canceller cette WS (chaque onglet sa propre conv).
            if (data.conversation_id !== currentConversationId) return;
            // Évite double-broadcast (loopback) : si CE onglet a émis,
            // ne pas re-réagir. ``event.target === _irisCancelBus`` est
            // tout le temps vrai côté listener — on filtre via tag.
            if (data._origin_tag && data._origin_tag === _irisCancelOriginTag) return;
            // Envoyer cancel sur NOTRE WS si elle a un run actif.
            if (ws && ws.readyState === WebSocket.OPEN && sendBtn
                && sendBtn.classList.contains('stop-mode')) {
                try { ws.send(JSON.stringify({ action: 'cancel' })); }
                catch (e) { /* defensive */ }
                try { window.__irisStreamingActive = false; } catch (e) { /* defensive */ }
            }
        };
    }
} catch (e) {
    _irisCancelBus = null;  /* navigateur sans BroadcastChannel — fallback OK */
}

// Tag unique par onglet pour filtrer son propre broadcast (anti-loopback).
var _irisCancelOriginTag = String(Date.now()) + '-' + Math.random().toString(36).slice(2);

function stopGeneration() {
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    if (!sendBtn || !sendBtn.classList.contains('stop-mode')) return;
    ws.send(JSON.stringify({ action: 'cancel' }));
    // L'utilisateur a explicitement abandonne le tour : on relache le
    // flag streaming sans attendre la confirmation serveur, sinon un
    // refresh juste apres "Stop" declencherait un warning beforeunload
    // alors que l'utilisateur a deja signifie qu'il abandonne. Le
    // serveur enverra ensuite text_complete/error qui passera par
    // ``resetAfterResponse`` et confirmera ce reset.
    try { window.__irisStreamingActive = false; } catch (e) { /* defensive */ }

    // Todo #38 — broadcast aux autres onglets de la même conv.
    if (_irisCancelBus) {
        try {
            _irisCancelBus.postMessage({
                type: 'iris-cancel',
                conversation_id: currentConversationId,
                _origin_tag: _irisCancelOriginTag,
            });
        } catch (e) { /* defensive */ }
    }
}

// ──── Sending ────

/**
 * Envoie le message saisi par l'utilisateur via WebSocket.
 * Appelé au clic sur le bouton envoi ou à la touche Entrée (sans Shift).
 */
/**
 * Retire le bandeau "run précédent interrompu" s'il est affiché. SSoT à appeler
 * dès qu'on relance la conversation, QUEL QUE SOIT le point d'entrée
 * (sendMessage, sendAutoFeedback, sendClarificationResponse). Avant (review
 * snapshot 20b8902, finding 8), le retrait n'était que dans sendMessage → en
 * reprenant via une carte de clarification/auto-feedback, le bandeau restait
 * affiché à tort.
 */
function _dismissInterruptedBanner() {
    var b = document.getElementById('irisInterruptedBanner');
    if (b) b.remove();
}

function sendMessage() {
    if (!messageInput) return;

    let text = messageInput.value.trim();

    // Task #13 — Accepter l'envoi avec un fichier attaché même si le
    // textarea est vide. Le backend rejette MESSAGE_EMPTY (iris.py:1424),
    // donc on substitue côté frontend un message par défaut explicite
    // qui s'affichera aussi dans le chat user pour traçabilité.
    // ``_getActiveAttachmentIndicator`` cherche partout dans le DOM (pas
    // de getElementById('uploadIndicator') cassé — cf. fix in-task).
    const _uploadIndicatorForSend = _getActiveAttachmentIndicator();
    const _hasAttachment = !!(_uploadIndicatorForSend
        && _uploadIndicatorForSend.dataset
        && _uploadIndicatorForSend.dataset.fileId);
    if (!text && _hasAttachment) {
        text = 'Analyse le fichier joint.';
    }
    if (!text) return;

    // Le bandeau "run précédent interrompu" (cf. _renderInterruptedRunBanner)
    // instruit l'utilisateur d'« envoyer un message pour reprendre ». Dès qu'il
    // le fait, on le retire — sinon il restait affiché indéfiniment : rien ne le
    // supprimait, il ne partait qu'à un refresh où le dernier event de la conv
    // était redevenu terminal. On le retire ici (après la validation de l'input,
    // donc seulement quand un message est réellement envoyé) — vaut aussi pour le
    // chemin "WS down → message mis en attente" ci-dessous : la reprise est lancée.
    _dismissInterruptedBanner();

    if (!ws || ws.readyState !== WebSocket.OPEN) {
        // Todo #36 — Au lieu de perdre le message tapé (l'user devait
        // retaper), on le stocke en localStorage (clé scopée user).
        // À la prochaine ``ws.onopen``, il est rejoué automatiquement.
        _savePendingMessage(text);
        addErrorMessage(
            'Connexion au serveur perdue. Ton message a été sauvegardé '
            + 'et sera renvoyé automatiquement dès la reconnexion.'
        );
        // Vider l'input pour donner le feedback visuel "message accepté"
        // (sinon l'user croit qu'il doit cliquer à nouveau).
        if (messageInput) {
            messageInput.value = '';
            try { messageInput.dispatchEvent(new Event('input')); } catch (e) {}
        }
        connectWebSocket();
        return;
    }

    // Reset step counter for new message
    toolStepCount = 0;
    // Reset flag feedback-auto (nouveau tour = nouveau contexte)
    _pendingExecuteSqlFeedback = false;

    // Marque le tour Iris comme actif DES MAINTENANT, sans attendre le
    // premier ``text_delta``. Sans ca, un long tour avec thinking +
    // tool_use sans texte ne declencherait pas le warning beforeunload
    // alors que c'est exactement le moment ou l'utilisateur perdrait
    // le tour. Le reset a ``false`` se fait dans ``resetAfterResponse``,
    // ``text_complete`` et au reset de conversation.
    try { window.__irisStreamingActive = true; } catch (e) { /* defensive */ }

    // Afficher le message utilisateur
    addUserMessage(text);

    // Masquer l'état de bienvenue
    if (welcomeState) welcomeState.style.display = 'none';

    // Afficher l'indicateur de frappe
    if (typingIndicator) typingIndicator.style.display = 'flex';

    // Désactiver l'input et afficher le bouton stop
    if (messageInput) messageInput.disabled = true;
    setSendButtonMode('stop');
    const inputWrapper = document.querySelector('.iris-input-wrapper');
    if (inputWrapper) inputWrapper.classList.add('processing');

    // Récupérer le file_id si un fichier est attaché
    var payload = {
        action: 'send_message',
        conversation_id: currentConversationId,
        message: text,
        mode: currentMode,
        // ``source: 'page'`` — discrimine la conv page ``/iris`` de celle
        // du floating widget côté backend (cf. ``ConversationSource``).
        source: 'page'
    };
    // Fix Task #13 — utilise _getActiveAttachmentIndicator au lieu de
    // getElementById('uploadIndicator') qui retournait TOUJOURS null
    // (aucun élément ne porte cet id). Sans ce fix, payload.file_id
    // n'était jamais setté → toute la feature trombone cassée.
    var uploadIndicator = _getActiveAttachmentIndicator();
    if (uploadIndicator && uploadIndicator.dataset.fileId) {
        // Task #42c (cycle #31) — bascule éphémère.
        // Si window.IRIS_CONFIG.ephemeral_mode est actif ET on a un
        // statsPayload pré-calculé (via #42a IrisStatsAggregator dans
        // _displayCsvInGrid), on envoie les stats au lieu du file_id.
        // Backend (#42b) accepte les 2 modes (file_id legacy reste
        // prioritaire si présent — mais on l'omet ici en mode éphémère).
        //
        // Default safe : ephemeral_mode = false → comportement legacy
        // inchangé. Le flag est testable via console (`window.IRIS_CONFIG.
        // ephemeral_mode = true`) pour preview interne. Future #56' :
        // exposer un toggle admin propre.
        var ephemeralMode = !!(
            window.IRIS_CONFIG && window.IRIS_CONFIG.ephemeral_mode
        );
        var statsCard = ephemeralMode
            ? _findStatsPayloadCard()
            : null;
        if (ephemeralMode && statsCard && statsCard.dataset.statsPayload) {
            try {
                payload.attachment_stats = JSON.parse(
                    statsCard.dataset.statsPayload
                );
                // Best-effort : ajouter le filename si disponible
                // (déduit du label du premier tab dans la grille).
                var label = statsCard.querySelector('.grid-tab-label, [data-tab-label]');
                if (label && label.textContent) {
                    payload.attachment_stats.filename = String(label.textContent).trim();
                }
                // NB : on N'ajoute PAS payload.file_id dans ce mode —
                // le fichier n'a même pas été uploadé au backend.
            } catch (statsParseErr) {
                console.warn(
                    '[Iris #42c] statsPayload invalide — fallback file_id',
                    statsParseErr
                );
                payload.file_id = uploadIndicator.dataset.fileId;
            }
        } else {
            payload.file_id = uploadIndicator.dataset.fileId;
        }
        // Clear l'indicateur après envoi (réutilise le helper Task #10
        // qui gère uniformément cache vs remove selon que c'est le div
        // statique #uploadPreview ou un node dynamique).
        _clearAttachment(uploadIndicator);
    }

    ws.send(JSON.stringify(payload));

    // Estimation live context-window : le message user va dans l'historique
    // pour le prochain appel LLM. Le ``context_progress`` post-appel
    // recalibrera avec la vraie valeur (cache + system prompt inclus).
    _cwAddEstimatedChars(text.length);

    // Vider et redimensionner l'input
    messageInput.value = '';
    messageInput.style.height = 'auto';
    // Le message est parti — on n'a plus besoin du draft sauvegardé.
    _clearDraft();

    scrollToBottom();
}

/**
 * Task #20 — Taxonomie unifiée des interactions question/réponse Iris.
 *
 * Le frontend reçoit aujourd'hui 5 « kinds » d'interactions, chacune avec son
 * propre type WS pour rétro-compat :
 *   - ``clarify_with_options`` : LLM Iris pose question + options cliquables.
 *     (type WS hérité : ``clarification``)
 *   - ``open_question``        : la pipeline NL→SQL pose une question libre
 *     (textfield obligatoire). (type WS hérité : ``pipeline_ask_user``)
 *   - ``consent``              : confirmation de lecture LLM des données SQL.
 *     (type WS hérité : ``data_read_consent_request``)
 *   - ``suggestions``          : 2-3 questions de suivi proposées.
 *     (type WS hérité : ``suggestions``)
 *   - ``feedback``             : carte auto-feedback post-execute_sql sans
 *     clarification suivante (déclenchée côté JS, pas par un event WS dédié).
 *
 * ``renderInteraction(payload)`` est le point d'entrée unique pour ces 5
 * familles. Le switch principal d'``handleEvent`` continue de router par
 * ``event.type`` (rétro-compat) mais délègue désormais à ce dispatcher,
 * supprimant la dispersion historique de 4 renderers indépendants.
 *
 * La taxonomie ``interaction_kind`` est ajoutée côté serveur dans chaque
 * payload — cf. ``app/services/ai/agent_service.py`` et
 * ``app/services/ai/pipeline_ask_user_bridge.py``. Quand un payload arrive
 * sans ``interaction_kind`` (clients pré-Task#20 ou tests standalone), le
 * dispatcher fait un fallback déterministe sur ``type``.
 */
var INTERACTION_KINDS = {
    CLARIFY_WITH_OPTIONS: 'clarify_with_options',
    OPEN_QUESTION:        'open_question',
    CONSENT:              'consent',
    SUGGESTIONS:          'suggestions',
    FEEDBACK:             'feedback'
};

// Fallback type → kind (rétro-compat) pour payloads sans interaction_kind.
var INTERACTION_TYPE_TO_KIND = {
    'clarification':             INTERACTION_KINDS.CLARIFY_WITH_OPTIONS,
    'pipeline_ask_user':         INTERACTION_KINDS.OPEN_QUESTION,
    'data_read_consent_request': INTERACTION_KINDS.CONSENT,
    'suggestions':               INTERACTION_KINDS.SUGGESTIONS
    // feedback : kind sans type WS — déclenché côté JS quand
    // _pendingExecuteSqlFeedback est vrai au 'done'.
};

function renderInteraction(payload) {
    if (!payload || typeof payload !== 'object') return;
    var kind = payload.interaction_kind
        || INTERACTION_TYPE_TO_KIND[payload.type]
        || null;
    if (!kind) {
        // Payload non reconnu — on logue en debug pour la traçabilité
        // mais on ne casse pas la conversation. Pas de fallback générique
        // (chaque kind a un contrat distinct : composer un message générique
        // produirait un rendu faux).
        if (window.console && console.debug) {
            console.debug('renderInteraction: kind inconnu', payload);
        }
        return;
    }
    switch (kind) {
        case INTERACTION_KINDS.CLARIFY_WITH_OPTIONS:
            // Buffer la clarification — le rendu groupé est déclenché au 'done'.
            bufferClarification(payload.question || '', payload.options || []);
            return;
        case INTERACTION_KINDS.OPEN_QUESTION:
            // Pipeline await directement la réponse — affichage immédiat.
            renderPipelineAskUser(
                payload.run_id,
                payload.ask_id || '',
                payload.question || '',
                payload.context || {}
            );
            return;
        case INTERACTION_KINDS.CONSENT:
            handleDataReadConsentRequest(payload);
            return;
        case INTERACTION_KINDS.SUGGESTIONS:
            renderSuggestions(payload.questions || []);
            return;
        case INTERACTION_KINDS.FEEDBACK:
            renderAutoFeedbackCard();
            return;
        default:
            if (window.console && console.debug) {
                console.debug('renderInteraction: kind non géré', kind, payload);
            }
            return;
    }
}

/**
 * Card feedback automatique affichée au 'done' quand execute_sql a renvoyé
 * des lignes mais que le LLM n'a pas appelé ask_user_clarification lui-même.
 * C'est une garantie côté frontend (code > prompt) — impossible que
 * l'utilisateur reste sans possibilité de valider/corriger.
 *
 * Task #21 — SSoT des libellés + icônes : ``app.constants.AUTO_FEEDBACK_OPTIONS``,
 * exposée via ``window.IRIS_CONFIG.autoFeedbackOptions``. Le tableau ci-dessous
 * ne sert QUE de fallback gracieux quand le bridge serveur→template→JS est
 * absent (preview, tests JS standalone, snapshot rétro-compat). Toute évolution
 * du wording passe par le constant Python, pas par cette ligne.
 */
function renderAutoFeedbackCard() {
    var card = document.createElement('div');
    card.className = 'iris-clarification iris-auto-feedback';

    var questionEl = document.createElement('p');
    questionEl.className = 'iris-clarification-question';
    questionEl.textContent = 'Les résultats te conviennent ?';
    card.appendChild(questionEl);

    var btnRow = document.createElement('div');
    btnRow.className = 'iris-clarification-options';

    // SSoT : window.IRIS_CONFIG.autoFeedbackOptions (servie depuis Python).
    // Fallback minimal et stable si IRIS_CONFIG n'est pas exposé (cas
    // pathologique — n'arrive pas en runtime nominal).
    var serverOptions = (window.IRIS_CONFIG && Array.isArray(window.IRIS_CONFIG.autoFeedbackOptions))
        ? window.IRIS_CONFIG.autoFeedbackOptions
        : null;
    var options = (serverOptions && serverOptions.length > 0)
        ? serverOptions
        : [
            { value: "C'est bon !",     icon: 'bi-check-circle-fill', feedback: 'positive' },
            { value: "Presque",         icon: 'bi-arrow-repeat',      feedback: 'adjust' },
            { value: "Ce n'est pas ça", icon: 'bi-x-circle-fill',     feedback: 'negative' }
        ];

    for (var i = 0; i < options.length; i++) {
        (function(opt) {
            // Tolère les deux noms historiques (``icon`` SSoT actuelle,
            // ``iconClass`` legacy) — évite de casser un cache navigateur
            // qui aurait gardé un payload v1 entre un déploiement et l'autre.
            var iconClass = opt.icon || opt.iconClass || 'bi-circle';
            var value = String(opt.value || '');
            if (!value) {
                return; // option malformée — on saute proprement
            }
            var btn = document.createElement('button');
            btn.type = 'button';
            btn.className = 'iris-clarif-btn';
            btn.innerHTML = '<i class="bi ' + escapeHtml(iconClass) + '"></i> ' + escapeHtml(value);
            btn.addEventListener('click', function() {
                card.querySelectorAll('.iris-clarif-btn').forEach(function(b) {
                    b.disabled = true;
                });
                btn.classList.add('selected');
                sendAutoFeedback(value);
            });
            btnRow.appendChild(btn);
        })(options[i]);
    }

    card.appendChild(btnRow);
    appendToMessages(card);
    scrollToBottom();
}

/**
 * POST le feedback Iris (``positive`` / ``adjust`` / ``negative``) vers
 * ``/api/iris/feedback`` → backend ``learn_from_conversation_feedback``.
 * SSoT du POST de feedback : partagé entre la row 👍/🔄/👎 ET la carte de
 * validation auto-feedback. Best-effort, timeout 10s. ``opts.onError`` permet
 * à l'appelant (row 👍) de ré-activer ses boutons ; absent = silencieux.
 */
function postIrisFeedback(feedback, opts) {
    opts = opts || {};
    var controller = new AbortController();
    var timer = setTimeout(function() { controller.abort(); }, 10000);
    return fetch('/api/iris/feedback', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-Xsrftoken': getCookie('_xsrf')
        },
        body: JSON.stringify({
            conversation_id: currentConversationId,
            feedback: feedback
        }),
        signal: controller.signal
    }).then(function(response) {
        clearTimeout(timer);
        if (!response.ok) {
            throw new Error('Feedback request failed: ' + response.status);
        }
    }).catch(function(err) {
        clearTimeout(timer);
        console.error('[Iris] Erreur feedback:', err);
        if (typeof opts.onError === 'function') opts.onError(err);
    });
}

/**
 * Mappe la valeur cliquée d'une option de validation (carte auto-feedback)
 * vers sa valeur de feedback déterministe, depuis la SSoT
 * ``IRIS_CONFIG.autoFeedbackOptions`` (servie par ``app/constants.py``).
 * Retourne ``null`` si la valeur ne correspond à aucune option taguée — dans
 * ce cas aucun feedback déterministe n'est déclenché (fail-safe).
 */
function autoFeedbackValueToFeedback(text) {
    var opts = (window.IRIS_CONFIG && Array.isArray(window.IRIS_CONFIG.autoFeedbackOptions))
        ? window.IRIS_CONFIG.autoFeedbackOptions
        : [];
    for (var i = 0; i < opts.length; i++) {
        if (opts[i] && String(opts[i].value) === String(text) && opts[i].feedback) {
            return String(opts[i].feedback);
        }
    }
    return null;
}

/**
 * Envoie le choix utilisateur de la carte de validation auto-feedback.
 *
 * DOUBLE effet (le 2e est le fix 2026-05-30) :
 *   1. Envoie ``text`` comme message conversationnel normal → Iris accuse
 *      réception (UX inchangée : l'utilisateur croit juste répondre à Iris).
 *   2. Déclenche l'apprentissage de façon DÉTERMINISTE via
 *      ``postIrisFeedback`` (positive/adjust/negative mappé depuis la SSoT) —
 *      au lieu de dépendre de la discrétion du LLM (``learn_insight``). C'est
 *      ce qui faisait que valider « C'est bon ! » ne créait aucune paire Q/SQL.
 */
function sendAutoFeedback(text) {
    if (!ws || ws.readyState !== WebSocket.OPEN) {
        addErrorMessage('Connexion perdue. Impossible d\'envoyer la réponse.');
        connectWebSocket();
        return;
    }
    // Reprise via la carte auto-feedback : retirer le bandeau "interrompu".
    _dismissInterruptedBanner();
    // Apprentissage DÉTERMINISTE : déclenche le feedback AVANT d'envoyer le
    // message conversationnel. L'ordre POST-puis-ws.send est une optimisation,
    // PAS une garantie de timing : le backend (learn_from_conversation_feedback)
    // EXCLUT déterministiquement les valeurs de la triade auto-feedback du choix
    // de la question apprise → même si le message déclencheur est persisté avant
    // le SELECT, la VRAIE question d'origine est retenue (race fix 20b8902).
    // Best-effort/silencieux — n'interrompt jamais le flux.
    var _autoFb = autoFeedbackValueToFeedback(text);
    if (_autoFb) {
        postIrisFeedback(_autoFb);
    }
    toolStepCount = 0;
    addUserMessage(text);
    if (welcomeState) welcomeState.style.display = 'none';
    if (typingIndicator) typingIndicator.style.display = 'flex';
    if (messageInput) messageInput.disabled = true;
    setSendButtonMode('stop');
    var inputWrapper = document.querySelector('.iris-input-wrapper');
    if (inputWrapper) inputWrapper.classList.add('processing');
    ws.send(JSON.stringify({
        action: 'send_message',
        conversation_id: currentConversationId,
        message: text,
        mode: currentMode,
        source: 'page'
    }));
    scrollToBottom();
}

/**
 * Envoie une réponse de clarification (quand l'utilisateur clique sur une option).
 * @param {string} response
 */
function sendClarificationResponse(response) {
    if (!ws || ws.readyState !== WebSocket.OPEN) {
        addErrorMessage('Connexion perdue. Impossible d\'envoyer la réponse.');
        if (sendBtn) sendBtn.disabled = false;
        if (messageInput) messageInput.disabled = false;
        connectWebSocket();
        return;
    }

    // Reprise via la carte de clarification : retirer le bandeau "interrompu".
    _dismissInterruptedBanner();
    // Si la réponse de clarification correspond EXACTEMENT à une option de
    // validation (triade SSoT ``autoFeedbackValueToFeedback``), déclenche aussi
    // l'apprentissage déterministe. Couvre le cas où Iris valide les résultats
    // via ``ask_user_clarification`` (la carte auto-feedback est alors
    // supprimée — cf. ``_pendingExecuteSqlFeedback``). Fail-safe : si la conv
    // n'a pas de SQL exécuté, ``learn_from_conversation_feedback`` no-op côté
    // serveur. Best-effort/silencieux — n'interrompt jamais le flux.
    var _clarifFb = autoFeedbackValueToFeedback(response);
    if (_clarifFb) {
        postIrisFeedback(_clarifFb);
    }

    ws.send(JSON.stringify({
        action: 'clarification_response',
        conversation_id: currentConversationId,
        response: response,
        source: 'page'
    }));

    // Montrer la réponse choisie comme message utilisateur
    addUserMessage(response);

    if (typingIndicator) typingIndicator.style.display = 'flex';
    if (messageInput) messageInput.disabled = true;
    setSendButtonMode('stop');
    const inputWrapperClarif = document.querySelector('.iris-input-wrapper');
    if (inputWrapperClarif) inputWrapperClarif.classList.add('processing');
}

// ──── Pipeline ask_user (architecture pipeline-driven Q/A) ────
//
// La pipeline elle-même (Phase 4 typiquement) pose une question à l'user
// via ``AskUserBridge.ask()``. Affichage inline dans le chat, l'user tape
// sa réponse, on l'envoie via WS action ``pipeline_ask_user_response`` qui
// résout le ``await future`` côté pipeline → la phase reprend sans crash.
// Cf. fix 2026-05-20 — câblage pipeline-driven (pas agent-recovery).

function renderPipelineAskUser(runId, askId, question, context) {
    if (!askId || typeof runId !== 'number') {
        // Defensive : log mais n'affiche rien. Le payload est mal formé,
        // probablement un bug backend — surfacer dans console pas dans UI.
        console.warn('renderPipelineAskUser: payload invalide', {runId: runId, askId: askId});
        return;
    }

    var card = document.createElement('div');
    card.className = 'iris-clarification iris-pipeline-ask';
    card.dataset.runId = String(runId);
    card.dataset.askId = askId;

    // En-tête : icône pipeline + label discret pour distinguer du
    // ``ask_user_clarification`` (qui vient du LLM). Utile pour le user :
    // sait que c'est la pipeline (irreversible si abandon → degraded mode)
    // et pas Iris (réversible).
    var header = document.createElement('div');
    header.style.cssText =
        'font-size:0.7rem;text-transform:uppercase;letter-spacing:0.05em;' +
        'color:var(--text-muted, #6b7280);margin-bottom:0.35rem;';
    header.textContent = '⚙ Pipeline — question';
    card.appendChild(header);

    // Question : multi-ligne (Phase 4 formatte avec liste numérotée).
    // ``white-space: pre-wrap`` préserve le formatting.
    var questionEl = document.createElement('p');
    questionEl.className = 'iris-clarification-question';
    questionEl.style.whiteSpace = 'pre-wrap';
    questionEl.textContent = question;
    card.appendChild(questionEl);

    // Input texte libre — la réponse peut être un numéro ("1", "2"…), un
    // texte libre, ou vide pour "laisser le système choisir" (cf. format
    // Phase 4 ligne 6623 de scripts/pipeline.py qui invite explicitement
    // « laisse vide pour me laisser choisir »).
    var inputRow = document.createElement('div');
    inputRow.style.cssText = 'display:flex;gap:0.5rem;align-items:stretch;';

    var input = document.createElement('input');
    input.type = 'text';
    input.className = 'iris-clarif-freetext-input';
    input.placeholder = 'Numéro de l\'option (1, 2…) ou réponse libre. Vide = laisse Iris choisir.';
    input.style.flex = '1';
    inputRow.appendChild(input);

    var sendBtn = document.createElement('button');
    sendBtn.type = 'button';
    sendBtn.className = 'iris-clarif-freetext-send';
    sendBtn.textContent = 'Envoyer';
    inputRow.appendChild(sendBtn);

    card.appendChild(inputRow);

    function submit() {
        var val = input.value;  // pas .trim() : "" est une réponse valide
        input.disabled = true;
        sendBtn.disabled = true;
        sendBtn.textContent = 'Envoi…';
        sendPipelineAskUserResponse(runId, askId, val);
        // Affichage récap dans le chat (ce que l'user a répondu).
        if (val.trim() !== '') {
            addUserMessage(val);
        } else {
            addUserMessage('(laisse Iris choisir)');
        }
        // Marque la card comme répondue (CSS peut griser).
        card.classList.add('responded');
    }

    sendBtn.addEventListener('click', submit);
    input.addEventListener('keydown', function(e) {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            submit();
        }
    });

    appendToMessages(card);
    scrollToBottom();
    // Focus l'input pour saisie immédiate.
    requestAnimationFrame(function() { input.focus(); });
}

function sendPipelineAskUserResponse(runId, askId, response) {
    if (!ws || ws.readyState !== WebSocket.OPEN) {
        addErrorMessage(
            'Connexion perdue. Impossible d\'envoyer la réponse à la pipeline. ' +
            'Reconnexion en cours…'
        );
        connectWebSocket();
        return;
    }
    ws.send(JSON.stringify({
        action: 'pipeline_ask_user_response',
        run_id: runId,
        ask_id: askId,
        response: response
    }));
}

// ──── Clear Conversation ────

/**
 * Efface la conversation courante via l'API et réinitialise l'état local.
 */
async function clearConversation() {
    // Reset de l'indicateur context-window AVANT le early-return : le bar
    // doit retomber à 0 dans les 2 branches (avec/sans conversation active),
    // sinon une UI rechargée avec un initial_context_tokens > 0 garderait
    // une valeur stale après clic « Nouvelle conversation ».
    try {
        var _cfgClear = window.IRIS_CONFIG || {};
        updateContextWindow({
            usedTokens: 0,
            contextWindow: _cfgClear.contextWindow || null,
            modelDisplay: _cfgClear.modelDisplay || null
        });
    } catch (e) { /* defensive */ }

    // Note (fix C — bug refresh) : on POST TOUJOURS /api/iris/clear même
    // si currentConversationId est null. Le serveur fait
    // ``UPDATE WHERE is_active=True`` (idempotent — no-op si rien à clear).
    // Sans ça, une conv créée par un autre onglet (ou pendant le delay
    // entre create et currentConversationId set) reste is_active=True en
    // BDD → revient au refresh.

    if (messagesArea) {
        var toRemoveEmpty = messagesArea.querySelectorAll(
            '.iris-message-row, .iris-tool-line, .iris-tool-wrap, .iris-tool-blocked, '
            + '.iris-concept-group, .iris-sql-build-group, .iris-sql-card, .iris-sql-jump-banner, '
            + '.iris-thinking-block, .iris-analysis-block, .iris-clarification, .iris-clarification-group, '
            + '.iris-suggestions, .iris-rag-sources, .iris-error-message, .iris-verification, '
            + '.iris-exploration-group, .iris-plan-group, .iris-system-message'
        );
        for (var j = 0; j < toRemoveEmpty.length; j++) {
            toRemoveEmpty[j].remove();
        }
    }
    // Reset state du widget plan (référence du turn courant) — le DOM a
    // déjà été retiré dans la boucle ci-dessus via ``.iris-plan-group``.
    resetPlanGroup();
    if (welcomeState) welcomeState.style.display = 'flex';
    if (typingIndicator) typingIndicator.style.display = 'none';

    try {
        // ``source: 'page'`` — clear scopé : ne touche PAS la conv du
        // floating widget (cf. ``IrisClearAPIHandler`` côté backend).
        const response = await fetch('/api/iris/clear', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Xsrftoken': getCookie('_xsrf')
            },
            body: JSON.stringify({ source: 'page' })
        });

        if (!response.ok) throw new Error('Erreur effacement');

        // Nettoyer les états de grilles persistés en localStorage.
        // Mo3 — passe le username pour matcher la clé scopée par user
        // (cf. _getPersistUsername + setPersistId ligne 1628).
        if (currentConversationId && typeof GridTabManager !== 'undefined') {
            GridTabManager.clearPersistedState(currentConversationId, _getPersistUsername());
        }

        // Reset état local
        currentConversationId = null;
        // Task #15 (M2) — reset le tracking _seq : nouvelle conv = flux frais.
        // Sinon, la 1ère event de la nouvelle conv (avec _seq potentiellement
        // bas) déclencherait un faux warning "dup".
        lastEventSeq = 0;
        lastAssistantBubble = null;
        currentStreamDiv = null;
        isStreaming = false;
        try { window.__irisStreamingActive = false; } catch (e) { /* defensive */ }
        pendingClarifications = [];
        _gridCounter = 0;
        // Drop refs aux grilles de l'ancienne conversation pour qu'elles
        // soient GC. Sinon le registre garde des refs sur des nodes DOM
        // détachés (fuite mémoire mineure mais accumulative sur usage long).
        // ``Map.clear()`` libère toutes les entrées en O(1) — pas besoin de
        // réassigner la variable.
        _gridsBySearchId.clear();
        _lastIndexedSearchId = null;

        // (Reset de l'indicateur context-window est fait en début de fonction,
        // avant l'early-return — couvre les 2 branches.)

        // Nettoyer l'UI — retirer les messages mais garder welcome + typing
        if (messagesArea) {
            // Remove only message rows and tool cards, keep structural elements
            var toRemove = messagesArea.querySelectorAll(
                '.iris-message-row, .iris-tool-line, .iris-tool-wrap, .iris-tool-blocked, '
                + '.iris-concept-group, .iris-sql-build-group, .iris-sql-card, .iris-sql-jump-banner, '
                + '.iris-thinking-block, .iris-analysis-block, .iris-clarification, .iris-clarification-group, '
                + '.iris-suggestions, .iris-rag-sources, .iris-error-message, .iris-verification, '
                + '.iris-exploration-group, .iris-system-message'
            );
            for (var i = 0; i < toRemove.length; i++) {
                toRemove[i].remove();
            }
            // Show welcome state, hide typing
            if (welcomeState) welcomeState.style.display = 'flex';
            if (typingIndicator) typingIndicator.style.display = 'none';
        }

        if (messageInput) {
            messageInput.disabled = false;
            messageInput.focus();
        }
    } catch (err) {
        console.error('[Iris] Erreur effacement conversation :', err);
        addErrorMessage('Impossible d\'effacer la conversation.');
    }
}

// ──── Role Selector ────

// ──── Restore turn visual events ────

/**
 * Rejoue les événements visuels d'un tour (element groups, suggestions, etc.)
 * depuis le journal turn_events stocké en BDD.
 * Appelé lors de la restauration d'un message assistant au refresh.
 * @param {Array<Object>} events — Liste ordonnée d'événements visuels
 */
function _restoreTurnEvents(events) {
    if (!events || !Array.isArray(events)) return;
    for (var i = 0; i < events.length; i++) {
        var evt = events[i];
        switch (evt.type) {
            case 'element_start':
                handleElementStart(
                    evt.element || '',
                    evt.index || 0,
                    evt.total || 0
                );
                break;
            case 'element_end':
                handleElementEnd(
                    evt.element || '',
                    evt.success !== false,
                    evt.location || ''
                );
                break;
            case 'tool_use':
                addToolIndicator(
                    evt.tool || '',
                    evt.icon || null,
                    evt.label || null,
                    evt.description || null,
                    true  // resolved
                );
                break;
            case 'tool_result': {
                // Find the FIRST (chronologically oldest) unrestored tool line for
                // this tool name. Events dans turn_events sont en ordre d'émission,
                // donc le 1er event décore la ligne la plus ancienne — sinon
                // l'appariement événement→ligne est inversé quand plusieurs tool_use
                // du même nom apparaissent dans le tour.
                var toolName_ = evt.tool || '';
                var restoreLines = messagesArea.querySelectorAll(
                    '.iris-tool-line[data-tool="' + (toolName_ || '').replace(/"/g, '') + '"]'
                );
                var restoreTarget = null;
                for (var ri = 0; ri < restoreLines.length; ri++) {
                    if (!restoreLines[ri].dataset.restored) { restoreTarget = restoreLines[ri]; break; }
                }
                if (!restoreTarget) break;
                restoreTarget.dataset.restored = '1';
                var success_ = evt.result && evt.result.success === true;
                if (!success_) restoreTarget.classList.add('iris-tool-line-hasError');
                // Stopper l'animation du dot (même si déjà résolu visuellement)
                var restoreDot = restoreTarget.querySelector('.iris-tool-line-dot');
                if (restoreDot) restoreDot.classList.remove('dot-active');
                restoreTarget.classList.add('tool-resolved');
                // Afficher elapsed_ms (identique au comportement live)
                var restoreTimeEl = restoreTarget.querySelector('.iris-tool-line-time');
                if (restoreTimeEl && evt.elapsed_ms != null) {
                    var restoreElapsed = evt.elapsed_ms;
                    var restoreTimeStr = restoreElapsed >= 1000
                        ? (restoreElapsed / 1000).toFixed(1) + 's'
                        : restoreElapsed + 'ms';
                    if (success_) {
                        restoreTimeEl.textContent = restoreTimeStr;
                    } else {
                        restoreTimeEl.innerHTML = '<span class="iris-tool-line-err">\u2717</span> '
                            + escapeHtml(restoreTimeStr);
                    }
                }
                var isExpandable_ = restoreTarget.classList.contains('iris-tool-line-expandable');
                if (!success_ && isExpandable_) {
                    var existingDesc_err = restoreTarget.querySelector('.iris-tool-line-desc');
                    var errBadge_ = document.createElement('span');
                    errBadge_.className = 'iris-tool-line-err-badge';
                    errBadge_.textContent = 'Erreur';
                    if (existingDesc_err) existingDesc_err.after(errBadge_);
                    else {
                        var labelEl_err = restoreTarget.querySelector('.iris-tool-line-label');
                        if (labelEl_err) labelEl_err.after(errBadge_);
                    }
                } else if (evt.summary) {
                    var existingDesc_ = restoreTarget.querySelector('.iris-tool-line-desc');
                    var summarySpan_ = document.createElement('span');
                    summarySpan_.className = 'iris-tool-line-summary' + (success_ ? '' : ' iris-tool-line-summary-err');
                    summarySpan_.textContent = '→ ' + evt.summary;
                    if (existingDesc_) existingDesc_.after(summarySpan_);
                    else {
                        var labelEl_ = restoreTarget.querySelector('.iris-tool-line-label');
                        if (labelEl_) labelEl_.after(summarySpan_);
                    }
                }
                // Surface error details in expanded panel (collapsed by default)
                var wrap_ = restoreTarget.closest('.iris-tool-wrap');
                if (wrap_ && restoreTarget.classList.contains('iris-tool-line-expandable') && !success_) {
                    var errEl_ = wrap_.querySelector('.iris-tool-expanded-error');
                    if (errEl_) {
                        var r_ = evt.result || {};
                        var errMsg_ = r_.error || r_.blocked_by || evt.summary || 'Erreur inconnue';
                        errEl_.hidden = false;
                        errEl_.innerHTML = '<span class="iris-tool-expanded-error-icon">⚠</span>'
                            + '<span class="iris-tool-expanded-error-text"></span>';
                        errEl_.querySelector('.iris-tool-expanded-error-text').textContent = String(errMsg_);
                        // C24 — parité avec le live : restaurer le bloc
                        // "Pistes pour débloquer" si persisté.
                        var nextActs_ = Array.isArray(r_.next_actions) ? r_.next_actions : null;
                        if (nextActs_ && nextActs_.length > 0) {
                            var actionsBox_ = document.createElement('div');
                            actionsBox_.className = 'iris-tool-next-actions';
                            var actionsTitle_ = document.createElement('div');
                            actionsTitle_.className = 'iris-tool-next-actions-title';
                            actionsTitle_.textContent = 'Pistes pour débloquer :';
                            actionsBox_.appendChild(actionsTitle_);
                            var ul_ = document.createElement('ul');
                            ul_.className = 'iris-tool-next-actions-list';
                            nextActs_.forEach(function(a) {
                                if (typeof a !== 'string' || !a.trim()) return;
                                var li = document.createElement('li');
                                li.textContent = a;
                                ul_.appendChild(li);
                            });
                            actionsBox_.appendChild(ul_);
                            errEl_.appendChild(actionsBox_);
                        }
                    }
                }
                // C26 — parité avec le live : restaurer le badge "Auto-corrigé"
                // si une correction a été appliquée.
                var rOk_ = evt.result || {};
                var autoCorrs_ = Array.isArray(rOk_.auto_corrected) ? rOk_.auto_corrected : null;
                if (success_ && autoCorrs_ && autoCorrs_.length > 0) {
                    var labelElAc_ = restoreTarget.querySelector('.iris-tool-line-label');
                    var correctedBadge_ = document.createElement('span');
                    correctedBadge_.className = 'iris-tool-line-autocorrected-badge';
                    correctedBadge_.textContent = 'Auto-corrigé';
                    correctedBadge_.title = autoCorrs_.map(function(c) {
                        return (c.category || '?') + ' — ' + (c.description || '');
                    }).join('\n');
                    if (labelElAc_) labelElAc_.after(correctedBadge_);
                }
                break;
            }
            case 'sql_results':
                if (Array.isArray(evt.columns) && evt.columns.length > 0) {
                    // Chercher les données complètes dans les rows (si présentes)
                    var rows = evt.rows || [];
                    var totalRows = evt.row_count || rows.length;
                    if (rows.length > 0) {
                        renderSQLResults(
                            evt.columns, rows,
                            evt.sql || '',
                            totalRows > rows.length ? totalRows : 0,
                            // #39 (A5-F4) — l'event sql_results persisté porte
                            // ``truncated`` (cf. agent_service) → badge cohérent
                            // avec le replay live (renderSQLResults primaire).
                            evt.truncated || false
                        );
                    }
                }
                break;
            case 'suggestions':
                renderSuggestions(evt.questions || []);
                break;
            case 'thinking':
                if (evt.content) renderThinkingCollapsed(evt.content);
                break;
            case 'verification': {
                // Au refresh, le tour est TERMINÉ — les `verification` persistés
                // en état "start" (ex: "Correction en cours (server_guard)…") ne
                // doivent PAS rester en jaune/italique comme s'ils étaient actifs.
                // On les rend directement en état `complete` avec un label historique
                // ("en cours" → "effectuée"). Pas de dépendance à #irisVerification
                // car il peut y en avoir plusieurs dans un même tour.
                var vEl = document.createElement('div');
                vEl.className = 'iris-verification complete';
                var rawMsg = String(evt.message || '').replace(/[\u2026.]{1,}$/, '').trim();
                var doneMsg = rawMsg
                    .replace(/\ben cours\b/gi, 'effectuée')
                    .replace(/\bVérification\b/g, 'Vérification');
                vEl.innerHTML = '\u2713 ' + escapeHtml(doneMsg || 'Vérification terminée');
                appendToMessages(vEl);
                break;
            }
            case 'rag_sources':
                renderRAGSources(evt.sources || []);
                break;
            case 'report_ready':
                renderReportReady(evt);
                break;
            case 'datastore_saved':
                renderDatastoreSaved(evt);
                break;
            case 'tool_blocked':
                renderToolBlocked(evt.tool || '', evt.reason || 'unknown', evt.message || '');
                break;
            case 'exploration_start':
                renderExplorationGroup();
                break;
            case 'exploration_catalog':
                updateExplorationStep('catalog', 'done', evt);
                break;
            case 'exploration_tables_selected':
                updateExplorationStep('selection', (evt.count > 0 ? 'done' : 'error'), evt);
                break;
            case 'exploration_fk_expanded':
                updateExplorationStep('fk', 'done', evt);
                break;
            case 'exploration_batch_progress':
                // Au restore, on voit tous les batch events l'un après l'autre —
                // seul le dernier persiste (updateExplorationStep remplace la
                // ligne). State 'done' car c'est l'état final.
                updateExplorationStep('batch', 'done', evt);
                break;
            case 'exploration_complementary':
                updateExplorationStep('complementary', 'done', evt);
                break;
            case 'exploration_complete': {
                var explOk_ = !evt.aborted;
                updateExplorationStep('complete', explOk_ ? 'done' : 'error', evt);
                // Mo1 — Si l'event porte duration_ms (persisté côté serveur
                // au moment du live), finalizeExplorationGroup l'utilisera
                // directement → durée correcte affichée au refresh. Sinon
                // (conv legacy pré-Mo1), on garde le _skipTimer pour
                // masquer un elapsed faux calculé depuis le _startTime
                // posé au restore. Source de vérité : event.duration_ms.
                var meta_;
                if (typeof evt.duration_ms === 'number' && evt.duration_ms >= 0) {
                    meta_ = evt;  // duration_ms suffit, pas besoin de skipTimer
                } else {
                    meta_ = Object.assign({}, evt, { _skipTimer: true });
                }
                // Capturer la ref AVANT finalize (qui met _currentExplorationGroup=null).
                var explGroupRef_ = _currentExplorationGroup;
                finalizeExplorationGroup(explOk_, meta_);
                // Collapse immédiat — pas d'animation au restore.
                if (explGroupRef_) {
                    explGroupRef_.classList.add('collapsed');
                }
                break;
            }
            case 'error':
                if (evt.message) addErrorMessage(evt.message);
                break;
            // feedback_request, phase_progress: pas de rendu visuel à restaurer
        }
    }
}

// ──── Replay au refresh : DOM-IDENTIQUE via le MÊME dispatcher que le live ────
//
// Source de vérité : ``window.IRIS_CONFIG.conversationEvents`` injecté par
// le template (rempli depuis la table ``conversation_events`` côté backend).
// Chaque entry a la forme ``{seq, turn_index, event_type, payload (str JSON),
// created_at}``. Le payload désérialisé est passé tel quel à
// ``handleWebSocketEvent()`` (le MÊME dispatcher que celui appelé par
// ``ws.onmessage`` en live) — garantie d'identité par construction : pas
// de chemin de rendu parallèle qui pourrait dériver. Cf. APEX 2026-05-09
// (Solution B).
//
// Mode replay : ``window.__irisReplayMode`` désactive ``scrollToBottom`` et
// les transitions CSS pendant le replay (sinon 100 scrolls smooth en
// cascade pour 100 events). Un scroll final est fait à la fin.
//
// Backward compat : si ``conversationEvents`` est vide (conversation legacy
// d'avant cette table), on tombe sur l'ancien restore loop basé sur
// ``conversationMessages``. Pas de régression pour les anciennes conv.

// Events qui produisent un side-effect RÉSEAU/IO en plus du rendu DOM.
// Au replay, on les skip car le side-effect a déjà eu lieu en live et le
// rejouer ouvrirait inutilement des EventSource/fetch (ex: sync_requested
// → ouverture EventSource /api/ai/schema/sync/stream + redéclenchement
// du sync schema côté backend). Cf. adversarial review BLOCKING #1.
var _REPLAY_SKIP_EVENT_TYPES = {
    'sync_requested': 1,
    // Note : ``cancelled`` n'est pas listé ici car déjà filtré côté backend
    // (``_TRANSIENT_EVENT_TYPES`` du persister). Il n'arrive jamais au replay.
};

// Indexe les sql_data.rows depuis savedMessages, par ordre d'apparition.
// Utilisé pour ré-injecter les rows dans les events sql_results dont le
// payload a été strip pour confidentialité (cf. backend
// ``_strip_confidential_fields`` dans conversation_event_persister.py).
//
// Mapping : on collecte les sql_data dans l'ordre des msgs role='tool', et
// on les pop FIFO quand on rencontre un event sql_results avec _rows_stripped.
// Cohérent avec l'ordre live : les tool msgs sont créés au moment où le
// résultat SQL arrive, AVANT l'event sql_results dans le même tour.
function _buildSqlDataQueueFromMessages(savedMessages) {
    var queue = [];
    if (!Array.isArray(savedMessages)) return queue;
    for (var i = 0; i < savedMessages.length; i++) {
        var msg = savedMessages[i];
        if (msg && msg.role === 'tool' && msg.sql_data
            && Array.isArray(msg.sql_data.columns)
            && Array.isArray(msg.sql_data.rows)) {
            queue.push(msg.sql_data);
        }
    }
    return queue;
}

function replayConversationEvents(events, savedMessages) {
    if (!Array.isArray(events) || events.length === 0) return;

    // **Fix MAJOR #5 adversarial session 19 (task #15 M2)** : initialiser
    // ``lastEventSeq`` depuis le max(seq) des events rehydratés. Sans ça,
    // les events live qui arrivent ensuite avec ``_seq <= max(replay)``
    // ne seraient PAS dedup (bug typique : reload mid-stream → replay
    // charge seq 1-10, WS reprend, live envoie seq=11 puis serveur replay
    // seq=10 → onglet réaffiche un bubble qu'on avait déjà).
    var _maxReplaySeq = 0;
    for (var _i = 0; _i < events.length; _i++) {
        var _s = events[_i] && events[_i].seq;
        if (typeof _s === 'number' && _s > _maxReplaySeq) _maxReplaySeq = _s;
    }
    if (_maxReplaySeq > 0) {
        lastEventSeq = _maxReplaySeq;
        console.info('[Iris replay] lastEventSeq init depuis replay = ' + _maxReplaySeq);
    }

    // Masquer le welcome
    if (welcomeState) welcomeState.style.display = 'none';

    // Pré-construit la queue des rows SQL pour les ré-injecter dans les
    // events sql_results dont les rows ont été strip (confidentialité).
    var sqlDataQueue = _buildSqlDataQueueFromMessages(savedMessages || []);

    // Activer le mode replay : désactive scrollToBottom + transitions CSS
    window.__irisReplayMode = true;
    if (document.documentElement) {
        document.documentElement.classList.add('iris-replay-mode');
    }

    try {
        for (var i = 0; i < events.length; i++) {
            var entry = events[i];
            if (!entry) continue;
            var payloadStr = entry.payload;
            if (typeof payloadStr !== 'string' || !payloadStr) continue;
            var evt = null;
            try {
                evt = JSON.parse(payloadStr);
            } catch (e) {
                console.warn('[Iris replay] payload non-JSON skippé seq=' + entry.seq);
                continue;
            }
            if (!evt || typeof evt !== 'object') continue;
            // Skip les events à side-effect réseau pour ne pas relancer
            // de vrais fetch/EventSource au refresh.
            if (_REPLAY_SKIP_EVENT_TYPES[evt.type]) continue;
            // Ré-injecte les rows SQL strippées par le backend (confidentialité)
            // depuis la queue pré-construite. FIFO car cohérent avec l'ordre
            // d'apparition live (tool msg créé AVANT event sql_results).
            if (evt.type === 'sql_results' && evt._rows_stripped
                && sqlDataQueue.length > 0) {
                var sqlData = sqlDataQueue.shift();
                evt.rows = sqlData.rows;
                if (!Array.isArray(evt.columns) || evt.columns.length === 0) {
                    evt.columns = sqlData.columns;
                }
                if (!evt.row_count) {
                    evt.row_count = sqlData.row_count || sqlData.rows.length;
                }
            }
            // Le dispatcher live est appelé EXACTEMENT comme en streaming.
            // Aucune branche `if (replay)` qui change la sémantique du rendu.
            try {
                handleWebSocketEvent(evt);
            } catch (e) {
                console.error('[Iris replay] handleWebSocketEvent threw on seq='
                    + entry.seq + ' type=' + (evt.type || '?'), e);
            }
        }
    } finally {
        // Désactiver le mode replay AVANT le scroll final pour que celui-ci
        // s'applique normalement.
        window.__irisReplayMode = false;
        if (document.documentElement) {
            document.documentElement.classList.remove('iris-replay-mode');
        }
        // Garantit que la prochaine activité live n'hérite pas du
        // ``_currentPlanGroup`` du dernier tour rejoué — si ce tour s'est
        // terminé par ``done``/``error``/``cancelled``, ``resetAfterResponse``
        // a déjà nettoyé ; sinon (run interrompu sans event de clôture)
        // on force le reset défensif ici. Bug observé : multi-turn replay
        // → dernier tour interrompu → premier ``plan_update`` du nouveau
        // tour live mutait l'ancien widget du dernier tour rejoué.
        resetPlanGroup();
    }

    // À la fin : un seul scroll vers le bas (cohérent avec l'état d'arrivée
    // du dernier event live d'une conv terminée).
    if (messagesArea) {
        // Désactive _userScrolledUp pour ce scroll initial post-restore.
        _userScrolledUp = false;
        messagesArea.scrollTo({ top: messagesArea.scrollHeight, behavior: 'auto' });
    }
    // typingIndicator doit être caché à l'état final d'une conv terminée.
    // Si le dernier event était un ``done``, il est déjà caché par le case
    // 'done'. Sécurité défensive ici.
    if (typingIndicator) typingIndicator.style.display = 'none';

    // Détecte un run interrompu (dernier event ≠ done/error/cancelled).
    // Sans ce bandeau, l'utilisateur voit un état figé sans aucun signal
    // que le run est mort et qu'il doit relancer (cf. incident 2026-05-10
    // conv #5 où David voyait des thinking partiels et attendait sans rien
    // savoir). Fail-loud > fail-silent.
    if (_isReplayRunInterrupted(events)) {
        _renderInterruptedRunBanner();
    }
}

// Renvoie true si le dernier event "significatif" indique un run pas terminé.
// Significatif = tout sauf les events skip-au-replay (cf. _REPLAY_SKIP_EVENT_TYPES)
// qui ne reflètent pas l'état d'avancement du tool loop.
//
// ``text_complete`` est considéré TERMINAL : Iris a produit une réponse
// user-visible, donc même si le ``done`` final n'a pas été persisté
// (race possible si la WS se ferme entre yield text_complete et yield done),
// on ne veut PAS afficher le bandeau "interrompu" — il n'y a rien à
// reprendre, l'user a sa réponse. Cf. adversarial review 2026-05-10
// BLOCKING #3 (faux positif systématique sans cette ligne).
function _isReplayRunInterrupted(events) {
    if (!Array.isArray(events) || events.length === 0) return false;
    var TERMINAL = { 'done': 1, 'error': 1, 'cancelled': 1, 'text_complete': 1 };
    for (var i = events.length - 1; i >= 0; i--) {
        var e = events[i];
        if (!e || typeof e.event_type !== 'string') continue;
        if (_REPLAY_SKIP_EVENT_TYPES[e.event_type]) continue;
        return !TERMINAL[e.event_type];
    }
    return false;
}

function _renderInterruptedRunBanner() {
    if (!messagesArea) return;
    // Idempotent : si l'utilisateur fait F5 plusieurs fois, ne pas empiler.
    if (document.getElementById('irisInterruptedBanner')) return;
    var banner = document.createElement('div');
    banner.id = 'irisInterruptedBanner';
    banner.className = 'iris-interrupted-banner';
    banner.setAttribute('role', 'status');
    banner.setAttribute('aria-live', 'polite');
    var icon = document.createElement('span');
    icon.className = 'iris-interrupted-icon';
    icon.setAttribute('aria-hidden', 'true');
    icon.textContent = '⚠';
    var msg = document.createElement('span');
    msg.className = 'iris-interrupted-text';
    msg.textContent = 'Le run précédent a été interrompu (réseau, refresh, ou crash). '
        + 'Envoie un message pour reprendre dans la même conversation.';
    banner.appendChild(icon);
    banner.appendChild(msg);
    appendToMessages(banner);
}

// ──── Init ────

// Couper le sync SSE si l'utilisateur quitte/recharge la page
window.addEventListener('beforeunload', function() {
    if (_syncSSE) { _syncSSE.close(); _syncSSE = null; }
});

document.addEventListener('DOMContentLoaded', function() {

    // Mo3 — Sweep des états de grille obsolètes (legacy pré-Mo3 sans
    // _savedAt OU > 30j). Une seule passe au boot, ms-level. Évite que
    // les clés s'accumulent indéfiniment sur poste partagé jusqu'au
    // quota localStorage 5-10 MB Chrome.
    try {
        if (typeof GridTabManager !== 'undefined'
                && typeof GridTabManager.purgeStaleKeys === 'function') {
            var _purged = GridTabManager.purgeStaleKeys();
            if (_purged > 0) {
                _irisDebug('[Iris] purgeStaleKeys: ' + _purged + ' clés grille obsolètes supprimées');
            }
        }
    } catch (e) { /* noop */ }

    // ── Smart scroll : tracker si l'utilisateur a scrollé vers le haut ──
    if (messagesArea) {
        messagesArea.addEventListener('scroll', function() {
            var threshold = 150;
            var atBottom = messagesArea.scrollHeight - messagesArea.scrollTop - messagesArea.clientHeight < threshold;
            _userScrolledUp = !atBottom;
        });
    }

    // Lire la config depuis window.IRIS_CONFIG (injecté par le template)
    const config = window.IRIS_CONFIG || {};
    if (config.conversationId) {
        currentConversationId = parseInt(config.conversationId) || null;
    }
    // Rôle auto-détecté par le backend

    // Initialiser l'indicateur context-window depuis la config serveur. Le
    // numérateur est l'estimation pré-turn (heuristique 4 chars/token sur
    // l'historique) — corrigé exactement par le 1er done event ensuite.
    updateContextWindow({
        usedTokens: config.initialContextTokens || 0,
        contextWindow: config.contextWindow || null,
        modelDisplay: config.modelDisplay || null
    });

    // ── Restaurer la conversation précédente ──
    //
    // **Path préféré** : replay des events bruts via le MÊME dispatcher que
    // le live (``handleWebSocketEvent``). DOM-IDENTIQUE au refresh par
    // construction. Cf. APEX 2026-05-09 (Solution B).
    //
    // **Fallback** : si la conv n'a pas d'events stockés (legacy d'avant la
    // table ``conversation_events``), on tombe sur l'ancien restore loop
    // basé sur ``conversationMessages`` qui agrège tool/assistant msgs +
    // turn_events JSON. Plus fragile (heuristiques pour l'ordre) mais
    // garde la backward compat.
    const conversationEvents = config.conversationEvents || [];
    const savedMessages = config.conversationMessages || [];
    const useEventReplay = conversationEvents.length > 0 && messagesArea;

    if (useEventReplay) {
        try {
            replayConversationEvents(conversationEvents, savedMessages);
        } catch (err) {
            console.error('[Iris] replayConversationEvents failed:', err);
        }
        // Pas de fallback sur le legacy ici — si le replay a partiellement
        // restauré, mélanger avec le legacy créerait des doublons. Le replay
        // est censé être complet par construction.
    } else if (savedMessages.length > 0 && messagesArea) {
        // Masquer le welcome state
        if (welcomeState) welcomeState.style.display = 'none';

        // Mo2 — Signaler le mode dégradé. Path B est activé quand la conv
        // n'a pas d'events bruts (legacy pré-2026-05-09 ou erreur SQL au
        // chargement côté serveur). Le rendu est plus fragile : timings
        // d'exploration faux (calculés depuis Date.now() au lieu de la
        // valeur originale), live timers tickent depuis le moment du
        // refresh, certains détails visuels peuvent manquer. L'utilisateur
        // doit savoir avant de blâmer "le bug" — bandeau info non-alarmant.
        addInfoBanner(
            "Mode compatibilité : cette conversation utilise l'ancien format de " +
            "restauration. Certains détails (timings d'exploration, durées d'outils) " +
            "peuvent manquer ou être approximatifs."
        );
        // Log côté console pour le développeur qui debug une conv affectée.
        console.warn('[Iris] Replay path B (legacy) activé — conv sans events bruts');

        // Suppress scrolling during restore (avoid N×2 scroll animations)
        var _origScroll = scrollToBottom;
        scrollToBottom = function() {};
        toolStepCount = 0;

        // ── Pré-scan : exploration events + dernier ASSISTANT msg par tour ────
        // En LIVE, l'ordre DOM est : bulle(timeline) → tool lines → texte final.
        // La bulle est créée par `exploration_start` AVANT les tool_use events.
        // En RESTORE naïf, les msgs TOOL sont itérés AVANT le dernier ASSISTANT
        // msg (par order_by id), donc la timeline serait créée APRÈS les tool lines.
        // Solution : découper en "tours" (USER → …), pré-rendre les events
        // exploration_* AVANT les tool lines du tour. Puis filtrer ces types
        // quand on rejoue turn_events au msg ASSISTANT porteur.
        //
        // En plus : identifier le DERNIER msg ASSISTANT de chaque tour pour
        // n'afficher les feedback buttons QUE sur celui-là (en live, text_complete
        // n'est émis qu'une fois par tour → un seul feedback row par tour).
        var _EXPL_TYPES = {
            'exploration_start': 1, 'exploration_catalog': 1,
            'exploration_tables_selected': 1, 'exploration_fk_expanded': 1,
            'exploration_batch_progress': 1, 'exploration_complementary': 1,
            'exploration_complete': 1
        };
        // Events à pré-rendre AVANT les tool indicators du tour pour reproduire
        // l'ordre live. Sans ce pré-rendu, ces events sont rendus dans le
        // ``_restoreTurnEvents`` du msg ASSISTANT porteur — qui vient APRÈS
        // tous les ``tool`` msgs séparés dans ``savedMessages`` → résultat :
        // les blocs apparaissent tout en bas de la conversation au refresh.
        // Bug visible : « le raisonnement finit en bas alors qu'en live il
        // précède les tool lines » (signalé 2026-05-09).
        var _PRE_RENDER_TYPES = {
            'thinking': 1,
            // (Pas analysis ici : il vient du content msg.content via regex
            // [ANALYSIS]…[/ANALYSIS], pas de turn_events typiquement.)
        };
        var _turnExplByUserIdx = {};   // index USER msg → events exploration du tour
        var _turnPreRenderByUserIdx = {};  // index USER msg → events thinking/etc à pré-rendre
        var _lastAsstIdxByUserIdx = {};  // index USER msg → index du dernier ASSISTANT msg du tour
        (function _preScanTurns() {
            var currentUserIdx = -1;
            for (var si = 0; si < savedMessages.length; si++) {
                var sm = savedMessages[si];
                if (sm.role === 'user') {
                    currentUserIdx = si;
                    continue;
                }
                if (currentUserIdx < 0) continue;
                if (sm.role === 'assistant') {
                    // Tracker le dernier ASSISTANT msg de ce tour (écrase les précédents)
                    _lastAsstIdxByUserIdx[currentUserIdx] = si;
                    if (Array.isArray(sm.turn_events)) {
                        // Cherche les events exploration_* + thinking dans ce tour (on
                        // garde la DERNIÈRE série trouvée par catégorie).
                        var collectedExpl = [];
                        var collectedPre = [];
                        for (var ei = 0; ei < sm.turn_events.length; ei++) {
                            var evtType = sm.turn_events[ei].type;
                            if (_EXPL_TYPES[evtType]) {
                                collectedExpl.push(sm.turn_events[ei]);
                            } else if (_PRE_RENDER_TYPES[evtType]) {
                                collectedPre.push(sm.turn_events[ei]);
                            }
                        }
                        if (collectedExpl.length > 0) {
                            _turnExplByUserIdx[currentUserIdx] = collectedExpl;
                        }
                        if (collectedPre.length > 0) {
                            _turnPreRenderByUserIdx[currentUserIdx] = collectedPre;
                        }
                    }
                }
            }
        })();
        // Ensemble des indices de msgs ASSISTANT "porteurs" (= dernier du tour)
        var _lastAsstIdxSet = {};
        Object.keys(_lastAsstIdxByUserIdx).forEach(function(k) {
            _lastAsstIdxSet[_lastAsstIdxByUserIdx[k]] = 1;
        });

        try {
            for (var _mi = 0; _mi < savedMessages.length; _mi++) {
                const msg = savedMessages[_mi];
                if (msg.role === 'user' && msg.content) {
                    addUserMessage(msg.content);
                    // Pré-rendre l'exploration du tour AVANT les tool lines, pour
                    // reproduire l'ordre DOM live (bulle timeline → tool lines).
                    if (_turnExplByUserIdx[_mi]) {
                        _restoreTurnEvents(_turnExplByUserIdx[_mi]);
                        // Reset currentStreamDiv pour que le texte suivant crée
                        // sa propre bulle (en live, text_delta après un tool_use
                        // ouvre une nouvelle bulle — la bulle timeline ne contient
                        // que la timeline, pas le texte final).
                        currentStreamDiv = null;
                    }
                    // Pré-rendre les blocs ``thinking`` AVANT les tool lines pour
                    // reproduire l'ordre live (le LLM réfléchit avant d'invoquer
                    // ses tools). Sans ce pré-rendu, ils finissent en dernier
                    // dans la séquence DOM, après tous les tool indicators.
                    if (_turnPreRenderByUserIdx[_mi]) {
                        _restoreTurnEvents(_turnPreRenderByUserIdx[_mi]);
                    }

                } else if (msg.role === 'tool' && msg.tool_name) {
                    // Clarification questions: render as question UI (not tool card)
                    if (msg.tool_name === 'ask_user_clarification' && msg.clarification) {
                        renderRestoredClarification(
                            msg.clarification.question || '',
                            msg.clarification.options || []
                        );
                        continue;
                    }
                    // Restored tool indicator with display info
                    addToolIndicator(
                        msg.tool_name,
                        msg.icon || null,
                        msg.label || null,
                        msg.description || null,
                        true
                    );
                    // Restore SQL result table if data is available
                    if (msg.sql_data && Array.isArray(msg.sql_data.columns) && msg.sql_data.columns.length > 0) {
                        var sqlRows = msg.sql_data.rows || [];
                        var totalRows = msg.sql_data.row_count || sqlRows.length;
                        renderSQLResults(
                            msg.sql_data.columns,
                            sqlRows,
                            msg.sql_data.sql || '',
                            totalRows > sqlRows.length ? totalRows : 0,
                            // #39 (A5-F4) — propager le flag de troncature pour
                            // afficher le badge « ⚠ limité » comme au replay live.
                            // Absent des conversations legacy → false (pas de badge).
                            msg.sql_data.truncated || false
                        );
                    }

                } else if (msg.role === 'assistant' && msg.content) {
                    // ── Restaurer turn_events (element groups, suggestions, etc.) ──
                    // Si turn_events est présent, rejouer les événements visuels
                    // AVANT le texte pour reproduire l'ordre d'affichage live.
                    // On filtre les events exploration_* car ils ont été pré-rendus
                    // après le USER msg (pour reproduire l'ordre live bulle → tools).
                    if (Array.isArray(msg.turn_events)) {
                        var _eventsToReplay = msg.turn_events.filter(function(e) {
                            // Filtre les types pré-rendus en début de tour
                            // (exploration_* + thinking) pour éviter les doublons.
                            return !_EXPL_TYPES[e.type] && !_PRE_RENDER_TYPES[e.type];
                        });
                        _restoreTurnEvents(_eventsToReplay);
                    }

                    // Extract thinking blocks from restored content
                    var thinkingRe = /\[THINKING\]([\s\S]*?)\[\/THINKING\]/gi;
                    var thinkContent;
                    while ((thinkContent = thinkingRe.exec(msg.content)) !== null) {
                        if (thinkContent[1].trim()) {
                            // Ne pas dupliquer si déjà dans turn_events
                            if (!Array.isArray(msg.turn_events) ||
                                !msg.turn_events.some(function(e) { return e.type === 'thinking'; })) {
                                renderThinkingCollapsed(thinkContent[1].trim());
                            }
                        }
                    }
                    // Extract analysis blocks from restored content
                    var analysisRe = /\[ANALYSIS\]([\s\S]*?)\[\/ANALYSIS\]/gi;
                    var analysisContent;
                    while ((analysisContent = analysisRe.exec(msg.content)) !== null) {
                        if (analysisContent[1].trim()) {
                            renderAnalysisCollapsed(analysisContent[1].trim());
                        }
                    }
                    // Extract [SUGGESTIONS] and render as chips (tolérant C20 :
                    // casse + espaces internes + singulier/pluriel)
                    var suggestionsRe = /\[\s*SUGGESTIONS?\s*\]([\s\S]*?)\[\s*\/\s*SUGGESTIONS?\s*\]/gi;
                    var sugMatch;
                    while ((sugMatch = suggestionsRe.exec(msg.content)) !== null) {
                        var raw = sugMatch[1].trim();
                        if (raw) {
                            var qs = raw.split('|').map(function(s) { return s.trim(); }).filter(Boolean);
                            // Ne pas dupliquer si déjà dans turn_events
                            if (qs.length > 0 && (!Array.isArray(msg.turn_events) ||
                                !msg.turn_events.some(function(e) { return e.type === 'suggestions'; }))) {
                                renderSuggestions(qs);
                            }
                        }
                    }
                    // Strip internal tags from display (tolérant aux espaces/casse)
                    var displayContent = msg.content
                        .replace(/\[\s*THINKING\s*\][\s\S]*?\[\s*\/\s*THINKING\s*\]/gi, '')
                        .replace(/\[\s*SUGGESTIONS?\s*\][\s\S]*?\[\s*\/\s*SUGGESTIONS?\s*\]/gi, '')
                        .replace(/\[\s*ANALYSIS\s*\][\s\S]*?\[\s*\/\s*ANALYSIS\s*\]/gi, '')
                        .replace(/\[\s*THINKING\s*\][\s\S]*$/gi, '')
                        .replace(/\[\s*SUGGESTIONS?\s*\][\s\S]*$/gi, '')
                        .replace(/\[\s*ANALYSIS\s*\][\s\S]*$/gi, '')
                        .replace(/\n{3,}/g, '\n\n')
                        .trim();
                    if (displayContent) {
                        var rendered = formatMarkdown(displayContent);
                        if (rendered && rendered.trim()) {
                            // Réutiliser la bulle créée par renderExplorationGroup()
                            // (via turn_events) pour éviter une bulle doublée au refresh.
                            // Si aucune bulle n'a encore été créée pour ce tour, en
                            // créer une nouvelle comme en live.
                            var bubble;
                            if (currentStreamDiv) {
                                bubble = currentStreamDiv;
                                currentStreamDiv = null;
                            } else {
                                bubble = createAssistantBubble();
                            }
                            bubble.innerHTML = sanitizeHtml(rendered);
                            // Feedback buttons UNIQUEMENT sur le DERNIER msg ASSISTANT
                            // de chaque tour (cohérent avec le live où text_complete
                            // n'est émis qu'une fois par tour). Les msgs ASSISTANT
                            // intermédiaires (segments entre tool calls) ne doivent pas
                            // avoir de feedback row.
                            var parentBubble = bubble.parentElement;
                            if (parentBubble && _lastAsstIdxSet[_mi]) {
                                var feedbackRow = _buildFeedbackRow(msg.feedback);
                                parentBubble.appendChild(feedbackRow);
                            }
                        }
                    }
                    // Reset inter-tour : éviter que le tour suivant hérite
                    // d'une bulle non consommée (ex: turn_events avec timeline
                    // mais displayContent vide → bulle créée mais pas remplie).
                    currentStreamDiv = null;
                }
            }
        } finally {
            // Always restore scrolling, even if an error occurred
            scrollToBottom = _origScroll;
            // Fermer tout element group ouvert restant
            if (_currentElementGroup) {
                _currentElementGroup.classList.add('collapsed');
                _currentElementGroup = null;
            }
        }
    }

    // Connexion WebSocket
    connectWebSocket();

    // Todo #37 — Distinguer offline réseau vs serveur down.
    // Le retry exponentiel existait déjà mais ne distinguait pas les
    // 2 cas — l'user voyait "Reconnexion en cours" même quand son wifi
    // était coupé, sans savoir s'il devait se reconnecter (réseau) ou
    // attendre (serveur). Maintenant : offline → banner explicite +
    // pause des messages, online → reset backoff + force reconnect
    // immédiat (sans attendre le prochain tick).
    if (typeof window !== 'undefined' && window.addEventListener) {
        window.addEventListener('offline', _handleNetworkOffline);
        window.addEventListener('online', _handleNetworkOnline);
        // Si l'user arrive sur la page DÉJÀ offline, afficher le banner
        // immédiatement (l'event 'offline' ne fire pas pour un état initial).
        if (navigator && navigator.onLine === false) {
            _showOfflineBanner();
        }
    }

    // Scroller en bas une seule fois si une conversation est ouverte
    if (currentConversationId && messagesArea) {
        _userScrolledUp = false;
        messagesArea.scrollTop = messagesArea.scrollHeight;
    }

    // ── Envoi du message ──

    if (sendBtn) {
        sendBtn.addEventListener('click', function() {
            if (sendBtn.classList.contains('stop-mode')) {
                stopGeneration();
            } else {
                sendMessage();
            }
        });
    }

    if (messageInput) {
        // Entrée = envoyer, Shift+Entrée = saut de ligne
        messageInput.addEventListener('keydown', function(e) {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                sendMessage();
            }
        });

        // Auto-resize du textarea
        messageInput.addEventListener('input', function() {
            this.style.height = 'auto';
            this.style.height = Math.min(this.scrollHeight, 200) + 'px';
            // Auto-save (cf. incident 2026-05-09 : draft long perdu après refresh).
            _saveDraft(this.value);
        });

        // ── Task #21 — Coller un fichier avec Cmd+V / Ctrl+V ─────────
        // État de l'art : l'utilisateur copie une image (capture d'écran)
        // ou un fichier dans son OS, puis colle dans le textarea. Si
        // l'item clipboard est un fichier, on le traite comme un upload
        // PC (réutilise _handleSelectedFile factorisé pour Task #20).
        // Sinon (texte normal), on laisse le paste natif fonctionner.
        //
        // IMPORTANT : ne JAMAIS preventDefault si le clipboard contient
        // juste du texte — sinon l'user ne pourrait plus coller du texte
        // dans son message. Le preventDefault n'est appelé QUE quand on
        // a trouvé un fichier à uploader.
        messageInput.addEventListener('paste', function(e) {
            if (!e.clipboardData || !e.clipboardData.items) return;
            // Task #24 — respecte l'état désactivé (LLM non configuré)
            // pour cohérence avec le bouton trombone et le drop window.
            var uploadBtnEl = document.getElementById('uploadBtn');
            if (uploadBtnEl && uploadBtnEl.disabled) return;
            // Task #12 — si un upload est déjà en cours, ne pas en
            // déclencher un autre via paste (cohérence avec sendBtn
            // disabled pendant upload).
            if (_uploadInFlight) {
                e.preventDefault();
                addErrorMessage('Upload déjà en cours, veuillez patienter.');
                return;
            }

            var items = e.clipboardData.items;
            for (var i = 0; i < items.length; i++) {
                var item = items[i];
                if (item.kind === 'file') {
                    var file = item.getAsFile();
                    if (file) {
                        // On a trouvé un fichier → intercepte le paste
                        // natif et traite via le flow d'upload PC.
                        e.preventDefault();
                        _handleSelectedFile(file);
                        return;
                    }
                }
            }
            // Aucun fichier dans le clipboard → laisse le paste natif
            // (texte) suivre son cours sans preventDefault.
        });

        // Deep-link prefill : pages externes (ex: /dashboards) peuvent ouvrir
        // Iris avec `?prompt=…` pour pré-remplir l'input. On ne soumet pas
        // automatiquement — l'utilisateur reste aux commandes.
        var prefill = (config && typeof config.promptPrefill === 'string')
            ? config.promptPrefill : '';
        if (prefill) {
            messageInput.value = prefill;
            messageInput.dispatchEvent(new Event('input', { bubbles: true }));
            // Focus après le prochain tick pour laisser le layout se stabiliser
            setTimeout(function() { messageInput.focus(); }, 0);
        } else {
            // Restore d'un draft interrompu. Le prefill prime (intention
            // explicite via deep-link). Le draft restauré déclenche un event
            // 'input' pour re-calculer la hauteur du textarea.
            var saved = _loadDraft();
            if (saved) {
                messageInput.value = saved;
                messageInput.dispatchEvent(new Event('input', { bubbles: true }));
                setTimeout(function() { messageInput.focus(); }, 0);
            }
        }
    }

    // ── Mode toggle (execution/explanation) ──

    const modeToggle = document.querySelector('.iris-mode-toggle');
    if (modeToggle) {
        modeToggle.addEventListener('click', function(e) {
            const btn = e.target.closest('[data-mode]');
            if (!btn) return;
            currentMode = btn.dataset.mode;
            modeToggle.querySelectorAll('[data-mode]').forEach(function(b) {
                b.classList.toggle('active', b.dataset.mode === currentMode);
            });
        });
    }

    // ── File upload ──

    const uploadBtn = document.getElementById('irisUploadBtn') || document.getElementById('uploadBtn');
    const fileInput = document.getElementById('irisFileInput') || document.getElementById('fileInput');

    var uploadMenu = document.getElementById('uploadMenu');
    var uploadFromPC = document.getElementById('uploadFromPC');
    var uploadFromDatastore = document.getElementById('uploadFromDatastore');
    var datastorePicker = document.getElementById('datastorePicker');
    var datastorePickerList = document.getElementById('datastorePickerList');
    var datastorePickerClose = document.getElementById('datastorePickerClose');

    if (uploadBtn && fileInput) {
        // Toggle le menu au clic sur le trombone
        uploadBtn.addEventListener('click', function(e) {
            e.stopPropagation();
            if (uploadMenu) {
                var visible = uploadMenu.style.display !== 'none';
                uploadMenu.style.display = visible ? 'none' : 'block';
            }
        });

        // Depuis mon ordinateur
        if (uploadFromPC) {
            uploadFromPC.addEventListener('click', function() {
                uploadMenu.style.display = 'none';
                fileInput.click();
            });
        }

        // Depuis le datastore
        if (uploadFromDatastore) {
            uploadFromDatastore.addEventListener('click', function() {
                uploadMenu.style.display = 'none';
                _openDatastorePicker();
            });
        }

        // Fermer le menu au clic en dehors
        document.addEventListener('click', function() {
            if (uploadMenu) uploadMenu.style.display = 'none';
        });

        // Fermer le datastore picker (Task #14 — passe par le helper
        // _closeDatastorePicker qui notifie OverlayManager pour libérer
        // le focus trap proprement)
        if (datastorePickerClose) {
            datastorePickerClose.addEventListener('click', function() {
                _closeDatastorePicker();
            });
        }
        // Task #14 — Click outside : ferme le picker si l'user clique
        // ailleurs sur la page. Exception : clic sur le bouton trombone
        // qui RE-déclenche l'ouverture (sinon on aurait ouvert/fermé
        // immédiatement dans le même tick).
        document.addEventListener('mousedown', function(e) {
            if (!datastorePicker || datastorePicker.style.display === 'none') return;
            if (datastorePicker.contains(e.target)) return;  // clic dans le modal
            if (uploadBtn && uploadBtn.contains(e.target)) return;  // clic sur le trombone
            if (uploadMenu && uploadMenu.contains(e.target)) return;  // clic dans le menu
            _closeDatastorePicker();
        });

        // Task #20 — Le flow de traitement d'un fichier sélectionné est
        // factorisé pour être réutilisé par le drag & drop (handlers
        // window plus bas). Avant : tout le code était inline dans le
        // listener fileInput.change → impossible à réutiliser sans
        // simulation hackée de DataTransfer.
        async function _handleSelectedFile(file) {
            if (!file) return;

            // Validate file exists, type, and size
            if (!file || !file.name) {
                addErrorMessage('Fichier invalide.');
                fileInput.value = '';
                return;
            }

            // Komptia workbook (.afz.json) → affichage grille local
            //
            // MED-6 fix 2026-05-26 — AVANT ce fix, on faisait un early
            // ``return`` ici, donc le fichier n'était JAMAIS uploadé
            // au backend → pas de file_id → Iris ne le voyait pas et
            // répondait « je ne vois pas de fichier ». Bug d'incohérence
            // UX (grille affichée mais LLM ignorait le fichier).
            //
            // Maintenant : on affiche la grille SI c'est un workbook
            // Komptia valide (best-effort, pas bloquant), puis on
            // continue le flow upload normal pour que ``file_id`` soit
            // setté et Iris puisse analyser via ``analyze_attachment``.
            if (file.name.match(/\.(?:afz\.)?json$/i)) {
                try {
                    // Lecture synchrone-like : on lit en attendant via
                    // une Promise pour ne pas désynchroniser le flow.
                    await new Promise(function(resolve) {
                        var reader = new FileReader();
                        reader.onload = function(ev) {
                            try {
                                var data = JSON.parse(ev.target.result);
                                if (data.app === 'komptia' && Array.isArray(data.tabs)) {
                                    var card = document.createElement('div');
                                    card.className = 'iris-sql-card';
                                    var tabMgr = new GridTabManager(card);
                                    tabMgr.loadWorkbook(data);
                                    appendToMessages(card);
                                    scrollToBottom();
                                }
                                // JSON non-Komptia : pas d'affichage grille
                                // ici, mais le flow upload va continuer
                                // (analyze_attachment supporte pd.read_json).
                            } catch (_err) { /* affichage best-effort */ }
                            resolve();
                        };
                        reader.onerror = function() { resolve(); };
                        reader.readAsText(file);
                    });
                } catch (_outer) { /* best-effort */ }
                // Pas de return — le flow upload continue ci-dessous
            }

            // Task #33 / #8 Phase 1 — CSV en grille inline (parity .json).
            // L'affichage local précède l'upload backend : l'utilisateur
            // voit son fichier IMMÉDIATEMENT comme une grille triable,
            // pendant que le backend traite l'upload en parallèle.
            // Cohérent avec le pattern .afz.json plus haut, mais on ne
            // ``return`` PAS — le flow continue avec l'upload pour
            // obtenir le file_id que analyze_attachment utilisera côté
            // LLM (jusqu'à Phase 4 qui basculera en stats agrégées).
            if (file.name.match(/\.csv$/i) || file.type === 'text/csv') {
                try {
                    // Best-effort — si le rendu échoue, le flow upload
                    // continue quand même (au pire, l'user voit juste
                    // l'indicator "✓ prêt" comme avant).
                    await _displayCsvInGrid(file);
                } catch (csvErr) {
                    console.warn('[Iris] CSV inline render failed:', csvErr);
                }
            }

            // SSoT — Task #11 : extensions et taille max dérivées de
            // IRIS_CONFIG.uploadConfig (backend = _ALLOWED_EXTENSIONS +
            // _MAX_UPLOAD_SIZE). Validation par extension (le navigateur
            // ne fournit pas toujours un MIME type fiable — surtout sur
            // Windows / IE legacy / certaines versions Safari). Le
            // backend reste de toute façon la garde finale via
            // _UploadValidator.
            const _uploadCfg = (window.IRIS_CONFIG && window.IRIS_CONFIG.uploadConfig) || null;
            const _allowedExts = (_uploadCfg && Array.isArray(_uploadCfg.extensions))
                ? _uploadCfg.extensions
                : [];
            const maxSize = (_uploadCfg && typeof _uploadCfg.max_size_bytes === 'number')
                ? _uploadCfg.max_size_bytes
                : 10 * 1024 * 1024;  // fallback défensif si config manquante
            const maxSizeMb = (_uploadCfg && typeof _uploadCfg.max_size_mb === 'number')
                ? _uploadCfg.max_size_mb
                : Math.round(maxSize / (1024 * 1024));

            // Extraire l'extension du nom de fichier (insensible à la casse)
            const _extMatch = file.name.match(/\.[^.]+$/);
            const _fileExt = _extMatch ? _extMatch[0].toLowerCase() : '';

            if (!_allowedExts.includes(_fileExt)) {
                const _allowedDisplay = _allowedExts.length > 0
                    ? _allowedExts.join(', ')
                    : 'aucune extension configurée (contactez l\'administrateur)';
                addErrorMessage('Format non supporté. Utilisez ' + _allowedDisplay + '.');
                fileInput.value = '';
                return;
            }
            if (file.size > maxSize) {
                addErrorMessage('Fichier trop volumineux (max ' + maxSizeMb + ' Mo).');
                fileInput.value = '';
                return;
            }

            // Show upload indicator (Task #10 — créé via helper qui branche
            // la croix de retrait automatiquement)
            const uploadIndicator = _createUploadIndicator(file.name, 'envoi en cours…', null);
            appendToMessages(uploadIndicator);
            scrollToBottom();

            // Task #12 — bloque ``sendBtn`` pendant le fetch upload pour
            // éviter la race condition F6 (user clique Envoyer pendant
            // que l'upload est encore en vol → message partait sans le
            // file_id, pas encore setté dans dataset.fileId).
            _setUploadInFlight(true);

            try {
                // Task #23 — Upload XHR avec progress reporting. Le helper
                // _uploadFileToBackend ré-encapsule le flow fetch précédent
                // mais permet d'afficher un % pendant les gros uploads.
                // Throttling : on update l'indicator au max 4 fois/seconde
                // (250ms) pour éviter le DOM thrashing sur uploads rapides.
                var _lastProgressUpdate = 0;
                var onProgress = function(frac) {
                    var now = Date.now();
                    if (now - _lastProgressUpdate < 250 && frac < 1) return;
                    _lastProgressUpdate = now;
                    var pct = Math.round(frac * 100);
                    var statusText = pct >= 100
                        ? 'traitement…'  // upload terminé, serveur valide
                        : 'envoi en cours (' + pct + ' %)…';
                    _renderUploadIndicatorInto(uploadIndicator, file.name, statusText, null);
                };

                const data = await _uploadFileToBackend(file, onProgress);

                if (data.success && data.file_id) {
                    _renderUploadIndicatorInto(uploadIndicator, file.name, '✓ prêt', 'success');

                    // Task #34 / #8 Phase 2 — Pour les Excel (.xlsx/.xls),
                    // appeler l'endpoint backend pandas pour afficher en
                    // grille inline (multi-onglets). CSV est déjà rendu
                    // localement plus haut via _displayCsvInGrid (Task #33).
                    // Best-effort : si l'endpoint échoue, on continue le flow
                    // (l'user voit l'indicator « ✓ prêt » comme avant).
                    if (file.name.match(/\.(xlsx?|xls)$/i)) {
                        _displayXlsxInGrid(data.file_id, file.name).catch(function(err) {
                            console.warn('[Iris] XLSX inline render failed:', err);
                        });
                    }

                    // Auto-send analysis request
                    if (messageInput) {
                        messageInput.value = 'Analyse ce fichier : ' + file.name;
                    }
                    // Store file_id for next message
                    uploadIndicator.dataset.fileId = data.file_id;
                } else {
                    // Backend a retourné 2xx mais success=false (rare —
                    // typiquement validation post-write). Compat statut
                    // pour _addUploadErrorWithReport.
                    var dataErr = new Error(data.error || 'Upload failed');
                    dataErr.status = 200;  // 2xx avec success=false
                    throw dataErr;
                }
            } catch (err) {
                console.error('[Iris] Upload error:', err);
                _renderUploadIndicatorInto(uploadIndicator, file.name, '✗ erreur', 'error');
                // Task #15 — message + Signaler conditionnel (5xx/réseau).
                _addUploadErrorWithReport(err, file.name, 'iris_upload_pc');
            } finally {
                // Task #12 — réactive sendBtn quoi qu'il arrive (success,
                // erreur réseau, exception parsing). Sans finally, une
                // erreur silencieuse laisserait le bouton bloqué jusqu'à
                // refresh.
                _setUploadInFlight(false);
            }

            fileInput.value = '';
        }  // fin de _handleSelectedFile

        // Task #20 — Change handler : délègue au helper extracté pour
        // que drag & drop puisse réutiliser la même logique.
        fileInput.addEventListener('change', async function() {
            await _handleSelectedFile(this.files[0]);
        });

        // ── Task #20 — Drag & drop sur la fenêtre Iris ─────────────
        // État de l'art ChatGPT/Claude/Gemini : l'user dépose un
        // fichier n'importe où sur la page et l'app le traite comme
        // un upload PC. Un overlay full-screen apparaît pendant le
        // drag pour signaler la zone de dépôt.
        //
        // Implémentation par compteur (``_dragDepth``) plutôt que par
        // boolean : ``dragenter``/``dragleave`` firent récursivement
        // pour chaque enfant DOM traversé — un boolean simple ferait
        // disparaître l'overlay dès le 1er dragleave d'enfant. Le
        // compteur ne tombe à 0 que quand on quitte VRAIMENT la fenêtre.
        var _dragDepth = 0;
        var _dropOverlay = document.getElementById('dropOverlay');

        function _isFileDrag(e) {
            // Filtre les drags qui ne sont pas des fichiers (texte sélectionné,
            // élément DOM draggable, etc.) — sinon l'overlay s'afficherait
            // sur n'importe quel drag interne à la page.
            if (!e.dataTransfer) return false;
            var types = e.dataTransfer.types;
            if (!types) return false;
            // ``types`` est un DOMStringList en spec, un Array en pratique.
            for (var i = 0; i < types.length; i++) {
                if (types[i] === 'Files') return true;
            }
            return false;
        }

        window.addEventListener('dragenter', function(e) {
            if (!_isFileDrag(e)) return;
            e.preventDefault();
            _dragDepth += 1;
            if (_dragDepth === 1 && _dropOverlay) {
                _dropOverlay.hidden = false;
                _dropOverlay.classList.add('iris-drop-overlay--active');
            }
        });

        window.addEventListener('dragover', function(e) {
            if (!_isFileDrag(e)) return;
            // preventDefault sur dragover EST OBLIGATOIRE — sans ça,
            // le 'drop' ne firera pas (spec HTML5 DnD).
            e.preventDefault();
            e.dataTransfer.dropEffect = 'copy';
        });

        window.addEventListener('dragleave', function(e) {
            if (!_isFileDrag(e)) return;
            _dragDepth = Math.max(0, _dragDepth - 1);
            if (_dragDepth === 0 && _dropOverlay) {
                _dropOverlay.hidden = true;
                _dropOverlay.classList.remove('iris-drop-overlay--active');
            }
        });

        window.addEventListener('drop', async function(e) {
            if (!_isFileDrag(e)) return;
            e.preventDefault();
            _dragDepth = 0;
            if (_dropOverlay) {
                _dropOverlay.hidden = true;
                _dropOverlay.classList.remove('iris-drop-overlay--active');
            }
            // Task #24 — si LLM non configuré, ne pas traiter le drop
            // (cohérent avec le bouton trombone désactivé). On affiche
            // un message au lieu de tenter un upload qui échouera.
            if (uploadBtn && uploadBtn.disabled) {
                addErrorMessage("Iris n'est pas configuré — joindre un fichier indisponible.");
                return;
            }
            var files = e.dataTransfer && e.dataTransfer.files;
            if (!files || files.length === 0) return;
            // Pour cohérence avec le single-file flow existant : on
            // traite uniquement le PREMIER fichier déposé. Multi-file
            // upload est dans le backlog (#21 inclut paste multi, #20
            // pourrait étendre plus tard).
            await _handleSelectedFile(files[0]);
        });
    }

    // ── Feedback buttons ──

    document.addEventListener('click', function(e) {
        const feedbackBtn = e.target.closest('.iris-feedback-btn');
        if (!feedbackBtn) return;

        const feedback = feedbackBtn.dataset.feedback;
        const row = feedbackBtn.closest('.iris-feedback-row');
        if (!row) return;

        // Visual feedback
        row.querySelectorAll('.iris-feedback-btn').forEach(function(b) { b.disabled = true; });
        feedbackBtn.classList.add('selected');
        row.classList.add('voted');  // garde la row visible même sans hover

        // Send to API — SSoT ``postIrisFeedback`` (partagé avec la carte de
        // validation auto-feedback). ``onError`` ré-active les boutons pour retry.
        postIrisFeedback(feedback, {
            onError: function(err) {
                var msg = err && err.name === 'AbortError'
                    ? 'Délai dépassé pour le feedback. Réessayez.'
                    : 'Échec de l\'envoi du feedback. Réessayez.';
                addErrorMessage(msg);
                row.querySelectorAll('.iris-feedback-btn').forEach(function(b) {
                    b.disabled = false;
                });
                feedbackBtn.classList.remove('selected');
                row.classList.remove('voted');
            }
        });
    });

    // ── Bouton effacer la conversation ──

    const clearBtn = document.getElementById('clearConversationBtn');
    if (clearBtn) {
        clearBtn.addEventListener('click', clearConversation);
    }

    // ── Boutons d'exemples de questions ──

    document.querySelectorAll('.iris-example-btn').forEach(function(btn) {
        btn.addEventListener('click', function() {
            const prompt = this.dataset.prompt;
            if (prompt && messageInput) {
                messageInput.value = prompt;
                sendMessage();
            }
        });
    });
});
