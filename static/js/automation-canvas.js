/* ============================================================
 * Komptia automation canvas — Phase 3b-2 (editable canvas).
 *
 * Architecture (cf. docs/design_automations_dag.md §4.10) :
 * - WorkflowStore : state local (nodes, edges, meta, maps)
 * - RendererAdapter : wrapper Drawflow, decouple modele et lib rendu
 * - PaletteController : drag-start vers le canvas
 * - SaveIndicator : 4 etats (idle/saving/saved/error) avec queue
 * - PanelController : formulaire dynamique selon step_type
 *
 * Events Drawflow branches :
 * - nodeMoved     → debounced PUT /layout
 * - connectionCreated/Removed → POST/DELETE /edges
 * - nodeRemoved   → DELETE /steps (cascade les edges cote DB)
 * - nodeSelected  → render panel config
 *
 * CSP strict : aucun inline handler, tout via addEventListener.
 * XSRF : header X-Xsrftoken sur les fetch POST/PUT/DELETE.
 * ============================================================ */

(function () {
    'use strict';

    // ============================================================
    // Resolve KomptiaFormat helper (browser ``window`` OU Node ``require``
    // pour les tests JS via subprocess — cf. tests/unit/test_automation_canvas_js.py).
    // ============================================================
    var _KomptiaFormat = (typeof window !== 'undefined' && window.KomptiaFormat)
        ? window.KomptiaFormat
        : (typeof require === 'function' ? require('./format-helpers.js') : null);
    // Fail-fast en Node si require échoue (sinon les tests crashent sans message clair).
    // En browser, l'absence de helper crashera au 1er appel (TypeError lisible).
    if (typeof window === 'undefined' && !_KomptiaFormat) {
        throw new Error(
            'automation-canvas.js: format-helpers.js require failed. '
            + 'Le helper doit être au même niveau (static/js/format-helpers.js).'
        );
    }

    // ============================================================
    // Constants
    // ============================================================
    const NODE_WIDTH = 220;
    const NODE_HEIGHT = 120;
    const LAYOUT_GRID_COLS = 4;
    const LAYOUT_DEFAULT_X = 100;
    const LAYOUT_DEFAULT_Y = 80;

    // Debounces (ms). Trop court = spam, trop long = perte si navigation.
    const DEBOUNCE_LAYOUT_MS = 800;
    const DEBOUNCE_CONFIG_MS = 600;
    const DEBOUNCE_NAME_MS = 800;

    // Timeout du save indicator "Enregistre" avant retour "Pret"
    const SAVED_BANNER_MS = 2000;

    // Approx. line-height en px utilise pour normaliser les WheelEvent
    // dont deltaMode === 1 (DOM_DELTA_LINE) — surtout Firefox sur Linux.
    // Valeur volontairement constante : la lib n'a pas acces au lineHeight
    // calcule du container au moment ou l'event est cree.
    const WHEEL_LINE_HEIGHT_PX = 16;

    // ============================================================
    // Helpers XSRF + fetch
    // ============================================================
    function getCookie(name) {
        const value = '; ' + document.cookie;
        const parts = value.split('; ' + name + '=');
        if (parts.length === 2) return parts.pop().split(';').shift();
        return null;
    }

    function xsrfHeader() {
        const token = getCookie('_xsrf');
        return token ? { 'X-Xsrftoken': token } : {};
    }

    // Cluster-N 2026-05-26 — Optimistic concurrency multi-onglets.
    // Stocke la version courante (BDD) de l'automation. Envoyée en
    // `If-Match` sur PUT/PATCH/DELETE ; ré-hydratée depuis la réponse
    // (champ `version` ou header `ETag`). Le serveur retourne 409
    // Conflict avec `code: "version_conflict"` si autre onglet a sauvé
    // entre temps. Cf. doctrine `feedback_no_double_cap` (admin SSoT).
    let _automationVersion = null;
    const _versionListeners = new Set();
    function getAutomationVersion() {
        return _automationVersion;
    }
    function setAutomationVersion(v) {
        const parsed = (v === null || v === undefined) ? null : parseInt(v, 10);
        if (parsed !== null && (!Number.isFinite(parsed) || parsed < 0)) return;
        if (parsed === _automationVersion) return;
        _automationVersion = parsed;
        _versionListeners.forEach(function (fn) {
            try { fn(parsed); } catch (e) { console.error('[komptiaCanvas] version listener', e); }
        });
    }
    function onVersionChange(fn) {
        if (typeof fn === 'function') _versionListeners.add(fn);
        return function unsub() { _versionListeners.delete(fn); };
    }

    // Cluster-N (fix tempête 409 2026-06-10) — handler de RE-SYNCHRO sur
    // conflit de version genuine (cross-onglet). Enregistré par le canvas
    // (`initCanvas`) ; appelé depuis `_doFetch` sur 409. Au niveau module car
    // `apiFetch` est défini hors de `initCanvas`. Null tant que non enregistré
    // → fallback sur le toast throttlé.
    let _onVersionConflict = null;
    function setVersionConflictHandler(fn) {
        _onVersionConflict = (typeof fn === 'function') ? fn : null;
    }

    // Cluster-N — Throttle anti-spam quand plusieurs PUT échouent en
    // série avec 409 (autosave avec config invalide encore en mémoire).
    let _lastConflictToastAt = 0;
    function _maybeShowConflictToast() {
        const now = Date.now();
        if (now - _lastConflictToastAt < 3000) return;
        _lastConflictToastAt = now;
        if (typeof window !== 'undefined' && typeof window.showToast === 'function') {
            window.showToast(
                'Cette automatisation a été modifiée ailleurs (autre onglet ou '
                + 'session) — vue resynchronisée avec la version à jour. '
                + 'Vérifiez vos dernières modifications.',
                'warning'
            );
        }
    }
    function _readVersionFromResponse(response, json) {
        // Priorité au JSON (canonique) puis fallback ETag header.
        if (json && typeof json === 'object') {
            if (Number.isFinite(json.version)) return json.version;
            if (json.automation && Number.isFinite(json.automation.version)) {
                return json.automation.version;
            }
        }
        const etag = response.headers && response.headers.get
            ? response.headers.get('ETag') : null;
        if (!etag) return null;
        const cleaned = etag.replace(/^W\//, '').replace(/^"/, '').replace(/"$/, '');
        // GARDE anti-poisoning (fix « 409 autre onglet » fantôme, 2026-06-12) :
        // seuls les ETags ENTIÈREMENT numériques sont des versions
        // d'optimistic-lock (posés par `_set_etag_header` côté backend). Les
        // endpoints SANS ETag explicite (ex: GET /step-types) reçoivent l'ETag
        // par défaut de Tornado = sha1 hex du body ; quand ce hash commence
        // par des chiffres (« 21bef6… »), `parseInt` en extrayait « 21 » →
        // `_automationVersion` empoisonné → premier autosave en 409 fantôme,
        // la re-synchro re-fetch step-types → re-poison → boucle sans issue.
        // Borne 12 chars : une version est un petit entier, un sha1 fait 40.
        if (!/^\d{1,12}$/.test(cleaned)) return null;
        const parsed = parseInt(cleaned, 10);
        return Number.isFinite(parsed) ? parsed : null;
    }

    // Exécute UNE requête HTTP. Les mutations posent `If-Match` depuis la
    // version courante, LUE AU MOMENT DE L'EXÉCUTION — c'est ce qui rend la
    // sérialisation (`apiFetch`) efficace : une mutation enfilée derrière une
    // autre lit la version APRÈS le `setAutomationVersion` de la précédente.
    async function _doFetch(url, options) {
        options = options || {};
        options.credentials = 'same-origin';
        const baseHeaders = {
            'Content-Type': 'application/json',
            'X-Requested-With': 'XMLHttpRequest',
        };
        // Cluster-N — ajouter If-Match sur les mutations si on a une
        // version connue. Non-GET implicite (POST/PUT/PATCH/DELETE).
        const method = String(options.method || 'GET').toUpperCase();
        if (method !== 'GET' && _automationVersion !== null) {
            baseHeaders['If-Match'] = '"' + _automationVersion + '"';
        }
        options.headers = Object.assign(
            baseHeaders,
            options.headers || {},
            xsrfHeader()
        );
        const response = await fetch(url, options);
        const text = await response.text().catch(() => '');
        let json = null;
        if (text) {
            try { json = JSON.parse(text); } catch (_) { /* non-JSON body */ }
        }
        if (!response.ok) {
            const err = new Error(
                (json && json.error) || `HTTP ${response.status}`
            );
            err.status = response.status;
            err.body = json;
            // Cluster-N — 409 version_conflict.
            // Les mutations étant sérialisées (cf. `apiFetch`), un self-race en
            // session unique est désormais IMPOSSIBLE : un 409 restant signifie
            // un VRAI conflit cross-onglet/session. Ancien comportement = geler
            // la version → storm de 409 jusqu'au refresh manuel. Nouveau : on
            // adopte la version BDD (`current_version`) pour DÉBLOQUER la file,
            // puis on délègue la RE-SYNCHRO de la vue au handler enregistré
            // (re-hydratation depuis le serveur) → l'utilisateur repart de
            // l'état réel. JAMAIS de blind-retry de la mutation perdue
            // (anti-overwrite silencieux préservé : on ne ré-émet pas le PUT).
            if (response.status === 409 && json && json.code === 'version_conflict') {
                err.isVersionConflict = true;
                err.dbVersion = _readVersionFromResponse(response, json);
                if (err.dbVersion !== null) setAutomationVersion(err.dbVersion);
                if (_onVersionConflict) {
                    try {
                        _onVersionConflict(err.dbVersion);
                    } catch (e) {
                        console.error('[komptiaCanvas] resync handler', e);
                        _maybeShowConflictToast();
                    }
                } else {
                    _maybeShowConflictToast();
                }
            }
            throw err;
        }
        // Succès : ré-hydrate version depuis réponse (canonique).
        const newVersion = _readVersionFromResponse(response, json);
        if (newVersion !== null) setAutomationVersion(newVersion);
        return json;
    }

    // Sérialisation des MUTATIONS (Cluster-N / fix tempête 409 2026-06-10).
    // Toutes les mutations (méthode ≠ GET) passent par une file FIFO à un
    // seul slot : une mutation ne démarre qu'APRÈS le règlement de la
    // précédente, donc lit `_automationVersion` une fois que la mutation
    // d'avant a appelé `setAutomationVersion`. Sans cette file, deux autosaves
    // concurrents (config debounce 600 ms + POST /edges immédiat, ou 2 PUT
    // /steps) partaient avec le MÊME If-Match → le CAS serveur en rejetait un
    // en 409 EN SESSION UNIQUE (bug reproduit en live 2026-06-10). Les GET
    // restent parallèles (ils ne bumpent pas la version). La file ne se rompt
    // jamais : la rejection d'une mutation est avalée POUR LA FILE (mais bien
    // propagée au caller via `result`). Pas de croissance mémoire : seul le
    // dernier maillon (`_mutationChain`) est retenu.
    let _mutationChain = Promise.resolve();
    function apiFetch(url, options) {
        const method = String((options && options.method) || 'GET').toUpperCase();
        if (method === 'GET') return _doFetch(url, options);
        const run = function () { return _doFetch(url, options); };
        const result = _mutationChain.then(run, run);
        _mutationChain = result.then(function () {}, function () {});
        return result;
    }

    // ============================================================
    // Escape helpers (XSS defense dans les contenus de nodes + palette)
    // ============================================================
    function escapeHtml(str) {
        if (str === null || str === undefined) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#x27;');
    }

    function escapeAttr(str) {
        return escapeHtml(str);
    }

    // ============================================================
    // Debounce
    // ============================================================
    function createDebouncer(fn, delay) {
        let timer = null;
        // Real-review #5 cycle 23 : `lastPromise` permet à `flushAndWait`
        // de retourner la promise de la dernière exécution. Sans ça,
        // `flushAll().then(toggle)` lance le toggle AVANT que le PUT /steps
        // commit côté serveur → validate lit l'ancienne config → faux
        // STEP_CONFIG_INCOMPLETE. C'était la racine de BUG-A.
        let lastPromise = null;
        const wrapped = function () {
            const args = arguments;
            if (timer) clearTimeout(timer);
            timer = setTimeout(function () {
                timer = null;
                lastPromise = Promise.resolve(fn.apply(null, args));
            }, delay);
        };
        wrapped.flush = function () {
            if (timer) {
                clearTimeout(timer);
                timer = null;
                lastPromise = Promise.resolve(fn());
            }
        };
        /** Flush + return the last in-flight save promise. Awaitable. */
        wrapped.flushAndWait = function () {
            if (timer) {
                clearTimeout(timer);
                timer = null;
                lastPromise = Promise.resolve(fn());
            }
            return lastPromise || Promise.resolve();
        };
        wrapped.cancel = function () {
            if (timer) {
                clearTimeout(timer);
                timer = null;
            }
        };
        return wrapped;
    }

    // ============================================================
    // EventBus : event-bus minimal pour decouplage canvas <-> modules
    // externes (preview, futurs add-ons). 3 evenements emis :
    //   'step-selected'   { step_id, step }    apres render panel
    //   'step-deselected' {}                   apres hide panel
    //   'config-changed'  { step_id }          apres PUT config 2xx
    // ============================================================
    function createEventBus() {
        const listeners = new Map(); // event(string) → Set<fn>
        return {
            on: function (event, fn) {
                if (typeof event !== 'string' || typeof fn !== 'function') return;
                if (!listeners.has(event)) listeners.set(event, new Set());
                listeners.get(event).add(fn);
            },
            off: function (event, fn) {
                const set = listeners.get(event);
                if (set) set.delete(fn);
            },
            emit: function (event, payload) {
                const set = listeners.get(event);
                if (!set || set.size === 0) return;
                // Snapshot pour eviter les mutations concurrentes (un
                // listener peut faire bus.off() pendant l'emit).
                Array.from(set).forEach(function (fn) {
                    try { fn(payload); } catch (e) { console.error('[komptiaCanvas] listener', event, e); }
                });
            },
        };
    }

    // ============================================================
    // WorkflowStore : state local (JSON pur + maps d'index)
    // ============================================================
    function createWorkflowStore(automationId) {
        return {
            automationId: automationId,
            automation: null,
            steps: [],
            stepsById: new Map(),        // stepId (int) → step dict
            edges: [],                   // list d'edges {id, from_step_id, to_step_id, data_type, ...}
            // Index pour lookup O(1) drawflow <-> step et edges sur node.
            drawflowIdByStepId: new Map(),  // stepId → drawflow_id
            stepIdByDrawflowId: new Map(),  // drawflow_id → stepId
            edgeByKey: new Map(),           // `${from}->${to}` → edge.id (DB)
            nodeTypes: {},               // step_type → meta (config_schema, inputs...)
            unpositionedStepIds: [],
            loaded: false,
            editable: false,
            // Positions en attente d'autosave (collectees depuis nodeMoved).
            pendingPositions: {},
            // Set des stepIds en cours de suppression. Remplace l'ancien
            // flag global + setTimeout(50ms) qui avait des races sous
            // charge CPU ou suppressions concurrentes. Chaque entree
            // vit tout le temps du DELETE /steps en vol, donc pas de
            // fenetre d'echappement pour les cascade `connectionRemoved`.
            removingStepIds: new Set(),
            // Flag bloquant pendant un rollback visuel (addConnection →
            // connectionCreated → POST echoue → removeConnection →
            // connectionRemoved → DELETE ... boucle potentielle).
            isRollingBack: false,
            // Panel config : step actuellement edite.
            selectedStepId: null,
        };
    }

    function rebuildIndexes(store) {
        store.stepsById = new Map(store.steps.map(function (s) { return [s.id, s]; }));
        store.edgeByKey = new Map(store.edges.map(function (e) {
            return [e.from_step_id + '->' + e.to_step_id, e.id];
        }));
    }

    // ============================================================
    // Layout auto : pose les nodes unpositionnes APRES la bounding-box
    // ============================================================
    function assignAutoLayout(steps, unpositionedIds) {
        const unpositioned = new Set(unpositionedIds);
        let maxY = LAYOUT_DEFAULT_Y - NODE_HEIGHT;
        for (const step of steps) {
            if (unpositioned.has(step.id)) continue;
            const y = step.layout_y ?? LAYOUT_DEFAULT_Y;
            if (y > maxY) maxY = y;
        }
        const startY = maxY + NODE_HEIGHT;
        let row = 0;
        for (const step of steps) {
            if (!unpositioned.has(step.id)) continue;
            step.layout_x = LAYOUT_DEFAULT_X + (row % LAYOUT_GRID_COLS) * NODE_WIDTH;
            step.layout_y = startY + Math.floor(row / LAYOUT_GRID_COLS) * NODE_HEIGHT;
            row += 1;
        }
    }

    // ============================================================
    // Save indicator : 4 etats avec queue
    // ============================================================
    function createSaveIndicator() {
        const el = document.getElementById('komptia-save-indicator');
        let inflight = 0;
        let lastError = null;
        let savedTimer = null;

        function render() {
            if (!el) return;
            if (lastError) {
                el.textContent = 'Erreur : ' + lastError;
                el.dataset.state = 'error';
                return;
            }
            if (inflight > 0) {
                el.textContent = 'Enregistrement...';
                el.dataset.state = 'saving';
                return;
            }
            if (savedTimer) {
                el.textContent = 'Enregistre';
                el.dataset.state = 'saved';
                return;
            }
            el.textContent = 'Pret';
            el.dataset.state = 'idle';
        }

        return {
            /** Marquer une operation comme demarree. */
            start: function () {
                inflight += 1;
                lastError = null;
                if (savedTimer) { clearTimeout(savedTimer); savedTimer = null; }
                render();
            },
            /** Marquer une operation comme terminee avec succes. */
            success: function () {
                inflight = Math.max(0, inflight - 1);
                if (inflight === 0 && !lastError) {
                    if (savedTimer) clearTimeout(savedTimer);
                    savedTimer = setTimeout(function () {
                        savedTimer = null;
                        render();
                    }, SAVED_BANNER_MS);
                }
                render();
            },
            /** Marquer une operation comme terminee avec erreur. */
            fail: function (message) {
                inflight = Math.max(0, inflight - 1);
                lastError = (message && String(message).slice(0, 60)) || 'operation echouee';
                render();
            },
            /** Efface les erreurs (apres retry reussi). */
            clearError: function () {
                lastError = null;
                render();
            },
        };
    }

    // ============================================================
    // UX erreur : overlay avec bouton Reessayer
    // ============================================================
    // DAG-4 — l'overlay #komptia-canvas-empty est RÉUTILISÉ pour afficher les
    // erreurs de chargement : showCanvasError détruit son contenu d'aide
    // (« Canvas vide / Glissez une étape »). On mémorise ce HTML d'aide ORIGINAL
    // une seule fois pour pouvoir le RESTAURER en sortie d'erreur (retry, retour
    // à l'état vide) — sinon l'overlay reste blanc.
    let _emptyHelpHTML = null;
    function restoreEmptyHelp(empty) {
        empty = empty || document.getElementById('komptia-canvas-empty');
        if (!empty) return;
        empty.style.pointerEvents = '';
        if (empty.classList.contains('komptia-canvas-error-overlay')) {
            empty.classList.remove('komptia-canvas-error-overlay');
            if (_emptyHelpHTML !== null) empty.innerHTML = _emptyHelpHTML;
        }
    }

    function showCanvasError(messageText, retryFn) {
        const empty = document.getElementById('komptia-canvas-empty');
        if (!empty) return;

        // DAG-4 — capturer le contenu d'aide AVANT de le détruire (une seule
        // fois : si on est déjà en état erreur, ne pas écraser le cache).
        if (_emptyHelpHTML === null && !empty.classList.contains('komptia-canvas-error-overlay')) {
            _emptyHelpHTML = empty.innerHTML;
        }

        empty.classList.remove('hidden');
        empty.classList.add('komptia-canvas-error-overlay');
        empty.style.pointerEvents = 'auto';

        while (empty.firstChild) empty.removeChild(empty.firstChild);

        const wrapper = document.createElement('div');
        wrapper.className = 'text-center';

        const title = document.createElement('p');
        title.className = 'text-lg font-semibold text-red-600 dark:text-red-400';
        title.textContent = 'Erreur de chargement';
        wrapper.appendChild(title);

        const detail = document.createElement('p');
        detail.className = 'text-sm text-gray-500 dark:text-gray-400 mt-1';
        detail.textContent = messageText;
        wrapper.appendChild(detail);

        // U6 — actions row : Reessayer + Signaler bug.
        const actions = document.createElement('div');
        actions.className = 'mt-3 flex items-center justify-center gap-2';

        if (typeof retryFn === 'function') {
            const btn = document.createElement('button');
            btn.type = 'button';
            btn.className = 'px-4 py-2 bg-brand-600 text-white rounded hover:bg-brand-700';
            btn.textContent = 'Reessayer';
            btn.addEventListener('click', function () {
                // DAG-4 — restaure le texte d'aide détruit avant de relancer,
                // pour que le retour à l'état vide ne soit pas un overlay blanc.
                restoreEmptyHelp(empty);
                empty.classList.add('hidden');
                retryFn();
            });
            actions.appendChild(btn);
        }

        // U6 — bouton Signaler contextuel : appelle feedback-reporter global
        // (feedback-reporter.js expose window.komptiaReportFeedback). Le rapport
        // pre-rempli avec context="automation_canvas" pour faciliter le tri.
        if (typeof window.komptiaReportFeedback === 'function') {
            const reportBtn = document.createElement('button');
            reportBtn.type = 'button';
            reportBtn.className = 'px-4 py-2 border border-gray-300 dark:border-gray-700 text-gray-700 dark:text-gray-300 rounded hover:bg-gray-50 dark:hover:bg-gray-800';
            reportBtn.textContent = 'Signaler';
            reportBtn.addEventListener('click', function () {
                try {
                    window.komptiaReportFeedback({
                        context: 'automation_canvas',
                        message: messageText,
                    });
                } catch (_) { /* feedback-reporter peut echouer silencieusement */ }
            });
            actions.appendChild(reportBtn);
        }

        if (actions.children.length > 0) wrapper.appendChild(actions);
        empty.appendChild(wrapper);
    }

    function showToast(message, type) {
        if (typeof window.showToast === 'function') {
            window.showToast(message, type || 'info');
        } else {
            // Fallback CSP-safe : console + pas de silent failure.
            if (type === 'error') console.error('Komptia:', message);
            else console.log('Komptia:', message);
        }
    }

    // ============================================================
    // Drop position : convertit (clientX, clientY) → (canvasX, canvasY)
    // en tenant compte du zoom et pan Drawflow.
    //
    // On utilise le container stable (`editor.container`, le div racine
    // qu'on passe au constructeur Drawflow) plutot que `editor.precanvas`
    // qui est degeneree (bbox 0) quand le canvas est vide. Puis on
    // decompose explicitement : world_coord = (client - container) / zoom
    // - translate_panned. Drawflow applique `transform: translate(Xpx,Ypx)
    // scale(Z)` sur precanvas, donc on compense canvas_x/canvas_y.
    // ============================================================
    function computeDropPosition(event, editor) {
        const zoom = (editor && editor.zoom) || 1;

        // PRIMARY : formule miroir de Drawflow interne — `precanvas.
        // getBoundingClientRect()` retourne les coordonnees POST-transform,
        // donc compense automatiquement le pan ET le scale (peu importe
        // le ``transform-origin`` choisi par Drawflow). C'est la seule
        // formule correcte a n'importe quel zoom.
        const precanvas = editor && editor.precanvas;
        if (precanvas && typeof precanvas.getBoundingClientRect === 'function') {
            const rect = precanvas.getBoundingClientRect();
            // Garde-fou : un precanvas degenere (width/height === 0) peut
            // exister avant que Drawflow n'ait un enfant DOM. ``rect.left``
            // tombe alors au coin top-left du container vide, ce qui
            // resterait correct, mais on prefere le fallback container
            // pour ne pas dependre d'un detail d'impl Drawflow.
            if (rect.width > 0 && rect.height > 0) {
                return {
                    x: Math.round((event.clientX - rect.left) / zoom),
                    y: Math.round((event.clientY - rect.top) / zoom),
                };
            }
        }

        // FALLBACK : container + canvas_x. Correct a zoom=1 mais peut
        // diverger a zoom != 1 si ``transform-origin`` est centre (50% 50%).
        // Seulement utilise quand precanvas est introuvable / vide.
        const container = (editor && editor.container) || (precanvas && precanvas.parentElement);
        if (!container || typeof container.getBoundingClientRect !== 'function') {
            return { x: 0, y: 0 };
        }
        const rect = container.getBoundingClientRect();
        const containerX = event.clientX - rect.left;
        const containerY = event.clientY - rect.top;
        const panX = (typeof editor.canvas_x === 'number') ? editor.canvas_x : 0;
        const panY = (typeof editor.canvas_y === 'number') ? editor.canvas_y : 0;
        return {
            x: Math.round((containerX - panX) / zoom),
            y: Math.round((containerY - panY) / zoom),
        };
    }

    // ============================================================
    // Validation client des edges (self-loop, type compat, fan-in mix)
    // ============================================================
    function validateEdgeClient(store, fromStepId, toStepId) {
        if (fromStepId === toStepId) {
            return { ok: false, error: 'Une etape ne peut pas se connecter a elle-meme.' };
        }
        const from = store.stepsById.get(fromStepId);
        const to = store.stepsById.get(toStepId);
        if (!from || !to) {
            return { ok: false, error: 'Etape introuvable.' };
        }
        const fromMeta = store.nodeTypes[from.step_type] || {};
        const toMeta = store.nodeTypes[to.step_type] || {};
        const fromOutputs = fromMeta.outputs || [];
        const toInputs = toMeta.inputs || [];
        if (fromMeta.is_sink || fromOutputs.length === 0) {
            return { ok: false, error: 'Cette etape ne peut rien envoyer en sortie.' };
        }
        if (toMeta.is_source || toInputs.length === 0) {
            return { ok: false, error: 'Cette etape ne peut rien recevoir en entree.' };
        }
        // Determine data_type : l'intersection de sortie source et entree cible.
        const commonTypes = fromOutputs.filter(function (t) { return toInputs.indexOf(t) !== -1; });
        if (commonTypes.length === 0) {
            return {
                ok: false,
                error: 'Types incompatibles (' + fromOutputs.join(',') + ' vs ' + toInputs.join(',') + ')',
            };
        }
        // Fan-in mixed types : si le noeud cible a deja des edges entrants
        // d'un autre type, on ne peut pas melanger.
        const existingIncomingTypes = store.edges
            .filter(function (e) { return e.to_step_id === toStepId; })
            .map(function (e) { return e.data_type; });
        for (const t of existingIncomingTypes) {
            if (commonTypes.indexOf(t) === -1) {
                return {
                    ok: false,
                    error: 'Cette etape recoit deja du ' + t + ', ne peut pas recevoir du ' + commonTypes[0] + '.',
                };
            }
        }
        const chosenType = existingIncomingTypes[0] || commonTypes[0];
        // Check duplicate edge
        if (store.edgeByKey.has(fromStepId + '->' + toStepId)) {
            return { ok: false, error: 'Connexion deja existante.' };
        }
        return { ok: true, data_type: chosenType };
    }

    // ============================================================
    // RendererAdapter : wrapper Drawflow
    // ============================================================
    function createRendererAdapter(container, options) {
        if (typeof window.Drawflow !== 'function') {
            throw new Error('Drawflow library not loaded');
        }
        const editor = new window.Drawflow(container);
        // Capture du flag editable une seule fois — évite des accès
        // ``options.editable`` éparpillés (et le bug ``editable is not
        // defined`` qui crashait le listener keydown global de la page
        // sur chaque frappe quand on était sur /automations/N/edit).
        const editable = !!(options && options.editable);
        editor.reroute = true;
        editor.curvature = 0.35;
        // Plage de zoom élargie. Drawflow defaults : 0.5 → 1.6. On va
        // 0.2 → 2.0 pour les DAG larges (vue d'ensemble) et la lecture
        // détaillée. Les bugs initialement observés à zoom < 0.5 (drop
        // qui tombe au mauvais endroit + pan souris ignoré sur la zone
        // visible réduite du precanvas) sont fixés en amont :
        //  - ``computeDropPosition`` utilise ``precanvas.getBoundingClientRect()``
        //    qui reflète le scale appliqué → coords correctes à tout zoom.
        //  - le mousedown listener capture phase re-dispatche un event
        //    synthétique sur le precanvas pour que le pan natif Drawflow
        //    accepte les clics dans la marge "vide" autour du precanvas
        //    réduit visuellement.
        editor.zoom_min = 0.2;
        editor.zoom_max = 2.0;
        editor.start();
        editor.editor_mode = editable ? 'edit' : 'view';

        // Pan souris : Drawflow accepte le pan-canvas UNIQUEMENT si
        // ``e.target.classList[0]`` vaut "parent-drawflow" ou "drawflow".
        // À zoom < 1 le precanvas est visuellement réduit (transform:
        // scale) et la zone "vide" autour reçoit ``e.target = #komptia-
        // canvas`` qui a "w-full" comme première classe — Drawflow
        // rejette → pan ignoré. Symptôme user : "ça marche dans la zone
        // centrale, le reste non" / "ça marche que au trackpad".
        //
        // Solution : on intercepte le mousedown EN CAPTURE PHASE (avant
        // Drawflow, listener bubble par défaut). Quand l'event tombe en
        // zone vide, on simule EXACTEMENT ce que Drawflow.click() fait
        // pour le case "drawflow" — mutation directe de ses variables
        // d'état interne. Drawflow.position() (mousemove) verra ensuite
        // ``editor_selected = true`` et pannera normalement. Le mouseup
        // natif Drawflow.dragEnd() commit le canvas_x final.
        //
        // Pourquoi pas un MouseEvent synthétique re-dispatché ? Tenté.
        // Pas fiable (isTrusted, event ordering, capture-vs-bubble du
        // listener Drawflow). La mutation directe est plus prévisible.
        container.addEventListener('mousedown', function (e) {
            if (e.button !== 0) return;
            if (!editor.precanvas) return;
            const t = e.target;
            // Cas où Drawflow gère nativement : on ne touche pas.
            //
            // ⚠ ATTENTION subtile : Drawflow ajoute la classe
            // ``parent-drawflow`` au container dans ``start()``, mais
            // SANS la mettre en 1ère position — le container
            // ``#komptia-canvas`` a déjà ``class="w-full h-full"``
            // (Tailwind), donc post-start :
            //    classList = ["w-full", "h-full", "parent-drawflow"]
            // Drawflow check ``classList[0]`` STRICT (pas contains) :
            //    classList[0] === "parent-drawflow" → FALSE
            // C'est pour ça que Drawflow rejette le pan dans la zone
            // vide à zoom < 1. On utilise EXACTEMENT le même critère
            // que Drawflow (classList[0] strict) pour identifier les
            // cas où Drawflow gère lui-même → précanvas a
            // ``classList = ["drawflow"]`` strict (créé par Drawflow,
            // donc "drawflow" est en 1ère position).
            if (t === editor.precanvas) return;
            if (t.classList && (
                t.classList[0] === 'drawflow'
                || t.classList[0] === 'parent-drawflow'
            )) return;
            if (t.closest && (
                t.closest('.drawflow-node')
                || t.closest('.connection')
                || t.closest('.drawflow-delete')
                || t.closest('.input')
                || t.closest('.output')
            )) return;

            // Zone "vide" — réplique du case "drawflow" de Drawflow.click()
            // (cf. drawflow.min.js : désélection + flag editor_selected
            // + capture pos_x/pos_y). Drawflow.position() et .dragEnd()
            // continuent leur cycle natif sur ces variables.
            if (editor.node_selected) {
                editor.node_selected.classList.remove('selected');
                try { editor.dispatch('nodeUnselected', true); } catch (_) { /* swallow */ }
                editor.node_selected = null;
            }
            if (editor.connection_selected) {
                editor.connection_selected.classList.remove('selected');
                if (typeof editor.removeReouteConnectionSelected === 'function') {
                    try { editor.removeReouteConnectionSelected(); } catch (_) { /* swallow */ }
                }
                editor.connection_selected = null;
            }
            editor.first_click = editor.precanvas;
            editor.ele_selected = editor.precanvas;
            editor.editor_selected = true;
            editor.pos_x = e.clientX;
            editor.pos_x_start = e.clientX;
            editor.pos_y = e.clientY;
            editor.pos_y_start = e.clientY;
            try { editor.dispatch('clickEnd', e); } catch (_) { /* swallow */ }
            // On NE bloque PAS la propagation : Drawflow.click() verra
            // l'event original mais son switch ne match aucun case
            // (e.target.classList[0] = "w-full"), donc il ne touche
            // pas à nos mutations. Si on stopPropageait, on bloquerait
            // aussi des handlers qui dépendent du dispatch click natif.
            e.preventDefault();
        }, true);  // capture=true → fire AVANT le listener Drawflow

        // ────────────────────────────────────────────
        // Suppression clavier (Delete / Backspace) sur la connexion ou
        // le node selectionne. Drawflow expose `editor.connection_selected`
        // / `editor.node_selected` mais ne branche AUCUN keybinding —
        // il fallait un menu contextuel ou un bouton dedie. Ici on
        // ajoute le pattern standard des editeurs de graphes : selection
        // + Delete = suppression. Les events `connectionRemoved` /
        // `nodeRemoved` Drawflow se propagent normalement → DELETE
        // backend deja branche plus bas.
        //
        // Garde-fou critique : ne PAS declencher si le focus est sur un
        // input/textarea/contenteditable (sinon Backspace dans le panel
        // de droite supprimerait un node !). On verifie via
        // `document.activeElement` qui est l'element focus courant.
        document.addEventListener('keydown', function (e) {
            if (!editable) return;
            const isDelete = (e.key === 'Delete' || e.key === 'Backspace');
            const isToggleType = (e.key === 't' || e.key === 'T');
            if (!isDelete && !isToggleType) return;
            // Skip si focus sur un editable — l'user tape, pas supprime/toggle.
            const active = document.activeElement;
            if (active) {
                const tag = (active.tagName || '').toLowerCase();
                if (tag === 'input' || tag === 'textarea' || tag === 'select') return;
                if (active.isContentEditable) return;
            }
            // Skip si focus est hors du conteneur de l'editeur (un autre
            // composant de la page peut consommer la touche legitimement).
            if (!container.contains(active) && active !== document.body) {
                return;
            }

            // Toggle type d'edge (data ↔ trigger) sur edge selectionnee.
            // Use case Feature 2 : permettre a l'user de basculer une
            // connexion entre « transmission de donnees » et « signal de
            // sequencement pur » sans recreer la connexion. PUT /edges/:id.
            if (isToggleType) {
                if (!editor.connection_selected) return;
                const conn = editor.connection_selected.parentElement;
                if (!conn) return;
                const cls = conn.className.baseVal || conn.getAttribute('class') || '';
                const matchOut = cls.match(/node_out_node-(\d+)/);
                const matchIn = cls.match(/node_in_node-(\d+)/);
                if (!matchOut || !matchIn) return;
                const fromDfId = parseInt(matchOut[1], 10);
                const toDfId = parseInt(matchIn[1], 10);
                const fromStepId = store.stepIdByDrawflowId.get(fromDfId);
                const toStepId = store.stepIdByDrawflowId.get(toDfId);
                if (fromStepId == null || toStepId == null) return;
                const edgeId = store.edgeByKey.get(fromStepId + '->' + toStepId);
                if (!edgeId) return;
                const edge = store.edges.find(function (e) { return e.id === edgeId; });
                if (!edge) return;
                // Toggle : si actuellement trigger → bascule au premier
                // type data compatible (intersection outputs/inputs hors
                // trigger). Si data → bascule a trigger (toujours valide
                // tant que les 2 types le supportent).
                const fromMeta = store.nodeTypes[(store.stepsById.get(fromStepId) || {}).step_type];
                const toMeta = store.nodeTypes[(store.stepsById.get(toStepId) || {}).step_type];
                if (!fromMeta || !toMeta) return;
                let newType;
                if (edge.data_type === 'trigger') {
                    const fromOuts = (fromMeta.outputs || []).filter(function (t) { return t !== 'trigger'; });
                    const toIns = (toMeta.inputs || []).filter(function (t) { return t !== 'trigger'; });
                    const common = fromOuts.filter(function (t) { return toIns.indexOf(t) !== -1; });
                    if (common.length === 0) {
                        showToast('Aucun type data commun entre ces 2 etapes.', 'error');
                        return;
                    }
                    newType = common[0];
                } else {
                    if ((fromMeta.outputs || []).indexOf('trigger') === -1
                        || (toMeta.inputs || []).indexOf('trigger') === -1) {
                        showToast('Une de ces etapes ne supporte pas le mode signal.', 'error');
                        return;
                    }
                    newType = 'trigger';
                }
                e.preventDefault();
                saveIndicator.start();
                api.put(
                    '/api/automations/' + automationId + '/edges/' + edgeId,
                    { data_type: newType }
                ).then(function () {
                    edge.data_type = newType;
                    saveIndicator.success();
                    showToast(
                        'Type de connexion : ' + (newType === 'trigger' ? 'signal seul' : newType),
                        'info'
                    );
                }).catch(function (err) {
                    saveIndicator.fail((err && err.message) || 'echec');
                    // P5.4 (audit 2026-05-26) — Avant : toast tronqué qui
                    // jetait ``err.body.errors`` (les erreurs structurées du
                    // DAG validator côté serveur). Maintenant : on aligne sur
                    // le pattern existant ligne 2141-2156 (appShowErrors) qui
                    // affiche la liste détaillée dans une modal.
                    var serverErrors = (err && err.body && err.body.errors) || [];
                    if (serverErrors.length && window.appShowErrors) {
                        window.appShowErrors(
                            (err && err.body && err.body.error) || 'Bascule type échec',
                            serverErrors
                        );
                    } else {
                        showToast(
                            'Bascule type echec : ' + ((err && err.message) || 'inconnue'),
                            'error'
                        );
                    }
                });
                return;
            }

            // --- Delete / Backspace : suppression ---
            if (editor.connection_selected) {
                // Recuperer les IDs depuis les classes du SVG de connexion.
                // Drawflow attache les classes ``node_in_node-X`` et
                // ``node_out_node-Y`` sur le SVG ``.connection``.
                const conn = editor.connection_selected.parentElement;
                if (!conn) return;
                const cls = conn.className.baseVal || conn.getAttribute('class') || '';
                const matchOut = cls.match(/node_out_node-(\d+)/);
                const matchIn = cls.match(/node_in_node-(\d+)/);
                if (!matchOut || !matchIn) return;
                const outId = parseInt(matchOut[1], 10);
                const inId = parseInt(matchIn[1], 10);
                // Drawflow stocke aussi les classes des slots (output_class,
                // input_class). Pour un graphe Komptia mono-output/mono-input,
                // c'est `output_1` / `input_1` par defaut (cf. addConnection).
                const matchOutSlot = cls.match(/(output_\d+)/);
                const matchInSlot = cls.match(/(input_\d+)/);
                const outSlot = matchOutSlot ? matchOutSlot[1] : 'output_1';
                const inSlot = matchInSlot ? matchInSlot[1] : 'input_1';
                e.preventDefault();
                try {
                    editor.removeSingleConnection(outId, inId, outSlot, inSlot);
                } catch (err) {
                    /* swallow — le DELETE ne sera juste pas trigger */
                }
                return;
            }
            if (editor.node_selected) {
                // Confirm pour eviter les suppressions accidentelles
                // (Backspace est facile a hit). nodeRemoved cascade les
                // edges en BDD via DELETE CASCADE FK.
                const dfId = editor.node_selected.id
                    && editor.node_selected.id.replace(/^node-/, '');
                if (!dfId) return;
                // Cluster-O 2026-05-26 — appConfirm (modal Komptia stylé)
                // remplace window.confirm (browser-native non-stylable).
                // preventDefault AVANT le confirm async pour bloquer
                // l'event Backspace pendant que l'utilisateur lit.
                // Si appConfirm n'est pas chargé → init JS cassée, on
                // log et abort (ne PAS bloquer avec dialog natif).
                e.preventDefault();
                if (typeof window.appConfirm !== 'function') {
                    console.error('[automation-canvas] appConfirm absent — abort delete');
                    return;
                }
                window.appConfirm(
                    'Supprimer cette etape ? (action definitive)',
                    'Supprimer l\'etape'
                ).then(function (ok) {
                    if (!ok) return;
                    try {
                        editor.removeNodeId('node-' + dfId);
                    } catch (err) {
                        /* swallow */
                    }
                });
            }
        });

        // Pan 2D au scroll trackpad (2 doigts) ou molette souris.
        // Drawflow natif gere le ctrlKey (zoom via zoom_enter), mais ne fait
        // rien sur un wheel sans modifier — on profite de cette fenetre pour
        // panner en mutant directement editor.canvas_x/y + le transform de
        // .precanvas (meme format que Drawflow utilise dans pointermove_handler
        // et zoom_refresh : "translate(Xpx, Ypx) scale(Z)"). Le pinch trackpad
        // macOS et ctrl+wheel desktop arrivent avec ctrlKey=true et restent
        // donc geres par le zoom natif Drawflow.
        container.addEventListener('wheel', function (e) {
            if (e.ctrlKey || !editor.precanvas) return;

            // Normaliser deltaMode : Firefox Linux peut envoyer des "lignes"
            // (deltaMode=1) ou des "pages" (deltaMode=2). Sans conversion, le
            // pan serait invisible (lignes) ou par sauts (pages).
            let dx = e.deltaX;
            let dy = e.deltaY;
            if (e.deltaMode === 1) {
                dx *= WHEEL_LINE_HEIGHT_PX;
                dy *= WHEEL_LINE_HEIGHT_PX;
            } else if (e.deltaMode === 2) {
                dx *= container.clientWidth;
                dy *= container.clientHeight;
            }
            // U7 — Safari trackpad clamp. Sur certains setups Safari/macOS,
            // un swipe trackpad rapide peut emettre un single delta enorme
            // (>5000px) qui fait sauter le canvas hors viewport. Clamp au
            // facteur empirique : 2x la dimension visible suffit pour les
            // pans humains rapides mais bloque les valeurs aberrantes.
            // Sur viewport <600px (rare), 1200px reste large pour 1 swipe ;
            // sur 4K (3840px), 7680px = pas un saut visible.
            const MAX_PAN_DELTA_FACTOR = 2;
            const MAX_DELTA_X = container.clientWidth * MAX_PAN_DELTA_FACTOR;
            const MAX_DELTA_Y = container.clientHeight * MAX_PAN_DELTA_FACTOR;
            if (dx > MAX_DELTA_X || dx < -MAX_DELTA_X || dy > MAX_DELTA_Y || dy < -MAX_DELTA_Y) {
                // Telemetry minimale (dev/qa : visible dans console F12).
                // Si le clamp se declenche en prod = bug Safari driver
                // toujours present, ou nouveau navigateur exotique.
                if (typeof console !== 'undefined' && console.debug) {
                    console.debug('[automation-canvas] wheel pan delta clamped',
                        { dx: dx, dy: dy, maxX: MAX_DELTA_X, maxY: MAX_DELTA_Y });
                }
                if (dx > MAX_DELTA_X) dx = MAX_DELTA_X;
                else if (dx < -MAX_DELTA_X) dx = -MAX_DELTA_X;
                if (dy > MAX_DELTA_Y) dy = MAX_DELTA_Y;
                else if (dy < -MAX_DELTA_Y) dy = -MAX_DELTA_Y;
            }
            if (dx === 0 && dy === 0) return;

            // Suppress page-level scroll behind the canvas. Requires
            // { passive: false } on the listener registration below.
            e.preventDefault();

            // Convention "natural scrolling" : deltaY > 0 (swipe vers le bas
            // sur trackpad) → la camera descend, le contenu remonte
            // visuellement, donc canvas_y diminue. Idem pour X.
            editor.canvas_x -= dx;
            editor.canvas_y -= dy;
            editor.precanvas.style.transform =
                'translate(' + editor.canvas_x + 'px, ' + editor.canvas_y + 'px) scale(' + editor.zoom + ')';

            // Mirror du dispatch que Drawflow emet quand l'utilisateur
            // drag-pan a la souris — keep external listeners coherents.
            if (typeof editor.dispatch === 'function') {
                try {
                    editor.dispatch('translate', { x: editor.canvas_x, y: editor.canvas_y });
                } catch (err) {
                    // Un listener externe ne doit pas casser le pan : on
                    // log a 'warn' (pas error) car le pan visuel a deja
                    // applique avec succes.
                    console.warn('Komptia: dispatch translate failed', err);
                }
            }
        }, { passive: false });

        function renderNodeHtml(step, meta) {
            meta = meta || {};
            const iconClass = meta.icon ? 'bi bi-' + meta.icon : 'bi bi-gear';
            const category = meta.category || 'autre';
            const label = meta.label || step.step_type;
            const safeLabel = escapeHtml(label);
            const safeName = escapeHtml(step.name || '?');
            return `
                <div class="komptia-node-category-${escapeAttr(category)}">
                    <div class="komptia-node-header">
                        <span class="komptia-node-icon"><i class="${escapeAttr(iconClass)}"></i></span>
                        <span class="komptia-node-name">${safeName}</span>
                    </div>
                    <div class="komptia-node-body">${safeLabel}</div>
                </div>
            `;
        }

        return {
            editor: editor,

            clear: function () { editor.clear(); },

            /**
             * Ajoute un node Drawflow + renvoie son drawflow_id (numerique).
             * Les ports IN/OUT sont determines par la signature du type.
             */
            addNode: function (step, meta) {
                meta = meta || {};
                // Consolide a 1 input + 1 output visuel par node (UX claire).
                // Le `data_type` reel de l'edge est negocie au moment de la
                // creation par `validateConnection` (intersection des types
                // compatibles entre source.outputs et target.inputs). Pas
                // de cercle dedie par data_type — l'ancien comportement
                // (1 cercle par type, ex: 3 cercles input pour `email`)
                // etait visuellement encombre quand un node accepte plusieurs
                // data_types. L'edge porte son type ; le node ne s'en
                // soucie pas visuellement.
                const nInputs = meta.is_source ? 0 : 1;
                const nOutputs = meta.is_sink ? 0 : 1;
                const posX = step.layout_x ?? LAYOUT_DEFAULT_X;
                const posY = step.layout_y ?? LAYOUT_DEFAULT_Y;
                const dfId = editor.addNode(
                    'step_' + step.id,
                    nInputs,
                    nOutputs,
                    posX,
                    posY,
                    'komptia-step-' + step.id,
                    { stepId: step.id, stepType: step.step_type },
                    renderNodeHtml(step, meta)
                );
                return dfId;
            },

            addConnection: function (fromDfId, toDfId) {
                try {
                    editor.addConnection(fromDfId, toDfId, 'output_1', 'input_1');
                } catch (e) {
                    console.error('Komptia: addConnection failed', e);
                }
            },

            /**
             * Met a jour le HTML d'un node deja rendu (name change via panel).
             * Drawflow ne propose pas d'API propre, on edit le DOM direct.
             */
            updateNodeContent: function (stepId, step, meta) {
                const el = container.querySelector('.komptia-step-' + stepId);
                if (!el) return;
                const nameEl = el.querySelector('.komptia-node-name');
                if (nameEl) nameEl.textContent = step.name || '?';
            },

            removeNode: function (stepId) {
                const dfId = findDrawflowIdByStepId(editor, stepId);
                if (dfId !== null) {
                    editor.removeNodeId('node-' + dfId);
                }
            },

            removeConnection: function (fromDfId, toDfId) {
                try {
                    editor.removeSingleConnection(fromDfId, toDfId, 'output_1', 'input_1');
                } catch (e) {
                    console.error('Komptia: removeConnection failed', e);
                }
            },

            setNodeStatus: function (stepId, status) {
                const el = container.querySelector('.komptia-step-' + stepId);
                if (!el) return;
                el.classList.remove(
                    'komptia-status-success',
                    'komptia-status-failed',
                    'komptia-status-skipped',
                    'komptia-status-running'
                );
                if (status) el.classList.add('komptia-status-' + status);
            },

            zoomIn: function () { editor.zoom_in(); },
            zoomOut: function () { editor.zoom_out(); },
            zoomReset: function () { editor.zoom_reset(); },

            /** Recupere la position actuelle d'un node (apres drag). */
            getNodePosition: function (stepId) {
                const dfId = findDrawflowIdByStepId(editor, stepId);
                if (dfId === null) return null;
                const node = editor.drawflow.drawflow.Home.data[dfId];
                if (!node) return null;
                return { x: Math.round(node.pos_x), y: Math.round(node.pos_y) };
            },
        };
    }

    function findDrawflowIdByStepId(editor, stepId) {
        const homeData = editor.drawflow.drawflow.Home.data || {};
        for (const dfId in homeData) {
            const node = homeData[dfId];
            if (node && node.data && node.data.stepId === stepId) {
                return parseInt(dfId, 10);
            }
        }
        return null;
    }

    // ============================================================
    // Palette : rendu + drag-start
    // ============================================================
    function renderPalette(listEl, categories) {
        if (!listEl) return;
        while (listEl.firstChild) listEl.removeChild(listEl.firstChild);

        for (const cat of categories) {
            const header = document.createElement('div');
            header.className = 'komptia-palette-category';
            header.textContent = cat.label || cat.name || 'Autres';
            listEl.appendChild(header);

            for (const step of (cat.steps || [])) {
                const item = document.createElement('div');
                item.className = 'komptia-palette-item';
                // Phase 3d : un step type marque `available=false` est
                // grise + non-draggable. On evite ainsi qu'un user
                // construise un workflow inactivable (validate_completeness
                // refusera, et le step crasherait a l'execution).
                const isAvailable = step.available !== false;
                if (!isAvailable) {
                    item.classList.add('komptia-palette-item-disabled');
                    item.setAttribute('draggable', 'false');
                    item.title = (step.description || step.label || step.type)
                        + ' — bientot disponible';
                } else {
                    item.setAttribute('draggable', 'true');
                    item.title = step.description || step.label || step.type;
                }
                item.dataset.stepType = step.type;

                const icon = document.createElement('span');
                icon.className = 'komptia-palette-icon komptia-cat-' + (step.category || 'autre');
                const i = document.createElement('i');
                i.className = 'bi bi-' + (step.icon || 'gear');
                icon.appendChild(i);
                item.appendChild(icon);

                const label = document.createElement('span');
                label.className = 'komptia-palette-label';
                label.textContent = step.label || step.type;
                item.appendChild(label);

                if (isAvailable) {
                    item.addEventListener('dragstart', function (e) {
                        if (!e.dataTransfer) return;
                        e.dataTransfer.setData('application/x-komptia-step-type', step.type);
                        e.dataTransfer.effectAllowed = 'copy';
                    });
                }

                listEl.appendChild(item);
            }
        }
    }

    /**
     * Vrai UNIQUEMENT si le drag transporte le type MIME de la palette
     * Komptia. Filtre les drags non pertinents (fichier OS, lien externe,
     * image, image-from-canvas) qui sinon declencheraient preventDefault +
     * l'overlay drop bleu, cassant le comportement natif du navigateur.
     */
    function dragHasKomptiaPayload(dataTransfer) {
        if (!dataTransfer) return false;
        const types = dataTransfer.types;
        if (!types) return false;
        return Array.prototype.indexOf.call(types, 'application/x-komptia-step-type') !== -1;
    }

    function wireCanvasDropZone(canvasEl, onDrop) {
        // Defense-in-depth : on attache `dragover/drop` au CANVAS et au
        // PRECANVAS (l'enfant interne où Drawflow met les nodes). Sans
        // ce dual-attachement, drop survolant un node existant peut etre
        // intercepté par les handlers Drawflow internes — l'event ne
        // bubble pas toujours jusqu'au canvasEl, ce qui se traduit par
        // un drop "qui ne se passe pas".
        function attachListeners(target) {
            target.addEventListener('dragover', function (e) {
                if (!dragHasKomptiaPayload(e.dataTransfer)) return;
                e.preventDefault();
                e.stopPropagation();
                e.dataTransfer.dropEffect = 'copy';
                canvasEl.classList.add('komptia-drop-active');
            });
            target.addEventListener('dragleave', function (e) {
                if (e.target === target || e.relatedTarget === null) {
                    canvasEl.classList.remove('komptia-drop-active');
                }
            });
            target.addEventListener('dragend', function () {
                canvasEl.classList.remove('komptia-drop-active');
            });
            target.addEventListener('drop', function (e) {
                if (!dragHasKomptiaPayload(e.dataTransfer)) return;
                e.preventDefault();
                e.stopPropagation();
                canvasEl.classList.remove('komptia-drop-active');
                const stepType = e.dataTransfer.getData('application/x-komptia-step-type');
                if (!stepType) return;
                onDrop(stepType, e);
            });
        }
        attachListeners(canvasEl);
        // #15/F5 (2026-05-28) — empêche la navigation du navigateur quand un
        // FICHIER (ou tout drag non-komptia) est lâché n'importe où sur la page
        // edit, y compris sur le canvas (où dragHasKomptiaPayload rejette les
        // fichiers SANS preventDefault) → sinon ouverture du fichier = perte du
        // travail non sauvegardé. Les drags komptia ne sont pas touchés (gérés +
        // stopPropagation ci-dessus, donc ne bubblent pas jusqu'à window).
        // Idempotent (flag global). CSP-safe (addEventListener).
        if (!window.__komptiaFileDropGuardInstalled) {
            window.__komptiaFileDropGuardInstalled = true;
            var _fileDropGuard = function (e) {
                if (dragHasKomptiaPayload(e.dataTransfer)) return;
                e.preventDefault();
            };
            window.addEventListener('dragover', _fileDropGuard);
            window.addEventListener('drop', _fileDropGuard);
        }
        // Différer l'attachement au precanvas : il est créé par
        // ``editor.start()`` mais peut ne pas être accessible
        // immédiatement (init order). On retry à chaque frame jusqu'à
        // 5 essais (~80 ms total).
        let tries = 0;
        const maxTries = 5;
        function tryAttachPrecanvas() {
            const precanvas = canvasEl.querySelector('.drawflow .parent-drawflow, .parent-drawflow, .drawflow');
            if (precanvas && precanvas !== canvasEl) {
                attachListeners(precanvas);
                return;
            }
            tries += 1;
            if (tries < maxTries) requestAnimationFrame(tryAttachPrecanvas);
        }
        requestAnimationFrame(tryAttachPrecanvas);
    }

    // ============================================================
    // Panel config : widgets + render + autosave
    // ============================================================
    function createPanelController(store, api, saveIndicator, renderer, bus) {
        // bus optionnel : si fourni, emet 'config-changed' apres chaque
        // PUT config 2xx (pour automation-preview.js qui invalide son
        // cache de preview quand la config a change).

        const panel = document.getElementById('komptia-node-panel');
        const title = document.getElementById('komptia-panel-title');
        const form = document.getElementById('komptia-panel-form');
        // La fleche de toggle est externe au panel (pas dedans). Sa
        // visibilite suit celle du panel : hidden si pas de node
        // selectionne, visible sinon. Sans ca, la fleche flotte au
        // milieu du canvas pointant vers un panel vide.
        const edgeToggle = document.getElementById('komptia-panel-toggle');

        function hide() {
            if (panel) panel.classList.add('hidden');
            if (edgeToggle) edgeToggle.classList.add('hidden');
            store.selectedStepId = null;
        }

        function show() {
            if (panel) panel.classList.remove('hidden');
            if (edgeToggle) edgeToggle.classList.remove('hidden');
        }

        /**
         * Debounce autosave par step_id : un timer par step en cours d'edition.
         * Un changement rapide sur plusieurs steps ne peut pas s'ecraser.
         */
        const savers = new Map(); // stepId → debouncer
        // Track les fields JSON avec syntaxe invalide — bloque l'activation
        // et informe l'utilisateur via l'indicateur de sauvegarde.
        const invalidJsonFields = new Set(); // `${stepId}:${fieldKey}`

        function getSaver(stepId) {
            if (!savers.has(stepId)) {
                savers.set(stepId, createDebouncer(function () {
                    const step = store.stepsById.get(stepId);
                    if (!step) return;
                    saveStepNow(step);
                }, DEBOUNCE_CONFIG_MS));
            }
            return savers.get(stepId);
        }

        function scheduleSave(stepId) {
            getSaver(stepId)();
        }

        /** Nettoie le debouncer pour un step supprime (free la memoire). */
        function removeStep(stepId) {
            const s = savers.get(stepId);
            if (s) {
                s.cancel();
                savers.delete(stepId);
            }
            // Retire les marqueurs JSON invalides pour ce step.
            Array.from(invalidJsonFields).forEach(function (k) {
                if (k.indexOf(stepId + ':') === 0) invalidJsonFields.delete(k);
            });
        }

        async function saveStepNow(step) {
            // Guard : si le step a ete supprime pendant le debounce (fenetre
            // entre le changement du user et le fire du timer), ne pas POST.
            if (!store.stepsById.has(step.id)) return;

            saveIndicator.start();
            try {
                const body = {
                    name: step.name,
                    config: step.config || {},
                    is_enabled: step.is_enabled !== false,
                };
                const resp = await api.put(
                    '/api/automations/' + store.automationId + '/steps/' + step.id,
                    body
                );
                // Merger : on preserve les champs editables (name, config,
                // is_enabled) qui peuvent avoir ete modifies par l'utilisateur
                // PENDANT la requete serveur. Sinon on ecrase les keystrokes
                // recents avec la version pre-edit renvoyee par le serveur.
                if (resp && resp.step && store.stepsById.has(step.id)) {
                    const current = store.stepsById.get(step.id);
                    const merged = Object.assign({}, resp.step, {
                        name: current.name,
                        config: current.config,
                        is_enabled: current.is_enabled,
                    });
                    store.stepsById.set(step.id, merged);
                    const idx = store.steps.findIndex(function (s) { return s.id === step.id; });
                    if (idx !== -1) store.steps[idx] = merged;
                    renderer.updateNodeContent(
                        step.id, merged, store.nodeTypes[merged.step_type]
                    );
                }
                saveIndicator.success();
                // Re-check : le step peut avoir ete supprime pendant le PUT
                // (race entre user qui delete et l'autosave pendante). On
                // n'emet pas un 'config-changed' pour un step disparu —
                // sinon les listeners (preview) appellent setNodeStatus
                // sur un node Drawflow qui n'existe plus (no-op silencieux
                // mais bruit logique).
                if (
                    bus
                    && typeof bus.emit === 'function'
                    && store.stepsById.has(step.id)
                ) {
                    bus.emit('config-changed', { step_id: step.id });
                }
            } catch (e) {
                saveIndicator.fail(e.message);
                // 409 version_conflict : `_doFetch` a déjà déclenché la
                // re-synchro (toast warning throttlé + re-hydratation). Un
                // second toast « Erreur sauvegarde : <texte serveur> » est un
                // doublon trompeur — il suggère une action utilisateur
                // (« rafraîchissez ») alors que la vue vient d'être
                // resynchronisée automatiquement.
                if (!e.isVersionConflict) {
                    showToast('Erreur sauvegarde : ' + e.message, 'error');
                }
            }
        }

        /**
         * Rend le formulaire pour un step donne selon son config_schema.
         * Les widgets mettent a jour step.config directement, et appellent
         * scheduleSave(step.id) sur change.
         */
        function render(step) {
            if (!form || !title) return;
            while (form.firstChild) form.removeChild(form.firstChild);
            title.textContent = step.name || step.step_type;

            const meta = store.nodeTypes[step.step_type] || {};
            const schema = meta.config_schema || {};

            // Champ name (toujours present)
            form.appendChild(
                buildField('Nom', 'string', { required: true }, step.name || '', function (val) {
                    step.name = val;
                    scheduleSave(step.id);
                })
            );

            // Champ is_enabled
            const enableWrapper = document.createElement('div');
            enableWrapper.className = 'komptia-field';
            const enableLabel = document.createElement('label');
            enableLabel.className = 'inline-flex items-center gap-2 text-xs text-gray-700 dark:text-gray-300';
            const enableCheck = document.createElement('input');
            enableCheck.type = 'checkbox';
            enableCheck.checked = step.is_enabled !== false;
            enableCheck.addEventListener('change', function () {
                step.is_enabled = enableCheck.checked;
                scheduleSave(step.id);
            });
            enableLabel.appendChild(enableCheck);
            const enableText = document.createElement('span');
            enableText.textContent = 'Etape active';
            enableLabel.appendChild(enableText);
            enableWrapper.appendChild(enableLabel);
            form.appendChild(enableWrapper);

            // Description du type
            if (meta.description) {
                const desc = document.createElement('p');
                desc.className = 'text-xs text-gray-500 dark:text-gray-400 pt-2 border-t border-gray-100 dark:border-gray-800';
                desc.textContent = meta.description;
                form.appendChild(desc);
            }

            // Champs du config_schema
            step.config = step.config || {};

            // Construction du contexte pour les pickers : parents directs
            // dans le DAG (utiles pour resoudre dynamiquement la liste
            // d'onglets pour format_copilot/export_workbook). On capture
            // automation_id pour les fetchs API.
            const parentStepIds = (store.edges || [])
                .filter(function (e) { return e.to_step_id === step.id; })
                .map(function (e) { return e.from_step_id; });
            const parentSteps = (store.steps || []).filter(function (s) {
                return parentStepIds.indexOf(s.id) >= 0;
            });
            const pickerCtx = {
                automationId: store.automation && store.automation.id,
                step: step,
                parentSteps: parentSteps,
            };

            for (const fieldKey in schema) {
                // `in` descend dans le prototype chain — on skippe les cles
                // non-propres pour eviter une interference si quelqu'un pollue
                // Object.prototype (defense-in-depth).
                if (!Object.prototype.hasOwnProperty.call(schema, fieldKey)) continue;

                const spec = schema[fieldKey];
                const current = (fieldKey in step.config) ? step.config[fieldKey] : (spec.default ?? '');
                // Cle pour tracker la validite JSON par step+field.
                const validityKey = step.id + ':' + fieldKey;
                const field = buildField(
                    spec.label || fieldKey,
                    spec.type || 'string',
                    spec,
                    current,
                    function (val) {
                        step.config[fieldKey] = val;
                        scheduleSave(step.id);
                    },
                    function onValidity(isValid) {
                        if (isValid) {
                            invalidJsonFields.delete(validityKey);
                        } else {
                            invalidJsonFields.add(validityKey);
                        }
                        // Propage a l'indicateur pour informer l'utilisateur
                        // qu'un champ bloque l'activation.
                        if (invalidJsonFields.size > 0) {
                            saveIndicator.fail('Champ JSON invalide');
                        } else {
                            saveIndicator.clearError();
                        }
                    },
                    pickerCtx
                );
                form.appendChild(field);
            }
        }

        /**
         * Construit un champ (label + widget + aide + erreur) selon le type.
         * `onValidity` (optionnel) n'est branche que pour les widgets qui
         * peuvent avoir un etat "invalide" localement sans ecraser la valeur
         * du store (actuellement : buildJsonEditor).
         *
         * Si `spec.widget` est defini ET que `window.komptiaPickers` est
         * charge, on delegue au picker — qui peut afficher un dropdown
         * resource, un autocomplete contacts, un file browser, etc.
         * Le `type` reste la source de verite cote validator backend ;
         * `widget` n'enrichit que l'UX (progressive enhancement).
         */
        function buildField(labelText, type, spec, value, onChange, onValidity, ctx) {
            const wrapper = document.createElement('div');
            wrapper.className = 'komptia-field';

            const label = document.createElement('label');
            label.className = 'komptia-field-label' + (spec.required ? ' komptia-field-required' : '');
            label.textContent = labelText;
            wrapper.appendChild(label);

            let input = null;

            // Dispatch widget custom (resource pickers) si dispo. Fallback
            // sur les widgets natifs ci-dessous si le module pickers n'est
            // pas charge ou retourne null pour ce widget inconnu.
            if (spec.widget && window.komptiaPickers && typeof window.komptiaPickers.build === 'function') {
                try {
                    input = window.komptiaPickers.build(spec.widget, spec, value, onChange, ctx || {});
                } catch (e) {
                    if (window.console && console.error) console.error('komptia picker fail', e);
                    input = null;
                }
            }

            if (input === null) {
                switch (type) {
                    case 'text':
                        input = buildTextArea(value, onChange);
                        break;
                    case 'number':
                        input = buildNumberInput(value, onChange);
                        break;
                    case 'select':
                        input = buildSelect(spec.options || [], value, onChange);
                        break;
                    case 'boolean':
                        input = buildBooleanInput(value, onChange);
                        break;
                    case 'list':
                        input = buildChipsInput(value, onChange);
                        break;
                    case 'key_value':
                        input = buildKeyValueEditor(value, onChange);
                        break;
                    case 'list_of_objects':
                        input = buildJsonEditor(value, onChange, onValidity);
                        break;
                    case 'string':
                    default:
                        input = buildStringInput(value, onChange);
                        break;
                }
            }
            wrapper.appendChild(input);

            if (spec.help || spec.description) {
                const help = document.createElement('p');
                help.className = 'komptia-field-help';
                help.textContent = spec.help || spec.description;
                wrapper.appendChild(help);
            }

            // Task #37 — Exemples cliquables : si le spec porte une liste
            // `examples` (templates d'instruction préremplis, fournis par le
            // backend dans config_schema), on les rend en puces cliquables sous
            // le champ. Au clic : insère la valeur (remplace si le champ est
            // vide, sinon ajoute à la ligne) puis déclenche onChange pour
            // persister + planifier la sauvegarde. Restreint au seul <textarea>
            // (champ multi-ligne) : l'append avec '\n' n'a de sens que là — un
            // <input> mono-ligne (string/number) corromprait sa valeur, et les
            // pickers custom ont leur propre UX. Aujourd'hui seul `instruction`
            // (type:text → textarea) porte des examples ; ce guard protège tout
            // futur champ générique.
            if (Array.isArray(spec.examples) && spec.examples.length > 0 && !spec.widget &&
                input && input.tagName === 'TEXTAREA') {
                const examplesWrap = document.createElement('div');
                examplesWrap.className = 'komptia-examples';

                const examplesLabel = document.createElement('span');
                examplesLabel.className = 'komptia-examples-label';
                examplesLabel.textContent = 'Exemples :';
                examplesWrap.appendChild(examplesLabel);

                spec.examples.forEach(function (ex) {
                    if (!ex || typeof ex.value !== 'string' || !ex.label) return;
                    const btn = document.createElement('button');
                    btn.type = 'button';
                    btn.className = 'komptia-example-btn';
                    btn.textContent = ex.label;
                    btn.title = ex.value;  // aperçu du template complet (attribut natif)
                    btn.addEventListener('click', function () {
                        const existing = (input.value || '').trim();
                        input.value = existing ? (existing + '\n' + ex.value) : ex.value;
                        onChange(input.value);
                        // Curseur en fin + scroll vers le bas : quand le champ
                        // contenait déjà du texte, l'exemple est AJOUTÉ dessous —
                        // on rend l'ajout visible (sinon l'utilisateur ne voit
                        // pas ce qui a changé et croit que rien ne s'est passé).
                        input.focus();
                        try {
                            input.setSelectionRange(input.value.length, input.value.length);
                        } catch (e) { /* champ sans API de sélection — sans effet */ }
                        input.scrollTop = input.scrollHeight;
                    });
                    examplesWrap.appendChild(btn);
                });

                wrapper.appendChild(examplesWrap);
            }

            return wrapper;
        }

        function buildStringInput(value, onChange) {
            const input = document.createElement('input');
            input.type = 'text';
            input.className = 'komptia-input';
            input.value = value == null ? '' : String(value);
            input.addEventListener('input', function () {
                onChange(input.value);
            });
            return input;
        }

        function buildBooleanInput(value, onChange) {
            // Wrapper inline (label + checkbox) pour ne pas dupliquer le
            // label de buildField — on affiche juste la checkbox a droite.
            const wrapper = document.createElement('label');
            wrapper.className = 'komptia-checkbox-wrapper';
            const input = document.createElement('input');
            input.type = 'checkbox';
            input.className = 'komptia-checkbox';
            input.checked = value === true || value === 'true' || value === 1;
            input.addEventListener('change', function () {
                onChange(input.checked);
            });
            wrapper.appendChild(input);
            const txt = document.createElement('span');
            txt.className = 'komptia-checkbox-label-inline';
            txt.textContent = input.checked ? 'Active' : 'Inactif';
            input.addEventListener('change', function () {
                txt.textContent = input.checked ? 'Active' : 'Inactif';
            });
            wrapper.appendChild(txt);
            return wrapper;
        }

        function buildNumberInput(value, onChange) {
            const input = document.createElement('input');
            input.type = 'number';
            input.className = 'komptia-input';
            input.value = (value === null || value === undefined || value === '') ? '' : String(value);
            input.addEventListener('input', function () {
                const v = input.value;
                // Chaine vide → null (pas de valeur). Sinon parseFloat.
                if (v === '') { onChange(null); return; }
                const num = parseFloat(v);
                onChange(isNaN(num) ? null : num);
            });
            return input;
        }

        function buildTextArea(value, onChange) {
            const input = document.createElement('textarea');
            input.className = 'komptia-textarea';
            input.rows = 4;
            input.value = value == null ? '' : String(value);
            input.addEventListener('input', function () {
                onChange(input.value);
            });
            return input;
        }

        function buildSelect(options, value, onChange) {
            const sel = document.createElement('select');
            sel.className = 'komptia-select';
            // Option vide
            const optEmpty = document.createElement('option');
            optEmpty.value = '';
            optEmpty.textContent = '-- Choisir --';
            sel.appendChild(optEmpty);
            for (const opt of options) {
                const optEl = document.createElement('option');
                optEl.value = String(opt);
                optEl.textContent = String(opt);
                if (value === opt) optEl.selected = true;
                sel.appendChild(optEl);
            }
            sel.addEventListener('change', function () {
                onChange(sel.value);
            });
            return sel;
        }

        /** Liste de strings avec chips. Enter/virgule pour ajouter. */
        function buildChipsInput(value, onChange) {
            const wrapper = document.createElement('div');
            wrapper.className = 'komptia-chips';
            let items = Array.isArray(value) ? value.slice() : [];

            function render() {
                while (wrapper.firstChild) wrapper.removeChild(wrapper.firstChild);
                items.forEach(function (item, idx) {
                    const chip = document.createElement('span');
                    chip.className = 'komptia-chip';
                    const text = document.createElement('span');
                    text.textContent = String(item);
                    chip.appendChild(text);
                    const rm = document.createElement('span');
                    rm.className = 'komptia-chip-remove';
                    rm.textContent = '×';
                    rm.setAttribute('role', 'button');
                    rm.setAttribute('aria-label', 'Supprimer');
                    rm.addEventListener('click', function () {
                        items.splice(idx, 1);
                        onChange(items.slice());
                        render();
                    });
                    chip.appendChild(rm);
                    wrapper.appendChild(chip);
                });
                const input = document.createElement('input');
                input.className = 'komptia-chips-input';
                input.type = 'text';
                input.placeholder = 'Ajouter...';
                input.addEventListener('keydown', function (e) {
                    if (e.key === 'Enter' || e.key === ',') {
                        e.preventDefault();
                        const v = input.value.trim();
                        if (v) {
                            items.push(v);
                            onChange(items.slice());
                            render();
                        }
                    } else if (e.key === 'Backspace' && input.value === '' && items.length > 0) {
                        items.pop();
                        onChange(items.slice());
                        render();
                    }
                });
                input.addEventListener('blur', function () {
                    const v = input.value.trim();
                    if (v) {
                        items.push(v);
                        onChange(items.slice());
                        render();
                    }
                });
                wrapper.appendChild(input);
            }
            render();
            return wrapper;
        }

        // Cles refusees : prototype pollution defensive. Les navigateurs
        // modernes traitent `__proto__` / `constructor` comme cles normales
        // dans `obj[k] = v`, mais serialiser/deserialiser via JSON les fait
        // voyager et peut alimenter des surfaces d'attaque en aval.
        const _KV_FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

        /** Editeur cle → valeur (mapping, checks, headers, aggregations). */
        function buildKeyValueEditor(value, onChange) {
            const wrapper = document.createElement('div');
            // `Object.create(null)` = objet sans prototype → impossible
            // d'escalader via `__proto__`. On copie les valeurs own seulement.
            const dict = Object.create(null);
            if (value && typeof value === 'object' && !Array.isArray(value)) {
                Object.keys(value).forEach(function (k) {
                    if (_KV_FORBIDDEN_KEYS.has(k)) return;
                    if (Object.prototype.hasOwnProperty.call(value, k)) {
                        dict[k] = value[k];
                    }
                });
            }

            function commit() {
                // Nettoie les cles vides/reservees avant de remonter.
                const clean = {};
                Object.keys(dict).forEach(function (k) {
                    if (!k || k.trim() === '') return;
                    if (_KV_FORBIDDEN_KEYS.has(k)) return;
                    clean[k] = dict[k];
                });
                onChange(clean);
            }

            function render() {
                while (wrapper.firstChild) wrapper.removeChild(wrapper.firstChild);
                Object.keys(dict).forEach(function (k) {
                    wrapper.appendChild(buildRow(k, dict[k]));
                });
                const addBtn = document.createElement('button');
                addBtn.type = 'button';
                addBtn.className = 'komptia-btn-add';
                addBtn.textContent = '+ Ajouter';
                addBtn.addEventListener('click', function () {
                    // Nouveau couple vide (evite collision si deja "" present).
                    let newKey = 'nouveau';
                    let n = 1;
                    while (newKey in dict) { newKey = 'nouveau_' + (++n); }
                    dict[newKey] = '';
                    commit();
                    render();
                });
                wrapper.appendChild(addBtn);
            }

            function buildRow(key, val) {
                const row = document.createElement('div');
                row.className = 'komptia-kv-row';

                const keyInput = document.createElement('input');
                keyInput.type = 'text';
                keyInput.className = 'komptia-input';
                keyInput.value = key;
                keyInput.placeholder = 'cle';
                keyInput.addEventListener('change', function () {
                    const newKey = keyInput.value.trim();
                    if (newKey === key) return;
                    if (_KV_FORBIDDEN_KEYS.has(newKey)) {
                        keyInput.value = key;
                        showToast('Cle reservee interdite', 'warning');
                        return;
                    }
                    if (newKey && !Object.prototype.hasOwnProperty.call(dict, newKey)) {
                        dict[newKey] = dict[key];
                        delete dict[key];
                        commit();
                        render();
                    } else if (!newKey) {
                        delete dict[key];
                        commit();
                        render();
                    } else {
                        keyInput.value = key;
                        showToast('Cette cle existe deja', 'warning');
                    }
                });

                const valInput = document.createElement('input');
                valInput.type = 'text';
                valInput.className = 'komptia-input';
                valInput.value = val == null ? '' : String(val);
                valInput.placeholder = 'valeur';
                valInput.addEventListener('input', function () {
                    dict[key] = valInput.value;
                    commit();
                });

                const rmBtn = document.createElement('button');
                rmBtn.type = 'button';
                rmBtn.className = 'komptia-row-remove';
                rmBtn.setAttribute('aria-label', 'Supprimer');
                rmBtn.textContent = '×';
                rmBtn.addEventListener('click', function () {
                    delete dict[key];
                    commit();
                    render();
                });

                row.appendChild(keyInput);
                row.appendChild(valInput);
                row.appendChild(rmBtn);
                return row;
            }

            render();
            return wrapper;
        }

        /** Editeur JSON brut pour list_of_objects (switch.cases, assignments). */
        /**
         * Editeur JSON brut pour list_of_objects.
         * `onValidity` (optionnel) est appele avec `true`/`false` a chaque
         * changement pour permettre au panel de tracer les fields invalides
         * et bloquer l'activation (`hasInvalidField()`).
         */
        function buildJsonEditor(value, onChange, onValidity) {
            const wrapper = document.createElement('div');
            const textarea = document.createElement('textarea');
            textarea.className = 'komptia-textarea';
            textarea.rows = 6;
            try {
                textarea.value = JSON.stringify(value || [], null, 2);
            } catch (_) {
                textarea.value = '[]';
            }
            const errorEl = document.createElement('p');
            errorEl.className = 'komptia-field-error';
            errorEl.style.display = 'none';

            const helpEl = document.createElement('p');
            helpEl.className = 'komptia-field-help';
            helpEl.textContent = 'Format JSON. Ex: [{"cle": "val"}]';

            textarea.addEventListener('input', function () {
                try {
                    const parsed = JSON.parse(textarea.value || '[]');
                    errorEl.style.display = 'none';
                    if (typeof onValidity === 'function') onValidity(true);
                    onChange(parsed);
                } catch (e) {
                    errorEl.textContent = 'JSON invalide : ' + e.message;
                    errorEl.style.display = 'block';
                    if (typeof onValidity === 'function') onValidity(false);
                    // On n'appelle PAS onChange si invalide — evite d'ecraser
                    // une config valide par un JSON cassé.
                }
            });

            wrapper.appendChild(textarea);
            wrapper.appendChild(errorEl);
            wrapper.appendChild(helpEl);
            return wrapper;
        }

        return {
            show: show,
            hide: hide,
            render: render,
            /** Vrai si au moins un field est dans un etat invalide (JSON
             * casse). Le canvas bloque l'activation dans ce cas pour eviter
             * d'appliquer une config silencieusement incomplete. */
            hasInvalidField: function () {
                return invalidJsonFields.size > 0;
            },
            /** Retire un step des debouncers + fields invalides. Appelee
             * depuis le handler nodeRemoved pour free la memoire et eviter
             * les PUT /steps/:id → 404 sur un step supprime. */
            removeStep: removeStep,
            /** Force un flush de tous les debouncers (ex: avant navigation). */
            flushAll: function () {
                savers.forEach(function (d) { d.flush(); });
            },
            /** Real-review #5 cycle 23 : flush + ATTEND tous les saves
             * en vol. Le caller `await flushAllAndWait()` AVANT de toggler
             * /validate / /toggle / /execute pour garantir que la BDD a
             * la dernière config. Sans ça, race condition garantie sur
             * les frappes rapides. Racine de BUG-A. */
            flushAllAndWait: function () {
                const promises = [];
                savers.forEach(function (d) { promises.push(d.flushAndWait()); });
                return Promise.all(promises);
            },
            /** Cluster-N (fix tempête 409 2026-06-10) — réinitialise l'état
             * d'édition AVANT une re-hydratation forcée (conflit cross-onglet).
             * ANNULE (pas flush) tous les autosaves en attente, vide les
             * debouncers + marqueurs JSON invalides, et FERME le panel. Sans ça,
             * le panel garde une référence de `step` PÉRIMÉE (capturée dans les
             * closures du formulaire) : les frappes ultérieures muteraient un
             * objet que `saveStepNow` n'utilise plus → édits silencieusement
             * perdus + debouncers zombies. On annule au lieu de flush : la
             * mutation perdue était en conflit, la re-hydratation fait foi
             * (l'utilisateur ré-applique sur l'état serveur à jour). */
            resetPending: function () {
                savers.forEach(function (d) {
                    try { d.cancel(); } catch (_) { /* noop */ }
                });
                savers.clear();
                invalidJsonFields.clear();
                try { hide(); } catch (_) { /* noop */ }
            },
        };
    }

    // ============================================================
    // API facade : wrap apiFetch + verbs
    // ============================================================
    function createApi() {
        return {
            get: function (url) {
                return apiFetch(url);
            },
            post: function (url, body) {
                return apiFetch(url, { method: 'POST', body: JSON.stringify(body || {}) });
            },
            put: function (url, body) {
                return apiFetch(url, { method: 'PUT', body: JSON.stringify(body || {}) });
            },
            del: function (url) {
                return apiFetch(url, { method: 'DELETE' });
            },
        };
    }

    // ============================================================
    // Main : init
    // ============================================================
    async function initCanvas() {
        const root = document.getElementById('komptia-edit-root');
        if (!root) return;
        const automationId = parseInt(root.getAttribute('data-komptia-automation-id'), 10);
        if (!automationId) {
            console.error('Komptia: automation_id manquant');
            showCanvasError('Identifiant automatisation manquant.', null);
            return;
        }
        const editable = root.getAttribute('data-komptia-editable') === 'true';
        const container = document.getElementById('komptia-canvas');
        if (!container) return;
        const emptyOverlay = document.getElementById('komptia-canvas-empty');

        const api = createApi();
        const saveIndicator = createSaveIndicator();
        const store = createWorkflowStore(automationId);
        store.editable = editable;

        // Cluster-N 2026-05-26 — BroadcastChannel cross-tab.
        // Quand tab A save (PUT 2xx → setAutomationVersion local), un
        // message `{version: N}` est diffusé. Tab B reçoit, met à jour
        // son state local + toast non-bloquant "mis à jour ailleurs".
        // Feature-detect : BroadcastChannel n'existe pas sur certains
        // navigateurs anciens (Safari < 15.4) → on tombe sur protection
        // backend (409 If-Match) sans warning UX cross-tab.
        let broadcastChannel = null;
        try {
            if (typeof BroadcastChannel === 'function') {
                broadcastChannel = new BroadcastChannel('komptia-automation-' + automationId);
                broadcastChannel.onmessage = function (ev) {
                    const data = (ev && ev.data) || {};
                    if (!Number.isFinite(data.version)) return;
                    const current = getAutomationVersion();
                    if (current !== null && data.version > current) {
                        setAutomationVersion(data.version);
                        if (typeof window.showToast === 'function') {
                            window.showToast(
                                'Cette automatisation a été modifiée dans un autre onglet. '
                                + 'Rafraîchissez la page pour voir la version à jour.',
                                'info'
                            );
                        }
                    }
                };
                // Diffuser à chaque MAJ locale. Le filtre lastBroadcastVersion
                // évite les renvois en boucle si on reçoit notre propre echo.
                let lastBroadcastVersion = null;
                onVersionChange(function (v) {
                    if (v === null || v === lastBroadcastVersion) return;
                    lastBroadcastVersion = v;
                    try {
                        broadcastChannel.postMessage({ version: v });
                    } catch (e) {
                        // Pas critique : seul effet = pas de notif cross-tab.
                        console.warn('[komptiaCanvas] broadcast failed', e);
                    }
                });
                // Cleanup au pagehide pour libérer le port (bfcache safety).
                window.addEventListener('pagehide', function () {
                    try { broadcastChannel.close(); } catch (_) { /* noop */ }
                }, { once: true });
            }
        } catch (e) {
            console.warn('[komptiaCanvas] BroadcastChannel init failed', e);
        }

        let renderer;
        try {
            renderer = createRendererAdapter(container, { editable: editable });
        } catch (e) {
            console.error('Komptia: init renderer failed', e);
            showCanvasError('Librairie canvas non chargee. Rafraichir la page.', function () {
                window.location.reload();
            });
            return;
        }

        const bus = createEventBus();
        const panel = createPanelController(store, api, saveIndicator, renderer, bus);

        // ────────────────────────────────────────────
        // Hydratation
        // ────────────────────────────────────────────
        async function hydrate() {
            saveIndicator.start();
            try {
                const dagData = await api.get('/api/automations/' + automationId + '/dag');
                store.automation = dagData.automation;
                store.steps = dagData.steps || [];
                store.edges = dagData.edges || [];
                store.unpositionedStepIds = dagData.unpositioned_step_ids || [];
                // Cluster-N — initialise la version courante depuis la BDD.
                // Fallback à 1 si l'automation legacy n'a pas encore le champ
                // (rétro-compat des autos antérieures à la migration).
                if (store.automation && Number.isFinite(store.automation.version)) {
                    setAutomationVersion(store.automation.version);
                } else {
                    setAutomationVersion(1);
                }
                rebuildIndexes(store);

                try {
                    const typesData = await api.get('/api/automations/step-types');
                    const typesByName = {};
                    for (const cat of (typesData.categories || [])) {
                        for (const s of (cat.steps || [])) {
                            typesByName[s.type] = s;
                        }
                    }
                    store.nodeTypes = typesByName;
                    // Palette
                    const paletteList = document.getElementById('komptia-palette-list');
                    if (editable && paletteList) {
                        renderPalette(paletteList, typesData.categories || []);
                    } else if (paletteList) {
                        paletteList.textContent = 'Lecture seule';
                    }
                } catch (e) {
                    console.warn('Komptia: step-types indisponible', e);
                    store.nodeTypes = {};
                }

                store.loaded = true;
                assignAutoLayout(store.steps, store.unpositionedStepIds);

                // Rendu initial
                renderer.clear();
                store.drawflowIdByStepId.clear();
                store.stepIdByDrawflowId.clear();
                // Bloquer les hooks `connectionCreated` cote handler pendant
                // l'hydratation initiale. Sans ce flag, chaque edge existant
                // ressort le hook (qui re-POST /edges, deja rejete par dedup
                // mais cree du bruit serveur).
                store.isHydrating = true;
                try {
                    for (const step of store.steps) {
                        const dfId = renderer.addNode(step, store.nodeTypes[step.step_type]);
                        store.drawflowIdByStepId.set(step.id, dfId);
                        store.stepIdByDrawflowId.set(dfId, step.id);
                    }
                    for (const edge of store.edges) {
                        const fromDf = store.drawflowIdByStepId.get(edge.from_step_id);
                        const toDf = store.drawflowIdByStepId.get(edge.to_step_id);
                        if (fromDf != null && toDf != null) {
                            renderer.addConnection(fromDf, toDf);
                        }
                    }
                } finally {
                    // Reset en microtask : garantit que les `connectionCreated`
                    // dispatches synchronement par addConnection sont bien
                    // ignores par le handler qui verifie isHydrating en tete.
                    Promise.resolve().then(function () { store.isHydrating = false; });
                }

                // Empty overlay
                if (emptyOverlay) {
                    // DAG-4 — si on ré-affiche l'état vide après une erreur,
                    // restaurer le texte d'aide (sinon overlay blanc).
                    if (store.steps.length === 0) restoreEmptyHelp(emptyOverlay);
                    emptyOverlay.classList.toggle('hidden', store.steps.length > 0);
                }

                // Top bar name + active
                const nameInput = document.getElementById('komptia-automation-name');
                if (nameInput && store.automation) {
                    nameInput.value = store.automation.name || '';
                    nameInput.readOnly = !editable;
                }
                const activeToggle = document.getElementById('komptia-active-toggle');
                if (activeToggle && store.automation) {
                    activeToggle.checked = !!store.automation.is_active;
                    activeToggle.disabled = !editable;
                }

                saveIndicator.success();
            } catch (e) {
                console.error('Komptia: erreur hydratation', e);
                saveIndicator.fail(e.message);
                showCanvasError(
                    'Impossible de charger l\'automatisation.',
                    hydrate
                );
                throw e;
            }
        }

        try {
            await hydrate();
        } catch (_) {
            return; // la showCanvasError est deja affichee avec Retry
        }

        // Cluster-N (fix tempête 409 2026-06-10) — re-synchro sur conflit de
        // version genuine (cross-onglet/session). Remplace l'ancien GEL
        // permanent (qui forçait un refresh manuel) par une re-hydratation
        // idempotente de l'état serveur. `_resyncing` empêche la réentrance si
        // plusieurs 409 arrivent en rafale. `hydrate()` est idempotent (clear +
        // rebuild depuis /dag, remet `_automationVersion` à la valeur BDD).
        let _resyncing = false;
        setVersionConflictHandler(function () {
            if (_resyncing) return;
            _resyncing = true;
            _maybeShowConflictToast();
            // Annule les autosaves en attente + ferme le panel AVANT de
            // re-hydrater : évite que des références de step périmées (closures
            // du formulaire) écrasent silencieusement l'état serveur re-chargé.
            try { panel.resetPending(); } catch (_) { /* noop */ }
            Promise.resolve()
                .then(function () { return hydrate(); })
                .catch(function () { /* showCanvasError déjà gérée par hydrate */ })
                .then(function () { _resyncing = false; });
        });

        // ────────────────────────────────────────────
        // Boutons zoom : `[-] 100% [+]`. Le pourcentage central reset
        // a 100% au clic. On synchronise le label apres chaque
        // interaction (Drawflow expose `editor.zoom` mais pas d'event
        // dedie reliable — on poll apres chaque action).
        // ────────────────────────────────────────────
        const zoomLevelText = document.getElementById('komptia-zoom-level-text');
        function updateZoomDisplay() {
            if (!zoomLevelText || !renderer || !renderer.editor) return;
            const z = renderer.editor.zoom;
            if (typeof z !== 'number' || !isFinite(z)) return;
            zoomLevelText.textContent = Math.round(z * 100) + '%';
        }
        const zoomIn = document.getElementById('komptia-zoom-in');
        if (zoomIn) zoomIn.addEventListener('click', function () {
            renderer.zoomIn(); updateZoomDisplay();
        });
        const zoomOut = document.getElementById('komptia-zoom-out');
        if (zoomOut) zoomOut.addEventListener('click', function () {
            renderer.zoomOut(); updateZoomDisplay();
        });
        const zoomLevelBtn = document.getElementById('komptia-zoom-level');
        if (zoomLevelBtn) zoomLevelBtn.addEventListener('click', function () {
            renderer.zoomReset(); updateZoomDisplay();
        });
        // Sync au mount + lors d'un zoom-by-wheel (Drawflow trap aussi le
        // wheel). On poll a un interval court — pas ideal mais simple, et
        // l'event Drawflow `zoom` n'est pas garanti sur toutes les versions.
        updateZoomDisplay();
        if (renderer && renderer.editor && typeof renderer.editor.on === 'function') {
            try { renderer.editor.on('zoom', updateZoomDisplay); } catch (_) {}
        }

        // ────────────────────────────────────────────
        // Nom automation : autosave
        // ────────────────────────────────────────────
        const nameInput = document.getElementById('komptia-automation-name');
        if (nameInput && editable) {
            const saveName = createDebouncer(async function () {
                saveIndicator.start();
                try {
                    const resp = await api.put('/automations/' + automationId, {
                        name: nameInput.value,
                    });
                    if (resp && resp.automation) store.automation = resp.automation;
                    saveIndicator.success();
                } catch (e) {
                    saveIndicator.fail(e.message);
                    showToast('Erreur sauvegarde nom : ' + e.message, 'error');
                }
            }, DEBOUNCE_NAME_MS);
            nameInput.addEventListener('input', saveName);
        }

        // ────────────────────────────────────────────
        // Active toggle : POST /toggle (enforce completude serveur)
        // ────────────────────────────────────────────
        const activeToggle = document.getElementById('komptia-active-toggle');
        if (activeToggle && editable) {
            activeToggle.addEventListener('change', async function () {
                // Bloquer l'activation si un champ JSON est invalide : on
                // refuserait de toute facon cote serveur apres PUT /steps
                // (config invalide), mais c'est plus clair de prevenir ici.
                if (activeToggle.checked && panel.hasInvalidField()) {
                    activeToggle.checked = false;
                    showToast(
                        'Impossible d\'activer : un champ JSON est invalide',
                        'error'
                    );
                    return;
                }
                // Flush les config en attente avant activation. Real-review
                // #5 cycle 23 : `flushAllAndWait()` retourne une promise qui
                // résout APRÈS que tous les PUT /steps en vol soient committed
                // côté serveur. Sans le `await`, la race condition (BUG-A
                // racine) faisait que /toggle lisait l'ancienne config.
                // Real-review #31 : disable le checkbox pour éviter les
                // double-clicks pendant la requête en vol.
                activeToggle.disabled = true;
                if (activeToggle.checked) {
                    try { await panel.flushAllAndWait(); } catch (_) { /* noop */ }
                }

                saveIndicator.start();
                try {
                    // A7-M2 : envoyer l'état CIBLE explicite (`target`) au lieu
                    // d'un flip aveugle → le backend rejette en 409 si l'auto est
                    // déjà dans cet état (anti-désync multi-onglets).
                    const resp = await api.post('/automations/' + automationId + '/toggle', {
                        target: activeToggle.checked
                    });
                    if (resp && typeof resp.is_active === 'boolean') {
                        if (store.automation) store.automation.is_active = resp.is_active;
                        activeToggle.checked = resp.is_active;
                    }
                    saveIndicator.success();
                    showToast(
                        (activeToggle.checked ? 'Active' : 'Desactive'),
                        'success'
                    );
                } catch (e) {
                    // A7-M2 : 409 = un autre onglet a déjà mis l'auto dans cet
                    // état. Refléter l'état RÉEL (e.body.is_active) au lieu d'un
                    // rollback aveugle qui afficherait l'inverse de la vérité.
                    if (e && e.status === 409 && e.body && typeof e.body.is_active === 'boolean') {
                        activeToggle.checked = e.body.is_active;
                        if (store.automation) store.automation.is_active = e.body.is_active;
                        saveIndicator.success();
                        showToast(e.body.error || 'État déjà à jour.', 'info');
                        activeToggle.disabled = false;
                        return;
                    }
                    // Rollback visuel
                    activeToggle.checked = !activeToggle.checked;
                    saveIndicator.fail(e.message);
                    // Afficher les errors serveur dans une LISTE structurée
                    // (modal globale appShowErrors), pas un toast tronqué.
                    // Click "Aller à cette étape" → sélectionne le node fautif.
                    const serverErrors = (e.body && e.body.errors) || [];
                    if (serverErrors.length && window.appShowErrors) {
                        window.appShowErrors(
                            (e.body && e.body.error) || 'Activation refusée',
                            serverErrors,
                            {
                                onErrorClick: function (err) {
                                    const nodeId = err && err.context && err.context.node_id;
                                    if (nodeId == null) return;
                                    const dfId = store.drawflowIdByStepId.get(nodeId);
                                    if (dfId != null && renderer && renderer.editor) {
                                        try { renderer.editor.click_node(dfId); } catch (_) { /* noop */ }
                                    }
                                }
                            }
                        );
                    } else {
                        showToast('Activation refusée : ' + e.message, 'error');
                    }
                } finally {
                    // Real-review #31 cycle 23 : ré-active le checkbox dans
                    // tous les cas (succès / erreur / cancel) — sinon un
                    // échec laisserait le user incapable de cliquer à nouveau.
                    activeToggle.disabled = false;
                }
            });
        }

        // ────────────────────────────────────────────
        // Bouton « Valider et activer » : POST /validate puis /toggle.
        // Validate-only au depart (Real-review #5 cycle 23) ; on ajoute
        // le toggle activate ici (decision David 2026-05-08) pour faire
        // de ce bouton un CTA complet "le workflow est pret a tourner".
        // 409 sur le toggle = deja active = traite comme succes.
        // ────────────────────────────────────────────
        const validateBtn = document.getElementById('komptia-validate-btn');
        if (validateBtn) {
            validateBtn.addEventListener('click', async function () {
                // Real-review #5 cycle 23 : flush + await les saves en vol
                // AVANT de demander la validation côté serveur. Sinon
                // l'utilisateur tape un fix et clique Valider dans les 600ms
                // → la BDD a encore l'ancienne config invalide.
                try { await panel.flushAllAndWait(); } catch (_) { /* noop */ }
                saveIndicator.start();
                try {
                    const resp = await api.post('/api/automations/' + automationId + '/validate', {});
                    saveIndicator.success();
                    if (resp && resp.valid) {
                        // Re-refacto 2026-05-08 (decision David) : Valider
                        // = valider + activer en une etape. Le bouton est le
                        // CTA principal de l'editeur ; faire valider sans
                        // activer obligeait l'utilisateur a re-toggler depuis
                        // la liste (action redondante).
                        //
                        // V1 fix 2026-06-10 : on visait `/api/automations/N/toggle`
                        // (route INEXISTANTE → 404) avec `{target_intent}` (le
                        // handler lit `target`). Le CTA n'activait donc JAMAIS
                        // (404 ≠ 409 → "activation echouee"). Corrigé : route
                        // réelle `/automations/N/toggle` (cf. routes.py) + champ
                        // `target:true` (aligné sur le toggle liste). Le serveur
                        // répond 409 si l'auto est DEJA dans cet état → succès.
                        let activationMsg = 'Automatisation validee et activee';
                        try {
                            saveIndicator.start();
                            await api.post(
                                '/automations/' + automationId + '/toggle',
                                { target: true }
                            );
                            saveIndicator.success();
                        } catch (toggleErr) {
                            // 409 (status structuré, pas de string-match fragile)
                            // = `target` == état courant → deja active = succès.
                            // Tout autre code → on garde le succès de la
                            // validation mais on signale l'échec d'activation.
                            if (toggleErr && toggleErr.status === 409) {
                                saveIndicator.success();
                                activationMsg = 'Automatisation valide (deja active)';
                            } else {
                                const msg = (toggleErr && toggleErr.message) || 'inconnue';
                                saveIndicator.fail(msg);
                                showToast(
                                    'Validee mais activation echouee : ' + msg
                                    + ' — toggler depuis la liste.',
                                    'warning'
                                );
                                window.location.href = '/automations';
                                return;
                            }
                        }
                        showToast(activationMsg, 'success');
                        window.location.href = '/automations';
                        return;
                    } else if (resp && resp.errors && resp.errors.length) {
                        // Affiche la liste COMPLÈTE des erreurs dans une modale
                        // structurée (pas un toast tronqué). Chaque erreur
                        // cliquable focus le node concerné si node_id présent.
                        if (window.appShowErrors) {
                            window.appShowErrors(
                                'Validation du DAG (' + resp.errors.length + ' erreur' + (resp.errors.length > 1 ? 's' : '') + ')',
                                resp.errors,
                                {
                                    onErrorClick: function (err) {
                                        const nodeId = err && err.context && err.context.node_id;
                                        if (nodeId == null) return;
                                        const dfId = store.drawflowIdByStepId.get(nodeId);
                                        if (dfId != null && renderer && renderer.editor) {
                                            try { renderer.editor.click_node(dfId); } catch (_) { /* noop */ }
                                        }
                                    }
                                }
                            );
                        } else {
                            const summary = resp.errors.slice(0, 3).map(function (err) {
                                return (err.code || '?') + ' : ' + (err.message || '');
                            }).join(' | ');
                            const more = resp.errors.length > 3 ? ' (+' + (resp.errors.length - 3) + ')' : '';
                            showToast('Invalide — ' + summary + more, 'error');
                        }
                    } else {
                        showToast('Validation : résultat inattendu', 'warning');
                    }
                } catch (e) {
                    saveIndicator.fail(e.message);
                    showToast('Erreur validation : ' + e.message, 'error');
                }
            });
        }

        // ────────────────────────────────────────────
        // Palette drop zone → POST /steps → addNode
        // ────────────────────────────────────────────
        if (editable) {
            wireCanvasDropZone(container, async function onDrop(stepType, event) {
                const pos = computeDropPosition(event, renderer.editor);
                // Drawflow positionne le node avec son COIN top-left a
                // (pos.x, pos.y) — sans cette compensation, le node
                // apparait NODE_WIDTH/2 a droite et NODE_HEIGHT/2 en bas
                // du curseur. Convention UX moderne (n8n, Make, Figma) :
                // le node se centre sur le point de drop.
                pos.x = Math.round(pos.x - NODE_WIDTH / 2);
                pos.y = Math.round(pos.y - NODE_HEIGHT / 2);
                const meta = store.nodeTypes[stepType] || {};
                saveIndicator.start();
                try {
                    const resp = await api.post('/api/automations/' + automationId + '/steps', {
                        step_type: stepType,
                        name: meta.label || stepType,
                        config: defaultConfigFor(meta),
                        layout_x: pos.x,
                        layout_y: pos.y,
                        is_enabled: true,
                    });
                    if (!resp || !resp.step) throw new Error('Reponse invalide');
                    // Le backend persiste desormais layout_x/y directement
                    // depuis le POST body (Phase 3b-2). Pas besoin d'un
                    // round-trip PUT /layout supplementaire apres drop.
                    const step = resp.step;
                    store.steps.push(step);
                    store.stepsById.set(step.id, step);
                    const dfId = renderer.addNode(step, store.nodeTypes[stepType]);
                    store.drawflowIdByStepId.set(step.id, dfId);
                    store.stepIdByDrawflowId.set(dfId, step.id);

                    if (emptyOverlay) {
                        restoreEmptyHelp(emptyOverlay);  // DAG-4 — restaure l'aide
                        emptyOverlay.classList.add('hidden');
                    }
                    saveIndicator.success();
                } catch (e) {
                    saveIndicator.fail(e.message);
                    showToast('Creation etape refusee : ' + e.message, 'error');
                }
            });
        }

        function defaultConfigFor(meta) {
            const out = {};
            const schema = meta.config_schema || {};
            for (const key in schema) {
                // Defense prototype pollution : on ignore les keys heritees
                // du proto (cas extreme : pollution Object.prototype par une
                // lib tierce). Coherent avec le pattern ligne ~786 du panel.
                if (!Object.prototype.hasOwnProperty.call(schema, key)) continue;
                const spec = schema[key];
                if (spec.default !== undefined) {
                    out[key] = spec.default;
                }
            }
            return out;
        }

        // ────────────────────────────────────────────
        // Autosave layout (nodeMoved → PUT /layout)
        // ────────────────────────────────────────────
        const flushLayoutSave = createDebouncer(async function () {
            const positions = Object.assign({}, store.pendingPositions);
            store.pendingPositions = {};
            if (Object.keys(positions).length === 0) return;
            saveIndicator.start();
            try {
                await api.put('/api/automations/' + automationId + '/layout', {
                    positions: positions,
                });
                // Mettre a jour le store
                for (const sidStr in positions) {
                    const sid = parseInt(sidStr, 10);
                    const step = store.stepsById.get(sid);
                    if (step) {
                        step.layout_x = positions[sidStr].x;
                        step.layout_y = positions[sidStr].y;
                    }
                }
                saveIndicator.success();
            } catch (e) {
                saveIndicator.fail(e.message);
                showToast('Erreur sauvegarde positions : ' + e.message, 'error');
            }
        }, DEBOUNCE_LAYOUT_MS);

        function schedulePositionSave(stepId) {
            const pos = renderer.getNodePosition(stepId);
            if (!pos) return;
            store.pendingPositions[String(stepId)] = pos;
            flushLayoutSave();
        }

        renderer.editor.on('nodeMoved', function (dfIdStr) {
            if (!editable) return;
            const dfId = parseInt(dfIdStr, 10);
            const stepId = store.stepIdByDrawflowId.get(dfId);
            if (stepId == null) return;
            schedulePositionSave(stepId);
        });

        // ────────────────────────────────────────────
        // connectionCreated → POST /edges
        // ────────────────────────────────────────────
        renderer.editor.on('connectionCreated', async function (info) {
            if (!editable) return;
            // Rollback en cours : ignorer pour eviter les boucles
            // addConnection→connectionCreated→POST→fail→removeConnection.
            if (store.isRollingBack) return;
            // Hydratation initiale : addConnection() au boot dispatche aussi
            // connectionCreated. Sans ce filtre, chaque rechargement de page
            // re-POST /edges (rejete par dedup mais bruit serveur).
            if (store.isHydrating) return;
            const fromStepId = store.stepIdByDrawflowId.get(parseInt(info.output_id, 10));
            const toStepId = store.stepIdByDrawflowId.get(parseInt(info.input_id, 10));
            if (fromStepId == null || toStepId == null) return;

            const outId = parseInt(info.output_id, 10);
            const inId = parseInt(info.input_id, 10);

            // Validation client
            const check = validateEdgeClient(store, fromStepId, toStepId);
            if (!check.ok) {
                showToast(check.error, 'error');
                rollbackRemoveConnection(outId, inId);
                return;
            }

            saveIndicator.start();
            try {
                const resp = await api.post('/api/automations/' + automationId + '/edges', {
                    from_step_id: fromStepId,
                    to_step_id: toStepId,
                    data_type: check.data_type,
                });
                if (!resp || !resp.edge) {
                    const msg = (resp && resp.errors && resp.errors.length)
                        ? resp.errors.map(function (er) { return er.message || er.code; }).join(', ')
                        : 'refus serveur';
                    throw new Error(msg);
                }
                const edge = resp.edge;
                store.edges.push(edge);
                store.edgeByKey.set(edge.from_step_id + '->' + edge.to_step_id, edge.id);
                saveIndicator.success();
            } catch (e) {
                rollbackRemoveConnection(outId, inId);
                // Sur conflit de version (cross-onglet), le handler de
                // re-synchro (fix tempête 409 2026-06-10) affiche DÉJÀ son
                // toast et re-hydrate la vue (qui redessine le graphe). Ne pas
                // doubler avec un toast « liaison » ici (double-toast trompeur).
                if (e && e.isVersionConflict) {
                    // Solder le compteur saveIndicator (le start() ci-dessus) —
                    // sinon `inflight` reste > 0 → spinner « Enregistre… » bloqué
                    // (revue adv. consolidée 2026-06-10). La re-synchro EST la
                    // résolution de cette opération (toast + redraw gérés ailleurs).
                    saveIndicator.success();
                    return;
                }
                // DAG-2 — surfacer la RAISON précise du refus (cycle / types
                // incompatibles / …). Le serveur la renvoie dans ``errors[]``
                // (attaché à ``e.body`` par le helper api), pas dans le
                // générique ``e.message`` (« Validation DAG echouee »).
                var _reason = e.message;
                if (e.body && Array.isArray(e.body.errors) && e.body.errors.length) {
                    _reason = e.body.errors.map(function (er) {
                        return er.message || er.code;
                    }).join(' ; ');
                }
                saveIndicator.fail(_reason);
                // « Connexion refusée » prêtait à confusion (= erreur RÉSEAU).
                // C'est un refus de LIAISON du graphe (cycle / types
                // incompatibles / liaison déjà existante).
                showToast('Impossible de créer la liaison : ' + _reason, 'error');
            }
        });

        function rollbackRemoveConnection(outId, inId) {
            store.isRollingBack = true;
            try {
                renderer.removeConnection(outId, inId);
            } finally {
                // Reset en microtask : garantit que le `connectionRemoved`
                // dispatche par `removeConnection` soit ignore par notre
                // handler (qui verifie `isRollingBack` au debut).
                Promise.resolve().then(function () { store.isRollingBack = false; });
            }
        }

        function rollbackAddConnection(outId, inId) {
            store.isRollingBack = true;
            try {
                renderer.addConnection(outId, inId);
            } finally {
                Promise.resolve().then(function () { store.isRollingBack = false; });
            }
        }


        // ────────────────────────────────────────────
        // connectionRemoved → DELETE /edges/:eid (sauf si cascade nodeRemoved)
        // ────────────────────────────────────────────
        renderer.editor.on('connectionRemoved', async function (info) {
            if (!editable) return;
            if (store.isRollingBack) return;
            if (store.isHydrating) return;
            const fromStepId = store.stepIdByDrawflowId.get(parseInt(info.output_id, 10));
            const toStepId = store.stepIdByDrawflowId.get(parseInt(info.input_id, 10));
            if (fromStepId == null || toStepId == null) return;
            // Cascade deja geree par DELETE /steps : la suppression du node
            // se traduit en connectionRemoved cote Drawflow pour chaque
            // edge, et en DELETE CASCADE cote BDD. Ignorer ici evite des
            // DELETE /edges redondants (→ 404 bruit + pression DB).
            if (store.removingStepIds.has(fromStepId) || store.removingStepIds.has(toStepId)) {
                return;
            }
            const edgeId = store.edgeByKey.get(fromStepId + '->' + toStepId);
            if (!edgeId) return; // edge non connue cote store (edge cascade ?)

            const outId = parseInt(info.output_id, 10);
            const inId = parseInt(info.input_id, 10);

            saveIndicator.start();
            try {
                await api.del('/api/automations/' + automationId + '/edges/' + edgeId);
                store.edges = store.edges.filter(function (e) { return e.id !== edgeId; });
                store.edgeByKey.delete(fromStepId + '->' + toStepId);
                saveIndicator.success();
            } catch (e) {
                saveIndicator.fail(e.message);
                showToast('Suppression connexion echouee : ' + e.message, 'error');
                rollbackAddConnection(outId, inId);
            }
        });

        // ────────────────────────────────────────────
        // nodeRemoved → DELETE /steps (cascade edges en BDD)
        // ────────────────────────────────────────────
        renderer.editor.on('nodeRemoved', async function (dfIdStr) {
            if (!editable) return;
            const dfId = parseInt(dfIdStr, 10);
            const stepId = store.stepIdByDrawflowId.get(dfId);
            if (stepId == null) return;

            // Set des stepIds en cours : remplace l'ancien flag global
            // + setTimeout(50ms) qui avait des races sous charge ou
            // suppressions concurrentes. L'entree vit tout le temps du
            // DELETE /steps en vol.
            store.removingStepIds.add(stepId);
            saveIndicator.start();
            try {
                await api.del('/api/automations/' + automationId + '/steps/' + stepId);
                store.steps = store.steps.filter(function (s) { return s.id !== stepId; });
                store.stepsById.delete(stepId);
                store.drawflowIdByStepId.delete(stepId);
                store.stepIdByDrawflowId.delete(dfId);
                // Retire toutes les edges liees au store (cascade DB = CASCADE FK)
                store.edges = store.edges.filter(function (e) {
                    if (e.from_step_id === stepId || e.to_step_id === stepId) {
                        store.edgeByKey.delete(e.from_step_id + '->' + e.to_step_id);
                        return false;
                    }
                    return true;
                });
                // Cleanup panel config state pour ce step (si en cours d'edition).
                if (store.selectedStepId === stepId) panel.hide();
                panel.removeStep(stepId);
                if (emptyOverlay && store.steps.length === 0) {
                    // DAG-4 — reset pointer-events + RESTAURE le texte d'aide
                    // détruit par un éventuel showCanvasError (sinon overlay
                    // blanc / intercepte les drops suivants).
                    restoreEmptyHelp(emptyOverlay);
                    emptyOverlay.classList.remove('hidden');
                }
                saveIndicator.success();
            } catch (e) {
                saveIndicator.fail(e.message);
                // DAG-1 — Drawflow a déjà retiré le node visuellement, mais le
                // serveur l'a CONSERVÉ (delete rejeté) → canvas désync (montre
                // MOINS d'étapes que la réalité). On re-render le DAG depuis le
                // serveur pour restaurer l'état réel (l'étape réapparaît) au lieu
                // de laisser l'user reload manuellement. ``renderer.clear()`` dans
                // ``hydrate`` = ``editor.clear()`` Drawflow, qui n'émet PAS de
                // ``nodeRemoved`` → aucune cascade de DELETE.
                showToast(
                    'Suppression étape échouée : ' + e.message
                    + ' — resynchronisation du canvas…',
                    'error'
                );
                try {
                    await hydrate();
                } catch (e2) {
                    // Dernier recours si même la resync échoue (serveur down) :
                    // l'état visuel reste faux, on demande un reload manuel.
                    showToast('Resynchronisation impossible — rechargez la page.', 'error');
                }
            } finally {
                store.removingStepIds.delete(stepId);
            }
        });

        // ────────────────────────────────────────────
        // DAG-3 — flush des saves EN ATTENTE à la fermeture / navigation
        // ────────────────────────────────────────────
        // Une édition de champ faite dans la fenêtre de debounce (600ms) puis
        // suivie d'une fermeture d'onglet ou navigation immédiate était PERDUE
        // silencieusement (le timer ne fire jamais). ``visibilitychange``
        // (hidden) se déclenche page ENCORE VIVANTE (changement d'onglet + juste
        // avant une navigation dans les navigateurs modernes) → le PUT a le temps
        // de partir et d'aboutir. ``pagehide`` est le dernier recours sur unload
        // (best-effort : on dispatche au moins le fetch).
        if (editable) {
            var _flushPendingSaves = function () {
                try { panel.flushAll(); } catch (_) { /* best-effort : champs */ }
                try { flushLayoutSave.flush(); } catch (_) { /* best-effort : positions */ }
            };
            document.addEventListener('visibilitychange', function () {
                if (document.visibilityState === 'hidden') _flushPendingSaves();
            });
            window.addEventListener('pagehide', _flushPendingSaves);
        }

        // ────────────────────────────────────────────
        // nodeSelected / nodeUnselected → panel show/hide
        //
        // On utilise un pattern "delayed hide" : nodeUnselected hide le
        // panel apres un setTimeout(50ms), mais nodeSelected (sur un
        // autre node) annule ce timer immediatement. Comme ca :
        //  - Click node A → panel show A
        //  - Click node B → nodeUnselected (A) puis nodeSelected (B) :
        //    le timer est annule, panel show B sans flash.
        //  - Click canvas vide → nodeUnselected sans nodeSelected
        //    suivant : timer fire, panel hide. (Pas de "flèche au milieu
        //    quand pas d'etape selectionnee".)
        // ────────────────────────────────────────────
        let unselectTimer = null;
        function cancelUnselectTimer() {
            if (unselectTimer) { clearTimeout(unselectTimer); unselectTimer = null; }
        }

        renderer.editor.on('nodeSelected', function (dfIdStr) {
            cancelUnselectTimer();
            const dfId = parseInt(dfIdStr, 10);
            const stepId = store.stepIdByDrawflowId.get(dfId);
            if (stepId == null) return;
            const step = store.stepsById.get(stepId);
            if (!step) return;
            store.selectedStepId = stepId;
            panel.render(step);
            panel.show();
            bus.emit('step-selected', { step_id: stepId, step: step });
        });

        renderer.editor.on('nodeUnselected', function () {
            cancelUnselectTimer();
            unselectTimer = setTimeout(function () {
                unselectTimer = null;
                panel.hide();  // hide aussi le bouton edge-toggle (cf. show/hide)
                store.selectedStepId = null;
                bus.emit('step-deselected', {});
            }, 50);
        });

        // ────────────────────────────────────────────
        // Before unload : persister les positions en attente
        //
        // `fetch` avec `await` est souvent annule par le navigateur au unload.
        // `fetch(..., { keepalive: true })` est garanti par la spec : la
        // requete part meme si la page ferme, en background. Contrainte :
        // max 64 KB par requete (largement suffisant pour des positions).
        // On garde les headers XSRF (sendBeacon ne permet pas — pour PUT
        // notre handler exige X-Xsrftoken + cookie double-submit).
        //
        // sendBeacon serait plus universel mais ne transporte pas les
        // headers → XSRF serait contourne sans un endpoint /beacon dédié.
        // Le parc navigateur Komptia (Chrome 80+, Firefox 80+, Safari 13+)
        // supporte keepalive partout.
        // ────────────────────────────────────────────
        function flushPendingPositionsOnUnload() {
            const positions = Object.assign({}, store.pendingPositions);
            if (Object.keys(positions).length === 0) return;
            store.pendingPositions = {};
            if (typeof fetch !== 'function') return;
            try {
                fetch('/api/automations/' + automationId + '/layout', {
                    method: 'PUT',
                    credentials: 'same-origin',
                    keepalive: true,
                    headers: Object.assign(
                        {
                            'Content-Type': 'application/json',
                            'X-Requested-With': 'XMLHttpRequest',
                        },
                        xsrfHeader()
                    ),
                    body: JSON.stringify({ positions: positions }),
                }).catch(function () { /* best-effort */ });
            } catch (_) { /* ne bloque jamais le unload */ }
        }

        window.addEventListener('beforeunload', function () {
            try {
                // Annule le debouncer en attente pour s'assurer que la
                // requete ci-dessous a TOUTES les positions pendantes.
                flushLayoutSave.cancel();
                flushPendingPositionsOnUnload();
                // Note : les autosave config (panel) ne sont pas flush
                // via sendBeacon — l'utilisateur tapait dans un input
                // quand il ferme, on privilegie la fermeture rapide.
                // Le debouncer 600ms + toast visible suffisent a alerter.
            } catch (_) { /* ne bloque jamais le unload */ }
        });

        // ────────────────────────────────────────────
        // API publique exposee sur window.komptiaCanvas
        //
        // Surface STABLE consommee par les modules externes
        // (automation-preview.js notamment). Les internals (store,
        // renderer, panel) ne sont exposes qu'en mode debug pour
        // limiter le couplage et faciliter d'eventuels refactors.
        //
        // Methodes :
        //   getAutomationId()         → int
        //   getStepById(stepId)       → step dict | null
        //   setNodeStatus(id, status) → void   (proxy renderer)
        //   on(event, fn) / off(event, fn) → bus
        //
        // Evenements emis par le bus :
        //   'step-selected'   { step_id, step }
        //   'step-deselected' {}
        //   'config-changed'  { step_id }
        // ────────────────────────────────────────────
        const isDebug = (
            window.location.hostname === 'localhost' ||
            window.location.hostname === '127.0.0.1' ||
            document.documentElement.dataset.debug === 'true'
        );
        const publicApi = {
            getAutomationId: function () { return store.automationId; },
            getStepById: function (stepId) {
                const id = parseInt(stepId, 10);
                if (!Number.isFinite(id)) return null;
                return store.stepsById.get(id) || null;
            },
            setNodeStatus: function (stepId, status) {
                if (renderer && typeof renderer.setNodeStatus === 'function') {
                    renderer.setNodeStatus(stepId, status);
                }
            },
            on: bus.on,
            off: bus.off,
        };
        if (isDebug) {
            publicApi._internals = { store: store, renderer: renderer, panel: panel, bus: bus };
        }
        window.komptiaCanvas = publicApi;
        // initCanvas() est `async` (await api.get hydrate). Donc
        // `window.komptiaCanvas` n'est cree qu'apres tous les awaits,
        // *apres* le DOMContentLoaded. Les modules externes
        // (automation-preview.js) qui essaient d'attacher leurs
        // listeners sur `window.komptiaCanvas.on(...)` au DOMContentLoaded
        // arriveraient trop tot. On dispatch un event sur `window` pour
        // signaler que l'API est prete — les modules s'y abonnent.
        try {
            window.dispatchEvent(new CustomEvent('komptia-canvas-ready', { detail: publicApi }));
        } catch (_) { /* CustomEvent pas dispo dans certains contextes */ }
    }

    // ============================================================
    // Phase 3c — Viewer DAG (readonly, sur /executions/:id)
    //
    // Hydratation : appelle GET /api/automations/:auto_id/dag pour la
    // topologie + GET /api/executions/:exec_id/steps pour les statuts.
    // Map les step_id → drawflow_id et applique setNodeStatus pour
    // colorer chaque node. Click → panel detail (charge step_input/output
    // sensibles via /api/executions/:id/steps/:step_exec_id).
    //
    // Le canvas n'a aucun handler mutant : pas de palette, pas d'autosave,
    // editor_mode = 'view' donc Drawflow bloque toute edition.
    // ============================================================

    /**
     * Format un timestamp ISO en HH:MM:SS local (ou "—" si null).
     * Single source of truth : KomptiaFormat.timeOfDay (format-helpers.js).
     */
    function formatTime(iso) {
        return _KomptiaFormat.timeOfDay(iso);
    }

    /**
     * Format une duree ms en lisible : 234ms, 12.4s, 2m 15s.
     * Single source of truth : KomptiaFormat.durationMs (format-helpers.js).
     */
    function formatDuration(ms) {
        return _KomptiaFormat.durationMs(ms);
    }

    /**
     * Construit le contenu du panel detail d'une step_execution.
     * Toutes les insertions DOM via textContent ou createElement (anti-XSS,
     * step_input/output peuvent contenir des donnees client non controlees).
     */
    function renderStepDetail(bodyEl, stepData) {
        while (bodyEl.firstChild) bodyEl.removeChild(bodyEl.firstChild);

        function row(label, value) {
            const wrapper = document.createElement('div');
            wrapper.className = 'flex justify-between gap-3 text-xs';
            const lab = document.createElement('span');
            lab.className = 'text-gray-500 dark:text-gray-400';
            lab.textContent = label;
            const val = document.createElement('span');
            val.className = 'text-gray-900 dark:text-gray-100 font-medium text-right';
            val.textContent = (value == null || value === '') ? '—' : String(value);
            wrapper.appendChild(lab);
            wrapper.appendChild(val);
            return wrapper;
        }

        // Status banner colore
        const statusEl = document.createElement('div');
        statusEl.className = 'p-2 rounded text-xs font-semibold ' + (
            stepData.status === 'success' ? 'bg-emerald-50 text-emerald-700 dark:bg-emerald-900/20 dark:text-emerald-300' :
            stepData.status === 'failed' ? 'bg-red-50 text-red-700 dark:bg-red-900/20 dark:text-red-300' :
            stepData.status === 'running' ? 'bg-blue-50 text-blue-700 dark:bg-blue-900/20 dark:text-blue-300' :
            stepData.status === 'skipped' ? 'bg-gray-50 text-gray-500 dark:bg-gray-800 dark:text-gray-400' :
            'bg-yellow-50 text-yellow-700 dark:bg-yellow-900/20 dark:text-yellow-300'
        );
        statusEl.textContent = stepData.status || '?';
        bodyEl.appendChild(statusEl);

        // Section : infos generales
        const infoBlock = document.createElement('div');
        infoBlock.className = 'space-y-1';
        infoBlock.appendChild(row('Type', stepData.step_type));
        infoBlock.appendChild(row('Ordre', stepData.step_order));
        if (stepData.attempt_number > 1) {
            infoBlock.appendChild(row('Tentative', stepData.attempt_number));
        }
        infoBlock.appendChild(row('Debut', formatTime(stepData.started_at)));
        infoBlock.appendChild(row('Fin', formatTime(stepData.finished_at)));
        infoBlock.appendChild(row('Duree', formatDuration(stepData.duration_ms)));
        if (stepData.rows_in != null || stepData.rows_out != null) {
            infoBlock.appendChild(row(
                'Lignes',
                (stepData.rows_in ?? '?') + ' → ' + (stepData.rows_out ?? '?')
            ));
        }
        // Coercer en Number pour eviter `toFixed` sur string (JSON peut
        // serialiser un Decimal en string selon le backend) — sinon le
        // panel reste en "Chargement..." sur TypeError silencieux.
        const cost = Number(stepData.llm_cost_eur);
        if (Number.isFinite(cost) && cost > 0) {
            infoBlock.appendChild(row('Cout LLM', cost.toFixed(4) + ' €'));
        }
        const tokensIn = Number(stepData.llm_tokens_in);
        const tokensOut = Number(stepData.llm_tokens_out);
        if (Number.isFinite(tokensIn) || Number.isFinite(tokensOut)) {
            const tIn = Number.isFinite(tokensIn) ? tokensIn : 0;
            const tOut = Number.isFinite(tokensOut) ? tokensOut : 0;
            if (tIn > 0 || tOut > 0) {
                infoBlock.appendChild(row('Tokens', tIn + ' / ' + tOut));
            }
        }
        if (stepData.trace_id) {
            infoBlock.appendChild(row('Trace ID', stepData.trace_id));
        }
        bodyEl.appendChild(infoBlock);

        // Erreur (si status failed)
        if (stepData.error_message) {
            const errBox = document.createElement('div');
            errBox.className = 'p-2 rounded bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800/60';
            const errLab = document.createElement('p');
            errLab.className = 'text-xs font-semibold text-red-800 dark:text-red-200 mb-1';
            errLab.textContent = 'Erreur';
            errBox.appendChild(errLab);
            const errMsg = document.createElement('p');
            errMsg.className = 'text-xs text-red-700 dark:text-red-300 break-all';
            errMsg.textContent = stepData.error_message;
            errBox.appendChild(errMsg);
            bodyEl.appendChild(errBox);
        }

        // Warnings
        if (stepData.warnings && stepData.warnings.length > 0) {
            const wBox = document.createElement('div');
            wBox.className = 'p-2 rounded bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800/60';
            const wLab = document.createElement('p');
            wLab.className = 'text-xs font-semibold text-yellow-800 dark:text-yellow-200 mb-1';
            wLab.textContent = 'Avertissements';
            wBox.appendChild(wLab);
            stepData.warnings.forEach(function (w) {
                const p = document.createElement('p');
                p.className = 'text-xs text-yellow-700 dark:text-yellow-300';
                p.textContent = '• ' + String(w);
                wBox.appendChild(p);
            });
            bodyEl.appendChild(wBox);
        }

        // SQL execute (champ sensible — chargé via /api/.../steps/:id)
        if (stepData.sql_executed) {
            const sqlBox = document.createElement('details');
            sqlBox.className = 'border-t border-gray-100 dark:border-gray-800 pt-2';
            const summary = document.createElement('summary');
            summary.className = 'cursor-pointer text-xs font-semibold text-gray-700 dark:text-gray-300';
            summary.textContent = 'SQL execute';
            sqlBox.appendChild(summary);
            const pre = document.createElement('pre');
            pre.className = 'mt-2 p-2 rounded bg-gray-50 dark:bg-gray-950 text-xs overflow-x-auto whitespace-pre-wrap break-all';
            pre.textContent = stepData.sql_executed;
            sqlBox.appendChild(pre);
            bodyEl.appendChild(sqlBox);
        }

        // step_output (JSON tronque par workbook_snapshot_for_db cote backend)
        if (stepData.step_output != null) {
            const outBox = document.createElement('details');
            outBox.className = 'border-t border-gray-100 dark:border-gray-800 pt-2';
            const summary = document.createElement('summary');
            summary.className = 'cursor-pointer text-xs font-semibold text-gray-700 dark:text-gray-300';
            summary.textContent = 'Sortie';
            outBox.appendChild(summary);
            const pre = document.createElement('pre');
            pre.className = 'mt-2 p-2 rounded bg-gray-50 dark:bg-gray-950 text-xs overflow-x-auto whitespace-pre-wrap break-all';
            try {
                pre.textContent = JSON.stringify(stepData.step_output, null, 2);
            } catch (_) {
                pre.textContent = String(stepData.step_output);
            }
            outBox.appendChild(pre);
            bodyEl.appendChild(outBox);
        }

        // step_input
        if (stepData.step_input != null) {
            const inBox = document.createElement('details');
            inBox.className = 'border-t border-gray-100 dark:border-gray-800 pt-2';
            const summary = document.createElement('summary');
            summary.className = 'cursor-pointer text-xs font-semibold text-gray-700 dark:text-gray-300';
            summary.textContent = 'Entree';
            inBox.appendChild(summary);
            const pre = document.createElement('pre');
            pre.className = 'mt-2 p-2 rounded bg-gray-50 dark:bg-gray-950 text-xs overflow-x-auto whitespace-pre-wrap break-all';
            try {
                pre.textContent = JSON.stringify(stepData.step_input, null, 2);
            } catch (_) {
                pre.textContent = String(stepData.step_input);
            }
            inBox.appendChild(pre);
            bodyEl.appendChild(inBox);
        }

        // config_snapshot
        if (stepData.config_snapshot != null) {
            const cfgBox = document.createElement('details');
            cfgBox.className = 'border-t border-gray-100 dark:border-gray-800 pt-2';
            const summary = document.createElement('summary');
            summary.className = 'cursor-pointer text-xs font-semibold text-gray-700 dark:text-gray-300';
            summary.textContent = 'Config (au moment de l\'execution)';
            cfgBox.appendChild(summary);
            const pre = document.createElement('pre');
            pre.className = 'mt-2 p-2 rounded bg-gray-50 dark:bg-gray-950 text-xs overflow-x-auto whitespace-pre-wrap break-all';
            try {
                pre.textContent = JSON.stringify(stepData.config_snapshot, null, 2);
            } catch (_) {
                pre.textContent = String(stepData.config_snapshot);
            }
            cfgBox.appendChild(pre);
            bodyEl.appendChild(cfgBox);
        }
    }

    async function initViewer() {
        const root = document.getElementById('komptia-viewer-root');
        if (!root) return;
        const executionId = parseInt(root.getAttribute('data-komptia-execution-id'), 10);
        const automationId = parseInt(root.getAttribute('data-komptia-automation-id'), 10);
        if (!executionId || !automationId) return;

        const container = document.getElementById('komptia-viewer-canvas');
        if (!container) return;
        const statusEl = document.getElementById('komptia-viewer-status');
        const emptyOverlay = document.getElementById('komptia-viewer-empty');
        const panel = document.getElementById('komptia-viewer-panel');
        const panelTitle = document.getElementById('komptia-viewer-panel-title');
        const panelBody = document.getElementById('komptia-viewer-panel-body');
        const panelClose = document.getElementById('komptia-viewer-panel-close');

        const api = createApi();

        function setStatus(text) {
            if (statusEl) statusEl.textContent = text;
        }

        let renderer;
        try {
            renderer = createRendererAdapter(container, { editable: false });
        } catch (e) {
            console.error('Komptia viewer: init renderer failed', e);
            setStatus('Erreur librairie');
            return;
        }

        // Index pour clic → step_execution detail
        // step_id (FK AutomationStep) → step_exec data { id, status, ...}
        const stepExecsByStepId = new Map();
        // drawflow_id → step_id
        const stepIdByDrawflowId = new Map();

        try {
            setStatus('Chargement...');
            // 3 requetes en parallele : la latence totale = max des trois,
            // pas la somme. step-types est isole en `.catch` pour ne pas
            // casser la page si l'endpoint ne repond pas (degradation
            // gracieuse : labels = step_type brut).
            const [dagData, stepsData, typesData] = await Promise.all([
                api.get('/api/automations/' + automationId + '/dag'),
                api.get('/api/executions/' + executionId + '/steps'),
                api.get('/api/automations/step-types').catch(function (err) {
                    console.warn('Komptia viewer: step-types unavailable', err);
                    return { categories: [] };
                }),
            ]);

            const typesByName = {};
            for (const cat of (typesData.categories || [])) {
                for (const s of (cat.steps || [])) {
                    typesByName[s.type] = s;
                }
            }

            const dagSteps = dagData.steps || [];
            // Auto-layout pour les nodes sans position (workflows non-positionnes)
            assignAutoLayout(dagSteps, dagData.unpositioned_step_ids || []);

            renderer.clear();
            for (const step of dagSteps) {
                const dfId = renderer.addNode(step, typesByName[step.step_type]);
                stepIdByDrawflowId.set(dfId, step.id);
            }
            // Track les edges silencieusement skippees (step manquant).
            // Sans ce comptage, le DAG affiche serait incomplet sans signal.
            let edgesRendered = 0;
            let edgesSkipped = 0;
            for (const edge of (dagData.edges || [])) {
                const fromDf = findDrawflowIdByStepId(renderer.editor, edge.from_step_id);
                const toDf = findDrawflowIdByStepId(renderer.editor, edge.to_step_id);
                if (fromDf != null && toDf != null) {
                    renderer.addConnection(fromDf, toDf);
                    edgesRendered += 1;
                } else {
                    edgesSkipped += 1;
                    console.warn(
                        'Komptia viewer: edge skipped (step not rendered)',
                        edge
                    );
                }
            }

            // Index des step_executions par step_id (FK).
            // Multi-attempts : on garde la derniere (max attempt_number)
            // avec preference au statut terminal (success > failed >
            // running > pending) si attempt_number egal — evite de
            // colorer un node "pending" alors qu'il a abouti en success
            // sur la meme tentative (race d'ordre serveur).
            // Les steps sans step_id (step supprime post-execution) sont
            // skippes silencieusement — pas de coloration possible.
            const stepExecs = stepsData.steps || [];
            const STATUS_PRIORITY = {
                success: 4, failed: 4, retried: 3,
                skipped: 2, running: 1, pending: 0,
            };
            for (const se of stepExecs) {
                if (se.step_id == null) continue;
                const existing = stepExecsByStepId.get(se.step_id);
                const newAttempt = (se.attempt_number == null) ? 0 : se.attempt_number;
                if (!existing) {
                    stepExecsByStepId.set(se.step_id, se);
                    continue;
                }
                const exAttempt = (existing.attempt_number == null) ? 0 : existing.attempt_number;
                if (newAttempt > exAttempt) {
                    stepExecsByStepId.set(se.step_id, se);
                } else if (newAttempt === exAttempt) {
                    // Tiebreak par priorite de statut.
                    const newPri = STATUS_PRIORITY[se.status] ?? -1;
                    const exPri = STATUS_PRIORITY[existing.status] ?? -1;
                    if (newPri > exPri) {
                        stepExecsByStepId.set(se.step_id, se);
                    }
                }
            }

            // Coloration des nodes par status
            for (const [stepId, se] of stepExecsByStepId.entries()) {
                renderer.setNodeStatus(stepId, se.status);
            }

            // Empty state
            if (emptyOverlay) {
                emptyOverlay.classList.toggle('hidden', dagSteps.length > 0);
            }

            // Status : "N etapes • X/Y liens" + warning si edges skippees.
            let statusText = stepExecs.length + ' etapes • ' + edgesRendered;
            if (edgesSkipped > 0) {
                statusText += '/' + (edgesRendered + edgesSkipped) +
                    ' liens (' + edgesSkipped + ' ignore' +
                    (edgesSkipped > 1 ? 's' : '') + ')';
            } else {
                statusText += ' liens';
            }
            setStatus(statusText);
        } catch (e) {
            console.error('Komptia viewer: hydration failed', e);
            setStatus('Erreur chargement');
            return;
        }

        // Click sur node → fetch detail + render panel
        renderer.editor.on('nodeSelected', async function (dfIdStr) {
            const dfId = parseInt(dfIdStr, 10);
            const stepId = stepIdByDrawflowId.get(dfId);
            if (stepId == null) return;
            const se = stepExecsByStepId.get(stepId);
            if (!se) {
                if (panelTitle) panelTitle.textContent = 'Pas execute';
                if (panelBody) {
                    while (panelBody.firstChild) panelBody.removeChild(panelBody.firstChild);
                    const p = document.createElement('p');
                    p.className = 'text-xs text-gray-500';
                    p.textContent = 'Cette etape n\'a pas de StepExecution lie a cette execution.';
                    panelBody.appendChild(p);
                }
                if (panel) panel.classList.remove('hidden');
                return;
            }

            if (panelTitle) panelTitle.textContent = se.step_name || se.step_type || '?';
            if (panelBody) {
                while (panelBody.firstChild) panelBody.removeChild(panelBody.firstChild);
                const loading = document.createElement('p');
                loading.className = 'text-xs text-gray-500';
                loading.textContent = 'Chargement...';
                panelBody.appendChild(loading);
            }
            if (panel) panel.classList.remove('hidden');

            try {
                const detail = await api.get(
                    '/api/executions/' + executionId + '/steps/' + se.id
                );
                if (panelBody && detail && detail.step) {
                    renderStepDetail(panelBody, detail.step);
                }
            } catch (e) {
                if (panelBody) {
                    while (panelBody.firstChild) panelBody.removeChild(panelBody.firstChild);
                    const p = document.createElement('p');
                    p.className = 'text-xs text-red-600';
                    p.textContent = 'Erreur: ' + e.message;
                    panelBody.appendChild(p);
                }
            }
        });

        if (panelClose) {
            panelClose.addEventListener('click', function () {
                if (panel) panel.classList.add('hidden');
            });
        }

        // Zoom buttons
        const zoomIn = document.getElementById('komptia-viewer-zoom-in');
        if (zoomIn) zoomIn.addEventListener('click', function () { renderer.zoomIn(); });
        const zoomOut = document.getElementById('komptia-viewer-zoom-out');
        if (zoomOut) zoomOut.addEventListener('click', function () { renderer.zoomOut(); });
        const zoomReset = document.getElementById('komptia-viewer-zoom-reset');
        if (zoomReset) zoomReset.addEventListener('click', function () { renderer.zoomReset(); });

        // Tabs DAG / Timeline
        const tabBtns = document.querySelectorAll('.komptia-tab-btn');
        const tabPanes = document.querySelectorAll('[data-komptia-tab-pane]');
        tabBtns.forEach(function (btn) {
            btn.addEventListener('click', function () {
                const target = btn.getAttribute('data-komptia-tab');
                tabBtns.forEach(function (b) {
                    const active = b === btn;
                    b.classList.toggle('border-brand-500', active);
                    b.classList.toggle('text-gray-900', active);
                    b.classList.toggle('dark:text-gray-100', active);
                    b.classList.toggle('border-transparent', !active);
                    b.classList.toggle('text-gray-500', !active);
                    b.setAttribute('aria-selected', active ? 'true' : 'false');
                });
                tabPanes.forEach(function (p) {
                    p.classList.toggle('hidden', p.getAttribute('data-komptia-tab-pane') !== target);
                });
            });
        });

        // Replay button
        const replayBtn = document.getElementById('komptia-replay-btn');
        if (replayBtn) {
            replayBtn.addEventListener('click', async function () {
                const original = replayBtn.textContent;
                replayBtn.disabled = true;
                replayBtn.textContent = 'Relance...';
                try {
                    const resp = await api.post(
                        '/api/executions/' + executionId + '/replay',
                        {}
                    );
                    if (resp && resp.execution_id) {
                        // B6 — Affiche le warning avant la redirection si
                        // backend signale "rerun" (re-execution avec donnees
                        // actuelles, pas reproduction snapshot). Le user doit
                        // savoir avant de voir le nouveau run aboutir.
                        if (resp.warning === 'rerun' && resp.warning_message) {
                            showToast(resp.warning_message, 'warning');
                        }
                        // Pause courte pour laisser le toast etre lu, puis redirige.
                        setTimeout(function () {
                            window.location.href = '/executions/' + resp.execution_id;
                        }, resp.warning === 'rerun' ? 2500 : 0);
                    } else {
                        showToast('Replay : reponse inattendue', 'warning');
                        replayBtn.disabled = false;
                        replayBtn.textContent = original;
                    }
                } catch (e) {
                    const msg = (e.body && e.body.error) || e.message;
                    showToast('Replay refuse : ' + msg, 'error');
                    replayBtn.disabled = false;
                    replayBtn.textContent = original;
                }
            });
        }
    }

    // Initialise uniquement dans un contexte navigateur (Node lit ce fichier
    // pour tests unitaires — les exports module sont installes en bas).
    if (typeof document !== 'undefined') {
        const boot = function () {
            // Mode editeur (canvas /automations/:id/edit) ou viewer
            // (/executions/:id) ? Les deux sont mutuellement exclusifs car
            // les IDs racines diffèrent.
            initCanvas();
            initViewer();
        };
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', boot);
        } else {
            boot();
        }
    }

    // ============================================================
    // Exports minimaux (testabilite pure JS — utilise par tests unit)
    // ============================================================
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = {
            computeDropPosition: computeDropPosition,
            validateEdgeClient: validateEdgeClient,
            assignAutoLayout: assignAutoLayout,
            escapeHtml: escapeHtml,
            escapeAttr: escapeAttr,
            createDebouncer: createDebouncer,
            formatTime: formatTime,
            formatDuration: formatDuration,
        };
    }
})();
