/* eslint-env browser */
/**
 * Komptia — Pickers de ressources pour la config des étapes d'automation.
 *
 * Module séparé d'`automation-canvas.js` pour ne pas grossir un fichier
 * déjà à 2400+ lignes. Chargé sur `/automations/N/edit` après le canvas
 * (cf. `templates/automations/edit.html`). Expose `window.komptiaPickers`.
 *
 * Le canvas appelle `window.komptiaPickers.build(widget, spec, value,
 * onChange, ctx)` quand un schema déclare un `widget` non-natif. On
 * retourne un élément DOM (input) ou `null` si on ne sait pas gérer
 * — le canvas tombe alors sur son widget natif (progressive enhancement).
 *
 * Pickers fournis :
 *  - ``datastore_sql_picker``      → dropdown des .sql du datastore (Iris)
 *  - ``distribution_list_picker``  → dropdown distribution lists
 *  - ``datastore_file_picker``     → ExternalSheetsPicker (path-only)
 *  - ``contacts_chips``            → chips + datalist autocomplete
 *  - ``workbook_tab_picker``       → dropdown onglets (dynamique)
 *  - ``workbook_tabs_multi_picker``→ multi-select onglets (dynamique)
 */
(function () {
    'use strict';

    // ── Cache mémoire TTL pour les listes de ressources ──────────
    // Évite de re-fetch à chaque sélection de noeud. Court (60s) car
    // l'utilisateur peut créer une saved_query / un contact dans un
    // autre onglet et revenir ici. Refresh on focus du picker.

    var CACHE_TTL_MS = 60 * 1000;
    var cache = Object.create(null);  // key → { ts, data }

    function cacheGet(key) {
        var entry = cache[key];
        if (!entry) return null;
        if (Date.now() - entry.ts > CACHE_TTL_MS) {
            delete cache[key];
            return null;
        }
        return entry.data;
    }

    function cachePut(key, data) {
        cache[key] = { ts: Date.now(), data: data };
    }

    function cacheInvalidate(prefix) {
        for (var k in cache) {
            if (Object.prototype.hasOwnProperty.call(cache, k) && k.indexOf(prefix) === 0) {
                delete cache[k];
            }
        }
    }

    // Invalidation au focus de la fenêtre : si l'utilisateur a passé
    // plus de TTL hors de la page (autre onglet où il a créé un
    // contact / saved_query / distribution_list), on dégage le cache
    // pour que le prochain build picker re-fetch des données fraîches.
    // Sans ça, à 8h d'utilisation, l'autocomplete suggère des contacts
    // supprimés (cf. finding C5 de l'adversarial review). À terme :
    // BroadcastChannel('komptia-resources') pour invalider sur events
    // mutations cross-onglets — flagué comme dette.
    var lastBlur = 0;
    if (typeof window !== 'undefined') {
        window.addEventListener('blur', function () { lastBlur = Date.now(); });
        window.addEventListener('focus', function () {
            if (lastBlur && (Date.now() - lastBlur) > CACHE_TTL_MS) {
                cacheInvalidate('');
            }
            lastBlur = 0;
        });
    }

    // ── Fetch helper avec timeout + erreur typée ─────────────────

    function fetchJson(url, opts) {
        opts = opts || {};
        var timeoutMs = opts.timeoutMs || 5000;
        var controller = (typeof AbortController !== 'undefined') ? new AbortController() : null;
        var timer = setTimeout(function () {
            if (controller) controller.abort();
        }, timeoutMs);
        return fetch(url, {
            credentials: 'same-origin',
            headers: { 'X-Requested-With': 'XMLHttpRequest' },
            signal: controller ? controller.signal : undefined,
        }).then(function (res) {
            clearTimeout(timer);
            if (!res.ok) {
                var err = new Error('HTTP ' + res.status);
                err.status = res.status;
                throw err;
            }
            return res.json();
        }, function (err) {
            clearTimeout(timer);
            throw err;
        });
    }

    // ── DOM helpers (mêmes conventions qu'`automation-preview.js`) ──

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
                    || k === 'list'
                ) {
                    node.setAttribute(k, attrs[k]);
                }
                else node[k] = attrs[k];
            }
        }
        if (children) {
            for (var i = 0; i < children.length; i += 1) {
                if (children[i] === null || children[i] === undefined) continue;
                if (typeof children[i] === 'string') {
                    node.appendChild(document.createTextNode(children[i]));
                } else node.appendChild(children[i]);
            }
        }
        return node;
    }

    /** Remplace le contenu d'un wrapper (clear puis append).
     *
     * Si le wrapper a été détaché du DOM entre le moment où on a lancé
     * un fetch et la résolution (ex : l'utilisateur a cliqué un autre
     * noeud, le panel s'est re-rendered, l'ancien wrapper est zombie)
     * on no-op : pas la peine de muter un DOM orphelin, et surtout pas
     * de risquer un onChange bind qui mute le mauvais step (cf. finding
     * C1 de l'adversarial review).
     */
    function setContent(wrapper, child) {
        if (!wrapper.isConnected) return;
        while (wrapper.firstChild) wrapper.removeChild(wrapper.firstChild);
        if (child) wrapper.appendChild(child);
    }

    function loadingNode(label) {
        return el('div', { class: 'komptia-picker-loading', text: label || 'Chargement…' });
    }

    function emptyNode(label) {
        return el('div', { class: 'komptia-picker-empty', text: label || 'Aucun élément.' });
    }

    function errorNode(label) {
        return el('div', { class: 'komptia-picker-error', role: 'alert', text: label });
    }

    // ── 1. Distribution list picker ──────────────────────────────

    function buildDistributionListPicker(spec, value, onChange) {
        var wrap = el('div', { class: 'komptia-picker-wrap' });
        wrap.appendChild(loadingNode('Chargement des listes de diffusion…'));

        function render(lists) {
            var sel = el('select', { class: 'komptia-select' });

            var ids = lists.map(function (l) { return l.id; });
            var hasOrphan = (
                value !== null && value !== undefined && value !== ''
                && ids.indexOf(Number(value)) < 0
            );

            var optEmpty = el('option', { value: '', text: '— Aucune liste —' });
            // Garde la même protection que saved_query (M1).
            if (hasOrphan) optEmpty.disabled = true;
            sel.appendChild(optEmpty);

            if (hasOrphan) {
                var orphan = el('option', {
                    value: String(value),
                    text: '⚠ ID ' + value + ' (introuvable / supprimée)',
                });
                orphan.selected = true;
                sel.appendChild(orphan);
            }

            lists.forEach(function (l) {
                var label = l.name || ('Liste #' + l.id);
                // DLIST-1 — la réponse /api/distribution-lists sérialise le compte
                // sous la clé ``contact_count`` (Contact.to_dict, SSoT, comme
                // contacts.js). On lisait ``member_count`` (le label SQL interne)
                // → toujours undefined → « N membre(s) » jamais affiché.
                var count = (l.contact_count !== undefined) ? (' — ' + l.contact_count + ' membre(s)') : '';
                var opt = el('option', { value: String(l.id), text: label + count });
                if (Number(value) === l.id) opt.selected = true;
                sel.appendChild(opt);
            });

            if (!lists.length && !hasOrphan) {
                setContent(wrap, emptyNode(
                    'Aucune liste de diffusion. Créez-en depuis /contacts.'
                ));
                return;
            }

            sel.addEventListener('change', function () {
                var v = sel.value;
                if (v === '') { onChange(null); return; }
                var num = parseInt(v, 10);
                onChange(isNaN(num) ? null : num);
            });
            setContent(wrap, sel);
        }

        var cached = cacheGet('distribution_lists');
        if (cached) {
            render(cached);
        } else {
            fetchJson('/api/distribution-lists').then(function (data) {
                if (!data || data.success === false) {
                    setContent(wrap, errorNode('Impossible de charger les listes.'));
                    return;
                }
                // Le service renvoie ``data.data.lists`` (cf. handler) ou
                // ``data.lists`` selon les versions ; tolérer les deux.
                var lists = (data.data && data.data.lists) || data.lists || [];
                cachePut('distribution_lists', lists);
                render(lists);
            }, function () {
                setContent(wrap, errorNode('Erreur de chargement. Vérifiez votre connexion.'));
            });
        }
        return wrap;
    }

    // ── 3. Datastore file picker ─────────────────────────────────
    // Single source of truth avec ``/reports`` : on réutilise le
    // composant ``ExternalSheetsPicker`` (cf. ``static/js/components/
    // external_sheets_picker.js``). Mode ``source`` → l'utilisateur
    // choisit un classeur (.afz.json), un onglet Excel ou un fichier
    // CSV ; on extrait le path qui sert à ``load_workbook.path``.
    //
    // Saisie manuelle conservée comme fallback (rétrocompat data legacy).

    var ALLOWED_EXTS = /\.(afz\.json|xlsx|xls|csv)$/i;

    // ── Datastore SQL picker ─────────────────────────────────────
    // Liste les ``.sql`` du datastore (générés par Iris via le bouton
    // « Enregistrer »). Scan récursif limité à 3 niveaux de dossiers
    // pour ne pas DoS le serveur sur un datastore enorme.

    async function fetchAllSqlFiles(rootPath, maxDepth) {
        var results = [];
        async function walk(path, depth) {
            if (depth > maxDepth) return;
            try {
                var url = '/api/datastore' + (path ? '?path=' + encodeURIComponent(path) : '');
                var data = await fetchJson(url);
                if (!data || data.success === false) return;
                var items = data.items || [];
                for (var i = 0; i < items.length; i += 1) {
                    var it = items[i];
                    if (it.is_dir) {
                        await walk(it.path, depth + 1);
                    } else if (/\.sql$/i.test(it.name || '')) {
                        results.push({ path: it.path, name: it.name });
                    }
                }
            } catch (_) { /* skip dossier inaccessible */ }
        }
        await walk(rootPath || '', 0);
        return results;
    }

    function buildDatastoreSqlPicker(spec, value, onChange) {
        var wrap = el('div', { class: 'komptia-picker-wrap' });
        wrap.appendChild(loadingNode('Recherche des fichiers .sql…'));

        function render(files) {
            var sel = el('select', { class: 'komptia-select' });
            // Tolérance valeur orpheline : on ajoute la valeur courante
            // si elle n'est pas dans la liste (fichier supprimé entre
            // deux configs). Préserve le path stocké sans écraser.
            var paths = files.map(function (f) { return f.path; });
            var hasOrphan = (
                value !== null && value !== undefined && value !== ''
                && paths.indexOf(value) < 0
            );
            var optEmpty = el('option', { value: '', text: '— Choisir un fichier .sql —' });
            if (hasOrphan) optEmpty.disabled = true;
            sel.appendChild(optEmpty);
            if (hasOrphan) {
                var orphan = el('option', {
                    value: String(value),
                    text: '⚠ ' + value + ' (introuvable)',
                });
                orphan.selected = true;
                sel.appendChild(orphan);
            }
            files.forEach(function (f) {
                var opt = el('option', { value: f.path, text: f.path });
                if (value === f.path) opt.selected = true;
                sel.appendChild(opt);
            });
            if (!files.length && !hasOrphan) {
                setContent(wrap, emptyNode(
                    'Aucun fichier .sql dans votre datastore. Allez dans /iris, '
                    + 'exécutez une requête, puis cliquez « Enregistrer » pour '
                    + 'la sauvegarder en .sql.'
                ));
                return;
            }
            sel.addEventListener('change', function () {
                onChange(sel.value || null);
            });
            setContent(wrap, sel);
        }

        var cached = cacheGet('datastore_sql_files');
        if (cached) {
            render(cached);
        } else {
            // 3 niveaux de profondeur : couvre 99% des arborescences.
            fetchAllSqlFiles('', 3).then(function (files) {
                cachePut('datastore_sql_files', files);
                render(files);
            }, function () {
                setContent(wrap, errorNode('Erreur de chargement du datastore.'));
            });
        }
        return wrap;
    }

    function buildDatastoreFilePicker(spec, value, onChange) {
        var wrap = el('div', { class: 'komptia-picker-wrap komptia-picker-file' });

        var pathDisplay = el('div', { class: 'komptia-picker-file-path' });
        var pathText = el('span', {
            text: value || '(aucun fichier sélectionné)',
        });
        if (!value) pathText.className = 'komptia-picker-empty-inline';
        pathDisplay.appendChild(pathText);

        function applyPath(p) {
            if (!p) return;
            onChange(p);
            pathText.textContent = p;
            pathText.className = '';
            btn.textContent = 'Changer…';
        }

        var btn = el('button', {
            type: 'button',
            class: 'komptia-picker-file-btn',
            text: value ? 'Changer…' : 'Choisir un fichier…',
        });
        btn.addEventListener('click', function () {
            if (!window.ExternalSheetsPicker
                || typeof window.ExternalSheetsPicker.open !== 'function') {
                // Cluster-O 2026-05-26 — Fallback dégradé : appPrompt
                // (modal Komptia stylé) remplace window.prompt natif
                // (non-stylable, dark-mode-incompatible). Si appPrompt
                // n'est pas chargé (init JS partielle), fallback console.
                if (typeof window.appPrompt === 'function') {
                    window.appPrompt(
                        'Chemin du fichier dans /datastore :',
                        'Saisie manuelle',
                        { defaultValue: value || '' }
                    ).then(function (v) {
                        if (v !== null && v !== '') applyPath(v);
                        else if (v === '') applyPath(null);
                    });
                } else {
                    console.warn('[automation-pickers] appPrompt absent — saisie manuelle indisponible');
                }
                return;
            }
            // Mode 'source' = l'utilisateur sélectionne une feuille mais
            // on extrait juste le path. Voir ``templates/reports/list.html
            // ::openExternalSheetsForReport`` pour le pattern de référence.
            window.ExternalSheetsPicker.open({
                mode: 'source',
                onSelect: function (items) {
                    if (!items || !items.length) return;
                    var item = items[0];  // un seul fichier pour load_workbook
                    var path = null;
                    if (item.type === 'workbook') path = item.classeur;
                    else if (item.type === 'excel') path = item.path;
                    else if (item.type === 'csv') path = item.path;
                    if (path) applyPath(path);
                },
            });
        });

        // Saisie manuelle cachée — bouton "saisie manuelle" pour la révéler.
        // Conserve la rétrocompat avec les automations existantes qui ont
        // un path tapé à la main qu'on ne veut pas casser.
        var manualLink = el('a', {
            href: '#',
            class: 'komptia-picker-manual-link',
            text: 'saisie manuelle',
        });
        var manualInput = el('input', {
            type: 'text',
            class: 'komptia-input komptia-picker-manual-input',
            value: value || '',
            placeholder: 'rapports/foo.afz.json',
        });
        manualInput.style.display = 'none';
        manualLink.addEventListener('click', function (e) {
            e.preventDefault();
            var visible = manualInput.style.display !== 'none';
            manualInput.style.display = visible ? 'none' : 'block';
            if (!visible) manualInput.focus();
        });

        // Validation client de la saisie manuelle (anti-confusion UX :
        // un user qui tape '../etc/passwd' ou '/abs/path' aurait un
        // crash backend cryptique).
        var manualError = el('span', {
            class: 'komptia-picker-manual-error',
            role: 'alert',
        });
        manualError.style.cssText = 'color:#b91c1c;font-size:11px;display:none;';
        manualInput.addEventListener('input', function () {
            var v = manualInput.value.trim();
            if (v && v.indexOf('..') >= 0) {
                manualError.textContent = 'Chemin relatif uniquement (pas de "..").';
                manualError.style.display = 'block';
                return;
            }
            if (v && v.charAt(0) === '/') {
                manualError.textContent = 'Chemin relatif uniquement (pas de "/" en tête).';
                manualError.style.display = 'block';
                return;
            }
            if (v && !ALLOWED_EXTS.test(v)) {
                manualError.textContent = 'Extensions acceptées : .afz.json, .xlsx, .xls, .csv';
                manualError.style.display = 'block';
                return;
            }
            manualError.style.display = 'none';
            onChange(v || null);
            pathText.textContent = v || '(aucun fichier sélectionné)';
            pathText.className = v ? '' : 'komptia-picker-empty-inline';
        });

        wrap.appendChild(pathDisplay);
        wrap.appendChild(btn);
        wrap.appendChild(manualLink);
        wrap.appendChild(manualInput);
        wrap.appendChild(manualError);
        return wrap;
    }


    // ── 4. Contacts chips (autocomplete via datalist HTML5) ──────

    function buildContactsChips(spec, value, onChange) {
        // Format de stockage : array de strings (cohérent avec
        // ``buildChipsInput`` natif). On tolère AUSSI :
        //  - string CSV legacy (``"a@x.fr,b@y.fr"``) → split. Sinon
        //    la première interaction écrasait silencieusement la
        //    valeur stockée par un array sans les anciens.
        //  - null/undefined → []
        //  - autre type → [] + warn console (donnée corrompue, on
        //    ne perd pas la donnée car l'autosave n'est armé que
        //    sur action user).
        var items;
        if (Array.isArray(value)) {
            items = value.slice();
        } else if (typeof value === 'string' && value.length > 0) {
            items = value.split(',').map(function (s) { return s.trim(); }).filter(Boolean);
        } else {
            items = [];
        }
        var wrap = el('div', { class: 'komptia-chips komptia-chips-with-suggest' });

        // Datalist ID unique pour ne pas collider entre plusieurs chips
        // sur la même page (to + cc + bcc en parallèle).
        var datalistId = 'komptia-contacts-datalist-' + Math.random().toString(36).slice(2, 9);
        var datalist = el('datalist', { id: datalistId });
        wrap.appendChild(datalist);

        var input = el('input', {
            type: 'text',
            class: 'komptia-chips-input',
            placeholder: 'email ou nom de contact…',
            list: datalistId,
            autocomplete: 'off',
        });

        function emit() {
            onChange(items.slice());
        }

        function renderChips() {
            // Retire toutes les chips actuelles (mais garde le datalist + input)
            var toRemove = [];
            for (var i = 0; i < wrap.children.length; i += 1) {
                var c = wrap.children[i];
                if (c === datalist || c === input) continue;
                toRemove.push(c);
            }
            toRemove.forEach(function (n) { wrap.removeChild(n); });

            // Insert chips before input
            items.forEach(function (text, idx) {
                var chip = el('span', { class: 'komptia-chip' });
                chip.appendChild(el('span', { text: text }));
                var x = el('span', {
                    class: 'komptia-chip-remove',
                    text: '×',
                    role: 'button',
                    'aria-label': 'Retirer ' + text,
                });
                x.addEventListener('click', function () {
                    items.splice(idx, 1);
                    renderChips();
                    emit();
                });
                chip.appendChild(x);
                wrap.insertBefore(chip, input);
            });
        }

        // Regex email pragmatique (RFC 5322 simplifiée). On valide CÔTÉ
        // CLIENT pour donner un retour instantané ; le backend
        // ``is_valid_email`` valide encore une fois — défense en profondeur.
        var EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

        function addItem(raw) {
            var v = (raw || '').trim();
            if (!v) return false;
            // Strip mailto: collé depuis un client mail
            if (v.toLowerCase().indexOf('mailto:') === 0) v = v.slice(7).trim();
            // Si le user a tapé le LABEL d'un contact ("Alice Dupont <alice@x.fr>"
            // ou "Alice (alice@x.fr)") on extrait juste l'email.
            var m = v.match(/<([^>]+)>$/) || v.match(/\(([^)]+)\)$/);
            if (m && m[1] && m[1].indexOf('@') > 0) v = m[1];
            v = v.trim();
            if (!EMAIL_RE.test(v)) {
                showInputError('Email invalide : ' + v);
                return false;
            }
            if (items.indexOf(v) < 0) items.push(v);
            return true;
        }

        // Indicateur d'erreur inline sous l'input (réutilisable à chaque tentative)
        var errorEl = el('span', {
            class: 'komptia-chips-error',
            role: 'alert',
        });
        errorEl.style.cssText = 'color:#b91c1c;font-size:11px;margin-top:0.25rem;display:none;';

        var errorTimer = null;
        function showInputError(msg) {
            errorEl.textContent = msg;
            errorEl.style.display = 'block';
            if (errorTimer) clearTimeout(errorTimer);
            errorTimer = setTimeout(function () {
                errorEl.style.display = 'none';
            }, 3000);
        }

        input.addEventListener('keydown', function (e) {
            if (e.key === 'Enter' || e.key === ',') {
                e.preventDefault();
                if (addItem(input.value)) {
                    input.value = '';
                    renderChips();
                    emit();
                }
                // Si invalide : on garde la valeur dans l'input pour que
                // le user corrige sans retaper.
            } else if (e.key === 'Backspace' && input.value === '' && items.length > 0) {
                items.pop();
                renderChips();
                emit();
            }
        });
        // Sélection via clic dans la datalist (pas d'event keyboard) :
        // browser remplit ``input.value`` et déclenche un ``change``.
        input.addEventListener('change', function () {
            if (input.value.trim() !== '' && addItem(input.value)) {
                input.value = '';
                renderChips();
                emit();
            }
        });

        // CHIPS-1 — recherche SERVEUR débouncée. Le datalist initial ne contient
        // que les 100 premiers contacts (cf. fetch plus bas) : un contact au-delà
        // était introuvable, sans aucune indication. On interroge
        // ``/api/contacts?q=`` au fil de la frappe (le backend filtre en ilike sur
        // email/prénom/nom/société) pour rendre TOUS les contacts atteignables.
        var searchTimer = null;
        var lastSearchQuery = null;
        input.addEventListener('input', function () {
            var q = input.value.trim();
            if (q === lastSearchQuery) return;  // dedup (le change/clear re-fire 'input')
            lastSearchQuery = q;
            if (searchTimer) clearTimeout(searchTimer);
            if (q.length < 2) return;  // pas de requête serveur sur 0-1 caractère
            searchTimer = setTimeout(function () {
                var ck = 'contacts:q:' + q.toLowerCase();
                var cachedQ = cacheGet(ck);
                if (cachedQ) { populateDatalist(datalist, cachedQ); return; }
                fetchJson('/api/contacts?per_page=50&q=' + encodeURIComponent(q)).then(function (data) {
                    if (!data || data.success === false) return;
                    var contacts = data.contacts || [];
                    cachePut(ck, contacts);
                    populateDatalist(datalist, contacts);
                }, function () {
                    // Silencieux : l'autocomplete reste une amélioration ; l'user
                    // peut toujours taper l'email complet.
                });
            }, 250);
        });
        input.addEventListener('blur', function () {
            if (input.value.trim() !== '') {
                if (addItem(input.value)) {
                    input.value = '';
                    renderChips();
                    emit();
                }
            }
        });

        wrap.appendChild(input);
        wrap.appendChild(errorEl);
        renderChips();

        // Charge les contacts en arrière-plan pour peupler le datalist.
        var cached = cacheGet('contacts');
        if (cached) {
            populateDatalist(datalist, cached);
        } else {
            fetchJson('/api/contacts?per_page=100').then(function (data) {
                if (!data || data.success === false) return;
                var contacts = data.contacts || [];
                cachePut('contacts', contacts);
                populateDatalist(datalist, contacts);
            }, function () {
                // Silencieux : autocomplete n'est qu'une amélioration.
                // L'user peut toujours taper l'email.
            });
        }
        return wrap;
    }

    function populateDatalist(datalist, contacts) {
        while (datalist.firstChild) datalist.removeChild(datalist.firstChild);
        contacts.forEach(function (c) {
            if (!c || !c.email) return;
            var name = '';
            if (c.first_name || c.last_name) {
                name = ((c.first_name || '') + ' ' + (c.last_name || '')).trim();
            }
            var label = name ? (name + ' <' + c.email + '>') : c.email;
            var opt = el('option', { value: c.email });
            // L'attribut ``label`` (Firefox/Safari) affiche le nom à côté de
            // l'email dans le dropdown.
            opt.setAttribute('label', label);
            datalist.appendChild(opt);
        });
    }

    // ── 5 & 6. Workbook tab pickers ──────────────────────────────
    // Pour format_copilot.tab_index (single) et export_workbook.tabs (multi).
    // Les onglets sont dynamiques : si parent = load_workbook avec un path,
    // on fetch les onglets via /api/workbooks/tabs?filename=PATH. Sinon
    // (parent = extract_sql/nl/saved_query qui produit 1 onglet, ou pas de
    // parent), on fallback sur un input number/string libre.

    function detectWorkbookSourcePath(ctx) {
        if (!ctx || !Array.isArray(ctx.parentSteps)) return null;
        // Cas multi-parents (fan-in) : si plusieurs parents sont des
        // load_workbook, l'ordre des onglets après merge n'est pas
        // déterministe sans regarder ``store.edges`` triés. On préfère
        // fallback sur input libre + aide explicite plutôt que de
        // afficher des onglets potentiellement faux (M5 review).
        var loadWbParents = [];
        for (var i = 0; i < ctx.parentSteps.length; i += 1) {
            var p = ctx.parentSteps[i];
            if (p && p.step_type === 'load_workbook') {
                var path = p.config && p.config.path;
                if (path && typeof path === 'string' && path.trim()) {
                    loadWbParents.push(path.trim());
                }
            }
        }
        if (loadWbParents.length === 1) return loadWbParents[0];
        return null;
    }

    function buildWorkbookTabPicker(spec, value, onChange, ctx) {
        var path = detectWorkbookSourcePath(ctx);
        var wrap = el('div', { class: 'komptia-picker-wrap' });

        if (!path) {
            // Pas de classeur statique en amont → fallback input number
            // avec aide explicite. L'user qui sait ce qu'il fait peut
            // toujours saisir l'index manuellement.
            //
            // Pas de hardcode '0' dans le champ : si la valeur est vide,
            // le champ reste vide. Sinon le user voit '0' affiché alors
            // que le state stocke null → mismatch UI/state (M4).
            var input = el('input', {
                type: 'number',
                class: 'komptia-input',
                value: (value === null || value === undefined || value === '') ? '' : String(value),
                min: '0',
                placeholder: '0',
            });
            input.addEventListener('input', function () {
                var v = input.value;
                if (v === '') { onChange(null); return; }
                var num = parseInt(v, 10);
                onChange(isNaN(num) ? null : num);
            });
            wrap.appendChild(input);
            wrap.appendChild(el('p', {
                class: 'komptia-field-help',
                text: 'L\'étape parent est dynamique — index 0 = premier onglet du résultat.',
            }));
            return wrap;
        }

        // Parent = load_workbook avec path connu → fetch onglets
        wrap.appendChild(loadingNode('Lecture des onglets…'));

        function render(tabs) {
            var sel = el('select', { class: 'komptia-select' });
            if (!tabs.length) {
                setContent(wrap, emptyNode('Aucun onglet trouvé dans ce classeur.'));
                return;
            }
            tabs.forEach(function (t) {
                var idx = (typeof t.index === 'number') ? t.index : tabs.indexOf(t);
                var opt = el('option', {
                    value: String(idx),
                    text: idx + ' — ' + (t.label || ('Onglet ' + (idx + 1))),
                });
                if (Number(value) === idx) opt.selected = true;
                sel.appendChild(opt);
            });
            sel.addEventListener('change', function () {
                onChange(parseInt(sel.value, 10));
            });
            setContent(wrap, sel);
        }

        var cacheKey = 'tabs:' + path;
        var cached = cacheGet(cacheKey);
        if (cached) {
            render(cached);
        } else {
            var url = '/api/workbooks/tabs?filename=' + encodeURIComponent(path);
            fetchJson(url).then(function (data) {
                if (!data || data.success === false) {
                    setContent(wrap, errorNode('Impossible de lire les onglets.'));
                    return;
                }
                var tabs = data.tabs || [];
                cachePut(cacheKey, tabs);
                render(tabs);
            }, function () {
                setContent(wrap, errorNode('Erreur de lecture du classeur.'));
            });
        }
        return wrap;
    }

    function buildWorkbookTabsMultiPicker(spec, value, onChange, ctx) {
        // Valeur stockée = string : "all" OU "0,2,3" (index csv)
        var path = detectWorkbookSourcePath(ctx);
        var wrap = el('div', { class: 'komptia-picker-wrap' });

        if (!path) {
            // Fallback input texte (rétrocompat) avec aide
            var input = el('input', {
                type: 'text',
                class: 'komptia-input',
                value: value || 'all',
                placeholder: 'all ou 0,2,3',
            });
            input.addEventListener('input', function () {
                onChange(input.value || 'all');
            });
            wrap.appendChild(input);
            wrap.appendChild(el('p', {
                class: 'komptia-field-help',
                text: '"all" = tous les onglets, ou liste d\'index (0,2,3).',
            }));
            return wrap;
        }

        wrap.appendChild(loadingNode('Lecture des onglets…'));

        function render(tabs) {
            if (!tabs.length) {
                setContent(wrap, emptyNode('Aucun onglet trouvé.'));
                return;
            }

            // Parse value : "all" ou liste d'index
            var initialAll = (value || 'all').toString().trim().toLowerCase() === 'all';
            var initialIdx = {};
            if (!initialAll) {
                String(value || '').split(',').forEach(function (tok) {
                    var n = parseInt(tok.trim(), 10);
                    if (!isNaN(n)) initialIdx[n] = true;
                });
            }

            var allBox = el('label', { class: 'komptia-multi-pick-row' });
            var allCb = el('input', { type: 'checkbox' });
            allCb.checked = initialAll;
            var allText = el('span', { text: 'Tous les onglets' });
            allBox.appendChild(allCb);
            allBox.appendChild(allText);

            var list = el('div', { class: 'komptia-multi-pick-list' });
            list.style.display = initialAll ? 'none' : 'block';

            var checkboxes = [];
            tabs.forEach(function (t) {
                var idx = (typeof t.index === 'number') ? t.index : tabs.indexOf(t);
                var row = el('label', { class: 'komptia-multi-pick-row' });
                var cb = el('input', { type: 'checkbox' });
                cb.value = String(idx);
                cb.checked = !!initialIdx[idx];
                var label = el('span', { text: idx + ' — ' + (t.label || ('Onglet ' + (idx + 1))) });
                row.appendChild(cb);
                row.appendChild(label);
                list.appendChild(row);
                checkboxes.push(cb);
            });

            // TABS-1 — avertissement quand « Tous » est décoché ET aucun onglet
            // n'est sélectionné : sinon l'utilisateur croit « ne rien exporter »
            // alors que l'ancien comportement exportait TOUT en silence.
            var warnNone = el('p', {
                class: 'komptia-field-help',
                text: '⚠ Aucun onglet sélectionné — l\'export échouera. '
                    + 'Cochez « Tous » ou au moins un onglet.',
            });
            warnNone.style.color = 'var(--danger, #dc2626)';
            warnNone.style.display = 'none';

            function emit() {
                if (allCb.checked) {
                    warnNone.style.display = 'none';
                    onChange('all');
                } else {
                    var picked = checkboxes
                        .filter(function (cb) { return cb.checked; })
                        .map(function (cb) { return cb.value; });
                    // TABS-1 — « tout décoché » DOIT être distinct de « tous » :
                    // on émet le sentinel 'none' (rejeté fail-closed côté backend)
                    // au lieu de '' qui était interprété comme « tous » → export
                    // silencieux de TOUT (donnée fausse).
                    var noneSelected = picked.length === 0;
                    warnNone.style.display = noneSelected ? 'block' : 'none';
                    onChange(noneSelected ? 'none' : picked.join(','));
                }
            }
            allCb.addEventListener('change', function () {
                list.style.display = allCb.checked ? 'none' : 'block';
                emit();
            });
            checkboxes.forEach(function (cb) {
                cb.addEventListener('change', emit);
            });

            setContent(wrap, allBox);
            wrap.appendChild(list);
            wrap.appendChild(warnNone);
            // État initial : une config rechargée sans « all » ni index valide
            // (ex. 'none', ou un legacy '') = rien de sélectionné → avertir.
            if (!initialAll && Object.keys(initialIdx).length === 0) {
                warnNone.style.display = 'block';
            }
        }

        var cacheKey = 'tabs:' + path;
        var cached = cacheGet(cacheKey);
        if (cached) {
            render(cached);
        } else {
            var url = '/api/workbooks/tabs?filename=' + encodeURIComponent(path);
            fetchJson(url).then(function (data) {
                if (!data || data.success === false) {
                    setContent(wrap, errorNode('Impossible de lire les onglets.'));
                    return;
                }
                var tabs = data.tabs || [];
                cachePut(cacheKey, tabs);
                render(tabs);
            }, function () {
                setContent(wrap, errorNode('Erreur de lecture du classeur.'));
            });
        }
        return wrap;
    }

    // ── Export public ────────────────────────────────────────────

    window.komptiaPickers = {
        build: function (widget, spec, value, onChange, ctx) {
            switch (widget) {
                case 'datastore_sql_picker':
                    return buildDatastoreSqlPicker(spec, value, onChange);
                case 'distribution_list_picker':
                    return buildDistributionListPicker(spec, value, onChange);
                case 'datastore_file_picker':
                    return buildDatastoreFilePicker(spec, value, onChange);
                case 'contacts_chips':
                    return buildContactsChips(spec, value, onChange);
                case 'workbook_tab_picker':
                    return buildWorkbookTabPicker(spec, value, onChange, ctx);
                case 'workbook_tabs_multi_picker':
                    return buildWorkbookTabsMultiPicker(spec, value, onChange, ctx);
                default:
                    // widget inconnu → null = canvas tombe sur le widget natif
                    return null;
            }
        },
        // Exposé pour invalider depuis l'UI si besoin (ex : bouton "Rafraîchir")
        invalidateCache: function (prefix) {
            cacheInvalidate(prefix || '');
        },
    };
})();
