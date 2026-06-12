/* ExternalSheetsPicker — composant partagé (iris, datastore, reports).
 *
 * Usage :
 *     window.ExternalSheetsPicker.open({
 *         onSelect: function(sheets) { ... },  // sheets = [{type, label, ...}]
 *         mode: 'data'          // 'data' → retourne colonnes+rows (par défaut)
 *                                // 'source' → retourne juste un descripteur de source (pour /reports)
 *     });
 *
 * En mode 'data' (par défaut), chaque sheet retourné contient :
 *   { type: 'workbook'|'excel'|'csv',
 *     label: str, columns: [], rows: [[]], row_count: int,
 *     merges: [],          // pour les feuilles Excel avec merged cells
 *     sql: str,            // SQL de la feuille source ('' si aucun — Excel/CSV)
 *     cellDetails: {},     // SQL/détails par cellule de la feuille source ({} si aucun)
 *     source: {...} }      // méta-info (type, path, sheet_name...) pour sérialisation
 *
 * En mode 'source', on retourne uniquement le descripteur de source :
 *   { type: 'workbook', classeur, tab_index, cell_key, label, estimated_tokens }
 *   { type: 'excel', path, sheet_name, label, estimated_tokens }
 *   { type: 'csv', path, encoding, separator, label, estimated_tokens }
 */
(function() {
    'use strict';

    // Signal de version pour diagnostic cache : si tu ne vois PAS ce log
    // dans la console après hard-refresh, le navigateur sert encore une
    // ancienne version (cache, service worker, proxy). À retirer une
    // fois la stabilité confirmée.
    if (window.console && console.info) {
        console.info('[ExternalSheetsPicker] v=2026-05-05 select-all-tabs');
    }

    var ENDPOINTS = {
        workbooks: '/api/workbooks',
        workbookTabs: '/api/workbooks/tabs',
        workbookTabData: '/api/workbooks/tab-data',
        excelSheets: '/api/external-sheets/excel/sheets',
        excelLoad: '/api/external-sheets/excel/load',
        csvLoad: '/api/external-sheets/csv/load',
        datastoreList: '/api/datastore',
        datastoreUpload: '/api/datastore/upload'
    };

    var state = {
        open: false,
        mode: 'data',
        onSelect: null,
        activeTab: 'workbook',
        workbooks: [],
        wbExpanded: {},          // filename -> tabs metadata
        wbSelected: {},          // "filename#tab_index" -> {classeur, tab_index, label, row_count, estimated_tokens}
        excelFile: null,         // {path, name, sheets: [str]}
        excelSelected: {},       // sheet_name -> {path, sheet_name, estimated_tokens}
        excelFirstRowHeader: false,
        csvSelected: {},         // path -> {path, name, estimated_tokens}
        datastoreFiles: null     // cached recursive list of files
    };

    function $(id) { return document.getElementById(id); }

    function getCookie(name) {
        var parts = (document.cookie || '').split('; ');
        for (var i = 0; i < parts.length; i++) {
            var kv = parts[i].split('=');
            if (kv[0] === name) return decodeURIComponent(kv.slice(1).join('='));
        }
        return '';
    }

    function xsrfHeaders(extra) {
        var h = extra || {};
        var t = getCookie('_xsrf');
        if (t) h['X-Xsrftoken'] = t;
        return h;
    }

    function showStatus(message, isError) {
        var el = $('ext-sheets-status');
        if (!el) return;
        if (!message) { el.classList.add('hidden'); el.textContent = ''; return; }
        el.textContent = message;
        el.classList.remove('hidden');
        el.className = 'px-4 py-2 text-xs border-b ' +
            (isError ? 'text-red-700 bg-red-50 border-red-200 dark:text-red-300 dark:bg-red-900/20 dark:border-red-800/60'
                     : 'text-blue-700 bg-blue-50 border-blue-200 dark:text-blue-300 dark:bg-blue-900/20 dark:border-blue-800/60');
    }

    function fetchJson(url, opts) {
        opts = opts || {};
        var init = {
            method: opts.method || 'GET',
            headers: xsrfHeaders(opts.headers || {'Content-Type': 'application/json'}),
            credentials: 'same-origin'
        };
        if (opts.body != null) init.body = opts.body;
        return fetch(url, init).then(function(r) {
            return r.json().then(function(data) {
                if (!r.ok || (data && data.error)) {
                    var msg = (data && data.message) || (data && data.error) || ('HTTP ' + r.status);
                    throw new Error(msg);
                }
                return data;
            });
        });
    }

    function setTab(tabName) {
        state.activeTab = tabName;
        var btns = document.querySelectorAll('.ext-tab-btn');
        btns.forEach(function(b) {
            if (b.getAttribute('data-ext-tab') === tabName) {
                b.setAttribute('data-active', '');
                b.style.background = 'var(--bg-surface, #ffffff)';
                b.style.borderBottom = '2px solid var(--status-info, #3b82f6)';
            } else {
                b.removeAttribute('data-active');
                b.style.background = '';
                b.style.borderBottom = '';
            }
        });
        var panes = document.querySelectorAll('[data-ext-pane]');
        panes.forEach(function(p) {
            p.classList.toggle('hidden', p.getAttribute('data-ext-pane') !== tabName);
        });
        if (tabName === 'workbook') loadWorkbookTree();
        refreshSelectionUi();
    }

    function refreshSelectionUi() {
        var total = Object.keys(state.wbSelected).length
            + Object.keys(state.excelSelected).length
            + Object.keys(state.csvSelected).length;
        var countEl = $('ext-sheets-count');
        if (countEl) {
            countEl.textContent = total + ' feuille' + (total > 1 ? 's' : '')
                + ' sélectionnée' + (total > 1 ? 's' : '');
        }
        var btnAdd = $('ext-sheets-add');
        if (btnAdd) btnAdd.disabled = (total === 0);
    }

    // ── Workbook tab ──

    function loadWorkbookTree() {
        var tree = $('ext-wb-tree');
        if (!tree) return;
        if (state.workbooks.length === 0) {
            tree.innerHTML = '<div class="text-xs text-gray-500 italic dark:text-gray-400">Chargement...</div>';
            fetchJson(ENDPOINTS.workbooks).then(function(data) {
                state.workbooks = data.classeurs || [];
                renderWorkbookTree();
            }).catch(function(err) {
                showStatus('Impossible de charger les classeurs : ' + err.message, true);
                tree.innerHTML = '';
            });
        } else {
            renderWorkbookTree();
        }
    }

    function renderWorkbookTree() {
        var tree = $('ext-wb-tree');
        var empty = $('ext-wb-empty');
        if (!tree || !empty) return;
        tree.innerHTML = '';
        if (state.workbooks.length === 0) {
            empty.classList.remove('hidden');
            return;
        }
        empty.classList.add('hidden');

        if (window.console && console.info) {
            console.info('[ExternalSheetsPicker] renderWorkbookTree — '
                + state.workbooks.length + ' classeur(s) à rendre');
        }
        state.workbooks.forEach(function(wb) {
            var container = document.createElement('div');
            container.className = 'border border-gray-200 rounded px-2 py-1';

            var header = document.createElement('div');
            header.className = 'flex items-center gap-2 cursor-pointer';
            header.setAttribute('data-wb-file', wb.filename);

            // Checkbox "tout sélectionner" pour le classeur entier.
            // ``stopPropagation`` sur ses events pour ne pas déclencher
            // le toggle expand du header parent. État synchronisé avec
            // les checkboxes individuelles (cf. ``refreshWorkbookCheckbox``).
            var allCb = document.createElement('input');
            allCb.type = 'checkbox';
            allCb.className = 'cursor-pointer';
            allCb.setAttribute('data-wb-all', wb.filename);
            allCb.setAttribute('aria-label', 'Sélectionner toutes les feuilles de ' + wb.name);
            allCb.title = 'Sélectionner toutes les feuilles';
            allCb.addEventListener('click', function(e) { e.stopPropagation(); });
            allCb.addEventListener('change', function(e) {
                e.stopPropagation();
                toggleAllTabsForWorkbook(wb.filename, allCb.checked, container);
            });

            var caret = document.createElement('span');
            // Classe ``wb-caret`` pour ciblage stable depuis ``toggleWorkbook``
            // — sans elle, ``querySelector('span:first-child')`` ne match
            // plus depuis qu'on a mis la checkbox "tout" en 1er enfant
            // du header.
            caret.className = 'wb-caret text-gray-500 dark:text-gray-400';
            caret.textContent = '▶';

            var name = document.createElement('span');
            name.className = 'flex-1 truncate font-medium';
            name.textContent = wb.name;

            var size = document.createElement('span');
            size.className = 'text-xs text-gray-500 dark:text-gray-400';
            size.textContent = formatSize(wb.size);

            header.appendChild(allCb);
            header.appendChild(caret);
            header.appendChild(name);
            header.appendChild(size);
            header.addEventListener('click', function() { toggleWorkbook(wb.filename, container, header); });
            container.appendChild(header);

            var panel = document.createElement('div');
            panel.className = 'ml-5 mt-1 hidden space-y-0.5';
            panel.setAttribute('data-wb-panel', wb.filename);
            container.appendChild(panel);

            tree.appendChild(container);

            // Etat initial de la checkbox "tout" : si les tabs sont
            // déjà chargés, on calcule directement ; sinon on laisse
            // décochée (l'état sera mis à jour au moment où l'user
            // expand le classeur ou clique la checkbox "tout").
            refreshWorkbookCheckbox(wb.filename, container);
        });
    }

    // Synchronise la checkbox "tout" du header avec l'état réel des
    // feuilles sélectionnées : cochée si TOUTES les feuilles utilisables
    // sont sélectionnées, indeterminate si seulement certaines, sinon
    // décochée. Si les tabs ne sont pas encore chargés, on n'a pas le
    // dénominateur — on laisse l'état tel quel.
    function refreshWorkbookCheckbox(filename, container) {
        var allCb = container.querySelector('[data-wb-all="' + cssEscape(filename) + '"]');
        if (!allCb) return;
        var tabs = state.wbExpanded[filename];
        if (!tabs) {
            // Pas encore chargés : on ne peut pas calculer fidèlement.
            // Si quelques tabs sont sélectionnés via interactions
            // précédentes, on affiche indeterminate pour le signaler.
            var hasAny = Object.keys(state.wbSelected).some(function(k) {
                return k.indexOf(filename + '#') === 0;
            });
            allCb.checked = false;
            allCb.indeterminate = hasAny;
            return;
        }
        var usable = tabs.filter(function(t) { return !t.is_unusable; });
        if (usable.length === 0) {
            allCb.checked = false;
            allCb.indeterminate = false;
            allCb.disabled = true;
            return;
        }
        var selectedCount = usable.filter(function(t) {
            return !!state.wbSelected[filename + '#' + t.index];
        }).length;
        if (selectedCount === 0) {
            allCb.checked = false;
            allCb.indeterminate = false;
        } else if (selectedCount === usable.length) {
            allCb.checked = true;
            allCb.indeterminate = false;
        } else {
            allCb.checked = false;
            allCb.indeterminate = true;
        }
    }

    // Coche/décoche toutes les feuilles utilisables du classeur. Charge
    // les tabs au besoin (cas où l'user clique "tout" sans avoir expand
    // le classeur d'abord).
    function toggleAllTabsForWorkbook(filename, shouldCheck, container) {
        function applyToTabs(tabs) {
            tabs.forEach(function(tab) {
                if (tab.is_unusable) return;
                var key = filename + '#' + tab.index;
                if (shouldCheck) {
                    state.wbSelected[key] = {
                        classeur: filename,
                        tab_index: tab.index,
                        label: tab.label,
                        row_count: tab.row_count,
                        estimated_tokens: tab.estimated_tokens || 0
                    };
                } else {
                    delete state.wbSelected[key];
                }
            });
            // Si le panel est ouvert, re-render pour synchroniser les
            // checkboxes individuelles avec le nouvel état.
            var panel = container.querySelector('[data-wb-panel="' + cssEscape(filename) + '"]');
            if (panel && !panel.classList.contains('hidden')) {
                renderTabsList(panel, filename, tabs);
            }
            refreshWorkbookCheckbox(filename, container);
            refreshSelectionUi();
        }

        if (state.wbExpanded[filename]) {
            applyToTabs(state.wbExpanded[filename]);
            return;
        }
        // Tabs pas encore chargés → fetch puis applique.
        fetchJson(ENDPOINTS.workbookTabs + '?filename=' + encodeURIComponent(filename))
            .then(function(data) {
                state.wbExpanded[filename] = data.tabs || [];
                applyToTabs(state.wbExpanded[filename]);
            }).catch(function(err) {
                showStatus('Erreur lecture classeur : ' + err.message, true);
                // Reset checkbox si fetch échoue
                refreshWorkbookCheckbox(filename, container);
            });
    }

    function toggleWorkbook(filename, container, header) {
        var panel = container.querySelector('[data-wb-panel="' + cssEscape(filename) + '"]');
        if (!panel) return;
        // Cible le caret par sa classe ``wb-caret`` plutôt que par
        // ``span:first-child`` (le 1er enfant du header est désormais
        // la checkbox "tout sélectionner", plus le caret).
        var caret = header.querySelector('.wb-caret');
        var isOpen = !panel.classList.contains('hidden');
        if (isOpen) {
            panel.classList.add('hidden');
            if (caret) caret.textContent = '▶';
            return;
        }
        panel.classList.remove('hidden');
        if (caret) caret.textContent = '▼';

        if (state.wbExpanded[filename]) {
            renderTabsList(panel, filename, state.wbExpanded[filename]);
            return;
        }
        panel.innerHTML = '<div class="text-xs text-gray-500 italic dark:text-gray-400">Chargement...</div>';
        fetchJson(ENDPOINTS.workbookTabs + '?filename=' + encodeURIComponent(filename))
            .then(function(data) {
                state.wbExpanded[filename] = data.tabs || [];
                renderTabsList(panel, filename, data.tabs || []);
            }).catch(function(err) {
                panel.innerHTML = '<div class="text-xs text-red-600 dark:text-red-400">Erreur : ' + escapeHtml(err.message) + '</div>';
            });
    }

    function renderTabsList(panel, filename, tabs) {
        panel.innerHTML = '';
        // Container parent (pour synchroniser la checkbox "tout" du header
        // quand l'utilisateur coche/décoche une feuille individuelle).
        // Le panel est un enfant direct du container du classeur (cf.
        // ``renderWorkbookTree`` : container > header + panel siblings).
        var wbContainer = panel.parentElement;
        if (tabs.length === 0) {
            panel.innerHTML = '<div class="text-xs text-gray-500 italic dark:text-gray-400">Classeur vide.</div>';
            // Met à jour la checkbox "tout" au cas où elle était indeterminate
            if (wbContainer) refreshWorkbookCheckbox(filename, wbContainer);
            return;
        }
        tabs.forEach(function(tab) {
            if (tab.is_unusable) return;
            var key = filename + '#' + tab.index;
            var label = document.createElement('label');
            label.className = 'flex items-center gap-2 py-0.5 cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-800 rounded px-1';
            var cb = document.createElement('input');
            cb.type = 'checkbox';
            cb.checked = !!state.wbSelected[key];
            cb.addEventListener('change', function() {
                if (cb.checked) {
                    state.wbSelected[key] = {
                        classeur: filename,
                        tab_index: tab.index,
                        label: tab.label,
                        row_count: tab.row_count,
                        estimated_tokens: tab.estimated_tokens || 0
                    };
                } else {
                    delete state.wbSelected[key];
                }
                if (wbContainer) refreshWorkbookCheckbox(filename, wbContainer);
                refreshSelectionUi();
            });
            var text = document.createElement('span');
            text.className = 'text-xs flex-1';
            text.textContent = tab.label + ' · ' + tab.row_count + ' lignes';
            label.appendChild(cb);
            label.appendChild(text);
            panel.appendChild(label);
        });
        // Une fois les tabs rendus, on connaît le dénominateur — on
        // peut maintenant synchroniser la checkbox "tout" avec exactitude.
        if (wbContainer) refreshWorkbookCheckbox(filename, wbContainer);
    }

    // ── Excel tab ──

    function openExcelUpload() {
        var inp = $('ext-excel-file-input');
        if (inp) inp.click();
    }

    function openExcelBrowse() {
        renderDatastoreFiles('excel');
    }

    function renderDatastoreFiles(kind) {
        var target = kind === 'excel' ? $('ext-excel-ds-list') : $('ext-csv-ds-list');
        if (!target) return;
        target.classList.remove('hidden');
        target.innerHTML = '<div class="text-xs text-gray-500 italic dark:text-gray-400">Chargement...</div>';

        fetchDatastoreFilesRecursive().then(function(files) {
            var filtered = files.filter(function(f) {
                var ext = (f.extension || '').toLowerCase();
                if (kind === 'excel') return ext === '.xlsx' || ext === '.xls';
                return ext === '.csv';
            });
            target.innerHTML = '';
            if (filtered.length === 0) {
                target.innerHTML = '<div class="text-xs text-gray-500 italic dark:text-gray-400">Aucun fichier '
                    + (kind === 'excel' ? 'Excel' : 'CSV') + ' trouvé.</div>';
                return;
            }
            filtered.forEach(function(f) {
                var row = document.createElement('div');
                row.className = 'flex items-center gap-2 py-1 hover:bg-gray-50 dark:hover:bg-gray-800 cursor-pointer rounded px-1';
                row.innerHTML = '<span class="flex-1 truncate">' + escapeHtml(f.path) + '</span>'
                    + '<span class="text-xs text-gray-500 dark:text-gray-400">' + formatSize(f.size || 0) + '</span>';
                row.addEventListener('click', function() {
                    if (kind === 'excel') onExcelFileSelected({ path: f.path, name: f.name });
                    else onCsvFileSelected({ path: f.path, name: f.name });
                    target.classList.add('hidden');
                });
                target.appendChild(row);
            });
        }).catch(function(err) {
            target.innerHTML = '<div class="text-xs text-red-600 dark:text-red-400">Erreur : ' + escapeHtml(err.message) + '</div>';
        });
    }

    function fetchDatastoreFilesRecursive() {
        if (state.datastoreFiles) return Promise.resolve(state.datastoreFiles);
        var results = [];
        function walk(path) {
            var url = ENDPOINTS.datastoreList + (path ? '?path=' + encodeURIComponent(path) : '');
            return fetchJson(url).then(function(data) {
                if (!data.items) return;
                var childPromises = [];
                data.items.forEach(function(it) {
                    if (it.is_dir) {
                        childPromises.push(walk(it.path));
                    } else {
                        results.push(it);
                    }
                });
                return Promise.all(childPromises);
            });
        }
        return walk('').then(function() {
            state.datastoreFiles = results;
            return results;
        });
    }

    function onExcelFileSelected(file) {
        state.excelFile = { path: file.path, name: file.name, sheets: [] };
        state.excelSelected = {};
        var label = $('ext-excel-selected-file');
        if (label) {
            label.classList.remove('hidden');
            label.textContent = 'Fichier : ' + file.path;
        }
        var sheetsWrap = $('ext-excel-sheets');
        var listEl = $('ext-excel-sheet-list');
        if (!sheetsWrap || !listEl) return;
        listEl.innerHTML = '<div class="text-xs text-gray-500 italic dark:text-gray-400">Chargement des onglets...</div>';
        sheetsWrap.classList.remove('hidden');

        fetchJson(ENDPOINTS.excelSheets, {
            method: 'POST',
            body: JSON.stringify({ path: file.path })
        }).then(function(data) {
            state.excelFile.sheets = data.sheets || [];
            renderExcelSheets();
        }).catch(function(err) {
            listEl.innerHTML = '<div class="text-xs text-red-600 dark:text-red-400">Erreur : ' + escapeHtml(err.message) + '</div>';
        });
    }

    function renderExcelSheets() {
        var listEl = $('ext-excel-sheet-list');
        if (!listEl) return;
        listEl.innerHTML = '';
        if (!state.excelFile || state.excelFile.sheets.length === 0) {
            listEl.innerHTML = '<div class="text-xs text-gray-500 italic dark:text-gray-400">Aucun onglet.</div>';
            return;
        }
        state.excelFile.sheets.forEach(function(name) {
            var label = document.createElement('label');
            label.className = 'flex items-center gap-2 py-0.5 hover:bg-gray-50 dark:hover:bg-gray-800 rounded px-1 cursor-pointer';
            var cb = document.createElement('input');
            cb.type = 'checkbox';
            cb.checked = !!state.excelSelected[name];
            cb.addEventListener('change', function() {
                if (cb.checked) {
                    state.excelSelected[name] = {
                        path: state.excelFile.path,
                        sheet_name: name
                    };
                } else {
                    delete state.excelSelected[name];
                }
                refreshSelectionUi();
            });
            var span = document.createElement('span');
            span.className = 'text-xs flex-1';
            span.textContent = name;
            label.appendChild(cb);
            label.appendChild(span);
            listEl.appendChild(label);
        });
    }

    function onExcelFileUpload(file) {
        if (!file) return;
        showStatus('Upload du fichier Excel en cours...', false);
        var fd = new FormData();
        fd.append('files', file);
        fd.append('path', '');
        fetch(ENDPOINTS.datastoreUpload, {
            method: 'POST',
            headers: xsrfHeaders({}),
            credentials: 'same-origin',
            body: fd
        }).then(function(r) {
            return r.json().then(function(data) { return { ok: r.ok, status: r.status, data: data }; });
        }).then(function(res) {
            var data = res.data || {};
            var uploaded = (data.uploaded && data.uploaded[0]);
            if (!res.ok || data.success === false || (!uploaded && data.errors && data.errors.length)) {
                throw new Error(describeUploadFailure(data, res.status, file.name));
            }
            if (!uploaded || !uploaded.path) {
                throw new Error(describeUploadFailure(data, res.status, file.name));
            }
            showStatus('');
            state.datastoreFiles = null; // invalidate cache
            onExcelFileSelected({
                path: uploaded.path,
                name: uploaded.name || file.name
            });
        }).catch(function(err) {
            showStatus('Upload échoué : ' + err.message, true);
        });
    }

    // ── CSV tab ──

    function openCsvUpload() {
        var inp = $('ext-csv-file-input');
        if (inp) inp.click();
    }

    function openCsvBrowse() {
        renderDatastoreFiles('csv');
    }

    function onCsvFileSelected(file) {
        if (state.csvSelected[file.path]) return;
        state.csvSelected[file.path] = { path: file.path, name: file.name };
        renderCsvSelectedList();
        refreshSelectionUi();
    }

    function renderCsvSelectedList() {
        var wrap = $('ext-csv-files');
        if (!wrap) return;
        wrap.innerHTML = '';
        var keys = Object.keys(state.csvSelected);
        if (keys.length === 0) return;
        keys.forEach(function(k) {
            var entry = state.csvSelected[k];
            var row = document.createElement('div');
            row.className = 'flex items-center justify-between bg-gray-50 dark:bg-gray-800/50 rounded px-2 py-1.5 text-xs';
            row.innerHTML = '<span class="truncate">' + escapeHtml(entry.path) + '</span>';
            var btn = document.createElement('button');
            btn.type = 'button';
            btn.className = 'ml-2 text-red-600 hover:text-red-800';
            btn.textContent = 'Retirer';
            btn.addEventListener('click', function() {
                delete state.csvSelected[k];
                renderCsvSelectedList();
                refreshSelectionUi();
            });
            row.appendChild(btn);
            wrap.appendChild(row);
        });
    }

    function onCsvFileUpload(files) {
        if (!files || !files.length) return;
        var uploads = [];
        for (var i = 0; i < files.length; i++) uploads.push(uploadOne(files[i]));
        showStatus('Upload CSV en cours...', false);
        Promise.allSettled(uploads).then(function(results) {
            state.datastoreFiles = null;
            var failed = [];
            results.forEach(function(res, i) {
                if (res.status === 'fulfilled' && res.value) {
                    onCsvFileSelected({ path: res.value.path, name: res.value.name });
                } else {
                    var fname = files[i] ? files[i].name : '?';
                    var msg = (res.reason && res.reason.message) || 'erreur inconnue';
                    failed.push(fname + ' (' + msg + ')');
                }
            });
            if (failed.length === 0) {
                showStatus('');
            } else if (failed.length === results.length) {
                showStatus('Upload échoué : ' + failed.join(', '), true);
            } else {
                showStatus(
                    failed.length + ' fichier(s) échoué(s) : ' + failed.join(', '),
                    true
                );
            }
        });

        function uploadOne(file) {
            var fd = new FormData();
            fd.append('files', file);
            fd.append('path', '');
            return fetch(ENDPOINTS.datastoreUpload, {
                method: 'POST',
                headers: xsrfHeaders({}),
                credentials: 'same-origin',
                body: fd
            }).then(function(r) {
                return r.json().then(function(d) { return { ok: r.ok, status: r.status, data: d }; });
            }).then(function(res) {
                var d = res.data || {};
                var up = (d.uploaded && d.uploaded[0]);
                if (!res.ok || d.success === false || (!up && d.errors && d.errors.length)) {
                    throw new Error(describeUploadFailure(d, res.status, file.name));
                }
                if (!up || !up.path) {
                    throw new Error(describeUploadFailure(d, res.status, file.name));
                }
                return up;
            });
        }
    }

    // ── Confirmation → retour au caller ──

    function confirmSelection() {
        var btnAdd = $('ext-sheets-add');
        if (btnAdd) btnAdd.disabled = true;
        showStatus('Chargement des données...', false);

        var mode = state.mode;
        var firstRowHeader = !!(state.excelFirstRowHeader);

        var promises = [];
        Object.keys(state.wbSelected).forEach(function(k) {
            var s = state.wbSelected[k];
            if (mode === 'source') {
                promises.push(Promise.resolve({
                    type: 'workbook',
                    classeur: s.classeur,
                    tab_index: s.tab_index,
                    cell_key: null,
                    label: s.label,
                    estimated_tokens: s.estimated_tokens || 0
                }));
            } else {
                var url = ENDPOINTS.workbookTabData
                    + '?filename=' + encodeURIComponent(s.classeur)
                    + '&tab_index=' + encodeURIComponent(s.tab_index);
                promises.push(fetchJson(url).then(function(data) {
                    return {
                        type: 'workbook',
                        label: s.label,
                        columns: data.columns || [],
                        rows: data.rows || [],
                        row_count: data.row_count || 0,
                        merges: [],
                        // SQL de la feuille + SQL des cellules (cellDetails) : le
                        // backend les renvoie déjà (reader.read_tab_data) — les
                        // transporter fidèlement pour que l'import ne les perde
                        // pas. Gardes de type : un .afz corrompu ne doit pas
                        // propager autre chose qu'un str / un dict.
                        sql: (typeof data.sql === 'string') ? data.sql : '',
                        cellDetails: (data.cellDetails && typeof data.cellDetails === 'object'
                            && !Array.isArray(data.cellDetails)) ? data.cellDetails : {},
                        source: {
                            type: 'workbook',
                            classeur: s.classeur,
                            tab_index: s.tab_index
                        }
                    };
                }));
            }
        });

        Object.keys(state.excelSelected).forEach(function(name) {
            var s = state.excelSelected[name];
            if (mode === 'source') {
                promises.push(Promise.resolve({
                    type: 'excel',
                    path: s.path,
                    sheet_name: s.sheet_name,
                    first_row_as_header: firstRowHeader,
                    label: s.path.split('/').pop() + ' — ' + s.sheet_name,
                    estimated_tokens: 0
                }));
            } else {
                promises.push(fetchJson(ENDPOINTS.excelLoad, {
                    method: 'POST',
                    body: JSON.stringify({
                        path: s.path,
                        sheet_name: s.sheet_name,
                        first_row_as_header: firstRowHeader
                    })
                }).then(function(data) {
                    return {
                        type: 'excel',
                        label: s.path.split('/').pop() + ' — ' + s.sheet_name,
                        columns: data.columns || [],
                        rows: data.rows || [],
                        row_count: data.row_count || 0,
                        merges: data.merges || [],
                        source: {
                            type: 'excel',
                            path: s.path,
                            sheet_name: s.sheet_name,
                            first_row_as_header: firstRowHeader
                        }
                    };
                }));
            }
        });

        Object.keys(state.csvSelected).forEach(function(k) {
            var s = state.csvSelected[k];
            if (mode === 'source') {
                promises.push(Promise.resolve({
                    type: 'csv',
                    path: s.path,
                    label: s.name || s.path.split('/').pop(),
                    estimated_tokens: 0
                }));
            } else {
                promises.push(fetchJson(ENDPOINTS.csvLoad, {
                    method: 'POST',
                    body: JSON.stringify({ path: s.path })
                }).then(function(data) {
                    return {
                        type: 'csv',
                        label: s.name || s.path.split('/').pop(),
                        columns: data.columns || [],
                        rows: data.rows || [],
                        row_count: data.row_count || 0,
                        merges: [],
                        source: {
                            type: 'csv',
                            path: s.path,
                            encoding: data.detected_encoding,
                            separator: data.detected_separator
                        }
                    };
                }));
            }
        });

        Promise.all(promises).then(function(sheets) {
            showStatus('');
            if (typeof state.onSelect === 'function') {
                try { state.onSelect(sheets); } catch (e) { console.error(e); }
            }
            close();
        }).catch(function(err) {
            showStatus('Erreur : ' + err.message, true);
            if (btnAdd) btnAdd.disabled = false;
        });
    }

    // ── Helpers ──

    function describeUploadFailure(data, httpStatus, fileName) {
        data = data || {};
        // 1) Erreurs de validation fichier par fichier renvoyées par le serveur
        if (Array.isArray(data.errors) && data.errors.length) {
            // Format: "nom.xlsx: raison précise" — retirer le préfixe nom si c'est le fichier courant
            var prefix = fileName ? (fileName + ': ') : '';
            var cleaned = data.errors.map(function(e) {
                var s = String(e);
                return (prefix && s.indexOf(prefix) === 0) ? s.slice(prefix.length) : s;
            });
            return cleaned.join(' ; ');
        }
        // 2) Erreur globale (quota, chemin invalide, auth)
        if (data.error) return String(data.error);
        if (data.message && data.success === false) return String(data.message);
        // 3) Fallback HTTP
        if (httpStatus === 401 || httpStatus === 403) return 'accès refusé (reconnectez-vous)';
        if (httpStatus === 413) return 'fichier trop volumineux pour le serveur';
        if (httpStatus >= 500) return 'erreur serveur (HTTP ' + httpStatus + ')';
        return 'raison inconnue (HTTP ' + (httpStatus || '?') + ')';
    }

    function escapeHtml(s) {
        // #101 (cohérence escaping) — échappe AUSSI `'` : un escaper HTML complet
        // (& < > " ') reste sûr si une future réutilisation passe en contexte
        // attribut (`title='...'`). Aligné sur iris-common.escapeAttr.
        if (s == null) return '';
        return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;')
            .replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }

    function cssEscape(s) {
        return String(s).replace(/["\\]/g, '\\$&');
    }

    function formatSize(n) {
        // Single source of truth : window.KomptiaFormat.fileSize (format-helpers.js).
        return window.KomptiaFormat.fileSize(n);
    }

    // ── Open / Close ──

    function open(opts) {
        opts = opts || {};
        state.open = true;
        state.mode = opts.mode || 'data';
        state.onSelect = opts.onSelect || null;
        state.workbooks = [];
        state.wbExpanded = {};
        state.wbSelected = {};
        state.excelFile = null;
        state.excelSelected = {};
        state.excelFirstRowHeader = false;
        state.csvSelected = {};
        state.datastoreFiles = null;

        var modal = $('ext-sheets-modal');
        if (!modal) {
            console.warn('[ExternalSheetsPicker] Modal HTML missing — include templates/partials/external_sheets_modal.html');
            return;
        }
        modal.classList.remove('hidden');
        refreshSelectionUi();
        var firstHdr = $('ext-excel-first-row-header');
        if (firstHdr) firstHdr.checked = false;
        renderCsvSelectedList();
        var label = $('ext-excel-selected-file');
        if (label) { label.classList.add('hidden'); label.textContent = ''; }
        var sheetsWrap = $('ext-excel-sheets');
        if (sheetsWrap) sheetsWrap.classList.add('hidden');
        showStatus('');

        if (!modal.getAttribute('data-ext-wired')) {
            wireEvents();
            modal.setAttribute('data-ext-wired', '1');
        }
        setTab('workbook');
    }

    function close() {
        state.open = false;
        state.onSelect = null;
        var modal = $('ext-sheets-modal');
        if (modal) modal.classList.add('hidden');
        showStatus('');
    }

    function wireEvents() {
        document.querySelectorAll('.ext-tab-btn').forEach(function(b) {
            b.addEventListener('click', function() { setTab(b.getAttribute('data-ext-tab')); });
        });
        document.querySelectorAll('[data-ext-sheets-close]').forEach(function(el) {
            el.addEventListener('click', close);
        });
        var btnCancel = $('ext-sheets-cancel');
        if (btnCancel) btnCancel.addEventListener('click', close);
        var btnAdd = $('ext-sheets-add');
        if (btnAdd) btnAdd.addEventListener('click', confirmSelection);

        var excelUp = $('ext-excel-upload-btn');
        if (excelUp) excelUp.addEventListener('click', openExcelUpload);
        var excelBrowse = $('ext-excel-browse-btn');
        if (excelBrowse) excelBrowse.addEventListener('click', openExcelBrowse);
        var excelInp = $('ext-excel-file-input');
        if (excelInp) excelInp.addEventListener('change', function(e) {
            var f = e.target.files && e.target.files[0];
            if (f) onExcelFileUpload(f);
            e.target.value = '';
        });
        var csvUp = $('ext-csv-upload-btn');
        if (csvUp) csvUp.addEventListener('click', openCsvUpload);
        var csvBrowse = $('ext-csv-browse-btn');
        if (csvBrowse) csvBrowse.addEventListener('click', openCsvBrowse);
        var csvInp = $('ext-csv-file-input');
        if (csvInp) csvInp.addEventListener('change', function(e) {
            if (e.target.files && e.target.files.length) onCsvFileUpload(e.target.files);
            e.target.value = '';
        });
        var firstHdr = $('ext-excel-first-row-header');
        if (firstHdr) firstHdr.addEventListener('change', function(e) {
            state.excelFirstRowHeader = !!e.target.checked;
        });
        document.addEventListener('keydown', function(e) {
            if (!state.open || e.key !== 'Escape') return;
            var modal = $('ext-sheets-modal');
            if (!modal || modal.classList.contains('hidden')) return;
            // Only close if focus is inside the modal (avoid hijacking other modals / inputs)
            var active = document.activeElement;
            if (active && !modal.contains(active) && active !== document.body) return;
            close();
        });
    }

    window.ExternalSheetsPicker = { open: open, close: close };
})();
