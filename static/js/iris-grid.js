/* VERSION_CHECK */
console.log('[iris-grid] VERSION 2026-04-04T18:45 loaded');
/**
 * SqlResultGrid — Composant interactif pour les résultats SQL dans Komptia.
 *
 * Phase 1 : tri, numéros de lignes, formatage intelligent, export CSV,
 *           copier tableau, plein écran, header enrichi.
 */

/* exported SqlResultGrid */

var SqlResultGrid = (function() {
    'use strict';

    // ── Escape helpers (local fallbacks if not defined by iris.js) ──

    function _escHtml(val) {
        if (typeof escapeHtml === 'function') return escapeHtml(val);
        if (val == null) return '';
        var div = document.createElement('div');
        div.textContent = String(val);
        return div.innerHTML;
    }

    function _escAttr(val) {
        if (typeof escapeAttr === 'function') return escapeAttr(val);
        if (val == null) return '';
        return String(val).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/'/g, '&#39;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }

    // ── Helpers ──

    function detectType(values) {
        var dominated = { number: 0, date: 0, string: 0, total: 0 };
        for (var i = 0; i < values.length; i++) {
            var v = values[i];
            if (v == null) continue;
            dominated.total++;
            if (typeof v === 'number' || (typeof v === 'string' && v !== '' && !isNaN(Number(v)) && v.trim() !== '')) {
                dominated.number++;
            } else if (typeof v === 'string' && /^\d{4}-\d{2}-\d{2}/.test(v)) {
                dominated.date++;
            } else {
                dominated.string++;
            }
        }
        if (dominated.total === 0) return 'string';
        if (dominated.number / dominated.total > 0.7) return 'number';
        if (dominated.date / dominated.total > 0.7) return 'date';
        return 'string';
    }

    function formatNumber(v) {
        // Single source of truth : window.KomptiaFormat (format-helpers.js).
        // Garde null/null pour tri (helper retournerait '' avec onInvalid='preserve').
        if (v == null) return null;
        return window.KomptiaFormat.numberFr(v, { onInvalid: 'preserve' });
    }

    function formatDate(v) {
        // Single source of truth : window.KomptiaFormat (format-helpers.js).
        // Spécifique iris-grid : omit time si minuit, preserve raw si non-parsable
        // (cellule peut contenir une string non-ISO à afficher tel quel).
        if (v == null) return null;
        return window.KomptiaFormat.dateTimeFr(v, {
            omitMidnightTime: true,
            onInvalid: 'preserve',
        });
    }

    function compareValues(a, b, type) {
        if (a == null && b == null) return 0;
        if (a == null) return 1;
        if (b == null) return -1;
        if (type === 'number') {
            var na = typeof a === 'number' ? a : Number(a);
            var nb = typeof b === 'number' ? b : Number(b);
            if (isNaN(na) && isNaN(nb)) return 0;
            if (isNaN(na)) return 1;
            if (isNaN(nb)) return -1;
            return na - nb;
        }
        return String(a).localeCompare(String(b), 'fr', { sensitivity: 'base' });
    }

    // Embellisseur SQL pour l'AFFICHAGE (panneau « Requête SQL exécutée »,
    // éditeur, etc.). CRITICAL : la sortie doit rester du SQL SÉMANTIQUEMENT
    // IDENTIQUE à l'entrée — l'utilisateur copie ce texte pour le ré-exécuter
    // (datastore / "Modifier & réexécuter" / "Enregistrer cette requête").
    //
    // On ne reflow QUE le « code ». Le contenu des string literals ('...'),
    // des identifiants quotés ("..." / [...]) et des commentaires (-- / /* */)
    // est émis VERBATIM. Sans cette protection, l'ancienne version (regex
    // globale `\s+`→' ' puis `\n` devant chaque mot-clé) cassait deux choses :
    //   1) un mot-clé DANS un commentaire `--` (ex: le `ORDER BY` de
    //      « STRING_AGG(...) WITHIN GROUP (ORDER BY ...) ») recevait un `\n`
    //      devant → le reste du commentaire passait à la ligne SANS `--` →
    //      devenait du SQL vivant → « Incorrect syntax near 'ORDER' » à la
    //      copie (incident dashboard 2026-06-09).
    //   2) un mot-clé DANS un string literal (`WHERE x = 'ORDER 2024'`) était
    //      coupé par un `\n`, et les espaces multiples d'un littéral écrasés
    //      → valeur de la chaîne MODIFIÉE silencieusement → résultats faux.
    //
    // Règle de jointure : un commentaire de ligne `--` DOIT être suivi d'un
    // `\n`, sinon le token suivant se retrouverait commenté.
    function formatSql(sql) {
        if (!sql) return sql;

        // ── 1) Tokenisation : code | protected (string/ident/bloc) | linecomment ──
        var tokens = [];
        var i = 0, n = sql.length, buf = '';
        function flush() { if (buf) { tokens.push({ kind: 'code', text: buf }); buf = ''; } }
        while (i < n) {
            var ch = sql.charAt(i);
            var two = sql.substr(i, 2);
            if (ch === "'") {
                // String literal, échappement SQL standard '' (apostrophe doublée).
                flush();
                var js = i + 1;
                while (js < n) {
                    if (sql.charAt(js) === "'") {
                        if (sql.charAt(js + 1) === "'") { js += 2; continue; }
                        js++; break;
                    }
                    js++;
                }
                tokens.push({ kind: 'protected', text: sql.slice(i, js) });
                i = js;
            } else if (ch === '"' || ch === '[') {
                // Identifiant quoté SQL Server : "..." ou [...].
                // Escape T-SQL : le caractère de fermeture DOUBLÉ est littéral
                // (`]]` dans [...], `""` dans "...") → on saute la paire et on
                // continue, sinon `[col]]with]]bracket]` serait tronqué au 1er ].
                flush();
                var close = (ch === '"') ? '"' : ']';
                var ji = i + 1;
                while (ji < n) {
                    if (sql.charAt(ji) === close) {
                        if (sql.charAt(ji + 1) === close) { ji += 2; continue; }
                        ji++; break;
                    }
                    ji++;
                }
                tokens.push({ kind: 'protected', text: sql.slice(i, ji) });
                i = ji;
            } else if (two === '--') {
                // Commentaire de ligne — jusqu'au \n (exclu, normalisé ensuite).
                flush();
                var jc = i + 2;
                while (jc < n && sql.charAt(jc) !== '\n') jc++;
                tokens.push({ kind: 'linecomment', text: sql.slice(i, jc) });
                i = jc;
            } else if (two === '/*') {
                // Commentaire bloc — T-SQL autorise l'IMBRICATION (`/* /* */ */`) :
                // chaque `/*` incrémente, chaque `*/` décrémente. Un indexOf('*/')
                // simple fermerait au 1er `*/` → laisserait du « code » mort en
                // SQL vivant. On compte donc la profondeur.
                flush();
                var depth = 1, jb = i + 2;
                while (jb < n && depth > 0) {
                    var p = sql.substr(jb, 2);
                    if (p === '/*') { depth++; jb += 2; }
                    else if (p === '*/') { depth--; jb += 2; }
                    else jb++;
                }
                // jb pointe après le `*/` correspondant (ou n si non fermé).
                tokens.push({ kind: 'protected', text: sql.slice(i, jb) });
                i = jb;
            } else {
                buf += ch; i++;
            }
        }
        flush();

        // ── 2) Reflow du CODE uniquement (mêmes règles qu'avant) ──
        // Le nettoyage cosmétique (espaces avant un \n) est fait ICI, sur le
        // code SEUL — JAMAIS sur l'output réassemblé : sinon il rognerait les
        // espaces/sauts de ligne À L'INTÉRIEUR d'un string literal ou d'un
        // commentaire (ex: 'a\n\n\nb' ou 'fin  \nsuite') = donnée fausse
        // silencieuse (bug trouvé en revue adversariale 2026-06-09).
        function beautify(s) {
            s = s.replace(/\s+/g, ' ');
            s = s.replace(/\b(SELECT|FROM|WHERE|GROUP\s+BY|ORDER\s+BY|HAVING|UNION|EXCEPT|INTERSECT|WITH)\b/gi, '\n$1');
            s = s.replace(/\b(LEFT\s+JOIN|RIGHT\s+JOIN|INNER\s+JOIN|OUTER\s+JOIN|FULL\s+JOIN|CROSS\s+JOIN|JOIN)\b/gi, '\n    $1');
            s = s.replace(/\b(AND|OR)\b/gi, '\n        $1');
            s = s.replace(/[ \t]+\n/g, '\n');
            return s;
        }

        // ── 3) Réassemblage : protected/linecomment verbatim ──
        var out = '';
        for (var k = 0; k < tokens.length; k++) {
            var t = tokens[k];
            if (t.kind === 'code') {
                out += beautify(t.text);
            } else if (t.kind === 'linecomment') {
                if (out.length && !/\s$/.test(out)) out += ' ';
                out += t.text;
                if (k < tokens.length - 1) out += '\n'; // un `--` DOIT être suivi d'un \n
            } else {
                out += t.text; // string / identifiant / commentaire bloc : intacts
            }
        }
        // PAS de post-traitement regex sur `out` ici : il toucherait le contenu
        // des tokens protégés. `trim()` ne rogne que les bords (whitespace de
        // formatage hors token, ou espaces d'un commentaire de fin — sans effet
        // sur l'exécution).
        return out.trim();
    }

    function csvEscape(val) {
        if (val == null) return '';
        var s = String(val);
        // CSV formula injection (CWE-1236) : préfixe ' si la cellule commence par
        // un déclencheur de formule. Cohérent avec `csv_safe_cell` backend. Une
        // valeur Sage ou un pseudonyme /data-privacy `=cmd|...` ne doit pas
        // devenir une formule exécutable à l'ouverture Excel (review 2026-06-01).
        if (s.length > 0 && '=+-@\t\r'.indexOf(s.charAt(0)) !== -1) {
            s = "'" + s;
        }
        if (s.indexOf('"') !== -1 || s.indexOf(';') !== -1 || s.indexOf('\n') !== -1) {
            return '"' + s.replace(/"/g, '""') + '"';
        }
        return s;
    }

    // ── Copilot prompt history (↑/↓ dans la textarea) ─────────────────
    //
    // Pattern moderne (ChatGPT, Cursor, terminal) : l'user peut rappeler
    // ses 20 derniers prompts copilot avec ↑ depuis une textarea vide ou
    // curseur en début. Stockage localStorage device-only — JAMAIS envoyé
    // au serveur (les prompts contiennent souvent des termes métier).
    //
    // Trade-off documenté : sur un device partagé multi-user, l'historique
    // est global au device (visible par tous les users qui se connectent
    // sur le même PC). Acceptable pour cabinet 1 device = 1 user.
    // Mitigation future possible : namespacer la clé par user_id JS-exposé.

    var COPILOT_PROMPT_HISTORY_KEY = 'komptia.copilot.prompt_history';
    var COPILOT_PROMPT_HISTORY_MAX = 20;
    var COPILOT_PROMPT_MAX_LEN = 4000;  // aligné avec backend _INSTR_MAX_LEN

    function _loadCopilotPromptHistory() {
        try {
            var raw = localStorage.getItem(COPILOT_PROMPT_HISTORY_KEY);
            if (!raw) return [];
            var parsed = JSON.parse(raw);
            if (!Array.isArray(parsed)) return [];
            // Filtre défensif : strings valides, sous le cap de longueur
            return parsed.filter(function(s) {
                return typeof s === 'string'
                    && s.length > 0
                    && s.length <= COPILOT_PROMPT_MAX_LEN;
            }).slice(-COPILOT_PROMPT_HISTORY_MAX);
        } catch (e) {
            // JSON corrompu, localStorage indisponible (mode privé Safari),
            // etc. → on retombe sur historique vide, comportement legacy.
            return [];
        }
    }

    function _saveCopilotPromptHistory(arr) {
        try {
            localStorage.setItem(COPILOT_PROMPT_HISTORY_KEY, JSON.stringify(arr));
        } catch (e) {
            // QuotaExceededError, mode privé, etc. — silent ; la navigation
            // ↑/↓ continue de fonctionner via la liste in-memory en cours,
            // juste sans persistance cross-session.
        }
    }

    function _pushCopilotPromptToHistory(prompt) {
        var trimmed = String(prompt || '').trim();
        if (!trimmed || trimmed.length > COPILOT_PROMPT_MAX_LEN) return;
        var history = _loadCopilotPromptHistory();
        // Dédup adjacent : si identique au dernier prompt, ne pas re-ajouter
        // (l'user qui re-clique Send sur le même texte ne pollue pas).
        if (history.length > 0 && history[history.length - 1] === trimmed) return;
        history.push(trimmed);
        if (history.length > COPILOT_PROMPT_HISTORY_MAX) {
            history = history.slice(-COPILOT_PROMPT_HISTORY_MAX);
        }
        _saveCopilotPromptHistory(history);
    }

    // ── ResultHistory — Undo/Redo state management per grid ──

    function ResultHistory(initialState) {
        this.states = [initialState];
        this.currentIndex = 0;
    }

    ResultHistory.prototype.push = function(state) {
        // Truncate redo history
        this.states = this.states.slice(0, this.currentIndex + 1);
        this.states.push(state);
        this.currentIndex++;
        // Cap at 50 states to avoid memory bloat
        if (this.states.length > 50) {
            this.states.shift();
            this.currentIndex--;
        }
    };

    ResultHistory.prototype.undo = function() {
        if (this.currentIndex > 0) {
            this.currentIndex--;
            return this.states[this.currentIndex];
        }
        return null;
    };

    ResultHistory.prototype.redo = function() {
        if (this.currentIndex < this.states.length - 1) {
            this.currentIndex++;
            return this.states[this.currentIndex];
        }
        return null;
    };

    ResultHistory.prototype.canUndo = function() {
        return this.currentIndex > 0;
    };

    ResultHistory.prototype.canRedo = function() {
        return this.currentIndex < this.states.length - 1;
    };

    // ── Cookie helper (fallback si base.html n'a pas chargé getCookie) ──

    function _getXsrfCookie() {
        if (typeof getCookie === 'function') return getCookie('_xsrf');
        var name = '_xsrf=';
        var parts = (document.cookie || '').split(';');
        for (var i = 0; i < parts.length; i++) {
            var c = parts[i].trim();
            if (c.indexOf(name) === 0) return c.substring(name.length);
        }
        return '';
    }

    /**
     * Compresse une string JSON en Blob gzip via ``CompressionStream`` pour
     * réduire ~20× le payload sur le réseau. Les ``.afz.json`` sont DÉJÀ
     * stockés gzippés côté serveur (``datastore.py`` gzip niveau 6) — le
     * handler d'upload détecte les magic bytes ``0x1f 0x8b`` et décompresse de
     * façon transparente à la réception, donc l'envoi compressé est lossless
     * et passe sous le cap nginx ``client_max_body_size`` sans rien gonfler.
     *
     * Retourne une ``Promise<Blob|null>`` — ``null`` si ``CompressionStream``
     * (ou ``Blob.prototype.stream``) est indisponible (vieux navigateur) ou en
     * cas d'échec : le caller retombe alors sur l'upload BRUT (aucune
     * régression, le serveur accepte les deux formats). Ne throw jamais.
     */
    function _gzipStringToBlob(jsonString) {
        try {
            if (typeof CompressionStream === 'undefined'
                || typeof Response === 'undefined'
                || typeof Blob === 'undefined') {
                return Promise.resolve(null);
            }
            var inputBlob = new Blob([jsonString], { type: 'application/json' });
            if (typeof inputBlob.stream !== 'function') {
                return Promise.resolve(null);
            }
            var stream = inputBlob.stream().pipeThrough(new CompressionStream('gzip'));
            return new Response(stream).blob().then(
                function (gz) { return (gz && gz.size > 0) ? gz : null; },
                function () { return null; }
            );
        } catch (e) {
            return Promise.resolve(null);
        }
    }

    /**
     * Lecture SÛRE d'une réponse fetch JSON. Délègue au helper global
     * ``window.komptiaReadJson`` (static/js/read-json.js, chargé en <head>).
     * **Filet (fix L1)** : si ce helper n'a pas chargé (CSP, réseau, ad-blocker,
     * ou un futur template qui n'étend pas base.html), on retombe sur une
     * implémentation locale équivalente — sinon CHAQUE save planterait en
     * ``komptiaReadJson is not a function`` (pire que le bug d'origine). Ne
     * throw jamais ; même contrat de retour que le helper global.
     */
    function _readJsonSafe(resp) {
        if (typeof window !== 'undefined' && typeof window.komptiaReadJson === 'function') {
            return window.komptiaReadJson(resp);
        }
        if (!resp || typeof resp.text !== 'function') {
            return Promise.resolve({
                ok: false, status: (resp && resp.status) || 0, data: null,
                error: 'Réponse réseau invalide.', errorCode: null,
                isHtmlError: false, tooLarge: false, rawText: ''
            });
        }
        return resp.text().then(function (t) {
            var d = null;
            try { d = t ? JSON.parse(t) : null; } catch (e) { d = null; }
            var hasFields = d && typeof d === 'object';
            return {
                ok: !!resp.ok, status: resp.status || 0, data: d,
                error: resp.ok ? null : ((hasFields && d.error) || 'Erreur (' + (resp.status || 0) + ').'),
                errorCode: (hasFields && d.error_code) || null,
                isHtmlError: false,
                tooLarge: resp.status === 413,
                rawText: t || ''
            };
        }, function () {
            return {
                ok: false, status: resp.status || 0, data: null,
                error: 'Lecture de la réponse impossible.', errorCode: null,
                isHtmlError: false, tooLarge: resp.status === 413, rawText: ''
            };
        });
    }

    // ── Modal custom pour saisir le nom du fichier SQL ───────────────
    // Pas de window.prompt/confirm : cohérent avec le reste de l'app.
    // Monté dynamiquement dans document.body ; une seule instance vit à la fois.
    // Support ESC, Enter, backdrop click, erreur inline, état "fichier existe".

    function _openSaveSqlModal(sql, btn, idleLabel) {
        if (document.getElementById('sql-save-modal')) return; // déjà ouvert

        var overlay = document.createElement('div');
        overlay.id = 'sql-save-modal';
        // z-index délégué à OverlayManager (layer='modal' = 2000+N×10).
        overlay.style.cssText =
            'position:fixed;inset:0;background:var(--bg-overlay, rgba(0,0,0,0.5));' +
            'display:flex;align-items:center;justify-content:center;';

        var card = document.createElement('div');
        card.style.cssText =
            'background:var(--bg-surface, #fff);color:var(--text-primary, #111827);' +
            'border-radius:0.75rem;box-shadow:var(--shadow-lg, 0 10px 40px rgba(0,0,0,0.2));' +
            'border:1px solid var(--border, transparent);' +
            'width:min(460px, 92vw);padding:1.25rem;';

        var title = document.createElement('h2');
        title.textContent = 'Enregistrer la requête SQL';
        title.style.cssText = 'font-size:0.95rem;font-weight:600;color:var(--text-primary, #111827);margin:0 0 0.25rem 0;';

        var sub = document.createElement('p');
        sub.textContent = 'Le fichier sera ajouté à votre datastore (extension .sql ajoutée si manquante).';
        sub.style.cssText = 'font-size:0.75rem;color:var(--text-muted, #6b7280);margin:0 0 1rem 0;';

        var label = document.createElement('label');
        label.textContent = 'Nom du fichier';
        label.style.cssText = 'display:block;font-size:0.75rem;font-weight:500;color:var(--text-secondary, #374151);margin-bottom:0.25rem;';

        var input = document.createElement('input');
        input.type = 'text';
        input.maxLength = 200;
        input.value = 'ma-requete-' + new Date().toISOString().slice(0, 10) + '.sql';
        input.style.cssText =
            'width:100%;padding:0.5rem 0.75rem;border:1px solid var(--border, #d1d5db);border-radius:0.375rem;' +
            'background:var(--bg-surface, #fff);color:var(--text-primary, #111827);' +
            'font-size:0.875rem;font-family:inherit;box-sizing:border-box;';

        var err = document.createElement('p');
        err.style.cssText = 'font-size:0.75rem;color:var(--status-error,#dc2626);margin:0.5rem 0 0 0;min-height:1rem;';

        var row = document.createElement('div');
        row.style.cssText = 'display:flex;justify-content:flex-end;gap:0.5rem;margin-top:1rem;';

        var btnCancel = document.createElement('button');
        btnCancel.type = 'button';
        btnCancel.textContent = 'Annuler';
        btnCancel.style.cssText =
            'padding:0.45rem 1rem;border:1px solid var(--border, #d1d5db);' +
            'background:var(--bg-surface, #fff);color:var(--text-secondary, #374151);' +
            'border-radius:0.375rem;font-size:0.8125rem;cursor:pointer;';

        var btnConfirm = document.createElement('button');
        btnConfirm.type = 'button';
        btnConfirm.textContent = 'Enregistrer';
        btnConfirm.style.cssText =
            'padding:0.45rem 1rem;border:none;background:var(--brand, var(--brand));color:#fff;' +
            'border-radius:0.375rem;font-size:0.8125rem;font-weight:500;cursor:pointer;';

        row.appendChild(btnCancel);
        row.appendChild(btnConfirm);
        card.appendChild(title);
        card.appendChild(sub);
        card.appendChild(label);
        card.appendChild(input);
        card.appendChild(err);
        card.appendChild(row);
        overlay.appendChild(card);
        document.body.appendChild(overlay);
        if (window.OverlayManager && typeof window.OverlayManager.open === 'function') {
            window.OverlayManager.open(overlay, {
                layer: 'modal',
                lockScroll: true,
                onClose: function() { close(); },
            });
        }

        setTimeout(function() { input.focus(); input.select(); }, 0);

        var closed = false;
        function close() {
            if (closed) return;
            closed = true;
            document.removeEventListener('keydown', onKey);
            if (window.OverlayManager && typeof window.OverlayManager.close === 'function') {
                try { window.OverlayManager.close(overlay); } catch (e) {}
            }
            if (overlay.parentNode) overlay.parentNode.removeChild(overlay);
            btn.disabled = false;
            btn.innerHTML = idleLabel;
        }
        function onKey(e) {
            // Escape : géré par OverlayManager (LIFO).
            if (e.key === 'Enter' && document.activeElement === input) {
                e.preventDefault();
                submit();
            }
        }
        function setBusy(busy) {
            input.disabled = busy;
            btnCancel.disabled = busy;
            btnConfirm.disabled = busy;
            btnConfirm.textContent = busy ? 'Enregistrement…' : 'Enregistrer';
        }
        // Drapeau stateful : vaut true après un 409 jusqu'à ce que l'utilisateur
        // édite le nom (retour au mode "create"). Évite la collision onclick +
        // addEventListener qui faisait double-fire en cas de clic sur "Écraser".
        var overwriteMode = false;

        function resetConfirmButton() {
            overwriteMode = false;
            btnConfirm.textContent = 'Enregistrer';
            btnConfirm.style.background = 'var(--brand, #111827)';
        }

        function submit() {
            var name = (input.value || '').trim();
            if (!name) {
                err.textContent = 'Le nom du fichier est obligatoire.';
                input.focus();
                return;
            }
            err.textContent = '';
            setBusy(true);
            fetch('/api/datastore/sql/save', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-XSRFToken': _getXsrfCookie(),
                },
                body: JSON.stringify({
                    filename: name, sql: sql, overwrite: !!overwriteMode,
                }),
            }).then(function(res) {
                return res.json().then(function(data) {
                    return { status: res.status, data: data };
                });
            }).then(function(ctx) {
                // User a fermé le modal (ESC / backdrop / Cancel) avant le
                // résultat du fetch : on ne touche plus à rien.
                if (closed) return;
                var data = ctx.data || {};
                if (ctx.status === 201 && data.success) {
                    close();
                    btn.textContent = '✓ ' + (data.filename || name);
                    setTimeout(function() { btn.innerHTML = idleLabel; }, 3000);
                    return;
                }
                if (ctx.status === 409 && data.code === 'exists') {
                    setBusy(false);
                    err.textContent =
                        'Un fichier « ' + (data.filename || name) + ' » existe déjà. ' +
                        'Cliquez sur « Écraser » pour le remplacer, ou modifiez le nom.';
                    overwriteMode = true;
                    btnConfirm.textContent = 'Écraser';
                    btnConfirm.style.background = 'var(--status-error, #b91c1c)';
                    return;
                }
                setBusy(false);
                err.textContent = data.error || 'Échec de l\'enregistrement.';
            }).catch(function(e) {
                // P5.4 (audit 2026-05-26) — capture `e` pour distinguer
                // offline / 502 / SyntaxError JSON parse.
                if (closed) return;
                setBusy(false);
                var detail = (e && e.message) ? String(e.message) : 'inconnue';
                err.textContent = 'Erreur réseau : ' + detail + '.';
            });
        }

        // Si l'utilisateur modifie le nom après un 409, on repasse en mode
        // "create" : le bouton "Écraser" ne s'applique plus à ce nouveau nom.
        input.addEventListener('input', function() {
            if (overwriteMode) resetConfirmButton();
            if (err.textContent) err.textContent = '';
        });

        btnCancel.addEventListener('click', close);
        overlay.addEventListener('click', function(e) {
            if (e.target === overlay) close();
        });
        btnConfirm.addEventListener('click', submit);
        document.addEventListener('keydown', onKey);
    }

    // ── Point d'entrée : déclenché par le bouton "Enregistrer cette requête"
    function _saveSqlToDatastore(sql, btn, idleLabel) {
        if (!sql || !sql.trim()) {
            btn.textContent = '⚠ SQL vide';
            setTimeout(function() { btn.innerHTML = idleLabel; }, 2500);
            return;
        }
        // ⚠ Check existence modal AVANT toute mutation du bouton : sinon un
        // 2e clic mettrait btn en "Enregistrement…" puis _openSaveSqlModal
        // return-would tôt sans que le 1er close() ne remette le label à jour
        // (btn/idleLabel sont capturés par closure du 1er appel).
        if (document.getElementById('sql-save-modal')) return;
        btn.disabled = true;
        btn.textContent = 'Enregistrement…';
        _openSaveSqlModal(sql, btn, idleLabel);
    }

    // ── Éditeur SQL : modale réutilisable ──
    //
    // Ouvre une textarea (monospace, autogrow, Tab indente, Ctrl+Entrée
    // soumet, Échap ferme via OverlayManager) avec 3 actions :
    //   - Annuler
    //   - Exécuter sans enregistrer  → POST /api/datastore/sql/execute {sql, path?}
    //   - Enregistrer et exécuter    → POST /save puis POST /execute {path}
    //
    // Le bouton "Enregistrer et exécuter" est désactivé quand opts.allowSave
    // est faux OU quand opts.filename est vide (cas /iris : la requête n'est
    // pas encore associée à un fichier datastore — l'utilisateur peut toujours
    // la sauvegarder a posteriori via le bouton "Enregistrer cette requête"
    // qui apparaît sur le résultat).
    //
    // opts = {
    //   sql:           string  (contenu initial),
    //   filename:      string|null (nom du fichier .sql d'origine, si connu),
    //   allowSave:     boolean (autorise "Enregistrer et exécuter"),
    //   maxBytes:      number  (cap, défaut 256 Ko — aligné backend),
    //   onSuccess:     function({sql, columns, rows, row_count,
    //                            execution_time_ms, truncated, max_rows,
    //                            savedFilename}),
    //   onCancel:      function() (optionnel, appelé si fermeture sans run),
    // }
    function _openSqlEditorModal(opts) {
        opts = opts || {};
        if (document.getElementById('sql-editor-modal')) return;

        var initialSql = opts.sql == null ? '' : String(opts.sql);
        var filename = opts.filename ? String(opts.filename) : '';
        // L'endpoint /api/datastore/sql/save (``_sanitize_user_filename``)
        // rejette les séparateurs de chemin → un fichier dans un sous-dossier
        // ne peut PAS être ré-enregistré via cette voie. On désactive
        // "Enregistrer et exécuter" plutôt que de laisser l'utilisateur
        // recevoir un 400 confus après coup. L'exécution transient reste
        // disponible.
        var filenameHasSubdir = filename.indexOf('/') !== -1 || filename.indexOf('\\') !== -1;
        var allowSave = !!opts.allowSave && !!filename && !filenameHasSubdir;
        var onSuccess = typeof opts.onSuccess === 'function' ? opts.onSuccess : null;
        var onCancel = typeof opts.onCancel === 'function' ? opts.onCancel : null;
        var maxBytes = (typeof opts.maxBytes === 'number' && opts.maxBytes > 0)
            ? opts.maxBytes
            : (256 * 1024);

        var overlay = document.createElement('div');
        overlay.id = 'sql-editor-modal';
        overlay.style.cssText =
            'position:fixed;inset:0;background:var(--bg-overlay, rgba(0,0,0,0.5));' +
            'display:flex;align-items:center;justify-content:center;padding:1rem;';

        var card = document.createElement('div');
        card.style.cssText =
            'background:var(--bg-surface, #fff);color:var(--text-primary, #111827);' +
            'border-radius:0.75rem;box-shadow:var(--shadow-lg, 0 10px 40px rgba(0,0,0,0.2));' +
            'border:1px solid var(--border, transparent);' +
            'width:min(820px, 96vw);max-height:90vh;display:flex;flex-direction:column;' +
            'padding:1.25rem;box-sizing:border-box;';

        var title = document.createElement('h2');
        title.textContent = opts.title
            ? String(opts.title)
            : (filename
                ? 'Modifier la requête SQL : ' + filename
                : 'Modifier la requête SQL');
        title.title = title.textContent;
        title.style.cssText =
            'font-size:0.95rem;font-weight:600;color:var(--text-primary, #111827);' +
            'margin:0 0 0.25rem 0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;';

        var sub = document.createElement('p');
        sub.textContent = opts.hint
            ? String(opts.hint)
            : (allowSave
                ? 'Modifie la requête puis exécute-la, ou enregistre la version modifiée dans le datastore.'
                : 'Modifie la requête puis exécute-la. La modification n\'est pas enregistrée.');
        sub.style.cssText =
            'font-size:0.75rem;color:var(--text-muted, #6b7280);margin:0 0 0.75rem 0;';

        var textareaWrap = document.createElement('div');
        textareaWrap.style.cssText = 'flex:1 1 auto;min-height:0;display:flex;';

        var textarea = document.createElement('textarea');
        textarea.id = 'sql-editor-modal-textarea';
        textarea.value = initialSql;
        textarea.setAttribute('spellcheck', 'false');
        textarea.setAttribute('autocomplete', 'off');
        textarea.setAttribute('autocapitalize', 'off');
        textarea.setAttribute('autocorrect', 'off');
        textarea.setAttribute('aria-label', 'Éditeur de requête SQL');
        textarea.rows = 14;
        textarea.style.cssText =
            'flex:1 1 auto;width:100%;min-height:280px;max-height:60vh;padding:0.75rem;' +
            'border:1px solid var(--border, #d1d5db);border-radius:0.375rem;' +
            'background:var(--bg-surface, #fff);color:var(--text-primary, #111827);' +
            'font-family:ui-monospace,"SF Mono",Menlo,Consolas,monospace;font-size:0.85rem;' +
            'line-height:1.4;resize:vertical;box-sizing:border-box;tab-size:2;';
        textareaWrap.appendChild(textarea);

        var infoRow = document.createElement('div');
        infoRow.style.cssText =
            'display:flex;align-items:center;justify-content:space-between;gap:0.5rem;' +
            'margin-top:0.5rem;font-size:0.7rem;color:var(--text-muted, #6b7280);';

        var hint = document.createElement('span');
        hint.textContent = 'Ctrl+Entrée pour lancer · Tab indente · Échap pour fermer';

        var counter = document.createElement('span');
        counter.id = 'sql-editor-modal-counter';
        counter.style.cssText = 'white-space:nowrap;';

        infoRow.appendChild(hint);
        infoRow.appendChild(counter);

        var err = document.createElement('p');
        err.style.cssText =
            'font-size:0.75rem;color:var(--status-error,#dc2626);margin:0.5rem 0 0 0;min-height:1rem;';
        err.setAttribute('role', 'alert');

        var row = document.createElement('div');
        row.style.cssText =
            'display:flex;justify-content:flex-end;gap:0.5rem;margin-top:0.75rem;flex-wrap:wrap;';

        var btnCancel = document.createElement('button');
        btnCancel.type = 'button';
        btnCancel.textContent = 'Annuler';
        btnCancel.style.cssText =
            'padding:0.45rem 1rem;border:1px solid var(--border, #d1d5db);' +
            'background:var(--bg-surface, #fff);color:var(--text-secondary, #374151);' +
            'border-radius:0.375rem;font-size:0.8125rem;cursor:pointer;';

        var btnRun = document.createElement('button');
        var BTN_RUN_LABEL = 'Exécuter sans enregistrer';
        btnRun.type = 'button';
        btnRun.textContent = BTN_RUN_LABEL;
        btnRun.style.cssText =
            'padding:0.45rem 1rem;border:1px solid var(--border, #d1d5db);' +
            'background:var(--bg-surface, #fff);color:var(--text-primary, #111827);' +
            'border-radius:0.375rem;font-size:0.8125rem;font-weight:500;cursor:pointer;';

        var btnSaveRun = document.createElement('button');
        var BTN_SAVE_RUN_LABEL = 'Enregistrer et exécuter';
        btnSaveRun.type = 'button';
        btnSaveRun.textContent = BTN_SAVE_RUN_LABEL;
        btnSaveRun.style.cssText =
            'padding:0.45rem 1rem;border:none;background:var(--brand, #111827);color:#fff;' +
            'border-radius:0.375rem;font-size:0.8125rem;font-weight:500;cursor:pointer;';
        if (!allowSave) {
            btnSaveRun.disabled = true;
            btnSaveRun.style.opacity = '0.5';
            btnSaveRun.style.cursor = 'not-allowed';
            btnSaveRun.title = filenameHasSubdir
                ? 'Le ré-enregistrement direct n\'est pas pris en charge pour les fichiers dans un sous-dossier. Utilise « Exécuter sans enregistrer ».'
                : filename
                    ? 'Disponible uniquement quand l\'enregistrement est autorisé.'
                    : 'Disponible uniquement pour une requête déjà enregistrée dans le datastore.';
        }

        row.appendChild(btnCancel);
        row.appendChild(btnRun);
        row.appendChild(btnSaveRun);

        card.appendChild(title);
        card.appendChild(sub);
        card.appendChild(textareaWrap);
        card.appendChild(infoRow);
        card.appendChild(err);
        card.appendChild(row);
        overlay.appendChild(card);
        document.body.appendChild(overlay);

        if (window.OverlayManager && typeof window.OverlayManager.open === 'function') {
            window.OverlayManager.open(overlay, {
                layer: 'modal',
                lockScroll: true,
                onClose: function() { close('overlay-manager'); },
            });
        }

        setTimeout(function() {
            textarea.focus();
            try {
                // Place le curseur à la fin pour que l'utilisateur édite tout de suite
                textarea.setSelectionRange(textarea.value.length, textarea.value.length);
                // Scroll au plus bas du textarea pour voir la dernière ligne (souvent là où l'erreur SQL se trouve)
                textarea.scrollTop = textarea.scrollHeight;
            } catch (e) { /* certains navigateurs anciens */ }
        }, 0);

        function _byteSize(s) {
            var v = s || '';
            try { return new Blob([v]).size; } catch (e) { /* try next fallback */ }
            // ``TextEncoder`` est UTF-8 garanti (Living Standard) — produit le
            // MÊME byte count que ``str.encode('utf-8')`` côté Python. Sans ça,
            // ``.length`` (char count) sous-estime fortement pour les SQL
            // contenant des commentaires FR accentués → frontend "vert" alors
            // que le backend renverra 413.
            try { return new TextEncoder().encode(v).length; } catch (e2) { /* IE-era */ }
            // Dernier filet : approximation UTF-8 (chars >= U+0080 = 2 bytes
            // minimum). Reste imparfait mais évite la divergence ASCII-stricte
            // du simple ``.length``.
            var approx = 0;
            for (var i = 0; i < v.length; i++) {
                var c = v.charCodeAt(i);
                approx += c < 0x80 ? 1 : (c < 0x800 ? 2 : 3);
            }
            return approx;
        }

        function updateCounter() {
            var bytes = _byteSize(textarea.value);
            var maxKb = Math.round(maxBytes / 1024);
            var kb = bytes / 1024;
            var kbStr = (bytes >= 10240) ? Math.round(kb) : kb.toFixed(1);
            counter.textContent = kbStr + ' / ' + maxKb + ' Ko';
            counter.style.color = bytes > maxBytes
                ? 'var(--status-error, #dc2626)'
                : 'var(--text-muted, #6b7280)';
        }
        updateCounter();
        textarea.addEventListener('input', updateCounter);

        var closed = false;
        function close(reason) {
            if (closed) return;
            closed = true;
            document.removeEventListener('keydown', onGlobalKey);
            if (window.OverlayManager && typeof window.OverlayManager.close === 'function') {
                try { window.OverlayManager.close(overlay); } catch (e) { /* déjà fermé */ }
            }
            if (overlay.parentNode) overlay.parentNode.removeChild(overlay);
            if (reason !== 'success' && onCancel) {
                try { onCancel(); } catch (e) { /* swallow */ }
            }
        }

        function onGlobalKey(e) {
            // Ctrl/Cmd+Entrée = action principale (Save+Run si autorisée, sinon Run).
            // Ne pas déclencher si l'utilisateur saisit dans un autre champ qui
            // capture déjà ces touches.
            if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
                if (document.activeElement === textarea
                    || document.activeElement === btnRun
                    || document.activeElement === btnSaveRun
                    || document.activeElement === btnCancel) {
                    e.preventDefault();
                    (allowSave ? btnSaveRun : btnRun).click();
                }
            }
        }

        // Tab insère 2 espaces dans la textarea (évite de tab-out hors champ).
        textarea.addEventListener('keydown', function(e) {
            if (e.key === 'Tab' && !e.shiftKey) {
                e.preventDefault();
                var start = textarea.selectionStart;
                var end = textarea.selectionEnd;
                var v = textarea.value;
                textarea.value = v.substring(0, start) + '  ' + v.substring(end);
                textarea.selectionStart = textarea.selectionEnd = start + 2;
                updateCounter();
            }
        });

        function setBusy(busy) {
            textarea.disabled = busy;
            btnCancel.disabled = busy;
            btnRun.disabled = busy;
            btnSaveRun.disabled = busy || !allowSave;
            if (busy) {
                btnRun.style.opacity = '0.6';
                btnRun.style.cursor = 'wait';
                btnSaveRun.style.opacity = '0.6';
                btnSaveRun.style.cursor = 'wait';
            } else {
                btnRun.style.opacity = '';
                btnRun.style.cursor = 'pointer';
                if (allowSave) {
                    btnSaveRun.style.opacity = '';
                    btnSaveRun.style.cursor = 'pointer';
                } else {
                    btnSaveRun.style.opacity = '0.5';
                    btnSaveRun.style.cursor = 'not-allowed';
                }
            }
        }

        function readSqlOrFail() {
            var raw = (textarea.value || '').trim();
            if (!raw) {
                err.textContent = 'La requête ne peut pas être vide.';
                textarea.focus();
                return null;
            }
            var bytes = _byteSize(raw);
            if (bytes > maxBytes) {
                err.textContent = 'Requête trop volumineuse ('
                    + Math.round(bytes / 1024) + ' / '
                    + Math.round(maxBytes / 1024) + ' Ko).';
                textarea.focus();
                return null;
            }
            return raw;
        }

        function finishSuccess(payload, savedFilename) {
            if (onSuccess) {
                try {
                    onSuccess({
                        sql: payload.sql || textarea.value,
                        columns: payload.columns || [],
                        rows: payload.rows || [],
                        row_count: payload.row_count || 0,
                        execution_time_ms: payload.execution_time_ms || 0,
                        truncated: !!payload.truncated,
                        max_rows: payload.max_rows,
                        savedFilename: savedFilename || null,
                    });
                } catch (e) {
                    // Le callback a throw — la requête a réussi côté serveur
                    // mais l'affichage côté UI est cassé. On ferme quand même
                    // la modale (sinon l'utilisateur croit qu'elle est figée)
                    // mais on signale l'erreur explicitement : sinon disparition
                    // silencieuse → "j'ai cliqué Exécuter, rien ne se passe".
                    try { console.error('[sql-editor] onSuccess threw:', e); } catch (_) {}
                    if (typeof window.showToast === 'function') {
                        window.showToast(
                            'Requête exécutée, mais l\'affichage du résultat a échoué. Voir la console.',
                            'warning'
                        );
                    }
                }
            }
            close('success');
        }

        function showFailure(data, fallback) {
            err.textContent = (data && data.error) || fallback;
        }

        function executeInline(sql) {
            err.textContent = '';
            setBusy(true);
            btnRun.textContent = 'Exécution…';
            var body = { sql: sql };
            if (filename) body.path = filename; // contexte audit uniquement
            fetch('/api/datastore/sql/execute', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-XSRFToken': _getXsrfCookie(),
                },
                body: JSON.stringify(body),
            }).then(function(res) {
                return res.json().then(function(data) {
                    return { status: res.status, data: data };
                });
            }).then(function(ctx) {
                if (closed) return;
                var data = ctx.data || {};
                if (data.success) {
                    finishSuccess(data, null);
                    return;
                }
                setBusy(false);
                btnRun.textContent = BTN_RUN_LABEL;
                showFailure(data, 'Erreur lors de l\'exécution.');
            }).catch(function(e) {
                // P5.4 (audit 2026-05-26) — Avant : catch sans capturer `e`,
                // toujours « Erreur réseau » même si c'était SyntaxError JSON
                // (backend 500 HTML), AbortError (timeout), TypeError parse.
                // Maintenant : on inclut e.message pour distinguer.
                if (closed) return;
                setBusy(false);
                btnRun.textContent = BTN_RUN_LABEL;
                var detail = (e && e.message) ? String(e.message) : 'inconnue';
                err.textContent = 'Erreur réseau : ' + detail + '. Vérifie la connexion puis réessaie.';
            });
        }

        function saveThenExecute(sql) {
            err.textContent = '';
            setBusy(true);
            btnSaveRun.textContent = 'Enregistrement…';
            fetch('/api/datastore/sql/save', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-XSRFToken': _getXsrfCookie(),
                },
                body: JSON.stringify({ filename: filename, sql: sql, overwrite: true }),
            }).then(function(res) {
                return res.json().then(function(data) {
                    return { status: res.status, data: data };
                });
            }).then(function(ctx) {
                if (closed) return null;
                var data = ctx.data || {};
                if (!(ctx.status === 201 && data.success)) {
                    setBusy(false);
                    btnSaveRun.textContent = BTN_SAVE_RUN_LABEL;
                    showFailure(data, 'Échec de l\'enregistrement.');
                    return null;
                }
                // Enregistré → exécute la version désormais sur disque.
                btnSaveRun.textContent = 'Exécution…';
                var savedFilename = data.filename || filename;
                return fetch('/api/datastore/sql/execute', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-XSRFToken': _getXsrfCookie(),
                    },
                    body: JSON.stringify({ path: savedFilename }),
                }).then(function(res) {
                    return res.json().then(function(d) {
                        return { status: res.status, data: d, savedFilename: savedFilename };
                    });
                });
            }).then(function(ctx2) {
                if (closed || ctx2 == null) return;
                var d2 = ctx2.data || {};
                if (d2.success) {
                    finishSuccess(d2, ctx2.savedFilename);
                    return;
                }
                setBusy(false);
                btnSaveRun.textContent = BTN_SAVE_RUN_LABEL;
                err.textContent = (d2.error || 'Erreur lors de l\'exécution.')
                    + ' (fichier enregistré, exécution échouée)';
            }).catch(function(e) {
                // P5.4 (audit 2026-05-26) — idem ``executeInline`` : capture
                // `e` pour distinguer offline / 502 / parse error.
                if (closed) return;
                setBusy(false);
                btnSaveRun.textContent = BTN_SAVE_RUN_LABEL;
                var detail = (e && e.message) ? String(e.message) : 'inconnue';
                err.textContent = 'Erreur réseau : ' + detail + '. Vérifie la connexion puis réessaie.';
            });
        }

        btnCancel.addEventListener('click', function() { close('cancel'); });
        overlay.addEventListener('click', function(e) {
            if (e.target === overlay) close('backdrop');
        });
        btnRun.addEventListener('click', function() {
            var sql = readSqlOrFail();
            if (!sql) return;
            executeInline(sql);
        });
        btnSaveRun.addEventListener('click', function() {
            if (!allowSave) return;
            var sql = readSqlOrFail();
            if (!sql) return;
            saveThenExecute(sql);
        });
        document.addEventListener('keydown', onGlobalKey);
    }

    // Exposé global pour /datastore et /iris (les deux chargent ce script).
    window.openSqlEditorModal = _openSqlEditorModal;

    // ── Constructor ──

    function SqlResultGrid(container, columns, rows, sql, totalRowCount, columnMetadata, options) {
        this.container = container;
        var hasCols = columns && columns.length > 0;
        var hasRows = rows && rows.length > 0;
        this._isBlankSheet = !hasCols && !hasRows && !sql;
        this._isDashboardSheet = this._isBlankSheet; // Stays true even after data arrives (E0d)
        if (this._isBlankSheet) {
            // Generate default spreadsheet columns (A-H) and empty rows
            columns = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H'];
            rows = [];
            for (var r = 0; r < 12; r++) {
                var row = [];
                for (var c = 0; c < 8; c++) row.push('');
                rows.push(row);
            }
        }
        this.columns = hasCols ? columns : (hasRows && typeof rows[0] === 'object' ? Object.keys(rows[0]) : columns || []);
        this.allRows = rows || [];
        this.sql = sql || '';
        this.totalRowCount = totalRowCount || this.allRows.length;
        this.isArrayFormat = this.allRows.length > 0 && Array.isArray(this.allRows[0]);
        this.columnMetadata = columnMetadata || null; // from /api/drilldown/analyze
        this._options = options || {}; // { onDrillResult, anonymizationState, onAnonymizationStateChange, ... }
        // Provenance de la feuille (externalSource du tab, posée par addTab).
        // Sert à distinguer une feuille SQL VIVANTE d'un SNAPSHOT importé
        // (« Ajouter feuilles externes… ») qui transporte son SQL d'origine
        // à titre de provenance — cf. _isImportedSnapshot.
        this._externalSource = this._options.externalSource || null;

        // ── État d'anonymisation piloté par l'utilisateur (v2) ──
        // Source de vérité = BDD serveur (table ``anonymization_terms`` du
        // user). Le state local est un CACHE rechargé :
        //  - au boot de la grille via ``GET /api/anonymization/terms``
        //  - après un save panneau via le body de ``PUT /api/anonymization/terms``
        //  - après un 409 ``ANON_PENDING_REVIEW`` (le backend renvoie le
        //    state réconcilié dans le body)
        //
        // Le state initial est un squelette vide ; la première fetch remplit.
        // Si ``options.anonymizationState`` est fourni (tests / embed), on
        // l'utilise et on saute la fetch.
        this._anonymizationState = (this._options.anonymizationState &&
            typeof this._options.anonymizationState === 'object')
            ? this._options.anonymizationState
            : { version: 1, terms: {} };
        this._anonymizationFetchPromise = null;
        this._anonymizationFetched = !!this._options.anonymizationState;
        // Timestamp du dernier échec réseau du fetch state (0 = aucun).
        // Porte le backoff anti-tempête de _fetchAnonymizationState.
        this._anonymizationFetchFailedAt = 0;
        // Jeton de révision du verrou optimiste PUT (fix lost update
        // 2026-06-10). null = pas encore connu → le premier PUT part en
        // legacy last-writer-wins (fail-open assumé : sans GET préalable,
        // il n'y a pas de base à protéger).
        this._anonRevision = null;
        // Tokens nouveaux depuis le dernier "vu" = dernière ouverture du
        // panneau. Utilisé uniquement pour afficher le badge NOUVEAU et
        // trier le rendu — vidé à l'ouverture du panneau (l'user les voit).
        this._anonNewTokensPending = Object.create(null);

        // Sync anonymisation cross-tab via BroadcastChannel. Quand l'user
        // a 2 onglets navigateur de la même grille ouverts, un toggle dans
        // tab A doit se refléter dans tab B sans re-fetch BDD. Channel
        // unique global pour Komptia → réception inter-grilles inter-tabs.
        //
        // Session ID per-instance : protection ceinture+bretelles contre
        // l'auto-réception (BroadcastChannel ne livre pas à l'émetteur,
        // mais on filtre quand même au cas où le navigateur dérive).
        // Flag ``_anonBroadcastSuppress`` empêche un re-broadcast quand
        // on applique un state reçu (sinon broadcast en cascade entre N
        // tabs ouverts).
        this._anonBroadcastSessionId = (typeof crypto !== 'undefined'
            && typeof crypto.randomUUID === 'function')
            ? crypto.randomUUID()
            : 'sess-' + Date.now() + '-' + Math.floor(Math.random() * 1e9);
        this._anonBroadcastSuppress = false;
        this._anonBroadcastChannel = null;
        try {
            if (typeof BroadcastChannel !== 'undefined') {
                this._anonBroadcastChannel = new BroadcastChannel('komptia-anonymization');
                var grid = this;
                this._anonBroadcastChannel.addEventListener('message', function(ev) {
                    var msg = ev && ev.data;
                    if (!msg || typeof msg !== 'object') return;
                    if (msg.type !== 'anon_state_changed') return;
                    if (msg.source_session === grid._anonBroadcastSessionId) return;
                    if (!msg.state || typeof msg.state !== 'object') return;
                    // Suppress re-broadcast pour ne pas cascader
                    grid._anonBroadcastSuppress = true;
                    try {
                        grid._setAnonymizationState(msg.state);
                        // Re-render conditionnel pour appliquer les marqueurs
                        // per-cell anon-active/anon-pending au nouveau state.
                        if (grid.tbodyEl) {
                            try { grid._renderBody && grid._renderBody(); }
                            catch (_e) { /* defensive : grille pas encore rendue */ }
                        }
                    } finally {
                        grid._anonBroadcastSuppress = false;
                    }
                });
            }
        } catch (e) {
            // BroadcastChannel indisponible (très vieux browser, contexte
            // sécurisé manquant) → dégradation silencieuse : chaque tab
            // garde son état isolé, comportement legacy.
            this._anonBroadcastChannel = null;
        }

        // Mémoire copilot : résumé factuel (avec tokens §…§ intacts pour
        // empêcher un leak cross-user, ~2000 chars max) laissé par un run
        // PRÉCÉDENT du copilot sur ce classeur. Vit à la racine du
        // .afz.json (clef `copilot_memory`), owned par le GridTabManager.
        //
        // **IMPORTANT** : on ne stocke PAS la mémoire localement sur la
        // grille (ce serait une valeur figée à la création — les onglets
        // frères ne verraient jamais les mises à jour). On utilise un
        // GETTER dynamique fourni par le TabManager pour lire la valeur
        // LIVE au moment du fetch, afin qu'une MAJ cross-tab dans un
        // même classeur bénéficie à tous les runs suivants quel que soit
        // l'onglet actif.
        this._getCopilotMemory = (typeof this._options.getCopilotMemory === 'function')
            ? this._options.getCopilotMemory
            : function() { return ''; };

        // State
        this.sortColIndex = -1;
        this.sortDirection = null; // 'asc' | 'desc'
        this.filters = {}; // { colIndex: { excluded: Set<string>, excludeNull: bool } }
        this.hiddenCols = new Set(); // Set<colIndex>
        this.columnOrder = this.columns.map(function(_, i) { return i; }); // display order
        this.displayRows = this.allRows.slice();
        this.isFullscreen = false;
        this._activePopup = null;

        // Drill-down navigation stack
        this._navStack = []; // { columns, allRows, sql, totalRowCount, columnMetadata, breadcrumb }
        this._breadcrumbs = []; // ['Résultat', 'Détail — exercice=2023']

        // Per-cell details for AI-generated values (detail SQL, columns, rows)
        this._cellDetails = {};  // { "row,col": { sql, columns, rows, row_count, description } }

        // Auto-fill ghost suggestions (Copilot-like)
        this._ghostValues = {};   // { "row,col": { value, detail } }
        this._autoFillTimer = null;
        this._autoFillPending = false;

        // Merged cells ([{r1,c1,r2,c2}, ...]) — 0-based inclusive rectangles
        this._merges = [];
        if (options && Array.isArray(options.merges)) {
            for (var mi = 0; mi < options.merges.length; mi++) {
                var m = options.merges[mi];
                if (_isValidMergeRect(m, this.allRows.length, this.columns.length)) {
                    this._merges.push({ r1: m.r1, c1: m.c1, r2: m.r2, c2: m.c2 });
                }
            }
        }
        this._mergeMap = null; // computed on demand, invalidated via _invalidateMergeMap

        // Detect column types from first 50 rows
        this.columnTypes = [];
        this._detectTypes();

        // DOM refs
        this.headerEl = null;
        this.theadEl = null;
        this.tbodyEl = null;
        this.wrapperEl = null;
        this._navBarEl = null;

        this._build();

        // Auto-analyze columns for drill-down if we have SQL with GROUP BY.
        // PAS pour une feuille importée (snapshot) : son SQL est une provenance,
        // pas une requête vivante — l'analyse déclencherait un appel réseau
        // inutile + ouvrirait le drill LIVE sur la BDD courante alors que les
        // lignes affichées sont un instantané (données ≠ silencieusement).
        if (this.sql && !this.columnMetadata && /GROUP\s+BY/i.test(this.sql)
            && !this._isImportedSnapshot()) {
            this._fetchColumnMetadata();
        }
    }

    // Clipboard partagé entre toutes les instances de grille (cross-tab copy/paste)
    // Format: { cells: [[{value, details, drilldownCtx},...], ...], rows: N, cols: N, tsv: '...' }
    SqlResultGrid._clipboard = null;

    // ── Merged cells helpers (static) ──

    function _isValidMergeRect(m, maxRows, maxCols) {
        if (!m || typeof m !== 'object') return false;
        if (typeof m.r1 !== 'number' || typeof m.c1 !== 'number') return false;
        if (typeof m.r2 !== 'number' || typeof m.c2 !== 'number') return false;
        if (m.r1 < 0 || m.c1 < 0 || m.r2 < m.r1 || m.c2 < m.c1) return false;
        if (maxRows != null && m.r2 >= maxRows) return false;
        if (maxCols != null && m.c2 >= maxCols) return false;
        // A merge must cover more than one cell
        if (m.r1 === m.r2 && m.c1 === m.c2) return false;
        return true;
    }

    function _mergesOverlap(a, b) {
        if (a.r2 < b.r1 || b.r2 < a.r1) return false;
        if (a.c2 < b.c1 || b.c2 < a.c1) return false;
        return true;
    }

    // Expose for tests / external use
    SqlResultGrid._isValidMergeRect = _isValidMergeRect;
    SqlResultGrid._mergesOverlap = _mergesOverlap;

    // ── Merged cells (instance methods) ──

    SqlResultGrid.prototype.getMerges = function() {
        var out = [];
        for (var i = 0; i < this._merges.length; i++) {
            var m = this._merges[i];
            out.push({ r1: m.r1, c1: m.c1, r2: m.r2, c2: m.c2 });
        }
        return out;
    };

    SqlResultGrid.prototype.setMerges = function(merges) {
        var clean = [];
        var rowCount = this.allRows.length;
        var colCount = this.columns.length;
        if (Array.isArray(merges)) {
            for (var i = 0; i < merges.length; i++) {
                var m = merges[i];
                if (!_isValidMergeRect(m, rowCount, colCount)) continue;
                var overlaps = false;
                for (var j = 0; j < clean.length; j++) {
                    if (_mergesOverlap(m, clean[j])) { overlaps = true; break; }
                }
                if (overlaps) continue;
                clean.push({ r1: m.r1, c1: m.c1, r2: m.r2, c2: m.c2 });
            }
        }
        this._merges = clean;
        this._invalidateMergeMap();
    };

    SqlResultGrid.prototype._invalidateMergeMap = function() {
        this._mergeMap = null;
    };

    SqlResultGrid.prototype._computeMergeMap = function() {
        if (this._mergeMap) return this._mergeMap;
        var map = {};
        for (var i = 0; i < this._merges.length; i++) {
            var m = this._merges[i];
            var rowspan = m.r2 - m.r1 + 1;
            var colspan = m.c2 - m.c1 + 1;
            for (var r = m.r1; r <= m.r2; r++) {
                for (var c = m.c1; c <= m.c2; c++) {
                    if (r === m.r1 && c === m.c1) {
                        map[r + ',' + c] = {
                            role: 'anchor',
                            rowspan: rowspan,
                            colspan: colspan
                        };
                    } else {
                        map[r + ',' + c] = {
                            role: 'hidden',
                            anchorR: m.r1,
                            anchorC: m.c1
                        };
                    }
                }
            }
        }
        this._mergeMap = map;
        return map;
    };

    SqlResultGrid.prototype._findMergeContaining = function(r, c) {
        for (var i = 0; i < this._merges.length; i++) {
            var m = this._merges[i];
            if (r >= m.r1 && r <= m.r2 && c >= m.c1 && c <= m.c2) return m;
        }
        return null;
    };

    SqlResultGrid.prototype._findMergeWithAnchor = function(r, c) {
        for (var i = 0; i < this._merges.length; i++) {
            var m = this._merges[i];
            if (m.r1 === r && m.c1 === c) return m;
        }
        return null;
    };

    SqlResultGrid.prototype._canModifyLayout = function() {
        return this._merges.length === 0;
    };

    // ── Capability matrix par type d'onglet ──
    //
    // Centralise les "quel type d'onglet supporte quelle feature" pour
    // qu'il n'y ait plus de chemin alternatif qui contourne un blocage
    // (ex: le menu contextuel cellule qui appliquait un filtre sur une
    // feuille mergée alors que le header le refusait → classeur coincé).
    //
    // Types identifiés :
    //  - ``sql``       : résultat d'une requête SQL (``this.sql`` non vide,
    //                    pas blank ni dashboard)
    //  - ``dashboard`` : template avec cellDetails structurés (recompute,
    //                    derived_formula) — cellules sémantiquement figées
    //  - ``blank``     : feuille vide nouvellement créée
    //  - ``imported``  : importée (xlsx, afz externe, etc.)
    //
    // Règles de base :
    //  - ``sort``, ``filter``, ``columns_dialog`` : nécessitent des rows
    //    data-like (SQL/imported). Dashboard = cellules figées → non
    //    sensé. Blank = pas de data → non sensé. Merges = casse le layout.
    //  - ``drill_down`` : uniquement si des cellDetails réels existent.
    //  - ``edit``, ``anon_menu``, ``copy``, ``export`` : OK partout.
    // Feuille importée d'une source externe (« Ajouter feuilles externes… ») :
    // les rows sont un SNAPSHOT du classeur/fichier source ; le sql transporté
    // (préservé depuis 2026-06-11) n'est qu'une PROVENANCE, pas une requête
    // vivante de cette feuille. NB : type 'sql_query' (onglet Requête SQL
    // dashboard) = feuille vivante, PAS un snapshot.
    SqlResultGrid.prototype._isImportedSnapshot = function() {
        var src = this._externalSource;
        return !!(src && (src.type === 'workbook'
            || src.type === 'excel' || src.type === 'csv'));
    };

    SqlResultGrid.prototype._sheetType = function() {
        if (this._isBlankSheet) return 'blank';
        if (this._isDashboardSheet) return 'dashboard';
        // Snapshot importé : reste 'imported' même s'il transporte un SQL de
        // provenance — sinon il serait classé feuille SQL vivante (drill live,
        // réexécution) alors que ses lignes sont figées.
        if (this._isImportedSnapshot()) return 'imported';
        if (this.sql) return 'sql';
        return 'imported';
    };

    SqlResultGrid.prototype._sheetSupports = function(feature) {
        var type = this._sheetType();
        var hasMerges = this._merges && this._merges.length > 0;
        switch (feature) {
            case 'sort':
            case 'filter_apply':
                // Actions mutantes qui réorganisent les lignes : réservées
                // aux sheets de type "data grille" ET sans merges.
                if (hasMerges) return false;
                return type === 'sql' || type === 'imported';
            case 'filter_clear':
                // Annuler un filtre existant : doit rester possible même
                // avec merges (pour réparer un état cassé).
                return type === 'sql' || type === 'imported';
            case 'columns_dialog':
                // Gestion colonnes (hide/show) : nécessite SQL/imported
                // sans merges (déjà appliqué côté visibility bouton).
                if (hasMerges) return false;
                return type === 'sql' || type === 'imported';
            case 'drill_down':
                // Présence de cellDetails réels vérifiée ailleurs
                // (``_cellHasRealDetail``). Ici on autorise le type
                // uniquement là où les cellDetails ont du sens.
                return type === 'dashboard' || type === 'sql';
            case 'edit':
                // Éditabilité universelle sauf readonly explicite —
                // passé par ``options.readonly`` au build.
                return !this._options.readonly;
            case 'anon_menu':
            case 'select_sum':
            case 'select_column':
            case 'copy_tsv':
            case 'resize_columns':
                return true;
            case 'export_csv':
                // Export trivial si feuille vide. Autorisé quand même —
                // l'user peut vouloir un CSV vide pour template.
                return true;
            default:
                return false;
        }
    };

    // ── Type detection ──

    SqlResultGrid.prototype._detectTypes = function() {
        var sampleSize = Math.min(this.allRows.length, 50);
        for (var c = 0; c < this.columns.length; c++) {
            var sample = [];
            for (var r = 0; r < sampleSize; r++) {
                var row = this.allRows[r];
                sample.push(this.isArrayFormat ? row[c] : row[this.columns[c]]);
            }
            this.columnTypes.push(detectType(sample));
        }
    };

    // ── Build ──

    SqlResultGrid.prototype._build = function() {
        this.container.innerHTML = '';
        this._resizeBarEl = null; // Reset — DOM destroyed by innerHTML=''
        this._buildNavBar();
        this._buildHeader();
        this._buildTable();
        this._buildFooter();
        // Notifier le parent (GridTabManager) pour persister l'état
        if (this._options && typeof this._options.onStateChange === 'function') {
            this._options.onStateChange();
        }
    };

    SqlResultGrid.prototype._buildHeader = function() {
        var self = this;
        var header = document.createElement('div');
        header.className = 'iris-sql-card-header';

        // Left: row count info
        var info = document.createElement('span');
        info.className = 'grid-header-info';
        header.appendChild(info);
        this.headerInfoEl = info;

        // Right: action buttons
        var actions = document.createElement('span');
        actions.className = 'grid-header-actions';

        // Clear filters button (hidden by default)
        var btnClearFilters = document.createElement('button');
        btnClearFilters.type = 'button';
        btnClearFilters.className = 'grid-action-btn grid-btn-clear-filters';
        btnClearFilters.title = 'Effacer tous les filtres';
        btnClearFilters.textContent = '✕ Filtres';
        btnClearFilters.style.display = 'none';
        btnClearFilters.addEventListener('click', function() { self._clearAllFilters(); });
        actions.appendChild(btnClearFilters);
        this.btnClearFilters = btnClearFilters;

        // Remove merges button (hidden unless merges exist)
        var btnClearMerges = document.createElement('button');
        btnClearMerges.type = 'button';
        btnClearMerges.className = 'grid-action-btn grid-btn-clear-merges';
        btnClearMerges.title = 'Retirer toutes les fusions de cellules';
        btnClearMerges.textContent = '✕ Fusions';
        btnClearMerges.style.display = 'none';
        btnClearMerges.addEventListener('click', function() { self._clearAllMerges(); });
        actions.appendChild(btnClearMerges);
        this.btnClearMerges = btnClearMerges;

        // Copy button
        var btnCopy = document.createElement('button');
        btnCopy.type = 'button';
        btnCopy.className = 'grid-action-btn';
        btnCopy.title = 'Copier le tableau (TSV)';
        btnCopy.innerHTML = '<i class="bi bi-clipboard"></i>';
        btnCopy.addEventListener('click', function() { self._copyToClipboard(btnCopy); });
        actions.appendChild(btnCopy);

        // CSV export button — visible UNIQUEMENT en mode standalone (hors
        // classeur). Quand la grille est embarquée dans un GridTabManager
        // (détecté via ``fullscreenTarget`` passé par le manager), l'export
        // est centralisé dans le dropdown unifié Excel+CSV du tab bar :
        // afficher un second bouton ici créerait de la redondance et
        // réintroduirait la couleur brique voyante dans une toolbar qui
        // doit rester discrète.
        var btnCSV = document.createElement('button');
        btnCSV.type = 'button';
        btnCSV.className = 'grid-action-btn';
        btnCSV.title = 'Exporter en CSV';
        btnCSV.textContent = 'CSV';
        btnCSV.addEventListener('click', function() { self._exportCSV(); });
        if (this._options.fullscreenTarget) btnCSV.style.display = 'none';
        actions.appendChild(btnCSV);

        // Bouton "Gestion des colonnes" (masquer/afficher). Visible
        // uniquement pour les feuilles qui sont le résultat d'une requête
        // SQL (présence de ``this.sql``, et pas une feuille blank/dashboard)
        // ET tant qu'aucune fusion n'est présente — sinon l'action n'a pas
        // de sens (on ne peut pas recomposer des colonnes fusionnées à la
        // volée). ``_updateHeaderInfo`` pilote la visibility dynamiquement
        // après chaque mutation (add/remove merge, rebuild).
        var btnCols = document.createElement('button');
        btnCols.type = 'button';
        btnCols.className = 'grid-action-btn';
        btnCols.title = 'Masquer/afficher des colonnes';
        btnCols.textContent = '☰';
        btnCols.style.display = 'none';  // revisible par _updateHeaderInfo si contexte approprié
        btnCols.addEventListener('click', function() { self._openColumnsDialog(); });
        actions.appendChild(btnCols);
        this.btnColumns = btnCols;

        // Fullscreen button (hidden when inside TabManager — moved to tab bar)
        var btnFs = document.createElement('button');
        btnFs.type = 'button';
        btnFs.className = 'grid-action-btn';
        btnFs.title = 'Plein écran (Escape pour quitter)';
        btnFs.textContent = '⛶';
        btnFs.addEventListener('click', function() { self._toggleFullscreen(); });
        if (this._options.fullscreenTarget) btnFs.style.display = 'none';
        actions.appendChild(btnFs);
        this.btnFullscreen = btnFs;

        header.appendChild(actions);
        this.container.appendChild(header);
        this.headerEl = header;

        this._updateHeaderInfo();
    };

    SqlResultGrid.prototype._updateHeaderInfo = function() {
        var displayed = this.displayRows.length;
        var total = this.allRows.length;
        var serverTotal = this.totalRowCount;
        var hasFilters = Object.keys(this.filters).length > 0;
        var html = '';
        if (hasFilters) {
            html = 'Filtrées : <strong>' + displayed + '</strong> / ' + total + ' ligne(s)';
        } else if (serverTotal > total) {
            html = '<strong>' + total + '</strong> ligne(s) sur <strong>' + serverTotal + '</strong> au total';
        } else {
            html = '<strong>' + total + '</strong> ligne(s)';
        }
        if (this._truncated) {
            // Wording générique : ce badge sert aux résultats SQL ET aux
            // aperçus de fichiers uploadés — « la requête » serait mensonger
            // pour un fichier, et la source complète reste intacte dans les
            // deux cas (cohérent avec le badge colonnes ci-dessous).
            html += ' <span class="grid-truncated-badge" title="Plus de ' + total
                + ' lignes au total — seul un aperçu est affiché ici, la source '
                + 'complète reste intacte.">⚠ limité</span>';
        }
        // Troncation COLONNES (aperçu pièce jointe : cap serveur, ex. 50 cols).
        // Sans ce badge, un fichier de 80 colonnes s'affiche avec 50 sans
        // AUCUNE indication — données fausses silencieuses (doctrine Q5).
        if (this._truncatedCols) {
            var colShown = this.columns.length;
            var colTitle = 'Aperçu limité aux ' + colShown + ' premières colonnes'
                + (typeof this._truncatedColsTotal === 'number'
                    ? ' sur ' + this._truncatedColsTotal : '')
                + '. Le fichier complet reste intact.';
            html += ' <span class="grid-truncated-badge" title="' + colTitle
                + '">⚠ colonnes limitées</span>';
        }
        if (this._merges && this._merges.length > 0) {
            html += ' <span class="grid-merges-badge" title="Tri, filtre et réorganisation des colonnes désactivés tant que des cellules sont fusionnées.">'
                + this._merges.length + ' fusion' + (this._merges.length > 1 ? 's' : '')
                + '</span>';
        }
        this.headerInfoEl.innerHTML = html;
        if (this.btnClearMerges) {
            this.btnClearMerges.style.display = (this._merges && this._merges.length > 0)
                ? '' : 'none';
        }
        // Bouton "Gestion des colonnes" (☰) : via helper centralisé.
        if (this.btnColumns) {
            this.btnColumns.style.display = this._sheetSupports('columns_dialog') ? '' : 'none';
        }
        // Sort arrows + filter icons dans les headers : se recalculent
        // quand les merges changent (add/remove). Pas de rebuild du thead
        // nécessaire — juste toggler ``display`` sur les éléments existants.
        if (this.theadEl) {
            var arrows = this.theadEl.querySelectorAll('.grid-sort-arrow');
            var sortOk = this._sheetSupports('sort');
            for (var ai = 0; ai < arrows.length; ai++) {
                arrows[ai].style.display = sortOk ? '' : 'none';
            }
            var filters = this.theadEl.querySelectorAll('.grid-filter-icon');
            var filterOk = this._sheetSupports('filter_clear');
            for (var fi = 0; fi < filters.length; fi++) {
                filters[fi].style.display = filterOk ? '' : 'none';
            }
        }
    };

    SqlResultGrid.prototype._clearAllMerges = function() {
        if (!this._merges || this._merges.length === 0) return;
        var ok = true;
        if (typeof window !== 'undefined' && typeof window.confirm === 'function') {
            ok = window.confirm(
                'Retirer les ' + this._merges.length + ' fusion(s) de cette feuille ?'
            );
        }
        if (!ok) return;
        this._merges = [];
        this._invalidateMergeMap();
        this._rebuildBody();
        this._updateHeaderInfo();
        if (this._options && typeof this._options.onStateChange === 'function') {
            this._options.onStateChange();
        }
    };

    // Bounding rectangle of the current multi-cell selection. Returns null
    // if nothing is selected.
    SqlResultGrid.prototype._getSelectionRect = function() {
        if (!this._selectedCells || this._selectedCells.length === 0) return null;
        var rMin = Infinity, rMax = -Infinity, cMin = Infinity, cMax = -Infinity;
        for (var i = 0; i < this._selectedCells.length; i++) {
            var td = this._selectedCells[i];
            var r = parseInt(td.getAttribute('data-row'), 10);
            var c = parseInt(td.getAttribute('data-col'), 10);
            if (isNaN(r) || isNaN(c)) continue;
            if (r < rMin) rMin = r;
            if (r > rMax) rMax = r;
            if (c < cMin) cMin = c;
            if (c > cMax) cMax = c;
        }
        if (!isFinite(rMin)) return null;
        return { rMin: rMin, cMin: cMin, rMax: rMax, cMax: cMax };
    };

    // Create a new merge from a rectangle. Returns true on success.
    SqlResultGrid.prototype.mergeCells = function(rMin, cMin, rMax, cMax) {
        if (rMin === rMax && cMin === cMax) return false;
        var newMerge = { r1: rMin, c1: cMin, r2: rMax, c2: cMax };
        if (!_isValidMergeRect(newMerge, this.allRows.length, this.columns.length)) return false;
        for (var i = 0; i < this._merges.length; i++) {
            if (_mergesOverlap(newMerge, this._merges[i])) {
                if (typeof window !== 'undefined' && typeof window.alert === 'function') {
                    window.alert('Fusion impossible : chevauche une fusion existante.');
                }
                return false;
            }
        }

        var nonNullCount = 0;
        for (var r = rMin; r <= rMax; r++) {
            for (var c = cMin; c <= cMax; c++) {
                var v = this.isArrayFormat
                    ? this.allRows[r][c]
                    : this.allRows[r][this.columns[c]];
                if (v != null && String(v) !== '') nonNullCount++;
                if (nonNullCount > 1) break;
            }
            if (nonNullCount > 1) break;
        }
        if (nonNullCount > 1) {
            var ok = true;
            if (typeof window !== 'undefined' && typeof window.confirm === 'function') {
                ok = window.confirm(
                    'Plusieurs cellules contiennent des données. Seule la première (en haut à gauche) sera conservée. Continuer ?'
                );
            }
            if (!ok) return false;
        }

        // Snapshot AVANT toute mutation (cellules nullifiées + merge ajouté).
        // Placé ici (pas en début de fonction) pour ne pas push quand on
        // refuse via guard (overlap, validité, confirm "Annuler").
        this._pushHistory();

        for (var r2 = rMin; r2 <= rMax; r2++) {
            for (var c2 = cMin; c2 <= cMax; c2++) {
                if (r2 === rMin && c2 === cMin) continue;
                if (this.isArrayFormat) {
                    this.allRows[r2][c2] = null;
                } else {
                    this.allRows[r2][this.columns[c2]] = null;
                }
                var key = r2 + ',' + c2;
                delete this._ghostValues[key];
            }
        }

        this._merges.push(newMerge);
        this._invalidateMergeMap();
        this.displayRows = this.allRows.slice();
        this._rebuildBody();
        this._updateHeaderInfo();
        if (this._options && typeof this._options.onStateChange === 'function') {
            this._options.onStateChange();
        }
        return true;
    };

    // Remove the merge that contains (r, c). Returns true on success.
    SqlResultGrid.prototype.unmergeCells = function(r, c) {
        var idx = -1;
        for (var i = 0; i < this._merges.length; i++) {
            var m = this._merges[i];
            if (r >= m.r1 && r <= m.r2 && c >= m.c1 && c <= m.c2) { idx = i; break; }
        }
        if (idx < 0) return false;
        this._pushHistory();
        this._merges.splice(idx, 1);
        this._invalidateMergeMap();
        this._rebuildBody();
        this._updateHeaderInfo();
        if (this._options && typeof this._options.onStateChange === 'function') {
            this._options.onStateChange();
        }
        return true;
    };

    SqlResultGrid.prototype._buildTable = function() {
        var wrapper = document.createElement('div');
        wrapper.className = 'iris-sql-table-wrap';

        if (this.allRows.length === 0) {
            wrapper.innerHTML = '<div class="iris-no-results">Aucun résultat retourné.</div>';
            this.container.appendChild(wrapper);
            this.wrapperEl = wrapper;
            return;
        }

        var table = document.createElement('table');
        table.className = 'iris-sql-table grid-interactive';

        // Thead
        this._buildThead(table);

        // Tbody
        var tbody = document.createElement('tbody');
        this.tbodyEl = tbody;
        // Reset listener guards — new tbody needs fresh event handlers
        this._detailClickAttached = false;
        this._selectionMousedownAttached = false;
        // Reset VS guards : nouveau wrapperEl/tbodyEl = handlers à ré-attacher
        // (sinon, sur un switch d'onglet, le scroll listener pointe vers
        // l'ancien wrapper détaché → scroll dans le nouvel onglet ignoré).
        this._tbodyHandlersAttached = false;
        this._editableHandlersAttached = false;
        this._vsScrollAttached = false;
        this._measuredRowHeight = null;
        table.appendChild(tbody);

        wrapper.appendChild(table);
        this.container.appendChild(wrapper);
        this.wrapperEl = wrapper;

        // Scroll activé uniquement au clic (évite de capturer le scroll du chat).
        // Affordance : sans indication, l'utilisateur croit que les lignes
        // sous le pli n'existent pas (bug vécu 2026-06-11 : « il manque des
        // lignes de mon fichier » sur un aperçu 714 lignes coupé à ~18).
        // Tooltip natif au survol prolongé (doctrine axe 4) + aria-label
        // (title n'est ni focusable ni tactile) + fade bas via .has-overflow.
        // Wording NEUTRE : pas de promesse « toutes les lignes sont chargées »
        // (faux pour les aperçus tronqués au cap serveur — la complétude est
        // l'affaire du header info + badges ⚠, single source of truth).
        var SCROLL_HINT = 'Cliquer dans le tableau pour activer le défilement';
        wrapper.title = SCROLL_HINT;
        wrapper.setAttribute('aria-label', SCROLL_HINT);
        wrapper.addEventListener('click', function() {
            if (!wrapper.classList.contains('scroll-active')) {
                wrapper.classList.add('scroll-active');
                wrapper.title = '';
            }
        });
        // Désactiver quand on clique en dehors. Handler STOCKÉ sur l'instance
        // (T12c) : avant, ce listener ``document`` anonyme était ré-ajouté à
        // CHAQUE ``_buildTable`` (switch d'onglet, rebuild) sans retirer le
        // précédent → accumulation intra-grille. On retire l'ancien avant de
        // ré-attacher, et ``destroy()`` le retire en fin de vie.
        if (this._scrollDeactivateHandler) {
            document.removeEventListener('click', this._scrollDeactivateHandler);
        }
        this._scrollDeactivateHandler = function(e) {
            if (!wrapper.contains(e.target) && wrapper.classList.contains('scroll-active')) {
                wrapper.classList.remove('scroll-active');
                wrapper.title = SCROLL_HINT;
            }
        };
        document.addEventListener('click', this._scrollDeactivateHandler);

        this._rebuildBody();
        this._initContextMenu();
    };

    /**
     * T12c — teardown d'une grille : retire les listeners ``document``
     * PERSISTANTS de cette instance pour éviter leur accumulation cross-instance
     * (fuite mémoire sous re-render répété, ex. auto-refresh dashboard).
     * Le handler ``mouseup`` ferme sur ``self`` (toute la grille + allRows) :
     * le retirer libère la plus grosse référence. Idempotent (re-appelable).
     */
    SqlResultGrid.prototype.destroy = function() {
        if (this._onMouseUp) {
            document.removeEventListener('mouseup', this._onMouseUp);
            this._onMouseUp = null;
        }
        if (this._scrollDeactivateHandler) {
            document.removeEventListener('click', this._scrollDeactivateHandler);
            this._scrollDeactivateHandler = null;
        }
    };

    SqlResultGrid.prototype._buildThead = function(table) {
        var self = this;
        var thead = document.createElement('thead');
        var tr = document.createElement('tr');

        // Row number header
        var thNum = document.createElement('th');
        thNum.className = 'grid-row-num-header';
        thNum.textContent = '#';
        tr.appendChild(thNum);

        // Column headers (respect columnOrder)
        for (var k = 0; k < this.columnOrder.length; k++) {
            var ci = this.columnOrder[k];
            if (this.hiddenCols.has(ci)) continue;
            (function(colIndex) {
                var th = document.createElement('th');
                th.className = 'grid-sortable-th';
                if (self.columnTypes[colIndex] === 'number') {
                    th.classList.add('grid-col-number');
                }
                th.setAttribute('data-col', colIndex);

                var label = document.createElement('span');
                label.className = 'grid-th-label';
                label.textContent = self.columns[colIndex];
                th.appendChild(label);

                // Sort arrow : affiché uniquement si le tri est supporté
                // (onglet data-like + pas de merges). Sur dashboard/blank
                // ou feuille mergée, le tri n'a pas de sens — pas d'arrow
                // = pas de confusion possible, pas de hover "cliquable".
                var arrow = document.createElement('span');
                arrow.className = 'grid-sort-arrow';
                if (!self._sheetSupports('sort')) arrow.style.display = 'none';
                th.appendChild(arrow);

                // Filter icon ▾ : idem. Affiché si l'onglet supporte le
                // filtrage (= actions mutantes OU clear filter disponible).
                // On l'affiche dès que "filter_clear" est supporté même
                // si "filter_apply" non, car le popup sait désactiver
                // sélectivement ses actions et l'user doit pouvoir
                // annuler un filtre existant.
                var filterBtn = document.createElement('span');
                filterBtn.className = 'grid-filter-icon';
                filterBtn.textContent = '▾';
                filterBtn.title = 'Filtrer';
                if (!self._sheetSupports('filter_clear')) {
                    filterBtn.style.display = 'none';
                }
                filterBtn.addEventListener('click', function(e) {
                    e.stopPropagation();
                    self._openFilterPopup(colIndex, th);
                });
                th.appendChild(filterBtn);

                // Resize handle
                var resizeHandle = document.createElement('span');
                resizeHandle.className = 'grid-resize-handle';
                resizeHandle.addEventListener('mousedown', function(e) {
                    e.stopPropagation();
                    e.preventDefault();
                    self._startResize(e, th);
                });
                th.appendChild(resizeHandle);

                // Click simple = tri. Dblclick = sélection colonne pour
                // afficher la somme (cf. dblclick handler ci-dessous).
                // Pattern debounce click : on diffère le tri de ~220ms
                // pour laisser une chance au dblclick d'arriver et
                // d'annuler le click. Évite le double-toggle de tri
                // disgracieux (tri+tri=identique, mais 2 re-render).
                var thClickTimer = null;
                th.addEventListener('click', function() {
                    if (thClickTimer) clearTimeout(thClickTimer);
                    thClickTimer = setTimeout(function() {
                        thClickTimer = null;
                        self._onHeaderClick(colIndex);
                    }, 220);
                });

                // Double-clic sur le header = sélectionne TOUTES les cellules
                // de la colonne. Déclenche le résumé (somme/moyenne) en bas
                // via ``_refreshSelectionSummary``. On filtre les clicks sur
                // les widgets internes (resize handle, filter icon) pour
                // qu'ils gardent leur comportement propre.
                // Option B : dblclick sur le LABEL du header = renommage
                // (handler dans ``_attachEditableHandlers``). On skip ici
                // pour ne pas voler l'event au handler de renommage.
                th.addEventListener('dblclick', function(e) {
                    // Annule le tri en attente (le click prédécesseur).
                    if (thClickTimer) { clearTimeout(thClickTimer); thClickTimer = null; }
                    var tgt = e.target;
                    if (tgt && tgt.classList && (
                        tgt.classList.contains('grid-resize-handle') ||
                        tgt.classList.contains('grid-filter-icon') ||
                        tgt.classList.contains('grid-th-label')
                    )) {
                        return;
                    }
                    // Si le clic est dans un descendant du label (icône, span
                    // imbriqué...), traiter comme un dblclick sur le label.
                    if (tgt && typeof tgt.closest === 'function' && tgt.closest('.grid-th-label')) {
                        return;
                    }
                    e.preventDefault();
                    self._selectEntireColumn(colIndex);
                });

                tr.appendChild(th);
            })(ci);
        }

        thead.appendChild(tr);
        table.appendChild(thead);
        this.theadEl = thead;
    };

    SqlResultGrid.prototype._rebuildBody = function() {
        if (!this.tbodyEl) return;
        // Q8 fix : si une édition cellule est en cours (input ouvert),
        // un rebuild détruirait l'input et perdrait la saisie. Skip rebuild
        // tant que l'user n'a pas commit (Enter, Tab, blur).
        if (this.tbodyEl.querySelector('input.grid-cell-input')) {
            return;
        }
        // Notifier le parent pour persister l'état après mutation
        if (this._options && typeof this._options.onStateChange === 'function') {
            var opts = this._options;
            clearTimeout(this._persistTimer);
            this._persistTimer = setTimeout(function() { opts.onStateChange(); }, 300);
        }
        var self = this;
        var rows = this.displayRows;
        var cols = this.columns;
        var types = this.columnTypes;
        var isArr = this.isArrayFormat;
        var html = '';

        // ── Virtual scrolling vanilla ───────────────────────────────
        // Convention : pas de troncation cachée (intent user 2026-05-14).
        // On rend uniquement la fenêtre visible + un buffer. Les rows hors
        // viewport sont remplacées par des <tr> spacer de hauteur fixe
        // pour préserver la scrollbar et la position du contenu.
        //
        // ``data-row`` reste l'index ABSOLU dans displayRows (pas le rank
        // dans le DOM rendu) → tout le code en aval qui lit data-row
        // (sélection, drill-down dblclick, anonymisation, SUM filtré...)
        // continue de fonctionner sans modification.
        //
        // Fallback "tout rendre" si :
        //   - Présence de merges (rowspan/colspan) : virtualizer un merge
        //     dont l'ancre sort du viewport casserait le rendu. Ces onglets
        //     (dashboards RATIO2) ont peu de rows en pratique.
        //   - Peu de rows (<= 500) : pas de gain VS, render direct plus
        //     simple à debugger.
        var ROW_HEIGHT_PX = self._measuredRowHeight || 32;
        var BUFFER_ROWS = 30;
        var VS_THRESHOLD = 500;

        var hasMerges = this._merges.length > 0;
        var useVirtual = !hasMerges && rows.length > VS_THRESHOLD && this.wrapperEl;

        var firstIdx, lastIdx;
        if (useVirtual) {
            var scrollTop = this.wrapperEl.scrollTop || 0;
            var viewportHeight = this.wrapperEl.clientHeight || 600;
            firstIdx = Math.max(0, Math.floor(scrollTop / ROW_HEIGHT_PX) - BUFFER_ROWS);
            lastIdx = Math.min(
                rows.length,
                Math.ceil((scrollTop + viewportHeight) / ROW_HEIGHT_PX) + BUFFER_ROWS
            );
        } else {
            firstIdx = 0;
            lastIdx = rows.length;
        }

        var mergeMap = hasMerges ? this._computeMergeMap() : null;
        // Nombre de colonnes visibles (pour le colspan des spacers).
        var visibleColCount = 1; // grid-row-num
        for (var ci = 0; ci < this.columnOrder.length; ci++) {
            if (!this.hiddenCols.has(this.columnOrder[ci])) visibleColCount++;
        }

        // Spacer top — simule l'espace virtuel avant la fenêtre visible.
        if (useVirtual && firstIdx > 0) {
            html += '<tr class="grid-vs-spacer" aria-hidden="true" '
                + 'style="height:' + (firstIdx * ROW_HEIGHT_PX) + 'px">'
                + '<td colspan="' + visibleColCount + '"></td></tr>';
        }

        // Render la fenêtre visible. ``i`` est l'index ABSOLU dans
        // displayRows — il sert pour data-row, le numéro de ligne, et
        // l'alternance row-even/row-odd (préserve l'apparence).
        for (var i = firstIdx; i < lastIdx; i++) {
            var row = rows[i];
            var rowClass = i % 2 === 0 ? 'row-even' : 'row-odd';
            html += '<tr class="' + rowClass + '">';

            // Row number (1-based, affiche l'index absolu).
            html += '<td class="grid-row-num">' + (i + 1) + '</td>';

            for (var oi = 0; oi < this.columnOrder.length; oi++) {
                var j = this.columnOrder[oi];
                if (this.hiddenCols.has(j)) continue;

                var spanAttrs = '';
                var mergeClass = '';
                if (hasMerges) {
                    var info = mergeMap[i + ',' + j];
                    if (info) {
                        if (info.role === 'hidden') {
                            continue; // skip covered cell — anchor takes the space
                        }
                        if (info.role === 'anchor') {
                            if (info.rowspan > 1) spanAttrs += ' rowspan="' + info.rowspan + '"';
                            if (info.colspan > 1) spanAttrs += ' colspan="' + info.colspan + '"';
                            mergeClass = ' grid-cell-merged';
                        }
                    }
                }

                var raw = isArr ? row[j] : row[cols[j]];
                var drillable = this._isDrillable(j);

                if (raw == null) {
                    var nullClasses = 'cell-null' + mergeClass;
                    if (drillable) nullClasses += ' grid-cell-drillable';
                    html += '<td class="' + nullClasses + '" data-row="' + i + '" data-col="' + j + '"'
                        + spanAttrs + '>null</td>';
                } else {
                    var formatted;
                    var classes = [];
                    if (types[j] === 'number') {
                        formatted = formatNumber(raw);
                        classes.push('grid-cell-number');
                    } else if (types[j] === 'date') {
                        formatted = formatDate(raw);
                    } else {
                        formatted = _escHtml(raw);
                    }
                    if (drillable) classes.push('grid-cell-drillable');
                    if (mergeClass) classes.push('grid-cell-merged');
                    var escaped = types[j] === 'number' || types[j] === 'date' ? _escHtml(formatted) : formatted;
                    var titleVal = _escAttr(raw);
                    var classStr = classes.length > 0 ? ' class="' + classes.join(' ') + '"' : '';
                    html += '<td' + classStr + ' title="' + titleVal + '" data-row="' + i + '" data-col="' + j + '"'
                        + spanAttrs + '>' + escaped + '</td>';
                }
            }
            html += '</tr>';
        }

        // Spacer bottom — simule l'espace virtuel après la fenêtre.
        if (useVirtual && lastIdx < rows.length) {
            html += '<tr class="grid-vs-spacer" aria-hidden="true" '
                + 'style="height:' + ((rows.length - lastIdx) * ROW_HEIGHT_PX) + 'px">'
                + '<td colspan="' + visibleColCount + '"></td></tr>';
        }

        // GRID-3 — corps vide muet : quand un filtre réduit la vue à 0 ligne
        // alors qu'il existe des données sous-jacentes, le <tbody> serait
        // totalement vide. L'utilisateur ne voit qu'un compteur d'en-tête
        // « Filtrées : 0 / N » facile à manquer et croit à un bug. On injecte
        // une ligne placeholder explicite + un lien de réinitialisation. On NE
        // touche PAS au cas « 0 résultat réel » (allRows vide) : il est déjà géré
        // par le message wrapper « Aucun résultat retourné. » à la construction.
        var _emptyFiltered = rows.length === 0 && this.allRows.length > 0;
        if (_emptyFiltered) {
            var _hasActiveFilters = this.filters && Object.keys(this.filters).length > 0;
            html += '<tr class="grid-empty-row"><td class="grid-empty-cell" colspan="'
                + visibleColCount + '" '
                + 'style="text-align:center;padding:1.25rem 0.75rem;'
                + 'color:var(--text-secondary, #6b7280);font-style:italic;">'
                + (_hasActiveFilters
                    ? 'Aucune ligne ne correspond au filtre actif — '
                      + '<a href="#" class="grid-empty-reset" '
                      + 'style="font-style:normal;color:var(--accent-primary, #2563eb);">'
                      + 'réinitialiser les filtres</a>'
                    : 'Aucune ligne à afficher.')
                + '</td></tr>';
        }

        this.tbodyEl.innerHTML = html;

        // GRID-3 — câbler le lien « réinitialiser les filtres » (CSP : jamais
        // d'onclick inline, addEventListener uniquement).
        if (_emptyFiltered) {
            var _resetLink = this.tbodyEl.querySelector('.grid-empty-reset');
            if (_resetLink) {
                _resetLink.addEventListener('click', function(ev) {
                    ev.preventDefault();
                    self._clearAllFilters();
                });
            }
        }

        // Affordance défilement : tant que le scroll n'est pas activé (clic),
        // un fade en bas (.has-overflow, CSS) signale qu'il reste des lignes
        // sous le pli. Sans ça, l'utilisateur croit le tableau complet.
        // Gaté hors rebuilds de pur scroll (rAF, >500 lignes) : lire
        // scrollHeight juste après innerHTML force un layout synchrone par
        // frame, et l'état d'overflow ne change pas pendant un scroll (les
        // spacers virtuels maintiennent la hauteur totale).
        if (this.wrapperEl && !this._isScrollRebuild) {
            var _hasOverflow = this.wrapperEl.scrollHeight > this.wrapperEl.clientHeight + 1;
            this.wrapperEl.classList.toggle('has-overflow', _hasOverflow);
        }

        // Mesurer la hauteur RÉELLE des rows au 1er render pour calibrer.
        // On prend la MÉDIANE de 5 premières rows (au lieu de juste la 1ère)
        // pour résister aux cas où la 1ère row a un wrap dynamique (texte
        // long avec white-space:normal) → hauteur différente des autres.
        // Sans médiane : firstIdx/lastIdx décalent et le viewport saute.
        if (useVirtual && !self._measuredRowHeight && lastIdx > firstIdx) {
            var sampleRows = this.tbodyEl.querySelectorAll('tr:not(.grid-vs-spacer)');
            var heights = [];
            for (var sri = 0; sri < Math.min(sampleRows.length, 5); sri++) {
                var h = sampleRows[sri].offsetHeight;
                if (h > 0) heights.push(h);
            }
            if (heights.length > 0) {
                heights.sort(function(a, b) { return a - b; });
                self._measuredRowHeight = heights[Math.floor(heights.length / 2)];
            }
        }

        // Attacher le scroll listener + ResizeObserver UNE SEULE FOIS.
        // requestAnimationFrame debounce : 1 re-render par frame max (60 fps),
        // même si l'utilisateur scrolle à vitesse maximale.
        // ResizeObserver : si l'user redimensionne la fenêtre browser,
        // viewportHeight change → faut recalculer firstIdx/lastIdx
        // sinon bande blanche en bas du tableau (Q6 adversarial).
        if (useVirtual && !this._vsScrollAttached && this.wrapperEl) {
            var rafId = null;
            var triggerRebuild = function() {
                if (rafId !== null) return;
                rafId = requestAnimationFrame(function() {
                    rafId = null;
                    // Rebuild PUREMENT visuel (scroll/resize) : ni la sélection ni
                    // les données ne changent → ``_rebuildBody`` saute le recalcul
                    // O(N) du résumé de sélection (le re-surlignage O(rendus) reste
                    // fait). Sinon, une colonne entière sélectionnée (N keys, jusqu'au
                    // cap admin) re-sommerait N lignes à CHAQUE frame de scroll = jank.
                    self._isScrollRebuild = true;
                    try {
                        self._rebuildBody();
                    } finally {
                        self._isScrollRebuild = false;
                    }
                });
            };
            this.wrapperEl.addEventListener('scroll', triggerRebuild);
            if (typeof ResizeObserver !== 'undefined') {
                this._vsResizeObserver = new ResizeObserver(triggerRebuild);
                this._vsResizeObserver.observe(this.wrapperEl);
            }
            this._vsScrollAttached = true;
        }

        // Re-apply grid-cell-has-detail UNIQUEMENT pour les cellules dont le
        // detail est réellement drillable (contrat _cellHasRealDetail).
        // Sans ce filtre, toute cellDetail dégradé (derived sans sql, match
        // sans source, label seul, sql="", rows=[] sans sql…) afficherait un
        // point violet mensonger puis le clic ne produirait rien.
        if (Object.keys(this._cellDetails).length > 0) {
            for (var detailKey in this._cellDetails) {
                if (!this._cellHasRealDetail(this._cellDetails[detailKey])) continue;
                var parts = detailKey.split(',');
                var detailTd = this.tbodyEl.querySelector(
                    'td[data-row="' + parts[0] + '"][data-col="' + parts[1] + '"]'
                );
                if (detailTd) detailTd.classList.add('grid-cell-has-detail');
            }
        }

        // Re-apply ghost values (auto-fill suggestions)
        this._renderGhosts();

        // Indicateurs d'anonymisation discrets : chaque cellule qui contient
        // au moins un terme anonymisé (enabled=True) ou pending (confirmed=False)
        // reçoit une classe CSS. Visual : underscore dotted pour actif,
        // fond rouge léger pour pending. Classes appliquées post-render
        // pour préserver le path chaud du renderBody.
        //
        // Le rebuild vient de réécrire innerHTML : toutes les classes posées
        // par un apply précédent ont disparu, mais le fingerprint (state +
        // rowCount) peut être identique — typiquement en virtual scrolling
        // où la fenêtre garde la même taille à chaque scroll. Sans
        // invalidation, le skip-cache laisserait les nouvelles cellules SANS
        // marquage (faux visuel silencieux — fix 2026-06-11, tâche #24).
        this._anonMarkerFingerprint = null;
        try { this._applyAnonymizationCellMarkers(); } catch (e) { /* defensive */ }

        // Bouton legacy "Afficher 200 de plus" supprimé — remplacé par
        // virtual scrolling (cf. début de _rebuildBody). Le user voit
        // TOUTES les rows via scroll natif, plus de cap silencieux.
        // ``_showMoreEl`` peut subsister sur un onglet rendu pré-VS lors
        // d'un upgrade in-flight ; on le nettoie au cas où.
        if (this._showMoreEl) { this._showMoreEl.remove(); this._showMoreEl = null; }

        // Handlers attachés au TBODY via event delegation — donc UNE SEULE
        // FOIS suffit (le tbody reste, seul son innerHTML change au scroll).
        // Re-attacher à chaque rebuild créerait des fuites listeners
        // catastrophiques en virtual scrolling (N dblclick après N scrolls
        // = N drill-downs ouverts d'un coup).
        if (!this._tbodyHandlersAttached) {
            this._attachDetailDblClickHandlers();
            try { this._attachAnonContextMenu(); } catch (e) { /* defensive */ }
            this._attachSelectionHandlers();
            this._tbodyHandlersAttached = true;
        } else {
            // Ré-applique la sélection LOGIQUE (Set "r,c") aux td DOM actuels.
            // Les td hors viewport ne reçoivent pas la classe mais leur key
            // reste tracée → réapparaissent sélectionnées au prochain scroll
            // vers leur position. Fix régression Q2 adversarial review.
            this._reapplySelectionToDom();
            // Le résumé (Σ/moyenne) est invariant au scroll : on ne le recalcule
            // PAS sur un rebuild purement visuel (``_isScrollRebuild``) — il est
            // déjà à jour dans le DOM. On le recalcule sur les rebuilds de DONNÉES
            // (édition/tri/filtre/fusion : flag non posé) et à chaque mutation de
            // sélection (les setters l'appellent directement). Évite O(N)/frame.
            if (!this._isScrollRebuild && typeof this._refreshSelectionSummary === 'function') {
                this._refreshSelectionSummary();
            }
        }

        // Éditabilité des cellules. Par défaut : activée pour tous les
        // types d'onglets SAUF ceux marqués explicitement ``readonly`` via
        // ``options`` (par exemple les résultats de drill-down en preview
        // seule). L'ancienne règle restreignait aux blank/dashboard sheets,
        // ce qui laissait les onglets importés (xlsx, afz externes, etc.)
        // non éditables — bloquant pour l'utilisateur qui souhaite corriger
        // des valeurs après import.
        //
        // Sur dashboard sheets : le dblclick sur cellule avec cellDetails
        // reste réservé au drill-down (géré dans _attachEditableHandlers).
        if (!this._options.readonly && !this._editableHandlersAttached) {
            this._attachEditableHandlers();
            this._editableHandlersAttached = true;
        }
    };

    // ── Cell selection & copy/paste ──

    SqlResultGrid.prototype._attachDetailDblClickHandlers = function() {
        var self = this;
        // Delegate: double-click on drillable/detail cells → open detail
        // Single-click = select cell, Right-click = full context menu
        this.tbodyEl.addEventListener('dblclick', function(e) {
            var td = e.target.closest('td:not(.grid-row-num)');
            if (!td) return;
            var rowIdx = parseInt(td.getAttribute('data-row'), 10);
            var colIdx = parseInt(td.getAttribute('data-col'), 10);

            // AI detail cell — guard against duplicate tab opening.
            // On exige que le detail soit RÉELLEMENT drillable (rows ou sql) ;
            // sinon fallthrough vers la branche ``isDrillable`` (drill-down
            // par colonne) plutôt que d'entrer ici puis sortir en silent
            // return — évite l'UX "rien ne se passe" sur les cellDetails
            // dégradés qui auraient pu arriver (classeurs anciens, edge cases).
            var key = rowIdx + ',' + colIdx;
            var detail = self._cellDetails[key];
            if (self._cellHasRealDetail(detail) && typeof self._options.onNewTab === 'function') {
                // Debounce: prevent opening same detail twice within 1s
                var now = Date.now();
                if (self._lastDetailOpenKey === key && now - (self._lastDetailOpenTime || 0) < 1000) {
                    return;
                }
                self._lastDetailOpenKey = key;
                self._lastDetailOpenTime = now;

                var lbl = (detail.description || 'Détail').substring(0, 30);
                if (detail.row_count) lbl += ' (' + detail.row_count + ')';
                if (detail.rows && detail.rows.length > 0) {
                    self._options.onNewTab(lbl, detail.columns, detail.rows, detail.sql, detail.row_count);
                } else if (detail.sql) {
                    self._fetchCellDetailRows(detail, lbl);
                }
                return;
            }

            // Drillable cell
            if (self._isDrillable(colIdx)) {
                self._drillDown(rowIdx, colIdx);
                return;
            }

            // Blank sheet cell → edit (existing behavior via _startCellEdit)
            // No action needed here — _attachEditableHandlers already handles dblclick
        });
    };

    /**
     * Fetch detail rows on demand (lazy loading from saved classeur).
     */
    SqlResultGrid.prototype._fetchCellDetailRows = function(detail, label) {
        var self = this;
        var xsrf = _getXsrfCookie();
        // Convention Komptia : la SEULE source de vérité du plafond SQL est
        // ``DatabaseConnection.max_rows`` (saisi par l'admin via
        // /admin/database). Le frontend envoie un cap "pratiquement infini"
        // (1 milliard) — ``sage_connector.execute()`` applique
        // ``min(caller, admin)`` et donc admin gagne toujours. Une valeur
        // plus basse côté frontend (historiquement 200 puis 5 000) écrasait
        // silencieusement l'intention de l'admin.
        fetch('/api/cell-detail/execute', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Xsrftoken': xsrf
            },
            body: JSON.stringify({ sql: detail.sql, max_rows: 1000000000 })
        })
        .then(function(r) { return r.json(); })
        .then(function(data) {
            if (data.error) {
                if (typeof self._showSaveToast === 'function') {
                    self._showSaveToast('Erreur chargement détail: ' + data.error, true);
                }
                return;
            }
            // Cache the rows back into cellDetails for subsequent clicks
            detail.rows = data.rows || [];
            detail.columns = data.columns || detail.columns;
            detail.row_count = data.row_count || detail.rows.length;
            // Open in tab (prefer onDetailTab which navigates, fallback to onNewTab)
            var openFn = self._options.onDetailTab || self._options.onNewTab;
            if (typeof openFn === 'function') {
                openFn(label, detail.columns, detail.rows, detail.sql, detail.row_count);
            }
        })
        .catch(function(err) {
            // .catch couvre 2 cas : (a) vraie panne réseau (TypeError) ;
            // (b) réponse HTTP non-2xx avec body HTML (Tornado 400/500) →
            // ``r.json()`` lève un SyntaxError. Distinguer les deux évite de
            // mentir au user avec "Erreur réseau" sur un rejet applicatif.
            console.error('[CellDetail] Fetch failed:', err);
            if (typeof self._showSaveToast === 'function') {
                var isNetwork = (err && err.name === 'TypeError');
                var msg = isNetwork
                    ? 'Erreur réseau : impossible de contacter le serveur.'
                    : 'Impossible de charger le détail (réponse invalide du serveur).';
                self._showSaveToast(msg, true);
            }
        });
    };

    SqlResultGrid.prototype._attachSelectionHandlers = function() {
        var self = this;
        if (!this.tbodyEl) return;

        this._selectedCells = [];
        this._selectionAnchor = null;
        // Reset de TOUTE la sélection à chaque (re)build de données — point
        // unique appelé par _buildTable (nouveau tbody) : load initial, undo/redo
        // (_restoreFromState), remplacement de contenu (applyResultModification /
        // replaceTabContentProgrammatic). Sans vider la sélection LOGIQUE
        // (_selectedKeys), une colonne entière sélectionnée AVANT un reload
        // laissait des keys positionnelles périmées → Σ recalculée sur les
        // NOUVELLES données (review adversariale, CRITIQUE Q5). On vide donc AUSSI
        // les keys + le flag colonne-entière ici.
        if (this._selectedKeys) this._selectedKeys.clear();
        this._entireColumnSelected = null;
        this._refreshSelectionSummary();

        // Guard: attach mousedown only once per tbodyEl
        if (this._selectionMousedownAttached) return;
        this._selectionMousedownAttached = true;

        // Drag state (selection + move)
        this._isDragging = false;
        this._dragStartCell = null;
        this._dragAdditive = false;
        this._dragPrevCells = [];
        this._dragLastCell = null;
        this._dragMode = null;  // 'select' or 'move'

        // Click to select, Shift+Click for range, Cmd/Ctrl+Click for multi-select
        this.tbodyEl.addEventListener('mousedown', function(e) {
            if (e.target.tagName === 'INPUT') return;
            var td = e.target.closest('td:not(.grid-row-num)');

            // Right-click (button=2) : préserver la sélection multi existante si
            // le clic est DANS la sélection (pattern Excel/Sheets). Sinon sélectionner
            // la cellule cliquée. Sans ce early-return, le mousedown reset la sélection
            // à 1 cellule AVANT que le menu contextuel s'ouvre → l'option "Fusionner
            // les cellules sélectionnées" n'apparaît jamais.
            if (e.button === 2) {
                if (!td) return;  // clic droit hors cellule → ne rien faire
                if (!td.classList.contains('grid-cell-selected')) {
                    self._clearSelection();
                    self._selectCell(td);
                    self._selectionAnchor = td;
                }
                return;  // le 'contextmenu' event prend le relais
            }

            if (!td) {
                // Click on row-num or outside cells → clear selection
                self._clearSelection();
                return;
            }
            if (self._isBlankSheet && e.detail >= 2) return;

            if (e.shiftKey && self._selectionAnchor) {
                e.preventDefault();
                self._selectRange(self._selectionAnchor, td);
                return;
            }

            // Detect move modes on already-selected cells.
            // - Ghost cell → move ghost values (existing behaviour).
            // - Real cell AND (multi-selection OR merge anchor) → move values + cellDetails + merges.
            // La règle "multi OR merge-anchor" évite de casser le toggle-désélection quand on
            // re-clique sur UNE seule cellule simple — qui reste un raccourci pour tout déselectionner.
            var isSelected = td.classList.contains('grid-cell-selected');
            var isGhost = td.classList.contains('grid-cell-ghost');
            var isSelectedGhost = isSelected && isGhost;
            var isMergeAnchor = (td.rowSpan && td.rowSpan > 1) || (td.colSpan && td.colSpan > 1);
            var hasMultiSelection = self._selectedCells && self._selectedCells.length >= 2;

            self._dragStartCell = td;
            self._dragLastCell = td;
            self._dragStartX = e.clientX;
            self._dragStartY = e.clientY;
            self._isDragging = false;
            self._dragPending = true;
            self._dragAdditive = e.ctrlKey || e.metaKey;

            if (isSelectedGhost && !self._dragAdditive) {
                // Move mode: will move selected ghosts on drag
                self._dragMode = 'move';
                self._dragPrevCells = [];
                self._selectionAnchor = td;
            } else if (isSelected && !isGhost && !self._dragAdditive
                       && (hasMultiSelection || isMergeAnchor)) {
                // Move-cells mode : déplacer valeurs réelles + cellDetails + merges.
                // Pas de mutation ici — tout arrive dans __finalizeMoveCells au mouseup,
                // si et seulement si un vrai drag a eu lieu (seuil dead-zone plus bas).
                self._dragMode = 'move-cells';
                self._dragPrevCells = [];
                self._selectionAnchor = td;
            } else {
                // Selection mode
                self._dragMode = 'select';
                if (self._dragAdditive) {
                    if (td.classList.contains('grid-cell-selected')) {
                        self._deselectCell(td);
                    } else {
                        self._selectCell(td);
                        self._selectionAnchor = td;
                    }
                    self._dragPrevCells = self._selectedCells.slice();
                } else {
                    // Toggle: re-click on the only selected cell → deselect
                    if (td.classList.contains('grid-cell-selected')
                        && self._selectedCells.length === 1) {
                        self._clearSelection();
                    } else {
                        self._clearSelection();
                        self._selectCell(td);
                        self._selectionAnchor = td;
                    }
                    self._dragPrevCells = [];
                }
            }

            e.preventDefault();
        });

        // Mousemove: drag-select range OR drag-move ghosts
        this.tbodyEl.addEventListener('mousemove', function(e) {
            if (!self._dragPending && !self._isDragging) return;
            if (!self._dragStartCell) return;

            // Dead zone
            if (self._dragPending && !self._isDragging) {
                var dx = Math.abs(e.clientX - self._dragStartX);
                var dy = Math.abs(e.clientY - self._dragStartY);
                if (dx + dy < 4) return;
                self._isDragging = true;
                self._dragPending = false;
                document.body.style.userSelect = 'none';
            }

            var td = e.target.closest('td:not(.grid-row-num)');
            if (!td || td === self._dragLastCell) return;
            self._dragLastCell = td;

            if (self._dragMode === 'move' || self._dragMode === 'move-cells') {
                // Les deux modes partagent la même preview (ajout de
                // .grid-cell-drop-target sur les cellules destinations).
                self.__showMovePreview(td);
            } else {
                self.__applyDragRange(self._dragStartCell, td);
            }
        });

        // Mouseup: finalize
        if (this._onMouseUp) {
            document.removeEventListener('mouseup', this._onMouseUp);
        }
        this._onMouseUp = function() {
            if (!self._isDragging && !self._dragPending) return;

            if (self._isDragging && self._dragMode === 'move' && self._dragLastCell) {
                self.__finalizeMoveGhosts(self._dragLastCell);
            } else if (self._isDragging && self._dragMode === 'move-cells' && self._dragLastCell) {
                self.__finalizeMoveCells(self._dragLastCell);
            } else if (!self._isDragging && self._dragMode === 'move-cells'
                       && self._selectedCells && self._selectedCells.length === 1) {
                // Clic sans drag sur une seule cellule sélectionnée (typiquement une
                // ancre de merge) : on préserve le toggle-désélection "clic = déselectionner"
                // qui existait avant l'ajout du move-cells. Sans ce garde-fou, une ancre de
                // merge sélectionnée seule devenait indéselectionnable par clic simple.
                self._clearSelection();
            }

            self._isDragging = false;
            self._dragPending = false;
            self._dragStartCell = null;
            self._dragPrevCells = [];
            self._dragLastCell = null;
            self._dragMode = null;
            document.body.style.userSelect = '';
            self.__clearMovePreview();
        };
        document.addEventListener('mouseup', this._onMouseUp);

        // Ctrl+C / Cmd+C / Delete
        if (!this._copyPasteAttached) {
            this._copyPasteAttached = true;
            this.container.addEventListener('keydown', function(e) {
                // Pour les inputs, laisser passer les raccourcis Cmd/Ctrl
                var tag = e.target.tagName;
                var isEditing = tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || e.target.isContentEditable;
                if (isEditing && !(e.ctrlKey || e.metaKey)) return;
                // En mode édition, laisser le navigateur gérer Cmd+C/V/Z nativement
                if (isEditing && (e.ctrlKey || e.metaKey)) return;

                // Tab → accept ghost suggestions (all or selected only)
                if (e.key === 'Tab' && Object.keys(self._ghostValues).length > 0) {
                    if (self._selectedCells && self._selectedCells.length > 0) {
                        // Check if any selected cells have ghosts before consuming Tab
                        var hasGhostInSelection = self._selectedCells.some(function(td) {
                            var k = td.getAttribute('data-row') + ',' + td.getAttribute('data-col');
                            return !!self._ghostValues[k];
                        });
                        if (hasGhostInSelection) {
                            e.preventDefault();
                            self._acceptSelectedGhosts();
                            return;
                        }
                        // No ghosts in selection → let Tab do its default behavior
                    } else {
                        e.preventDefault();
                        self._acceptGhosts();
                        return;
                    }
                }
                // Escape → dismiss ghost suggestions
                if (e.key === 'Escape' && Object.keys(self._ghostValues).length > 0) {
                    e.preventDefault();
                    self._dismissGhosts();
                    return;
                }

                if ((e.ctrlKey || e.metaKey) && (e.key === 'c' || e.key === 'C')) {
                    if (self._selectedCells && self._selectedCells.length > 0) {
                        e.preventDefault();
                        self._copySelection();
                    }
                }
                // Cmd+V → paste (works on all sheets via unified clipboard)
                if ((e.ctrlKey || e.metaKey) && (e.key === 'v' || e.key === 'V')) {
                    e.preventDefault();
                    if (SqlResultGrid._clipboard && self._selectedCells.length > 0) {
                        // Paste from internal clipboard at selected cell
                        var anchor = self._selectedCells[0];
                        var pr = parseInt(anchor.getAttribute('data-row'), 10);
                        var pc = parseInt(anchor.getAttribute('data-col'), 10);
                        self._pasteClipboardAt(pr, pc);
                    } else if (self._isBlankSheet) {
                        // Fallback: paste from system clipboard (external paste)
                        self._pasteFromClipboard();
                    }
                }
                // Ctrl+Z → undo, Ctrl+Y / Ctrl+Shift+Z → redo
                if ((e.ctrlKey || e.metaKey) && (e.key === 'z' || e.key === 'Z') && !e.shiftKey) {
                    e.preventDefault();
                    self._copilotUndo();
                }
                if ((e.ctrlKey || e.metaKey) && (e.key === 'y' || e.key === 'Y' || ((e.key === 'z' || e.key === 'Z') && e.shiftKey))) {
                    e.preventDefault();
                    self._copilotRedo();
                }
                // Delete / Backspace → clear selected cells. Gated via
                // ``_sheetSupports('edit')`` — l'édition clavier doit être
                // cohérente avec l'édition via menu contextuel. Avant :
                // restreint arbitrairement à blank/dashboard, alors que
                // les onglets SQL/imported avaient l'entry "Effacer la
                // cellule" dans le menu mais pas via clavier.
                if ((e.key === 'Delete' || e.key === 'Backspace') && self._sheetSupports('edit')) {
                    if (self._selectedCells && self._selectedCells.length > 0) {
                        e.preventDefault();
                        self._clearSelectedCells();
                    }
                }
                // Ctrl+S → save workbook
                if ((e.ctrlKey || e.metaKey) && (e.key === 's' || e.key === 'S')) {
                    e.preventDefault();
                    if (typeof self._options.onSave === 'function') self._options.onSave();
                }
                // Arrow keys → navigate selection
                if (['ArrowUp', 'ArrowDown', 'ArrowLeft', 'ArrowRight'].indexOf(e.key) >= 0) {
                    if (self._selectedCells.length > 0 && !e.ctrlKey && !e.metaKey) {
                        e.preventDefault();
                        self._navigateArrow(e.key, e.shiftKey);
                    }
                }
            });
            // Deselect cells when user focuses an input/textarea anywhere in the container
            this.container.addEventListener('focusin', function(e) {
                var tag = e.target.tagName;
                if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || e.target.isContentEditable) {
                    self._clearSelection();
                }
            });
        }
    };

    // Q2 fix : sélection persistante au scroll en VS.
    // En plus de ``_selectedCells`` (refs DOM, peuvent devenir stale après
    // innerHTML= en virtual scrolling), on maintient ``_selectedKeys`` =
    // Set de "r,c" (indices LOGIQUES dans displayRows). Au rebuild, on
    // ré-applique la classe `.grid-cell-selected` sur les td qui matchent
    // une key dans ``_selectedKeys``. Les cells hors viewport sont juste
    // absentes du DOM mais leur key reste tracée → réapparaissent
    // sélectionnées au scroll vers elles.
    SqlResultGrid.prototype._selectCell = function(td) {
        // Toute sélection cellule-par-cellule (clic/drag/range) est PARTIELLE →
        // annule le mode « colonne entière » (sinon _refreshView re-dériverait
        // toute la colonne au tri/filtre au lieu de respecter la sélection
        // manuelle). _selectEntireColumn n'appelle PAS _selectCell (il peuple les
        // keys en direct), donc ce reset ne concerne que les gestes manuels.
        this._entireColumnSelected = null;
        if (td.classList.contains('grid-cell-selected')) return;  // dedup
        td.classList.add('grid-cell-selected');
        this._selectedCells.push(td);
        if (!this._selectedKeys) this._selectedKeys = new Set();
        var r = td.getAttribute('data-row');
        var c = td.getAttribute('data-col');
        if (r !== null && c !== null) this._selectedKeys.add(r + ',' + c);
        // Make container focusable for keyboard events
        this.container.tabIndex = -1;
        this.container.focus();
        this._refreshSelectionSummary();
    };

    SqlResultGrid.prototype._deselectCell = function(td) {
        // Désélectionner UNE cellule (Ctrl/Cmd+Click) rend la sélection PARTIELLE
        // → sortir du mode « colonne entière » (symétrique de _selectCell), sinon
        // _refreshView re-dériverait toute la colonne au tri/filtre et ré-
        // intégrerait silencieusement la cellule retirée (review adversariale Q5).
        this._entireColumnSelected = null;
        td.classList.remove('grid-cell-selected');
        this._selectedCells = this._selectedCells.filter(function(c) { return c !== td; });
        if (this._selectedKeys) {
            var r = td.getAttribute('data-row');
            var c = td.getAttribute('data-col');
            if (r !== null && c !== null) this._selectedKeys.delete(r + ',' + c);
        }
        this._refreshSelectionSummary();
    };

    SqlResultGrid.prototype._clearSelection = function() {
        for (var i = 0; i < this._selectedCells.length; i++) {
            this._selectedCells[i].classList.remove('grid-cell-selected');
        }
        this._selectedCells = [];
        if (this._selectedKeys) this._selectedKeys.clear();
        this._entireColumnSelected = null;
        this._refreshSelectionSummary();
    };

    // Réapplique la sélection logique aux td actuellement présents dans
    // le DOM. Appelée après chaque ``innerHTML=`` du tbody (rebuild,
    // scroll-induced re-render). Sans ça, en virtual scrolling, la
    // sélection disparaît visuellement dès qu'on scrolle hors viewport
    // alors qu'elle est encore tracée logiquement.
    SqlResultGrid.prototype._reapplySelectionToDom = function() {
        // PERF : on itère les ``<td>`` effectivement RENDUS (≈ fenêtre visible du
        // virtual scrolling, ~30-60) et on teste l'appartenance au Set (O(1)),
        // PLUTÔT que de faire un ``querySelector`` par key. Sans ça, une sélection
        // de colonne entière (``_selectEntireColumn`` peuple 1 key/ligne →
        // potentiellement des centaines de milliers) déclencherait autant de
        // requêtes DOM à CHAQUE rebuild (scroll) = gel. Coût désormais O(rendus),
        // indépendant de la taille de la sélection.
        if (!this._selectedKeys || this._selectedKeys.size === 0 || !this.tbodyEl) {
            this._selectedCells = [];
            return;
        }
        var cells = [];
        var tds = this.tbodyEl.querySelectorAll('td[data-row]');
        for (var i = 0; i < tds.length; i++) {
            var td = tds[i];
            var key = td.getAttribute('data-row') + ',' + td.getAttribute('data-col');
            if (this._selectedKeys.has(key)) {
                td.classList.add('grid-cell-selected');
                cells.push(td);
            }
        }
        this._selectedCells = cells;
    };

    // Parse une cellule en nombre ou retourne null si ce n'est pas numérique.
    // Accepte : entiers, décimaux (virgule ou point), signés, scientifique,
    // avec espaces de millier (style FR " " ou NBSP). Rejette dates, texte.
    SqlResultGrid.prototype._parseCellNumber = function(raw) {
        if (raw === null || raw === undefined) return null;
        if (typeof raw === 'number') return isFinite(raw) ? raw : null;
        if (typeof raw !== 'string') return null;
        var s = raw.trim();
        if (!s) return null;
        // Normalise les séparateurs FR : retire espaces/NBSP (milliers),
        // convertit la virgule décimale en point.
        s = s.replace(/[  \s]/g, '').replace(/,/g, '.');
        // Rejette les formats date-like (ex: "2024-10-15") même si ils
        // contiennent des chiffres — ils ne sont pas sommables.
        if (/^-?\d+-\d+(-\d+)?$/.test(raw.trim())) return null;
        // Pattern strict : optionnel -, digits, optionnel .digits, optionnel exp.
        if (!/^-?\d+(\.\d+)?([eE][+-]?\d+)?$/.test(s)) return null;
        var n = Number(s);
        return isFinite(n) ? n : null;
    };

    // Sélectionne toutes les cellules d'une colonne (dblclick header).
    // Batch : désactive le refresh résumé pendant la boucle, déclenche
    // une seule fois à la fin pour éviter N recalculs (important sur
    // des classeurs > 1000 lignes).
    SqlResultGrid.prototype._selectEntireColumn = function(colIndex) {
        if (!this.tbodyEl) return;
        // Sélection LOGIQUE de TOUTE la colonne sur ``displayRows`` (vue
        // triée/filtrée, intégralement en mémoire) — PAS via le DOM. En virtual
        // scrolling, ``tbodyEl`` ne contient que ~30-60 ``<td>`` visibles :
        // l'ancien ``querySelectorAll('td[data-col=N]')`` ne sélectionnait donc
        // que le visible → la somme ne portait que sur les cellules CHARGÉES et
        // changeait même au scroll (bug rapporté 2026-06-03). On peuple
        // ``_selectedKeys`` (indices LOGIQUES "r,c") pour TOUTES les lignes ;
        // ``_reapplySelectionToDom`` surligne les td visibles (et re-surligne au
        // scroll) ; ``_refreshSelectionSummary`` calcule sur les keys.
        this._suppressSelectionRefresh = true;
        try {
            this._clearSelection();
            if (!this._selectedKeys) this._selectedKeys = new Set();
            var n = this.displayRows ? this.displayRows.length : 0;
            for (var r = 0; r < n; r++) {
                this._selectedKeys.add(r + ',' + colIndex);
            }
            // Surligne les cellules actuellement dans le DOM + reconstruit
            // ``_selectedCells`` (les lignes hors viewport seront surlignées au
            // scroll, leur key restant tracée).
            this._reapplySelectionToDom();
            if (n > 0 && this.container) {
                // Focusable pour la copie clavier (cohérent avec ``_selectCell``).
                this.container.tabIndex = -1;
                this.container.focus();
            }
        } finally {
            this._suppressSelectionRefresh = false;
        }
        // Marque la sélection comme « colonne entière » : permet à _refreshView
        // (tri/filtre) de la RE-DÉRIVER sur la nouvelle vue (toujours toute la
        // colonne → Σ correcte) au lieu de la clearer comme une sélection
        // partielle (cf. _refreshView). Réinitialisé par toute sélection
        // partielle (_selectCell) et par _clearSelection.
        this._entireColumnSelected = colIndex;
        this._refreshSelectionSummary();
    };

    // Calcule un résumé (count, somme, moyenne) sur la sélection si toutes
    // les cellules sont numériques. Affiche dans ``_selectionInfoEl`` si
    // exploitable, cache sinon. Appelé depuis les mutations de sélection.
    SqlResultGrid.prototype._refreshSelectionSummary = function() {
        if (this._suppressSelectionRefresh) return;
        var el = this._selectionInfoEl;
        if (!el) return;
        // Calcul sur la sélection LOGIQUE (``_selectedKeys`` = indices "r,c" dans
        // ``displayRows``), JAMAIS sur les refs DOM (``_selectedCells``) qui, en
        // virtual scrolling, ne couvrent que les lignes VISIBLES → la
        // somme/moyenne ne portait que sur les cellules chargées et changeait au
        // scroll (bug "somme de colonne" 2026-06-03). ``displayRows`` est la vue
        // triée/filtrée intégralement en mémoire → on agrège TOUTE la colonne.
        var keys = this._selectedKeys ? Array.from(this._selectedKeys) : [];
        if (keys.length < 2) {
            // Moins de 2 cellules → somme pas pertinente. Cache.
            el.style.display = 'none';
            el.textContent = '';
            return;
        }
        var sum = 0;
        var count = 0;
        var considered = 0; // cellules réellement DANS la vue courante (in-bounds)
        var allNumeric = true;
        for (var i = 0; i < keys.length; i++) {
            // Valeur source : indices LOGIQUES dans ``displayRows`` (vue
            // triée/filtrée), PAS ``allRows`` (bug confirmé : Σ d'une colonne
            // filtrée lisait les mauvaises lignes brutes). Lecture directe depuis
            // le modèle (pas le texte DOM) → pas de souci de formatage ("1 234,56").
            var parts = keys[i].split(',');
            var r = parseInt(parts[0], 10);
            var c = parseInt(parts[1], 10);
            // Key hors borne (cas : sélection plein-colonne PUIS filtre réduisant
            // ``displayRows``) → la ligne n'existe plus dans la vue → ignorée ET
            // NON comptée (sinon le dénominateur « vides ignorées » imputerait à
            // tort les lignes filtrées à des cellules vides — review adversariale).
            if (isNaN(r) || isNaN(c) || !this.displayRows[r]) {
                continue;
            }
            considered += 1;
            var raw = this.isArrayFormat
                ? this.displayRows[r][c]
                : this.displayRows[r][this.columns[c]];
            if (raw === null || raw === undefined || raw === '') {
                // Cellule in-bounds mais vide → ignorée du calcul, comptée au
                // dénominateur (« vides ignorées »).
                continue;
            }
            var num = this._parseCellNumber(raw);
            if (num === null) {
                allNumeric = false;
                break;
            }
            sum += num;
            count += 1;
        }
        if (!allNumeric || count === 0 || considered < 2) {
            el.style.display = 'none';
            el.textContent = '';
            return;
        }
        var avg = sum / count;
        // Format FR : espace fine insécable comme séparateur de millier,
        // max 4 décimales supprimées si trailing zeros.
        function fmt(n) {
            var abs = Math.abs(n);
            var maxFrac = abs >= 1000 ? 2 : (abs >= 1 ? 4 : 6);
            return n.toLocaleString('fr-FR', {
                maximumFractionDigits: maxFrac,
            });
        }
        // Honnêteté (conséquences Q5) : si le résultat SQL a été TRONQUÉ côté
        // serveur (cap admin ``max_rows``), même toute la colonne chargée reste
        // PARTIELLE vs la requête réelle → on le signale plutôt que d'afficher un
        // total faussement complet. Sinon, on indique les cellules vides ignorées.
        var suffix = '';
        if (this._truncated) {
            suffix = '    ·    ⚠ ' + considered + ' lignes chargées (résultat tronqué)';
        } else if (count < considered) {
            suffix = ' / ' + considered + ' (vides ignorées)';
        }
        el.textContent =
            'Σ ' + fmt(sum) +
            '    ·    Moyenne ' + fmt(avg) +
            '    ·    Nombre ' + count +
            suffix;
        el.style.display = 'block';
    };

    // Expand a selection rectangle so that any merged region is either fully
    // inside or fully outside. Iterates until stable (a merge might extend to
    // cover another merge, etc.).
    SqlResultGrid.prototype._expandRangeForMerges = function(rMin, cMin, rMax, cMax) {
        if (this._merges.length === 0) {
            return { rMin: rMin, cMin: cMin, rMax: rMax, cMax: cMax };
        }
        var changed = true;
        while (changed) {
            changed = false;
            for (var i = 0; i < this._merges.length; i++) {
                var m = this._merges[i];
                var intersects = !(m.r2 < rMin || m.r1 > rMax || m.c2 < cMin || m.c1 > cMax);
                if (!intersects) continue;
                if (m.r1 < rMin) { rMin = m.r1; changed = true; }
                if (m.c1 < cMin) { cMin = m.c1; changed = true; }
                if (m.r2 > rMax) { rMax = m.r2; changed = true; }
                if (m.c2 > cMax) { cMax = m.c2; changed = true; }
            }
        }
        return { rMin: rMin, cMin: cMin, rMax: rMax, cMax: cMax };
    };

    SqlResultGrid.prototype._selectRange = function(anchor, target) {
        this._clearSelection();
        var r1 = parseInt(anchor.getAttribute('data-row'), 10);
        var c1 = parseInt(anchor.getAttribute('data-col'), 10);
        var r2 = parseInt(target.getAttribute('data-row'), 10);
        var c2 = parseInt(target.getAttribute('data-col'), 10);
        var rMin = Math.min(r1, r2), rMax = Math.max(r1, r2);
        var cMin = Math.min(c1, c2), cMax = Math.max(c1, c2);
        var expanded = this._expandRangeForMerges(rMin, cMin, rMax, cMax);
        rMin = expanded.rMin; cMin = expanded.cMin; rMax = expanded.rMax; cMax = expanded.cMax;

        var rows = this.tbodyEl.querySelectorAll('tr');
        for (var r = rMin; r <= rMax && r < rows.length; r++) {
            var cells = rows[r].querySelectorAll('td:not(.grid-row-num)');
            for (var c = 0; c < cells.length; c++) {
                var colIdx = parseInt(cells[c].getAttribute('data-col'), 10);
                if (colIdx >= cMin && colIdx <= cMax) {
                    this._selectCell(cells[c]);
                }
            }
        }
    };

    // Drag range: compute range from start to current, merge with previous selection
    SqlResultGrid.prototype.__applyDragRange = function(startTd, endTd) {
        var r1 = parseInt(startTd.getAttribute('data-row'), 10);
        var c1 = parseInt(startTd.getAttribute('data-col'), 10);
        var r2 = parseInt(endTd.getAttribute('data-row'), 10);
        var c2 = parseInt(endTd.getAttribute('data-col'), 10);
        var rMin = Math.min(r1, r2), rMax = Math.max(r1, r2);
        var cMin = Math.min(c1, c2), cMax = Math.max(c1, c2);
        var expanded = this._expandRangeForMerges(rMin, cMin, rMax, cMax);
        rMin = expanded.rMin; cMin = expanded.cMin; rMax = expanded.rMax; cMax = expanded.cMax;

        // Clear current selection
        this._clearSelection();

        // Restore previous selection if additive (Cmd/Ctrl held)
        if (this._dragAdditive && this._dragPrevCells) {
            for (var i = 0; i < this._dragPrevCells.length; i++) {
                this._selectCell(this._dragPrevCells[i]);
            }
        }

        // Add drag range
        var rows = this.tbodyEl.querySelectorAll('tr');
        for (var r = rMin; r <= rMax && r < rows.length; r++) {
            var cells = rows[r].querySelectorAll('td:not(.grid-row-num)');
            for (var c = 0; c < cells.length; c++) {
                var colIdx = parseInt(cells[c].getAttribute('data-col'), 10);
                if (colIdx >= cMin && colIdx <= cMax) {
                    this._selectCell(cells[c]);
                }
            }
        }

        this._selectionAnchor = startTd;
    };

    // Show preview of where ghosts will land during drag-move
    SqlResultGrid.prototype.__showMovePreview = function(targetTd) {
        this.__clearMovePreview();
        if (!this._selectedCells || this._selectedCells.length === 0) return;
        if (!this._dragStartCell) return;

        // Compute delta from drag start to current target
        var startR = parseInt(this._dragStartCell.getAttribute('data-row'), 10);
        var startC = parseInt(this._dragStartCell.getAttribute('data-col'), 10);
        var targetR = parseInt(targetTd.getAttribute('data-row'), 10);
        var targetC = parseInt(targetTd.getAttribute('data-col'), 10);
        var dR = targetR - startR;
        var dC = targetC - startC;

        // Highlight destination cells
        var rows = this.tbodyEl.querySelectorAll('tr');
        for (var i = 0; i < this._selectedCells.length; i++) {
            var td = this._selectedCells[i];
            var r = parseInt(td.getAttribute('data-row'), 10) + dR;
            var c = parseInt(td.getAttribute('data-col'), 10) + dC;
            if (r >= 0 && r < rows.length) {
                var destTd = rows[r].querySelector('td[data-col="' + c + '"]');
                if (destTd) {
                    destTd.classList.add('grid-cell-drop-target');
                }
            }
        }
    };

    SqlResultGrid.prototype.__clearMovePreview = function() {
        var targets = this.tbodyEl.querySelectorAll('.grid-cell-drop-target');
        for (var i = 0; i < targets.length; i++) {
            targets[i].classList.remove('grid-cell-drop-target');
        }
    };

    // Finalize: move selected ghosts to new positions
    SqlResultGrid.prototype.__finalizeMoveGhosts = function(targetTd) {
        if (!this._selectedCells || this._selectedCells.length === 0) return;
        if (!this._dragStartCell) return;

        var startR = parseInt(this._dragStartCell.getAttribute('data-row'), 10);
        var startC = parseInt(this._dragStartCell.getAttribute('data-col'), 10);
        var targetR = parseInt(targetTd.getAttribute('data-row'), 10);
        var targetC = parseInt(targetTd.getAttribute('data-col'), 10);
        var dR = targetR - startR;
        var dC = targetC - startC;

        if (dR === 0 && dC === 0) return;  // no movement

        // Collect ghosts to move
        var toMove = [];
        for (var i = 0; i < this._selectedCells.length; i++) {
            var td = this._selectedCells[i];
            var r = parseInt(td.getAttribute('data-row'), 10);
            var c = parseInt(td.getAttribute('data-col'), 10);
            var key = r + ',' + c;
            if (this._ghostValues[key]) {
                toMove.push({
                    oldKey: key,
                    newRow: r + dR,
                    newCol: c + dC,
                    ghost: this._ghostValues[key]
                });
            }
        }

        if (toMove.length === 0) return;

        // Build set of old keys being moved (for overlap detection)
        var movingKeys = {};
        for (var j = 0; j < toMove.length; j++) {
            movingKeys[toMove[j].oldKey] = true;
        }

        // Check: no duplicate destinations
        var destKeys = {};
        for (var j2 = 0; j2 < toMove.length; j2++) {
            var dk = toMove[j2].newRow + ',' + toMove[j2].newCol;
            if (destKeys[dk]) return;  // two ghosts would land on same cell
            destKeys[dk] = true;
        }

        // Check all destinations are valid
        for (var j3 = 0; j3 < toMove.length; j3++) {
            var nr = toMove[j3].newRow;
            var nc = toMove[j3].newCol;
            if (nr < 0 || nc < 0 || nc >= this.columns.length) return;

            // Check if destination has a real (non-ghost) value
            if (nr < this.allRows.length) {
                var realVal = this.isArrayFormat
                    ? this.allRows[nr][nc]
                    : this.allRows[nr][this.columns[nc]];
                if (realVal !== '' && realVal !== null && realVal !== undefined) {
                    var destKey = nr + ',' + nc;
                    if (!this._ghostValues[destKey]) return;  // blocked by real value
                }
            }

            // Protect unselected ghosts at destination
            var destKey2 = nr + ',' + nc;
            if (this._ghostValues[destKey2] && !movingKeys[destKey2]) {
                return;  // would destroy an unselected ghost
            }
        }

        // Expand grid if needed
        var maxRow = 0;
        for (var j4 = 0; j4 < toMove.length; j4++) {
            if (toMove[j4].newRow > maxRow) maxRow = toMove[j4].newRow;
        }
        while (maxRow >= this.allRows.length && this.allRows.length < 500) {
            var newRow = [];
            for (var x = 0; x < this.columns.length; x++) newRow.push('');
            this.allRows.push(newRow);
        }
        this.displayRows = this.allRows.slice();
        this.totalRowCount = this.allRows.length;

        // Execute move: remove old keys, add new keys
        for (var k = 0; k < toMove.length; k++) {
            delete this._ghostValues[toMove[k].oldKey];
        }
        for (var m = 0; m < toMove.length; m++) {
            var newKey = toMove[m].newRow + ',' + toMove[m].newCol;
            this._ghostValues[newKey] = toMove[m].ghost;
        }

        // Re-render
        this._clearSelection();
        this._rebuildBody();

        // Re-select the moved ghosts at their new positions
        var rows = this.tbodyEl.querySelectorAll('tr');
        for (var n = 0; n < toMove.length; n++) {
            var nr2 = toMove[n].newRow;
            var nc2 = toMove[n].newCol;
            if (nr2 < rows.length) {
                var newTd = rows[nr2].querySelector('td[data-col="' + nc2 + '"]');
                if (newTd) this._selectCell(newTd);
            }
        }
    };

    // Move REAL cells (values + cellDetails + merges) — symétrique de __finalizeMoveGhosts
    // mais opère sur les données de la grille, pas les ghosts. Merge-aware : un merge dont
    // l'ancre est sélectionnée est translaté en entier. Fail-safe : toute validation KO
    // déclenche un toast et n'altère rien.
    SqlResultGrid.prototype.__finalizeMoveCells = function(targetTd) {
        var self = this;
        if (!this._selectedCells || this._selectedCells.length === 0) return;
        if (!this._dragStartCell) return;

        var startR = parseInt(this._dragStartCell.getAttribute('data-row'), 10);
        var startC = parseInt(this._dragStartCell.getAttribute('data-col'), 10);
        var targetR = parseInt(targetTd.getAttribute('data-row'), 10);
        var targetC = parseInt(targetTd.getAttribute('data-col'), 10);
        var dR = targetR - startR;
        var dC = targetC - startC;
        if (dR === 0 && dC === 0) return;  // no-op

        var toast = (typeof showToast === 'function')
            ? showToast
            : function(m) { console.warn('[move-cells]', m); };

        // GARDE : data-row reflète l'index dans displayRows (vue triée/filtrée),
        // PAS dans allRows. Déplacer en indexant allRows directement écraserait
        // la mauvaise ligne silencieusement. On refuse tant que tri/filtre actif.
        var sortActive = typeof this.sortColIndex === 'number' && this.sortColIndex >= 0;
        var filtersActive = false;
        if (this.filters) {
            for (var fk in this.filters) {
                if (!this.filters.hasOwnProperty(fk)) continue;
                var f = this.filters[fk];
                if (f && ((f.excluded && f.excluded.size > 0) || f.excludeNull)) {
                    filtersActive = true;
                    break;
                }
            }
        }
        if (sortActive || filtersActive) {
            toast('Désactivez le tri/filtre avant de déplacer des cellules', 'error');
            return;
        }

        // Note : pas de _pushHistory ici — il existe déjà après la validation
        // cap 500 (étape 7 plus bas). Double-push détecté à la review.

        // 1. Collecter les cells sélectionnées (avec leur merge éventuel).
        //    Règle : un merge bouge ssi son ancre td est sélectionnée.
        var mergesByAnchor = {};
        for (var mi = 0; mi < this._merges.length; mi++) {
            var mg = this._merges[mi];
            mergesByAnchor[mg.r1 + ',' + mg.c1] = mg;
        }

        var sources = [];  // [{r, c, val, detail, merge}]
        for (var i = 0; i < this._selectedCells.length; i++) {
            var td = this._selectedCells[i];
            var sr = parseInt(td.getAttribute('data-row'), 10);
            var sc = parseInt(td.getAttribute('data-col'), 10);
            var key = sr + ',' + sc;
            var val = this.isArrayFormat
                ? (sr < this.allRows.length ? this.allRows[sr][sc] : '')
                : (sr < this.allRows.length ? this.allRows[sr][this.columns[sc]] : '');
            var det = this._cellDetails[key] || null;
            var mergeAtAnchor = mergesByAnchor[key] || null;
            sources.push({ r: sr, c: sc, val: val, detail: det, merge: mergeAtAnchor, oldKey: key });
        }

        // 2. Validation bornes grille.
        var colCount = this.columns.length;
        var maxNeededRow = 0;
        for (var v1 = 0; v1 < sources.length; v1++) {
            var s = sources[v1];
            var nr = s.r + dR;
            var nc = s.c + dC;
            if (nr < 0 || nc < 0 || nc >= colCount) {
                toast('Déplacement hors de la grille', 'error'); return;
            }
            if (s.merge) {
                var mnr2 = s.merge.r2 + dR;
                var mnc2 = s.merge.c2 + dC;
                if (mnc2 >= colCount) {
                    toast('Cellule fusionnée hors de la grille', 'error'); return;
                }
                if (mnr2 > maxNeededRow) maxNeededRow = mnr2;
            }
            if (nr > maxNeededRow) maxNeededRow = nr;
        }

        // 3. Construire set des positions (row,col) occupées par la sélection
        //    (cells simples + toutes les positions INTERNES des merges sélectionnés)
        //    pour distinguer "dans la sélection" vs "hors de la sélection".
        var inSelection = {};
        for (var v2 = 0; v2 < sources.length; v2++) {
            var ss = sources[v2];
            if (ss.merge) {
                for (var rr = ss.merge.r1; rr <= ss.merge.r2; rr++) {
                    for (var cc = ss.merge.c1; cc <= ss.merge.c2; cc++) {
                        inSelection[rr + ',' + cc] = true;
                    }
                }
            } else {
                inSelection[ss.r + ',' + ss.c] = true;
            }
        }

        // 4. Construire set des positions DESTINATION (pareil — cells + rects merges).
        var destOccupied = {};  // newKey → 'merge' | 'cell'
        for (var v3 = 0; v3 < sources.length; v3++) {
            var src = sources[v3];
            if (src.merge) {
                for (var rr2 = src.merge.r1 + dR; rr2 <= src.merge.r2 + dR; rr2++) {
                    for (var cc2 = src.merge.c1 + dC; cc2 <= src.merge.c2 + dC; cc2++) {
                        var dk = rr2 + ',' + cc2;
                        if (destOccupied[dk]) {
                            toast('Collision interne entre cellules déplacées', 'error'); return;
                        }
                        destOccupied[dk] = 'merge';
                    }
                }
            } else {
                var dk2 = (src.r + dR) + ',' + (src.c + dC);
                if (destOccupied[dk2]) {
                    toast('Collision interne entre cellules déplacées', 'error'); return;
                }
                destOccupied[dk2] = 'cell';
            }
        }

        // 5. Vérifier qu'aucun merge non-sélectionné ne recouvre une destination.
        for (var mi2 = 0; mi2 < this._merges.length; mi2++) {
            var mg2 = this._merges[mi2];
            var anchorKey = mg2.r1 + ',' + mg2.c1;
            // Si ce merge fait partie de la sélection (son ancre y est), il bouge avec nous.
            if (inSelection[anchorKey] && mergesByAnchor[anchorKey] === mg2) continue;
            // Sinon, vérifier que toutes ses positions sont libres côté destination.
            for (var rr3 = mg2.r1; rr3 <= mg2.r2; rr3++) {
                for (var cc3 = mg2.c1; cc3 <= mg2.c2; cc3++) {
                    // Si cette position est une source qui s'en va, c'est OK : elle sera libérée.
                    // Sinon, si elle est une destination, on refuse (on ne casse pas un merge existant).
                    var pk = rr3 + ',' + cc3;
                    if (destOccupied[pk] && !inSelection[pk]) {
                        toast('Chevauchement avec une cellule fusionnée existante', 'error');
                        return;
                    }
                }
            }
        }

        // 6. Pré-validation du cap 500 AVANT toute mutation ou snapshot.
        //    (Sinon, en cas de dépassement, on aurait laissé des lignes fantômes
        //    dans allRows + une entrée undo bidon.)
        if (maxNeededRow >= 500) {
            toast('Limite de 500 lignes atteinte', 'error');
            return;
        }

        // 7. Validation OK → snapshot undo AVANT toute mutation.
        if (typeof this._pushHistory === 'function') this._pushHistory();

        // 8. Étendre la grille si destination déborde en lignes.
        while (maxNeededRow >= this.allRows.length) {
            var newRow;
            if (this.isArrayFormat) {
                newRow = [];
                for (var x = 0; x < colCount; x++) newRow.push('');
            } else {
                newRow = {};
                for (var y = 0; y < colCount; y++) newRow[this.columns[y]] = '';
            }
            this.allRows.push(newRow);
        }

        // Helper pour set/clear selon le format.
        var setVal = function(r, c, v) {
            if (self.isArrayFormat) self.allRows[r][c] = v;
            else self.allRows[r][self.columns[c]] = v;
        };

        // 8. PHASE A — lire les détails déjà fait (dans sources). Rien à faire ici.

        // 9. PHASE B — clear sources : tous les rects merges + toutes les cells simples sélectionnées.
        //    Supprime aussi leurs cellDetails.
        for (var b1 = 0; b1 < sources.length; b1++) {
            var sb = sources[b1];
            if (sb.merge) {
                for (var rr4 = sb.merge.r1; rr4 <= sb.merge.r2; rr4++) {
                    for (var cc4 = sb.merge.c1; cc4 <= sb.merge.c2; cc4++) {
                        setVal(rr4, cc4, '');
                        delete this._cellDetails[rr4 + ',' + cc4];
                    }
                }
            } else {
                setVal(sb.r, sb.c, '');
                delete this._cellDetails[sb.oldKey];
            }
        }

        // 10. PHASE C — clear destinations : tous les rects destinations.
        //     (écrase silencieusement les cells simples non-merge occupées à l'arrivée,
        //      cohérent avec la policy "move = cut-paste")
        for (var c1 = 0; c1 < sources.length; c1++) {
            var sc1 = sources[c1];
            if (sc1.merge) {
                for (var rr5 = sc1.merge.r1 + dR; rr5 <= sc1.merge.r2 + dR; rr5++) {
                    for (var cc5 = sc1.merge.c1 + dC; cc5 <= sc1.merge.c2 + dC; cc5++) {
                        setVal(rr5, cc5, '');
                        delete this._cellDetails[rr5 + ',' + cc5];
                    }
                }
            } else {
                var nr6 = sc1.r + dR;
                var nc6 = sc1.c + dC;
                setVal(nr6, nc6, '');
                delete this._cellDetails[nr6 + ',' + nc6];
            }
        }

        // 11. PHASE D — écrire valeurs + cellDetails à destination.
        for (var d1 = 0; d1 < sources.length; d1++) {
            var sd = sources[d1];
            var dnr = sd.r + dR;
            var dnc = sd.c + dC;
            var dkey = dnr + ',' + dnc;
            setVal(dnr, dnc, sd.val);
            if (sd.detail) this._cellDetails[dkey] = sd.detail;
        }

        // 12. PHASE E — translater les merges. setMerges() valide + dédoublonne.
        var newMerges = [];
        for (var e1 = 0; e1 < this._merges.length; e1++) {
            var emg = this._merges[e1];
            var eanchor = emg.r1 + ',' + emg.c1;
            if (inSelection[eanchor] && mergesByAnchor[eanchor] === emg) {
                newMerges.push({
                    r1: emg.r1 + dR, c1: emg.c1 + dC,
                    r2: emg.r2 + dR, c2: emg.c2 + dC
                });
            } else {
                newMerges.push({ r1: emg.r1, c1: emg.c1, r2: emg.r2, c2: emg.c2 });
            }
        }
        if (typeof this.setMerges === 'function') this.setMerges(newMerges);

        this.displayRows = this.allRows.slice();
        this.totalRowCount = this.allRows.length;

        // 13. Re-render + resélectionner les cells à leur nouvelle position.
        this._clearSelection();
        this._rebuildBody();

        var rows = this.tbodyEl.querySelectorAll('tr');
        for (var n = 0; n < sources.length; n++) {
            var nrr = sources[n].r + dR;
            var ncc = sources[n].c + dC;
            if (nrr < rows.length) {
                var newTd = rows[nrr].querySelector('td[data-col="' + ncc + '"]');
                if (newTd) this._selectCell(newTd);
            }
        }
    };

    SqlResultGrid.prototype._navigateArrow = function(key, shiftKey) {
        // Find the "active" cell (last selected or anchor)
        var active = this._selectionAnchor || this._selectedCells[this._selectedCells.length - 1];
        if (!active) return;

        var row = parseInt(active.getAttribute('data-row'), 10);
        var col = parseInt(active.getAttribute('data-col'), 10);
        var visibleCols = this._getVisibleColIndices();
        var visPos = visibleCols.indexOf(col);

        // Compute target
        if (key === 'ArrowUp') row = Math.max(0, row - 1);
        else if (key === 'ArrowDown') row = Math.min(this.displayRows.length - 1, row + 1);
        else if (key === 'ArrowLeft') visPos = Math.max(0, visPos - 1);
        else if (key === 'ArrowRight') visPos = Math.min(visibleCols.length - 1, visPos + 1);

        var targetCol = visibleCols[visPos];
        var targetTd = this.tbodyEl.querySelector('td[data-row="' + row + '"][data-col="' + targetCol + '"]');
        if (!targetTd) return;

        if (shiftKey) {
            // Extend selection range
            this._selectRange(this._selectionAnchor || active, targetTd);
        } else {
            this._clearSelection();
            this._selectCell(targetTd);
            this._selectionAnchor = targetTd;
        }

        // Scroll into view
        targetTd.scrollIntoView({ block: 'nearest', inline: 'nearest' });
    };

    SqlResultGrid.prototype._copySelection = function() {
        if (!this._selectedCells.length) return;
        var self = this;

        // Clear previous marching ants
        SqlResultGrid._clearClipboardAnts();

        // Group cells by row → 2D grid (lire depuis displayRows pour cohérence avec data-row)
        var byRow = {};
        for (var i = 0; i < this._selectedCells.length; i++) {
            var td = this._selectedCells[i];
            var r = parseInt(td.getAttribute('data-row'), 10);
            var c = parseInt(td.getAttribute('data-col'), 10);
            var rawText = '';
            var rowSrc = this.displayRows[r];
            if (rowSrc) {
                rawText = this.isArrayFormat ? rowSrc[c] : rowSrc[this.columns[c]];
                if (rawText == null) rawText = '';
                else rawText = String(rawText);
            }
            if (!byRow[r]) byRow[r] = [];
            byRow[r].push({ col: c, td: td, text: rawText });
        }

        // Build TSV + unified clipboard (2D cell array)
        var lines = [];
        var clipCells = [];
        var rowKeys = Object.keys(byRow).sort(function(a, b) { return a - b; });
        for (var j = 0; j < rowKeys.length; j++) {
            var rowCells = byRow[rowKeys[j]].sort(function(a, b) { return a.col - b.col; });
            lines.push(rowCells.map(function(c) { return c.text; }).join('\t'));

            var clipRow = [];
            for (var k = 0; k < rowCells.length; k++) {
                var rc = rowCells[k];
                var key = rowKeys[j] + ',' + rc.col;
                var details = self._cellDetails[key] || null;
                var drillCtx = null;
                if (!details && self._isDrillable(rc.col) && self.sql) {
                    var rowData = self.displayRows[parseInt(rowKeys[j], 10)];
                    var rowVals = {};
                    for (var ci = 0; ci < self.columns.length; ci++) {
                        var v = self.isArrayFormat ? rowData[ci] : rowData[self.columns[ci]];
                        rowVals[self.columns[ci]] = v;
                    }
                    drillCtx = { original_sql: self.sql, col_index: rc.col, row_values: rowVals };
                }
                clipRow.push({ value: rc.text, details: details, drilldownCtx: drillCtx });
            }
            clipCells.push(clipRow);
        }

        SqlResultGrid._clipboard = {
            cells: clipCells,
            rows: clipCells.length,
            cols: clipCells[0] ? clipCells[0].length : 0,
            tsv: lines.join('\n')
        };

        var tsv = SqlResultGrid._clipboard.tsv;

        var toast = (typeof showToast === 'function')
            ? showToast
            : function(m) { console.warn('[copy]', m); };

        // Succès : flash vert puis marching ants (comportement d'origine).
        function _flashCopied() {
            var cells = self._selectedCells.slice();
            for (var m = 0; m < cells.length; m++) cells[m].classList.add('grid-cell-copied');
            setTimeout(function() {
                for (var n = 0; n < cells.length; n++) {
                    cells[n].classList.remove('grid-cell-copied');
                    cells[n].classList.add('grid-cell-clipboard');
                }
                SqlResultGrid._clipboardAnts = cells;
            }, 400);
        }

        // GRID-4 — l'écriture presse-papier peut échouer SILENCIEUSEMENT : contexte
        // non sécurisé (HTTP par IP au 1er déploiement), document non focalisé,
        // refus transitoire de permission, ou API clipboard absente. On (1) tente
        // l'API moderne, (2) retombe sur execCommand('copy') via un textarea
        // temporaire, (3) avertit l'utilisateur si tout échoue — jamais de faux
        // silence où l'user croit avoir copié alors que rien n'est dans le presse-papier.
        function _legacyCopy() {
            try {
                var ta = document.createElement('textarea');
                ta.value = tsv;
                ta.setAttribute('readonly', '');
                ta.style.cssText = 'position:fixed;top:-9999px;left:-9999px;opacity:0;';
                document.body.appendChild(ta);
                ta.select();
                var ok = document.execCommand('copy');
                document.body.removeChild(ta);
                if (ok) { _flashCopied(); return true; }
            } catch (e) { /* géré par le toast ci-dessous */ }
            return false;
        }

        if (navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
            navigator.clipboard.writeText(tsv).then(_flashCopied).catch(function() {
                if (!_legacyCopy()) {
                    toast('Copie impossible — vérifiez les permissions du presse-papier (une connexion HTTPS peut être requise).', 'error');
                }
            });
        } else if (!_legacyCopy()) {
            toast('Copie impossible — le presse-papier n\'est pas accessible dans ce contexte.', 'error');
        }
    };

    // Clear marching ants from all grids
    SqlResultGrid._clipboardAnts = [];
    SqlResultGrid._clearClipboardAnts = function() {
        var ants = SqlResultGrid._clipboardAnts;
        for (var i = 0; i < ants.length; i++) {
            if (ants[i] && ants[i].classList) ants[i].classList.remove('grid-cell-clipboard');
        }
        SqlResultGrid._clipboardAnts = [];
    };

    SqlResultGrid.prototype._pasteFromClipboard = function() {
        var self = this;
        var toast = (typeof showToast === 'function')
            ? showToast
            : function(m) { console.warn('[paste]', m); };
        // GRID-4 (jumeau lecture) — readText() peut être indisponible (contexte
        // non sécurisé) ou rejeter (permission refusée). Sans garde, le collage
        // échoue en silence : l'utilisateur fait Ctrl+V et rien ne se passe, sans
        // savoir pourquoi. Pas de fallback execCommand fiable en lecture → on
        // informe et on oriente vers le Ctrl+V natif dans une cellule.
        if (!navigator.clipboard || typeof navigator.clipboard.readText !== 'function') {
            toast('Collage impossible — le presse-papier n\'est pas accessible dans ce contexte (HTTPS requis).', 'error');
            return;
        }
        navigator.clipboard.readText().then(function(text) {
            if (!text) return;
            self._pushHistory();

            // Find paste start: first selected cell, or (0,0)
            var startRow = 0, startCol = 0;
            if (self._selectedCells.length > 0) {
                startRow = parseInt(self._selectedCells[0].getAttribute('data-row'), 10) || 0;
                startCol = parseInt(self._selectedCells[0].getAttribute('data-col'), 10) || 0;
            }

            var lines = text.split('\n');
            for (var r = 0; r < lines.length; r++) {
                var values = lines[r].split('\t');
                var rowIdx = startRow + r;
                // Add rows if needed
                while (rowIdx >= self.allRows.length && self.allRows.length < 500) {
                    var newRow = [];
                    for (var x = 0; x < self.columns.length; x++) newRow.push('');
                    self.allRows.push(newRow);
                }
                if (rowIdx >= self.allRows.length) break;

                for (var c = 0; c < values.length; c++) {
                    var colIdx = startCol + c;
                    // Add columns if needed
                    while (colIdx >= self.columns.length && self.columns.length < 52) {
                        var nextChar = String.fromCharCode(65 + self.columns.length);
                        if (self.columns.length >= 26) nextChar = 'Col' + (self.columns.length + 1);
                        self.columns.push(nextChar);
                        self.columnTypes.push('string');
                        self.columnOrder.push(self.columns.length - 1);
                        for (var ri = 0; ri < self.allRows.length; ri++) {
                            if (self.isArrayFormat) self.allRows[ri].push('');
                        }
                    }
                    if (colIdx >= self.columns.length) break;

                    if (self.isArrayFormat) {
                        self.allRows[rowIdx][colIdx] = values[c];
                    } else {
                        self.allRows[rowIdx][self.columns[colIdx]] = values[c];
                    }
                }
            }

            self.displayRows = self.allRows.slice();
            self.totalRowCount = self.allRows.length;
            self._detectTypes();
            self._rebuildThead();
            self._rebuildBody();
            self._updateHeaderInfo();

            // Trigger auto-fill après paste système
            if (self._isDashboardSheet) {
                if (self._autoFillAbort) self._autoFillAbort.abort();
                self._autoFillCompleted = false;
                self._autoFillPending = false;
                clearTimeout(self._autoFillTimer);
                self._autoFillTimer = setTimeout(function() {
                    self._triggerAutoFill();
                }, 3000);
            }
        }).catch(function() {
            toast('Collage impossible — autorisez l\'accès au presse-papier, ou collez directement dans une cellule avec Ctrl+V.', 'error');
        });
    };

    // ── Editable cells for blank sheets ──

    SqlResultGrid.prototype._attachEditableHandlers = function() {
        var self = this;
        var cells = this.tbodyEl.querySelectorAll('td:not(.grid-row-num)');
        for (var i = 0; i < cells.length; i++) {
            cells[i].classList.add('grid-cell-editable');
            cells[i].addEventListener('dblclick', function(e) {
                // Cellule avec cellDetails (valeur issue d'un SQL) : le dblclick
                // est réservé au drill-down (géré par _attachDetailDblClickHandlers
                // via le bubbling sur tbody). L'édition passe par le menu
                // contextuel "Modifier la cellule".
                var cellKey = this.getAttribute('data-row') + ',' + this.getAttribute('data-col');
                if (self._cellDetails && self._cellDetails[cellKey]) return;
                self._startCellEdit(this, e);
            });
        }
        // Column headers editable — Option B : dblclick UNIQUEMENT sur le
        // label texte du header pour le renommage. Dblclick ailleurs sur le
        // <th> est laissé à _selectEntireColumn (sum/avg). Convention Excel
        // inversée : ici on garde la sélection comme geste principal.
        if (this.theadEl) {
            var ths = this.theadEl.querySelectorAll('.grid-sortable-th');
            for (var j = 0; j < ths.length; j++) {
                ths[j].classList.add('grid-cell-editable');
                ths[j].addEventListener('dblclick', function(e) {
                    var tgt = e.target;
                    var onLabel = tgt && tgt.classList && tgt.classList.contains('grid-th-label');
                    if (!onLabel && tgt && typeof tgt.closest === 'function') {
                        onLabel = !!tgt.closest('.grid-th-label');
                    }
                    if (!onLabel) return;
                    e.stopPropagation();
                    self._startHeaderEdit(this);
                });
            }
        }
        // Resize toolbar (once only)
        if (!this._resizeBarEl) {
            this._buildResizeToolbar();
        }
    };

    // ── Resize toolbar for blank sheets ──

    SqlResultGrid.prototype._buildResizeToolbar = function() {
        if (!this._isBlankSheet) return;
        var self = this;
        var bar = document.createElement('div');
        bar.className = 'grid-resize-bar';

        var btnAddRow = document.createElement('button');
        btnAddRow.type = 'button';
        btnAddRow.className = 'grid-resize-btn';
        btnAddRow.textContent = '+ Ligne';
        btnAddRow.addEventListener('click', function() { self._addRow(); });
        bar.appendChild(btnAddRow);

        var btnDelRow = document.createElement('button');
        btnDelRow.type = 'button';
        btnDelRow.className = 'grid-resize-btn';
        btnDelRow.textContent = '- Ligne';
        btnDelRow.addEventListener('click', function() { self._removeRow(); });
        bar.appendChild(btnDelRow);

        var btnAddCol = document.createElement('button');
        btnAddCol.type = 'button';
        btnAddCol.className = 'grid-resize-btn';
        btnAddCol.textContent = '+ Colonne';
        btnAddCol.addEventListener('click', function() { self._addColumn(); });
        bar.appendChild(btnAddCol);

        var btnDelCol = document.createElement('button');
        btnDelCol.type = 'button';
        btnDelCol.className = 'grid-resize-btn';
        btnDelCol.textContent = '- Colonne';
        btnDelCol.addEventListener('click', function() { self._removeColumn(); });
        bar.appendChild(btnDelCol);

        // Insert after the table wrapper, before the footer
        if (this.wrapperEl && this.wrapperEl.nextSibling) {
            this.container.insertBefore(bar, this.wrapperEl.nextSibling);
        } else {
            this.container.appendChild(bar);
        }
        this._resizeBarEl = bar;
    };

    SqlResultGrid.prototype._addRow = function() {
        if (this.allRows.length >= 500) return; // Perf cap
        // Snapshot AVANT mutation — pour que Ctrl+Z annule l'ajout de ligne.
        this._pushHistory();
        var row = [];
        for (var i = 0; i < this.columns.length; i++) row.push('');
        this.allRows.push(row);
        this.displayRows = this.allRows.slice();
        this.totalRowCount = this.allRows.length;
        // Structure changée (lignes) → la sélection positionnelle (_selectedKeys
        // + flag colonne-entière) est périmée → on la vide (fail-closed) sinon Σ
        // fausse silencieuse sur des keys hors borne (review convergence Q5).
        this._clearSelection();
        this._rebuildBody();
        this._updateHeaderInfo();
        this._updateResizeButtons();
        // E0d: allow auto-fill to re-trigger for new empty cells
        this._autoFillCompleted = false;
        this._lastAutoFillHash = null;
    };

    SqlResultGrid.prototype._removeRow = function() {
        if (this.allRows.length <= 1) return;
        this._pushHistory();
        this.allRows.pop();
        this.displayRows = this.allRows.slice();
        this.totalRowCount = this.allRows.length;
        this._clearSelection(); // structure changée → sélection périmée (cf. _addRow)
        this._rebuildBody();
        this._updateHeaderInfo();
        this._updateResizeButtons();
    };

    SqlResultGrid.prototype._addColumn = function() {
        if (this.columns.length >= 52) return; // Cap A-Z then Col27-52
        this._pushHistory();
        var nextChar = String.fromCharCode(65 + this.columns.length);
        if (this.columns.length >= 26) nextChar = 'Col' + (this.columns.length + 1);
        this.columns.push(nextChar);
        this.columnTypes.push('string');
        this.columnOrder.push(this.columns.length - 1);
        for (var i = 0; i < this.allRows.length; i++) {
            if (this.isArrayFormat) {
                this.allRows[i].push('');
            } else {
                this.allRows[i][nextChar] = '';
            }
        }
        this.displayRows = this.allRows.slice();
        this._clearSelection(); // structure changée (colonnes) → sélection périmée
        this._rebuildThead();
        this._rebuildBody();
        this._updateResizeButtons();
        // E0d: allow auto-fill to re-trigger for new empty cells
        this._autoFillCompleted = false;
        this._lastAutoFillHash = null;
    };

    SqlResultGrid.prototype._removeColumn = function() {
        if (this.columns.length <= 1) return;
        this._pushHistory();
        var lastIdx = this.columns.length - 1;
        var removedName = this.columns[lastIdx];
        this.columns.pop();
        this.columnTypes.pop();
        this.columnOrder = this.columnOrder.filter(function(i) { return i < lastIdx; });
        this.hiddenCols.delete(lastIdx);
        for (var i = 0; i < this.allRows.length; i++) {
            if (this.isArrayFormat) {
                this.allRows[i].pop();
            } else {
                delete this.allRows[i][removedName];
            }
        }
        this.displayRows = this.allRows.slice();
        this._clearSelection(); // structure changée (colonnes) → sélection périmée
        this._rebuildThead();
        this._rebuildBody();
        this._updateResizeButtons();
    };

    SqlResultGrid.prototype._updateResizeButtons = function() {
        if (!this._resizeBarEl) return;
        var btns = this._resizeBarEl.querySelectorAll('.grid-resize-btn');
        // btns: [+Row, -Row, +Col, -Col]
        if (btns[0]) btns[0].disabled = this.allRows.length >= 500;
        if (btns[1]) btns[1].disabled = this.allRows.length <= 1;
        if (btns[2]) btns[2].disabled = this.columns.length >= 52;
        if (btns[3]) btns[3].disabled = this.columns.length <= 1;
    };

    // ── Cell editing ──

    SqlResultGrid.prototype._startCellEdit = function(td, evt) {
        if (td.querySelector('input')) return;

        // Si c'est une cellule ghost, pré-remplir avec "=" + label pour édition
        var isGhost = td.classList.contains('grid-cell-ghost');
        var ghostKey = td.getAttribute('data-row') + ',' + td.getAttribute('data-col');
        var ghostEditPrefix = '';
        if (isGhost && this._ghostValues[ghostKey]) {
            var gv = this._ghostValues[ghostKey];
            var ghostLabel = gv.label || gv.match
                ? (gv.label || Object.values(gv.match || {}).join(' · '))
                : '';
            ghostEditPrefix = '=' + ghostLabel;
            // Don't delete ghost yet — only on commit with a non-ghost value
        }
        if (isGhost) {
            td.classList.remove('grid-cell-ghost', 'grid-cell-ghost-label', 'grid-cell-ghost-value');
            td.removeAttribute('title');
        }

        // Lire la valeur MACHINE depuis allRows (pas td.textContent qui est formaté)
        var rowIdx = parseInt(td.getAttribute('data-row'), 10);
        var colIdx = parseInt(td.getAttribute('data-col'), 10);
        var rawVal = '';
        if (isGhost) {
            rawVal = ghostEditPrefix;
        } else if (!isNaN(rowIdx) && !isNaN(colIdx) && this.allRows[rowIdx]) {
            rawVal = this.isArrayFormat
                ? this.allRows[rowIdx][colIdx]
                : this.allRows[rowIdx][this.columns[colIdx]];
            if (rawVal == null || String(rawVal) === 'null') rawVal = '';
            else rawVal = String(rawVal);
        }
        var oldVal = rawVal;
        var input = document.createElement('input');
        input.type = 'text';
        input.className = 'grid-cell-input';
        input.value = oldVal;
        td.textContent = '';
        td.appendChild(input);
        input.focus();

        // Curseur à la position du clic (mesure via canvas)
        if (evt && oldVal && oldVal !== 'null') {
            try {
                var clickX = evt.clientX - td.getBoundingClientRect().left - 4;
                var canvas = document.createElement('canvas');
                var ctx = canvas.getContext('2d');
                ctx.font = getComputedStyle(input).font;
                var pos = 0;
                for (var ci = 0; ci <= input.value.length; ci++) {
                    if (ctx.measureText(input.value.substring(0, ci)).width > clickX) break;
                    pos = ci;
                }
                input.setSelectionRange(pos, pos);
            } catch (_e) { /* fallback: curseur au début */ }
        }

        var self = this;
        var dropdown = null;
        var selectedIdx = -1;

        var cachedSuggestions = null; // Cache LLM results
        var fetchingInProgress = false;

        var closeSuggestions = function() {
            if (dropdown) { dropdown.remove(); dropdown = null; selectedIdx = -1; }
        };

        var applySuggestion = function(text) {
            closeSuggestions();
            // Remettre la suggestion dans l'input pour que l'utilisateur
            // puisse la modifier avant de valider avec Enter.
            input.value = '=' + text;
            input.focus();
            // Placer le curseur à la fin
            input.setSelectionRange(input.value.length, input.value.length);
        };

        // Suggestions panel: inserted in the grid container (always visible, no clipping)
        var renderSuggestions = function(suggestions, filter) {
            closeSuggestions();
            var filtered = suggestions;
            if (filter && filter.length > 0) {
                var f = filter.toLowerCase();
                filtered = suggestions.filter(function(s) { return s.toLowerCase().indexOf(f) !== -1; });
            }
            if (!filtered.length) return;

            dropdown = document.createElement('div');
            dropdown.className = 'grid-cell-suggestions';
            var title = document.createElement('div');
            title.className = 'grid-cell-suggestion-title';
            title.textContent = 'Suggestions IA pour cette cellule :';
            dropdown.appendChild(title);
            for (var s = 0; s < Math.min(filtered.length, 8); s++) {
                (function(sug) {
                    var item = document.createElement('div');
                    item.className = 'grid-cell-suggestion-item';
                    item.textContent = sug;
                    // FIX: utiliser mousedown + preventDefault pour empêcher le blur naturel
                    item.addEventListener('mousedown', function(e) {
                        e.preventDefault();  // Empêche le navigateur de blur l'input
                        applySuggestion(sug);
                    });
                    dropdown.appendChild(item);
                })(filtered[s]);
            }
            // Insert in grid container, before the copilot bar
            var copilotBar = self.container.querySelector('.grid-copilot-bar');
            if (copilotBar) {
                self.container.insertBefore(dropdown, copilotBar);
            } else {
                self.container.appendChild(dropdown);
            }
        };

        var showLoading = function() {
            closeSuggestions();
            dropdown = document.createElement('div');
            dropdown.className = 'grid-cell-suggestions';
            dropdown.innerHTML = '<div class="grid-cell-suggestion-loading">Chargement des suggestions\u2026</div>';
            var copilotBar = self.container.querySelector('.grid-copilot-bar');
            if (copilotBar) {
                self.container.insertBefore(dropdown, copilotBar);
            } else {
                self.container.appendChild(dropdown);
            }
        };

        // Fetch suggestions from LLM on first "=" then cache
        input.addEventListener('input', function() {
            var val = input.value;
            if (val.charAt(0) === '=') {
                var filter = val.substring(1).toLowerCase();
                if (cachedSuggestions) {
                    renderSuggestions(cachedSuggestions, filter);
                } else if (!fetchingInProgress) {
                    fetchingInProgress = true;
                    showLoading();
                    self._fetchCellSuggestions(td, function(suggestions, determined) {
                        fetchingInProgress = false;
                        cachedSuggestions = suggestions;
                        console.log('[Copilot] Suggestions received:', suggestions, 'determined:', determined);
                        // If input lost focus during fetch (blur was blocked by fetchingInProgress guard),
                        // run the deferred commit now instead of rendering orphan suggestions
                        if (!input.parentNode || document.activeElement !== input) {
                            closeSuggestions();
                            doCommit();
                            return;
                        }
                        if (determined && suggestions.length === 1) {
                            // System determined the cell meaning — show pre-selected, user confirms with Enter
                            renderSuggestions(suggestions, '');
                            selectedIdx = 0;
                            if (dropdown) {
                                var firstItem = dropdown.querySelector('.grid-cell-suggestion-item');
                                if (firstItem) firstItem.classList.add('active');
                            }
                        } else if (suggestions && suggestions.length > 0) {
                            renderSuggestions(suggestions, '');
                        } else {
                            closeSuggestions();
                        }
                    });
                }
            } else {
                closeSuggestions();
            }
        });

        var commit = function(force) {
            if (!force && fetchingInProgress) {
                return;
            }
            // Si les suggestions sont visibles et l'utilisateur clique dessus
            // (mousedown → applySuggestion), ne pas commiter immédiatement.
            // Mais si l'input a perdu le focus (clic ailleurs), forcer le commit après un délai.
            if (dropdown && !force) {
                setTimeout(function() {
                    if (document.activeElement !== input) {
                        commit(true);
                    }
                }, 200);
                return;
            }
            // Fermer les suggestions avant de commiter
            closeSuggestions();
            doCommit();
        };
        var committed = false;
        // Helper : l'édition manuelle écrase une valeur qui peut provenir d'un
        // SQL (cellDetails). On supprime ce lien AVANT toute branche d'édition
        // (=AI, valeur directe, etc.) pour éviter que le drill-down ne renvoie
        // une donnée incohérente avec ce que l'utilisateur vient de saisir.
        // Le _fillCellWithAI peut reposer un nouveau cellDetails juste après
        // (hasFullResult=true dans sa callback) ; sinon la cellule reste
        // simplement sans drill, ce qui est cohérent avec la saisie manuelle.
        var dropCellDetailIfAny = function() {
            if (isNaN(rowIdx) || isNaN(colIdx)) return;
            var ckey = rowIdx + ',' + colIdx;
            if (self._cellDetails && self._cellDetails[ckey]) {
                delete self._cellDetails[ckey];
                td.classList.remove('grid-cell-has-detail');
                if (self._options && typeof self._options.onStateChange === 'function') {
                    self._options.onStateChange();
                }
            }
        };
        var doCommit = function() {
            if (committed) return;
            committed = true;
            closeSuggestions();
            var newVal = input.value;

            // AI cell: if value starts with "=" → ask AI to fill
            if (newVal.length > 1 && newVal.charAt(0) === '=') {
                var instruction = newVal.substring(1).trim();
                if (instruction) {
                    dropCellDetailIfAny();
                    self._fillCellWithAI(td, instruction);
                    return;
                }
            }

            // Si cellule laissée vide ou inchangée et qu'il y avait un ghost → restaurer
            var unchanged = !newVal.trim() || (isGhost && newVal === ghostEditPrefix);
            if (unchanged && isGhost && self._ghostValues[ghostKey]) {
                var gv = self._ghostValues[ghostKey];
                self._applyGhostToCell(td, gv);
                return;
            }
            // Si l'utilisateur a écrit dans une cellule ghost → supprimer le ghost
            if (isGhost && newVal.trim()) {
                delete self._ghostValues[ghostKey];
            }
            var cmtN = Number(newVal);
            td.textContent = (newVal && !isNaN(cmtN) && isFinite(cmtN)) ? formatNumber(cmtN) : (newVal || '');
            // Compare la valeur soumise à la valeur originale (capturée ligne ~2648
            // comme oldVal, stringifiée pour la cohérence avec l'input HTML). On ne
            // mute allRows ET on ne supprime le cellDetails QUE si vraie modif.
            // Sans cette garde, un simple dblclick pour COPIER le contenu d'une
            // cellule supprimait silencieusement le drill-down associé (bug observé
            // sur RATIO2 — perte de cellDetails 8,1 sans modification réelle).
            var oldValStr = (oldVal == null) ? '' : String(oldVal);
            var newValStr = (newVal == null) ? '' : String(newVal);
            var actuallyChanged = newValStr !== oldValStr;
            if (!isNaN(rowIdx) && !isNaN(colIdx) && self.allRows[rowIdx] && actuallyChanged) {
                // Snapshot AVANT mutation — sinon Ctrl+Z saute par-dessus
                // l'édition manuelle directement vers l'état d'avant le
                // dernier copilot/paste, laissant l'utilisateur perdu.
                self._pushHistory();
                if (self.isArrayFormat) {
                    self.allRows[rowIdx][colIdx] = newVal;
                } else {
                    self.allRows[rowIdx][self.columns[colIdx]] = newVal;
                }
                self.displayRows = self.allRows.slice();
                // Drop cellDetails si présent (cohérence valeur↔SQL).
                // dropCellDetailIfAny() notifie déjà onStateChange dans ce cas.
                var hadDetail = !!(self._cellDetails && self._cellDetails[rowIdx + ',' + colIdx]);
                dropCellDetailIfAny();
                // Sinon, la valeur a été modifiée mais il n'y avait pas de cellDetails :
                // on déclenche explicitement onStateChange pour que l'édit soit
                // persistée (sans ça, elle ne survivrait qu'à un Ctrl+S manuel).
                if (!hadDetail && self._options && typeof self._options.onStateChange === 'function') {
                    self._options.onStateChange();
                }
                // Une édition inline change la valeur affichée → recalcule le résumé
                // de sélection si la cellule éditée fait partie d'une sélection
                // active (sinon Σ figée sur l'ancienne valeur — review adversariale
                // Q5). Idempotent si aucune sélection.
                self._refreshSelectionSummary();
                // L'édition mute td.textContent SANS passer par _rebuildBody :
                // si la nouvelle valeur contient (ou ne contient plus) un terme
                // d'anonymisation, le marquage serait stale. On invalide le
                // skip-cache et on re-applique (coalescé par rAF) —
                // review adversariale tâche #24.
                self._anonMarkerFingerprint = null;
                self._applyAnonymizationCellMarkers();
            }
            td.classList.add('grid-cell-editable');
            // Auto-fill ghost :
            // - feuille blanche : on relance le ghost après 3s (assistance active)
            // - feuille copilot (dashboard non-blank) : on fige _autoFillCompleted,
            //   l'édition manuelle est volontaire, le ghost ne doit pas
            //   repasser par-dessus la saisie
            if (self._isDashboardSheet) {
                if (self._autoFillAbort) self._autoFillAbort.abort();
                clearTimeout(self._autoFillTimer);
                if (self._isBlankSheet) {
                    self._autoFillCompleted = false;
                    self._autoFillPending = false;
                    self._autoFillTimer = setTimeout(function() {
                        self._triggerAutoFill();
                    }, 3000);
                } else {
                    self._autoFillCompleted = true;
                    self._autoFillPending = false;
                }
            }
        };
        // Blur : commit uniquement si l'utilisateur clique sur une autre cellule
        // de la grille. Sinon (clic ailleurs, changement de fenêtre), garder l'input.
        input.addEventListener('blur', function() {
            setTimeout(function() {
                if (committed || !input.parentNode) return;
                // Si le focus est allé sur une autre cellule de la grille → commit
                var active = document.activeElement;
                var clickedCell = active && active.closest
                    && active.closest('td[data-row]');
                if (clickedCell && self.tbodyEl.contains(clickedCell)) {
                    commit(true);
                    return;
                }
                // Sinon garder l'input ouvert
                input.focus();
            }, 50);
        });
        input.addEventListener('keydown', function(e) {
            // Navigate suggestions with arrows
            if (dropdown) {
                var items = dropdown.querySelectorAll('.grid-cell-suggestion-item');
                if (e.key === 'ArrowDown') {
                    e.preventDefault();
                    selectedIdx = Math.min(selectedIdx + 1, items.length - 1);
                    for (var i = 0; i < items.length; i++) items[i].classList.toggle('active', i === selectedIdx);
                    return;
                }
                if (e.key === 'ArrowUp') {
                    e.preventDefault();
                    selectedIdx = Math.max(selectedIdx - 1, 0);
                    for (var i2 = 0; i2 < items.length; i2++) items[i2].classList.toggle('active', i2 === selectedIdx);
                    return;
                }
                if (e.key === 'Enter' && selectedIdx >= 0 && items[selectedIdx]) {
                    e.preventDefault();
                    applySuggestion(items[selectedIdx].textContent);
                    return;
                }
            }
            if (e.key === 'Enter') {
                e.preventDefault();
                doCommit();
                if (input.parentNode) input.remove();
            }
            if (e.key === 'Escape') {
                if (dropdown) { closeSuggestions(); }
                else { input.value = oldVal === 'null' ? '' : oldVal; doCommit(); if (input.parentNode) input.remove(); }
            }
            if (e.key === 'Tab') {
                e.preventDefault();
                doCommit();
                if (input.parentNode) input.remove();
                var nextTd = e.shiftKey ? td.previousElementSibling : td.nextElementSibling;
                if (nextTd && !nextTd.classList.contains('grid-row-num')) {
                    self._startCellEdit(nextTd);
                }
            }
        });
    };

    SqlResultGrid.prototype._startHeaderEdit = function(th) {
        if (th.querySelector('input')) return;
        var colIdx = parseInt(th.getAttribute('data-col'), 10);
        var oldName = this.columns[colIdx] || '';
        var arrow = th.querySelector('.grid-sort-arrow');

        var input = document.createElement('input');
        input.type = 'text';
        input.className = 'grid-cell-input';
        input.value = oldName;
        th.textContent = '';
        th.appendChild(input);
        if (arrow) th.appendChild(arrow);
        input.focus();
        input.select();

        var self = this;
        var commit = function() {
            var newName = input.value.trim() || oldName;
            if (newName === oldName) {
                th.textContent = oldName;
                if (arrow) th.appendChild(arrow);
                th.classList.add('grid-cell-editable');
                return;
            }
            self._pushHistory();
            self.columns[colIdx] = newName;
            th.textContent = newName;
            if (arrow) th.appendChild(arrow);
            th.classList.add('grid-cell-editable');

        };
        input.addEventListener('blur', commit);
        input.addEventListener('keydown', function(e) {
            if (e.key === 'Enter') { e.preventDefault(); input.blur(); }
            if (e.key === 'Escape') { input.value = oldName; input.blur(); }
        });
    };

    // ── Cell suggestions (LLM-powered, cached per cell session) ──

    SqlResultGrid.prototype._fetchCellSuggestions = function(td, callback) {
        var rowIdx = parseInt(td.getAttribute('data-row'), 10);
        var colIdx = parseInt(td.getAttribute('data-col'), 10);
        var colName = (!isNaN(colIdx) && this.columns[colIdx]) ? this.columns[colIdx] : '';

        // Collect tabs context
        var tabsContext = null;
        if (typeof this._options.getTabsContext === 'function') {
            tabsContext = this._options.getTabsContext();
        }

        // Full sheet snapshot: headers + all non-empty cells with row/col position
        // Enriched with source_sql/match/label from _cellDetails (same as copilot)
        var sheetContent = [];
        for (var r = 0; r < Math.min(this.allRows.length, 20); r++) {
            for (var c = 0; c < this.columns.length; c++) {
                var v = this.isArrayFormat ? this.allRows[r][c] : this.allRows[r][this.columns[c]];
                if (v && String(v).trim()) {
                    var entry = {
                        row: r + 1,
                        col: this.columns[c],
                        col_idx: c,
                        value: String(v)
                    };
                    var dk = r + ',' + c;
                    var det = this._cellDetails ? this._cellDetails[dk] : null;
                    if (det) {
                        if (det.sql) entry.source_sql = det.sql;
                        if (det.match) entry.match = det.match;
                        entry.label = det.label || det.description || null;
                    }
                    sheetContent.push(entry);
                }
            }
        }

        var suggestToken = this._beginSync('Suggestion de valeur…');
        var self = this;
        fetch('/api/iris/cell-suggest', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Xsrftoken': _getXsrfCookie()
            },
            body: JSON.stringify({
                column_name: colName,
                cell_position: { row: (rowIdx || 0) + 1, col: colName, col_idx: colIdx },
                columns: this.columns,
                tabs_context: tabsContext,
                sheet_content: sheetContent.length > 0 ? sheetContent : null
            })
        })
        .then(function(resp) { return resp.json(); })
        .then(function(data) {
            self._endSync(suggestToken, false);
            // Provider LLM non configuré : ne pas masquer le cas en
            // « 0 suggestion » silencieux (le user croirait à un bug).
            // Le banner global est déjà affiché ; on ajoute un toast
            // contextuel UNE seule fois par session de grille (dedup via
            // flag instance) pour ne pas spam un user qui tape `=` dans
            // 20 cellules consécutives.
            if (data && data.reason === 'not_configured') {
                if (typeof showToast === 'function' && !self._notConfiguredToastShown) {
                    showToast(data.error || data.message || 'IA non configurée.', 'warning');
                    self._notConfiguredToastShown = true;
                }
                callback([], false);
                return;
            }
            // Reset dedup au prochain succès (admin a fix la config).
            self._notConfiguredToastShown = false;
            callback(data.suggestions || [], !!data.determined);
        })
        .catch(function() {
            self._endSync(suggestToken, true);
            callback([], false);
        });
    };

    // ── AI cell fill (=instruction) ──

    SqlResultGrid.prototype._fillCellWithAI = function(td, instruction) {
        var self = this;
        td.textContent = '';
        td.classList.add('grid-cell-ai-loading');
        var spinner = document.createElement('span');
        spinner.className = 'grid-cell-spinner';
        spinner.textContent = '\u2026';
        td.appendChild(spinner);

        var colIdx = parseInt(td.getAttribute('data-col'), 10);
        var rowIdx = parseInt(td.getAttribute('data-row'), 10);
        var colName = (!isNaN(colIdx) && this.columns[colIdx]) ? this.columns[colIdx] : ('Colonne ' + (colIdx + 1));

        // Collect tabs context
        var tabsContext = null;
        if (typeof this._options.getTabsContext === 'function') {
            tabsContext = this._options.getTabsContext();
        }

        // B4 guard: don't send if no context at all
        if (!tabsContext && !this.sql) {
            td.classList.remove('grid-cell-ai-loading');
            td.textContent = '';
            return;
        }

        // Collect sheet_content enriched with _cellDetails (same as copilot/suggestions)
        var sheetContent = [];
        for (var r = 0; r < Math.min(this.allRows.length, 20); r++) {
            for (var c = 0; c < this.columns.length; c++) {
                var v = this.isArrayFormat ? this.allRows[r][c] : this.allRows[r][this.columns[c]];
                if (v && String(v).trim()) {
                    var cellEntry = {
                        row: r + 1,
                        col: this.columns[c],
                        value: String(v)
                    };
                    var detailKey = r + ',' + c;
                    var detail = this._cellDetails ? this._cellDetails[detailKey] : null;
                    if (detail) {
                        if (detail.sql) cellEntry.source_sql = detail.sql;
                        if (detail.match) cellEntry.match = detail.match;
                        cellEntry.label = detail.label || detail.description || null;
                    }
                    sheetContent.push(cellEntry);
                }
            }
        }

        var payload = {
            sql: this.sql || '',
            instruction: 'Remplis la cellule "' + colName + '" avec : ' + instruction,
            columns: this.columns,
            display_state: {},
            tabs_context: tabsContext,
            sheet_content: sheetContent.length > 0 ? sheetContent : null,
            sheet_context: {
                target_cell: { row: (!isNaN(rowIdx) ? rowIdx + 1 : null), col: colName, col_idx: colIdx },
                operation: 'FILL_SINGLE_CELL_ONLY',
                active_tab: (tabsContext && tabsContext.length > 0) ? tabsContext[0].label : 'Active'
            }
        };

        fetch('/api/iris/result-modify', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Xsrftoken': _getXsrfCookie()
            },
            body: JSON.stringify(payload)
        })
        .then(function(resp) { return resp.json(); })
        .then(function(data) {
            if (!document.contains(td)) return;
            td.classList.remove('grid-cell-ai-loading');
            td.textContent = '';
            var value = '';
            var hasFullResult = false;

            // Provider LLM non configuré : cell vide propre + toast.
            // Sans ce branch, le ``data.error`` ci-dessous afficherait
            // "⚠ L'IA n'est pas configurée..." DANS la cellule, ce qui
            // est moche et trompeur (l'user croit à une valeur "⚠ ...").
            // Le banner global gère l'info globale ; ici on garde la
            // cellule propre et on signale l'action manquée via toast
            // (dedup via flag instance — un user qui retry 5x ne voit
            // qu'1 toast).
            if (data && data.reason === 'not_configured') {
                if (typeof showToast === 'function' && !self._notConfiguredToastShown) {
                    showToast(data.error || data.message || 'IA non configurée.', 'warning');
                    self._notConfiguredToastShown = true;
                }
                td.classList.add('grid-cell-editable');
                return;
            }
            // Reset dedup au prochain succès (admin a fix la config).
            self._notConfiguredToastShown = false;

            if (data.error) {
                value = '⚠ ' + data.error;
            } else if (data.type === 'cell' && data.value != null) {
                value = String(data.value);
                hasFullResult = !!data.sql;
            } else if (data.type === 'sql' && data.rows && data.rows.length > 0) {
                var firstRow = data.rows[0];
                value = String(Array.isArray(firstRow) ? firstRow[0] : Object.values(firstRow)[0]);
                hasFullResult = true;
            } else if (data.type === 'fill' && data.cells) {
                if (data.cells.length > 0 && data.cells[0].value != null) {
                    value = String(data.cells[0].value);
                }
            } else if (data.type === 'fill_sql' && data.cells) {
                // fill_sql response: backend already executed SQL and matched cells
                if (data.cells.length > 0 && data.cells[0].value != null) {
                    value = String(data.cells[0].value);
                    hasFullResult = !!data.cells[0].sql;
                }
            } else if (data.type === 'multi' && data.cells) {
                // multi response: labels + values merged by backend
                var targetRow = (!isNaN(rowIdx) ? rowIdx + 1 : null);
                var targetCol = colName;
                var found = null;
                for (var ci = 0; ci < data.cells.length; ci++) {
                    var mc = data.cells[ci];
                    if (mc.row === targetRow && mc.col === targetCol && mc.value != null) {
                        found = mc; break;
                    }
                }
                if (found) {
                    value = String(found.value);
                } else if (data.cells.length > 0 && data.cells[0].value != null) {
                    value = String(data.cells[0].value);
                }
            } else {
                value = '';
                td.title = data.description || 'Calcul impossible';
            }

            // Affichage visuel français, stockage machine
            var numV = Number(value);
            td.textContent = (value && !isNaN(numV) && isFinite(numV)) ? formatNumber(numV) : value;
            td.classList.add('grid-cell-editable');

            // Save to allRows (format machine)
            var rowIdx = parseInt(td.getAttribute('data-row'), 10);
            if (!isNaN(rowIdx) && !isNaN(colIdx) && self.allRows[rowIdx]) {
                if (self.isArrayFormat) self.allRows[rowIdx][colIdx] = value;
                else self.allRows[rowIdx][self.columns[colIdx]] = value;
                self.displayRows = self.allRows.slice();
                // Écriture asynchrone (la réponse IA arrive après coup) : si une
                // sélection est active (ex. colonne entière sélectionnée pendant
                // l'attente réseau), recalculer le résumé pour intégrer la nouvelle
                // valeur (idempotent si aucune sélection — review adversariale).
                self._refreshSelectionSummary();
                // Contenu injecté par l'IA hors _rebuildBody : il peut contenir
                // un terme d'anonymisation → re-marquage (rAF-coalescé) sinon
                // marquage stale (review adversariale tâche #24).
                self._anonMarkerFingerprint = null;
                self._applyAnonymizationCellMarkers();
            }

            // Store detail data for this cell (for copy/paste preservation)
            if (hasFullResult) {
                var detailData = {
                    sql: data.sql || '',
                    columns: data.columns || [],
                    rows: data.rows || [],
                    row_count: data.row_count || (data.rows ? data.rows.length : 0),
                    description: data.description || instruction
                };
                var cellKey = rowIdx + ',' + colIdx;
                self._cellDetails[cellKey] = detailData;
                if (self._cellHasRealDetail(detailData)) {
                    td.classList.add('grid-cell-has-detail');
                }
            }

            // Open full result in a new tab (with SQL query visible)
            if (hasFullResult && typeof self._options.onNewTab === 'function') {
                var tabCols, tabRows, tabSql, tabCount;
                if (data.type === 'cell' && data.sql) {
                    // Cell type: re-execute as full query to get all rows
                    tabCols = data.columns || [colName];
                    tabRows = data.rows || [[data.value]];
                    tabSql = data.sql;
                    tabCount = tabRows.length;
                } else {
                    tabCols = data.columns || [];
                    tabRows = data.rows || [];
                    tabSql = data.sql || '';
                    tabCount = data.row_count || tabRows.length;
                }
                var label = (data.description || instruction).substring(0, 30);
                if (tabCount) label += ' (' + tabCount + ')';
                self._options.onNewTab(label, tabCols, tabRows, tabSql, tabCount);
            }

            // Relancer l'auto-fill immédiatement pour mettre à jour les ghosts
            if (self._isDashboardSheet && value) {
                if (self._autoFillAbort) self._autoFillAbort.abort();
                self._autoFillCompleted = false;
                self._autoFillPending = false;
                clearTimeout(self._autoFillTimer);
                self._triggerAutoFill();
            }
        })
        .catch(function(err) {
            if (!document.contains(td)) return;
            td.classList.remove('grid-cell-ai-loading');
            td.textContent = '⚠ Erreur';
            td.classList.add('grid-cell-editable');
        });
    };

    SqlResultGrid.prototype._buildFooter = function() {
        var self = this;

        // ── Zone d'info sélection : somme / moyenne / count des cellules
        // sélectionnées si elles sont TOUTES numériques. Reste cachée
        // sinon. Alimenté par ``_refreshSelectionSummary`` appelé depuis
        // les points de mutation de la sélection (_selectCell, _deselectCell,
        // _clearSelection, dblclick header).
        var selInfo = document.createElement('div');
        selInfo.className = 'grid-selection-info';
        selInfo.style.cssText =
            'display:none;padding:0.35rem 0.75rem;' +
            'font-size:0.8125rem;color:var(--text-secondary, #374151);' +
            'background:var(--bg-surface-2, rgba(99, 102, 241, 0.05));' +
            'border-top:1px solid var(--border, #e5e7eb);' +
            'font-family:ui-monospace, SFMono-Regular, Menlo, monospace;' +
            'letter-spacing:0.01em;';
        this.container.appendChild(selInfo);
        this._selectionInfoEl = selInfo;

        // ── SQL collapsible with inline "Save query to datastore" button ──
        if (this.sql) {
            var details = document.createElement('details');
            details.className = 'iris-sql-details';

            var summary = document.createElement('summary');
            summary.textContent = 'Voir le SQL exécuté';

            // Le bouton d'action est placé DANS le contenu du <details>
            // (pas dans <summary>) pour deux raisons :
            //  1) Clarté : il apparaît juste au-dessus du code SQL qu'il va
            //     enregistrer → l'utilisateur comprend que c'est BIEN la
            //     requête SQL qui sera sauvegardée, pas les données.
            //  2) Ergonomie : plus de clic à "bloquer" sur <summary>, plus
            //     de risque d'ouvrir/fermer le details par erreur.
            var actionRow = document.createElement('div');
            actionRow.className = 'iris-sql-action-row';
            actionRow.style.cssText =
                'display:flex;align-items:center;justify-content:space-between;' +
                'gap:0.5rem;margin:0.5rem 0;flex-wrap:wrap;';

            var hint = document.createElement('span');
            // Snapshot importé : le SQL affiché est celui de la feuille SOURCE
            // (provenance), pas une requête que CETTE feuille a exécutée.
            hint.textContent = this._isImportedSnapshot()
                ? 'Requête SQL d\'origine (feuille importée) :'
                : 'Requête SQL exécutée :';
            hint.style.cssText = 'font-size:0.7rem;text-transform:uppercase;letter-spacing:0.02em;color:var(--text-muted,#6b7280);font-weight:500;';

            // Wrapper droite pour deux boutons (Modifier, Enregistrer) alignés.
            var actionBtns = document.createElement('div');
            actionBtns.style.cssText = 'display:flex;gap:0.4rem;flex-wrap:wrap;';

            var editBtn = document.createElement('button');
            var EDIT_IDLE_LABEL = '<i class="bi bi-pencil"></i> Modifier &amp; réexécuter';
            editBtn.type = 'button';
            editBtn.className = 'iris-copy-sql-btn iris-edit-sql-btn';
            editBtn.innerHTML = EDIT_IDLE_LABEL;
            editBtn.title = 'Modifier la requête SQL puis la réexécuter';
            editBtn.setAttribute('aria-label', 'Modifier la requête SQL et la réexécuter');
            editBtn.addEventListener('click', function(e) {
                e.stopPropagation();
                if (typeof window.openSqlEditorModal !== 'function') {
                    if (typeof window.showToast === 'function') {
                        window.showToast('Éditeur SQL indisponible.', 'error');
                    }
                    return;
                }
                window.openSqlEditorModal({
                    sql: self.sql,
                    filename: null, // /iris : pas de fichier backing par défaut
                    allowSave: false,
                    onSuccess: function(payload) {
                        try {
                            // Réutilise le pipeline copilot (push history pour undo,
                            // rebuild header + body, fetch column metadata si GROUP BY).
                            self._applyCopilotResult({
                                type: 'sql',
                                sql: payload.sql,
                                columns: payload.columns,
                                rows: payload.rows,
                                row_count: payload.row_count,
                                truncated: payload.truncated,
                                description: 'Requête modifiée',
                            });
                            // Reflète le nouveau SQL dans le <pre><code> du details.
                            if (self._sqlCodeEl) {
                                self._sqlCodeEl.textContent = formatSql(self.sql);
                            }
                            // Petit badge "(modifiée)" sur la summary pour indiquer que
                            // ce qu'on voit n'est plus le SQL d'origine. Idempotent : si
                            // l'utilisateur réédite plusieurs fois, on ne re-crée pas le
                            // span.
                            if (self._sqlDetailsEl) {
                                var summary = self._sqlDetailsEl.querySelector('summary');
                                if (summary && !summary.querySelector('.iris-sql-modified-badge')) {
                                    var badge = document.createElement('span');
                                    badge.className = 'iris-sql-modified-badge';
                                    badge.textContent = ' (modifiée)';
                                    badge.style.cssText =
                                        'font-size:0.7rem;color:var(--text-muted,#6b7280);'
                                        + 'font-weight:400;font-style:italic;margin-left:0.25rem;';
                                    summary.appendChild(badge);
                                }
                            }
                            // Feature « feuilles SQL » (widget dashboard) :
                            // persiste le nouveau SQL de CETTE feuille.
                            // payload.sql = requête D'ORIGINE saisie (jamais
                            // filtre-wrappée). No-op hors dashboard / feuille
                            // non-SQL (callback absent).
                            if (typeof self._options.onSqlAuthored === 'function') {
                                self._options.onSqlAuthored(payload.sql);
                            }
                        } catch (err) {
                            // Le grid lui-même a probablement été remplacé entre temps.
                            // Fallback : afficher un toast pour signaler le succès.
                            if (typeof window.showToast === 'function') {
                                window.showToast('Requête exécutée.', 'success');
                            }
                        }
                    },
                });
            });

            var saveBtn = document.createElement('button');
            var IDLE_LABEL = '<i class="bi bi-floppy"></i> Enregistrer cette requête';
            saveBtn.type = 'button';
            saveBtn.className = 'iris-copy-sql-btn';
            saveBtn.innerHTML = IDLE_LABEL;
            saveBtn.title = 'Enregistrer la requête SQL dans votre datastore';
            saveBtn.addEventListener('click', function(e) {
                e.stopPropagation();
                _saveSqlToDatastore(self.sql, saveBtn, IDLE_LABEL);
            });

            // Snapshot importé : SQL en LECTURE SEULE — « Modifier &
            // réexécuter » exécuterait la requête de PROVENANCE sur la BDD
            // courante et REMPLACERAIT les lignes importées (+ éditions
            // manuelles) par un jeu de données potentiellement différent,
            // sans avertissement (revue adversariale F1, données fausses
            // silencieuses). « Enregistrer cette requête » reste : il ne
            // touche pas aux données, il copie juste le SQL au datastore.
            if (!this._isImportedSnapshot()) {
                actionBtns.appendChild(editBtn);
            }
            actionBtns.appendChild(saveBtn);
            actionRow.appendChild(hint);
            actionRow.appendChild(actionBtns);

            var pre = document.createElement('pre');
            var code = document.createElement('code');
            code.textContent = formatSql(this.sql);
            pre.appendChild(code);

            details.appendChild(summary);
            details.appendChild(actionRow);
            details.appendChild(pre);
            this.container.appendChild(details);
            this._sqlDetailsEl = details;
            this._sqlCodeEl = code;
        }

        // ── Copilot bar — AI-powered result modification ──
        // role="group" + aria-label = landmark sémantique pour SR sans
        // imposer un contrat clavier qu'on ne respecte pas. NB : role="toolbar"
        // exigerait roving tabindex (1 tabindex=0 + ArrowLeft/Right) ET
        // n'autorise pas de <textarea> dans ses descendants (WAI-ARIA APG).
        // "group" donne le bénéfice landmark sans ces contraintes.
        var bar = document.createElement('div');
        bar.className = 'grid-copilot-bar';
        bar.setAttribute('role', 'group');
        bar.setAttribute('aria-label', 'Assistant copilot pour les résultats');

        // Undo button — title (tooltip souris) + aria-label (lecteur d'écran).
        // Le glyph ↩ est purement visuel, sans aria-label le SR lit "bouton"
        // sans contexte. title seul est ignoré par certains SR mobiles.
        var btnUndo = document.createElement('button');
        btnUndo.type = 'button';
        btnUndo.className = 'grid-copilot-undo';
        btnUndo.title = 'Annuler (Ctrl+Z)';
        btnUndo.setAttribute('aria-label', 'Annuler la dernière action (Ctrl+Z)');
        btnUndo.setAttribute('aria-keyshortcuts', 'Control+Z');
        btnUndo.textContent = '↩';
        btnUndo.disabled = true;
        btnUndo.addEventListener('click', function() { self._copilotUndo(); });
        bar.appendChild(btnUndo);
        this._copilotUndoBtn = btnUndo;

        // Redo button
        var btnRedo = document.createElement('button');
        btnRedo.type = 'button';
        btnRedo.className = 'grid-copilot-redo';
        btnRedo.title = 'Rétablir (Ctrl+Y)';
        btnRedo.setAttribute('aria-label', 'Rétablir l\'action annulée (Ctrl+Y)');
        btnRedo.setAttribute('aria-keyshortcuts', 'Control+Y');
        btnRedo.textContent = '↪';
        btnRedo.disabled = true;
        btnRedo.addEventListener('click', function() { self._copilotRedo(); });
        bar.appendChild(btnRedo);
        this._copilotRedoBtn = btnRedo;

        // ── Zone "input + anon discret + send" ──
        // Pattern "bitmoji sur Snap" : le bouton de confidentialité vit
        // discrètement à droite de l'input, partiellement caché derrière
        // le submit. Il sort de sa cachette (slide-out + fade-in + scale-up)
        // quand la souris entre dans la send-area, ET avec plus d'emphase
        // s'il y a des termes à reviewer. Badge rouge toujours visible si
        // pending > 0 pour signaler sans être intrusif.
        var sendArea = document.createElement('div');
        sendArea.className = 'grid-copilot-send-area';
        sendArea.style.cssText =
            'position:relative;flex:1;display:flex;align-items:flex-end;gap:4px;';

        // Textarea — aria-label explicite pour les lecteurs d'écran :
        // le placeholder est NON FIABLE pour l'annonce SR (lu uniquement
        // si le champ est vide ET focus, et certains SR ne le lisent pas
        // du tout). Le <label> serait l'idéal mais coût visuel important
        // pour 1 caractère gagné — aria-label est le bon compromis ici.
        var input = document.createElement('textarea');
        input.className = 'grid-copilot-input';
        input.placeholder = 'Demande à Iris\u2026';
        input.setAttribute('aria-label', 'Demande à Iris');
        input.rows = 1;
        input.autocomplete = 'off';
        input.spellcheck = true;
        input.addEventListener('input', function() {
            this.style.height = 'auto';
            this.style.height = Math.min(this.scrollHeight, 80) + 'px';
            sendBtn.disabled = !this.value.trim();
            // Reset l'index de navigation historique : l'user a tapé
            // quelque chose, il n'est plus en train de naviguer dans
            // ses anciens prompts.
            self._copilotPromptHistoryIdx = null;
        });
        // IME composition guard : un user CJK (chinois/japonais/coréen) qui
        // tape Enter pour VALIDER une syllabe en cours de composition ne
        // doit PAS déclencher le submit. Sans ce flag, sa requête partirait
        // à chaque syllabe terminée — inutilisable. ``compositionend`` est
        // émis APRÈS le keyup correspondant, donc on capture l'état au
        // moment du keydown via ``e.isComposing`` (spec moderne) + le flag
        // local en fallback pour les navigateurs qui ne settent pas le
        // flag de manière fiable.
        input.addEventListener('compositionstart', function() {
            self._copilotInputComposing = true;
        });
        input.addEventListener('compositionend', function() {
            self._copilotInputComposing = false;
        });
        // Filet de sécurité : si l'IME est interrompu (user clic outside
        // sans valider/canceller la composition), compositionend n'est
        // pas garanti d'être émis sur tous les browsers/IME. Le flag
        // resterait true et bloquerait Enter indéfiniment. Reset au blur.
        input.addEventListener('blur', function() {
            self._copilotInputComposing = false;
        });
        input.addEventListener('keydown', function(e) {
            if (e.key === 'Enter' && !e.shiftKey) {
                // Skip si IME en cours de composition (cf. listeners
                // compositionstart/end). e.isComposing est la spec
                // moderne ; self._copilotInputComposing est notre filet
                // de sécurité pour les browsers où le flag arrive trop
                // tard ou n'est pas posé.
                if (e.isComposing || self._copilotInputComposing) {
                    return;
                }
                e.preventDefault();
                if (this.value.trim()) self._sendCopilotRequest(this.value.trim());
                return;
            }
            // Escape : vide la textarea + reset l'auto-resize. Standard
            // moderne (ChatGPT, Cursor). Ne fait rien si déjà vide.
            if (e.key === 'Escape' && this.value) {
                e.preventDefault();
                this.value = '';
                this.style.height = 'auto';
                sendBtn.disabled = true;
                self._copilotPromptHistoryIdx = null;
                return;
            }
            // Navigation historique avec ↑/↓ — pattern moderne (ChatGPT,
            // Cursor, terminal). Conditions de déclenchement :
            //   ↑ : textarea vide OU curseur en position 0 (sinon ↑ doit
            //       garder son comportement natif = ligne précédente en
            //       multi-ligne)
            //   ↓ : textarea vide OU curseur en fin de texte
            // L'index de navigation est tracké sur l'instance grille
            // pour survivre aux re-keydown.
            if (e.key === 'ArrowUp') {
                var atStart = this.selectionStart === 0 && this.selectionEnd === 0;
                if (this.value === '' || atStart) {
                    var historyUp = _loadCopilotPromptHistory();
                    if (historyUp.length === 0) return;
                    e.preventDefault();
                    var curIdx = self._copilotPromptHistoryIdx;
                    var nextIdx = (curIdx === null || curIdx === undefined)
                        ? historyUp.length - 1
                        : Math.max(0, curIdx - 1);
                    self._copilotPromptHistoryIdx = nextIdx;
                    this.value = historyUp[nextIdx];
                    // Re-trigger auto-resize via l'event 'input' (le
                    // listener ci-dessus reset aussi l'idx, donc on doit
                    // le re-poser APRÈS — d'où le timing).
                    this.style.height = 'auto';
                    this.style.height = Math.min(this.scrollHeight, 80) + 'px';
                    sendBtn.disabled = false;
                    // Curseur en fin pour permettre édition immédiate
                    var endPos = this.value.length;
                    this.setSelectionRange(endPos, endPos);
                    // Restaure l'index (l'event 'input' du setter aurait
                    // pu le reset, mais setter de .value ne déclenche pas
                    // d'event 'input' programmatiquement — ok).
                    self._copilotPromptHistoryIdx = nextIdx;
                    return;
                }
            }
            if (e.key === 'ArrowDown') {
                var atEnd = this.selectionStart === this.value.length
                    && this.selectionEnd === this.value.length;
                if ((this.value === '' || atEnd)
                    && self._copilotPromptHistoryIdx !== null
                    && self._copilotPromptHistoryIdx !== undefined) {
                    e.preventDefault();
                    var historyDown = _loadCopilotPromptHistory();
                    var nextDown = self._copilotPromptHistoryIdx + 1;
                    if (nextDown >= historyDown.length) {
                        // Fin de l'historique → input vide (l'user "sort"
                        // de la navigation pour taper du neuf).
                        self._copilotPromptHistoryIdx = null;
                        this.value = '';
                        this.style.height = 'auto';
                        sendBtn.disabled = true;
                    } else {
                        self._copilotPromptHistoryIdx = nextDown;
                        this.value = historyDown[nextDown];
                        this.style.height = 'auto';
                        this.style.height = Math.min(this.scrollHeight, 80) + 'px';
                        sendBtn.disabled = false;
                        var endPos2 = this.value.length;
                        this.setSelectionRange(endPos2, endPos2);
                    }
                    return;
                }
            }
            // Shift+Enter : laisse le browser-default insérer le \n.
            // L'event 'input' suivant déclenche l'auto-resize via le
            // listener ci-dessus, donc rien à faire ici.
        });
        sendArea.appendChild(input);
        this._copilotInput = input;

        // Bouton "Confidentialité" discret : petit, semi-transparent,
        // positionné en absolute à côté du submit. Animation hover de la
        // sendArea le fait "sortir" (slide-out + fade-in).
        var btnAnon = document.createElement('button');
        btnAnon.type = 'button';
        btnAnon.className = 'grid-copilot-anon';
        btnAnon.title = 'Confidentialité — choisir les termes à anonymiser';
        // Accessibilité : le bouton étant discret (opacity 0.35, petit),
        // un user clavier ou avec lecteur d'écran doit quand même pouvoir
        // y accéder. tabindex=0 + aria-label explicite.
        btnAnon.setAttribute('aria-label', 'Ouvrir le panneau de confidentialité des termes');
        btnAnon.tabIndex = 0;
        // ``padding-top: 10px`` : décale l'icône vers le bas pour compenser
        // l'illusion optique que crée le badge rouge en haut-droite.
        // Le SVG reste centré par le flex dans l'espace restant.
        btnAnon.style.cssText =
            'position:absolute;bottom:4px;right:40px;' +
            'width:26px;height:26px;padding:10px 0 0 0;' +
            'display:inline-flex;align-items:center;justify-content:center;' +
            'border:none;background:transparent;cursor:pointer;' +
            'color:var(--text-secondary, #374151);' +
            'opacity:0.35;transform:scale(0.8) translateX(10px);' +
            'transition:opacity 180ms ease, transform 240ms cubic-bezier(0.34, 1.56, 0.64, 1);' +
            'z-index:2;border-radius:50%;';
        // SVG cadenas (style Heroicons) — rendu cohérent cross-plateforme,
        // s'adapte au thème via currentColor. ``display:block`` neutralise
        // l'alignement baseline SVG.
        btnAnon.innerHTML =
            '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" ' +
            'fill="none" stroke="currentColor" stroke-width="2" ' +
            'stroke-linecap="round" stroke-linejoin="round" ' +
            'width="14" height="14" aria-hidden="true" ' +
            'style="display:block;">' +
            '<rect x="4" y="11" width="16" height="10" rx="2"/>' +
            '<path d="M8 11V8a4 4 0 0 1 8 0v3"/>' +
            '</svg>';
        // Focus clavier : le bouton "sort" de sa cachette pour être visible
        // à l'utilisateur qui navigue au Tab.
        btnAnon.addEventListener('focus', function() {
            btnAnon.style.opacity = '1';
            btnAnon.style.transform = 'scale(1.05) translateX(0)';
            btnAnon.style.outline = '2px solid var(--brand, #2563eb)';
            btnAnon.style.outlineOffset = '2px';
        });
        btnAnon.addEventListener('blur', function() {
            btnAnon.style.outline = '';
            btnAnon.style.outlineOffset = '';
            // Fix : si l'user est sorti via Tab (sans jamais survoler la
            // sendArea), on remet le bouton caché. Sinon laisse hideAnon
            // gérer via mouseleave.
            if (!sendArea.matches(':hover')) hideAnon();
        });
        btnAnon.addEventListener('click', function(e) {
            e.stopPropagation();
            self._openAnonymizationPanel();
        });
        // Badge discret : petite pastille en haut-droite. Dimensions
        // délibérément compactes (11×11, font 7px) pour ne PAS déséquilibrer
        // visuellement l'icône — un badge trop gros donne l'illusion optique
        // que le SVG est décentré. Positionné près du corps (top -1, right -1)
        // pour rester lisible sans trop déborder.
        var anonBadge = document.createElement('span');
        anonBadge.className = 'grid-copilot-anon-badge';
        anonBadge.style.cssText =
            'position:absolute;top:-1px;right:-1px;min-width:11px;height:11px;' +
            'padding:0 2px;border-radius:6px;background:#dc2626;color:#fff;' +
            'font-size:7px;font-weight:700;line-height:11px;text-align:center;' +
            'box-sizing:border-box;display:none;pointer-events:none;';
        btnAnon.appendChild(anonBadge);
        sendArea.appendChild(btnAnon);
        this._copilotAnonBtn = btnAnon;
        this._copilotAnonBadge = anonBadge;

        // Send/Stop button — alterne entre les deux états selon le run en cours.
        // Send (➤) : envoie l'instruction si textarea non vide.
        // Stop (■) : annule le run en cours (POST /api/iris/result-cancel +
        // abort fetch local). Le bouton garde son emplacement (pas de switch
        // d'élément DOM) pour éviter le flash visuel ; seule l'icône + le
        // title + la classe changent dans _setCopilotProcessing.
        var sendBtn = document.createElement('button');
        sendBtn.type = 'button';
        sendBtn.className = 'grid-copilot-send';
        sendBtn.title = 'Envoyer';
        sendBtn.setAttribute('aria-label', 'Envoyer la demande au copilot');
        sendBtn.innerHTML = '&#10148;'; // ➤
        sendBtn.disabled = true;
        sendBtn.addEventListener('click', function() {
            // Si processing en cours, c'est un Stop ; sinon Send.
            if (self._copilotProcessingActive) {
                self._cancelCopilotRun();
                return;
            }
            var text = input.value.trim();
            if (text) self._sendCopilotRequest(text);
        });
        sendArea.appendChild(sendBtn);
        bar.appendChild(sendArea);
        this._copilotSendBtn = sendBtn;
        this._copilotSendArea = sendArea;

        // Animation hover : le bouton anon sort de sa cachette. Plus
        // emphatique si pending > 0 (scale + fade complet) ; sinon juste
        // opacity légère pour rappeler qu'il existe.
        function showAnon() {
            var hasPending = self._anonPendingTerms
                ? self._anonPendingTerms().length > 0 : false;
            if (hasPending) {
                btnAnon.style.opacity = '1';
                btnAnon.style.transform = 'scale(1.1) translateX(0)';
            } else {
                btnAnon.style.opacity = '0.65';
                btnAnon.style.transform = 'scale(0.9) translateX(4px)';
            }
        }
        function hideAnon() {
            btnAnon.style.opacity = '0.35';
            btnAnon.style.transform = 'scale(0.8) translateX(10px)';
        }
        sendArea.addEventListener('mouseenter', showAnon);
        sendArea.addEventListener('mouseleave', hideAnon);
        btnAnon.addEventListener('mouseenter', showAnon);
        input.addEventListener('focus', showAnon);

        this.container.appendChild(bar);
        this._copilotBar = bar;

        // Status line (below bar) — région ARIA live pour que les lecteurs
        // d'écran annoncent automatiquement les changements :
        //   - "Modification en cours…" / subject de plan_in_progress
        //   - "Annulé."
        //   - "Erreur : …" / "Succès : …"
        //   - Messages anonymisation (ANON_PENDING_REVIEW, etc.)
        // Sans aria-live, un user qui clique Envoyer et n'a pas de retour
        // visuel n'entend rien — il ne sait pas si sa demande est partie.
        //
        // role="status" implique aria-live="polite" + aria-atomic="true"
        // (ARIA 1.2) → pas besoin de les répéter explicitement. Les writes
        // de textContent côté polling doivent gate sur égalité (cf
        // _startCopilotProgressPoll) pour ne pas spammer le SR à chaque
        // tick de 1s même quand le subject n'a pas changé.
        var status = document.createElement('div');
        status.className = 'grid-copilot-status';
        status.setAttribute('role', 'status');
        this.container.appendChild(status);
        this._copilotStatus = status;

        // ── Tour onboarding 1ère visite — modal explicatif ──
        //
        // Déclenché DANS le build de la copilot-bar (pas au load de page)
        // pour ne pop QUE quand l'user a effectivement une grille avec
        // copilot-bar visible — pas sur /iris si l'user n'a pas encore
        // fait de requête, par exemple.
        //
        // Le composant ``KomptiaOnboarding`` gère la dédup (key v1
        // persistée serveur + localStorage) + l'anti-cascade (max 1
        // modal d'onboarding par session). Pattern aligné avec les
        // 9 autres tours de Komptia (iris_v1, dashboards_v1, etc.).
        // Idempotent : même si _buildCopilotBar est rappelé (rebuild
        // grille), le tour ne ré-affiche qu'une fois.
        if (window.KomptiaOnboarding
            && typeof window.KomptiaOnboarding.start === 'function') {
            try {
                window.KomptiaOnboarding.start({
                    key: 'grille_copilot_v1',
                    title: 'Iris peut transformer vos résultats',
                    steps: [
                        {
                            icon: 'sparkle',
                            title: 'Demandez en français',
                            text: 'Dans la barre en bas du tableau, écrivez ce que vous voulez : trier, filtrer, croiser, comparer, expliquer un chiffre. Iris adapte le SQL et met à jour le classeur.'
                        },
                        {
                            icon: 'chart',
                            title: 'Quelques exemples',
                            text: '« trie par montant décroissant » · « garde les montants > 1000 » · « croise par mois et catégorie » · « pourquoi le total Q4 baisse ? ». Iris peut aussi créer plusieurs onglets en une seule demande (« un onglet par région »).'
                        },
                        {
                            icon: 'rocket',
                            title: 'Cibler une zone précise',
                            text: 'Sélectionnez des cellules avant d\'envoyer pour qu\'Iris travaille uniquement sur cette zone du tableau. Le cadenas à droite vous permet de protéger les noms et valeurs sensibles avant envoi à l\'IA.'
                        },
                        {
                            icon: 'bell',
                            title: 'Annuler et reprendre',
                            text: 'Le bouton Stop arrête Iris à tout moment. Ctrl+Z annule sa dernière action. ↑ et ↓ rappellent vos demandes précédentes pour les réutiliser ou les ajuster.'
                        }
                    ]
                });
            } catch (e) { /* Best-effort — tour facultatif. */ }
        }

        // ── Initialize history with current state (only on first build) ──
        if (!this._history) {
            this._history = new ResultHistory(this._captureState());
        }
        this._updateUndoRedoButtons();

        // Charge le state d'anonymisation depuis la BDD serveur (source
        // de vérité cross-classeurs). Si déjà fetched ou fourni en options,
        // skip le fetch. Le reconcile local suit pour détecter les tokens
        // ajoutés par le classeur courant qui ne seraient pas encore en BDD.
        this._fetchAnonymizationState().finally(function() {
            try { self._reconcileAnonymizationState(); } catch (e) { /* defensive */ }
            self._updateAnonymizationBadge();
            // Si la grille a déjà été rendue, re-render pour appliquer
            // les indicateurs per-cell (classes anon-active/pending) qui
            // dépendent du state fraîchement récupéré.
            if (self.tbodyEl) {
                try { self._renderBody(); } catch (e) { /* defensive */ }
            }
        });

        // Keyboard shortcuts (Ctrl+Z / Ctrl+Y) — attach once only
        if (!this._copilotKbAttached) {
            this._copilotKbAttached = true;
            this.container.addEventListener('keydown', function(e) {
                if ((e.ctrlKey || e.metaKey) && e.key === 'z' && !e.shiftKey) {
                    e.preventDefault();
                    self._copilotUndo();
                } else if ((e.ctrlKey || e.metaKey) && (e.key === 'y' || (e.key === 'z' && e.shiftKey))) {
                    e.preventDefault();
                    self._copilotRedo();
                }
            });
        }
    };

    // ── Copilot — State capture & restore ──

    // Deep clone helper for snapshot state.
    // `structuredClone` (evergreen 2022+) gère array/object nested rapidement.
    // Fallback JSON pour des cas exotiques (non attendu sur allRows qui ne
    // contient que strings/numbers/null, mais filet de sécurité). Slice() était
    // shallow et laissait les rows partagées par référence — une mutation
    // ultérieure (ex allRows[r][c] = X) corrompait silencieusement le
    // snapshot précédent. Bug subtil : Ctrl+Z retournait un état FAUX, pas
    // une erreur visible.
    SqlResultGrid.prototype._deepCloneSafe = function(value) {
        if (value == null) return value;
        try { return structuredClone(value); }
        catch (e) { return JSON.parse(JSON.stringify(value)); }
    };

    SqlResultGrid.prototype._captureState = function() {
        return {
            sql: this.sql,
            columns: this.columns.slice(),
            allRows: this._deepCloneSafe(this.allRows),
            totalRowCount: this.totalRowCount,
            isArrayFormat: this.isArrayFormat,
            columnMetadata: this._deepCloneSafe(this.columnMetadata),
            cellDetails: (function(cd) {
                var slim = {};
                for (var k in cd) {
                    if (cd.hasOwnProperty(k)) {
                        slim[k] = {
                            sql: cd[k].sql || '',
                            columns: cd[k].columns || [],
                            row_count: cd[k].row_count || 0,
                            description: cd[k].description || '',
                            match: cd[k].match || null,
                            label: cd[k].label || null,
                            // Champs nécessaires à la reconstruction des rows
                            // de détail à l'export Excel quand `rows` n'est
                            // pas en cache (cellules dashboard/emit_tab :
                            // l'utilisateur n'a pas encore double-cliqué).
                            match_exclude: cd[k].match_exclude || null,
                            source_tab_index: (typeof cd[k].source_tab_index === 'number')
                                ? cd[k].source_tab_index : null,
                            value_column: cd[k].value_column || null,
                            derived_formula: cd[k].derived_formula || null
                        };
                    }
                }
                return slim;
            })(this._cellDetails),
            hiddenCols: new Set(this.hiddenCols),
            columnOrder: this.columnOrder.slice(),
            sortColIndex: this.sortColIndex,
            sortDirection: this.sortDirection,
            isBlankSheet: this._isBlankSheet,
            isDashboardSheet: this._isDashboardSheet,
            truncated: this._truncated,
            truncatedCols: this._truncatedCols || false,
            truncatedColsTotal:
                typeof this._truncatedColsTotal === 'number' ? this._truncatedColsTotal : null,
            filters: JSON.parse(JSON.stringify(this.filters, function(k, v) {
                return v instanceof Set ? Array.from(v) : v;
            })),
            merges: (typeof this.getMerges === 'function' ? this.getMerges() : [])
        };
    };

    SqlResultGrid.prototype._restoreFromState = function(state) {
        if (!state || !state.columns) return; // Defensive guard
        this.sql = state.sql || '';
        this.columns = (state.columns || []).slice();
        // Split light/heavy (grid-store, cf. docs/design/grid_storage_tiered_indexeddb.md) :
        //  - ``state.allRows`` DÉFINI (undo/redo, legacy monolithique, état déjà
        //    hydraté depuis IndexedDB) — y compris ``[]`` pour un résultat
        //    légitimement vide → on l'applique tel quel. Deep clone : sinon une
        //    édition post-undo muterait le snapshot redo-cible (rows partagées
        //    par référence).
        //  - ``state.allRows`` ABSENT (``undefined``) = tier "intention" seul
        //    (les données vivent en IndexedDB, pas encore hydratées OU
        //    indisponibles) → on PRÉSERVE les rows déjà en place (fournies par
        //    le backend au rendu). Sans ça, restaurer l'intention VIDERAIT la
        //    grille (régression données — invariant #1/#2 du design).
        if (state.allRows !== undefined) {
            this.allRows = this._deepCloneSafe(Array.isArray(state.allRows) ? state.allRows : []);
        } else if (!Array.isArray(this.allRows)) {
            this.allRows = [];
        }
        this.totalRowCount = state.totalRowCount || 0;
        this.isArrayFormat = typeof state.isArrayFormat === 'boolean'
            ? state.isArrayFormat
            : (this.allRows.length > 0 && Array.isArray(this.allRows[0]));
        this.columnMetadata = this._deepCloneSafe(state.columnMetadata || null);
        this._cellDetails = state.cellDetails
            ? JSON.parse(JSON.stringify(state.cellDetails))
            : {};
        this.hiddenCols = new Set(state.hiddenCols || []);
        this.columnOrder = (state.columnOrder || []).slice();
        this.sortColIndex = state.sortColIndex;
        this.sortDirection = state.sortDirection;
        if (typeof this.setMerges === 'function') {
            this.setMerges(Array.isArray(state.merges) ? state.merges : []);
        }
        // Restore filters (Sets were serialized as arrays, defensive)
        this.filters = {};
        var raw = state.filters || {};
        for (var key in raw) {
            if (raw.hasOwnProperty(key)) {
                var f = raw[key] || {};
                this.filters[key] = {
                    excluded: new Set(Array.isArray(f.excluded) ? f.excluded : []),
                    excludeNull: typeof f.excludeNull === 'boolean' ? f.excludeNull : false
                };
            }
        }
        this._isBlankSheet = !!state.isBlankSheet;
        this._isDashboardSheet = !!state.isDashboardSheet || !!state.isBlankSheet;
        this._truncated = !!state.truncated;
        this._truncatedCols = !!state.truncatedCols;
        this._truncatedColsTotal =
            typeof state.truncatedColsTotal === 'number' ? state.truncatedColsTotal : null;
        this.displayRows = this.allRows.slice();
        this._detectTypes();
        this._build();
        this._updateUndoRedoButtons();
    };

    SqlResultGrid.prototype._pushHistory = function() {
        // Marqueur « l'utilisateur a muté la grille depuis le rendu ». Posé AVANT
        // le guard _history (une mutation a lieu même si l'undo n'est pas câblé).
        // _pushHistory est le point de passage OBLIGÉ de toute mutation user
        // (édition cellule, add/remove ligne/colonne, tri, filtre, fusion, paste,
        // copilot) et n'est JAMAIS appelé à l'init/build/restore. Sert à
        // _loadPersistedState pour ne pas écraser une édition faite pendant
        // l'hydratation async des données (course ~ms) — sinon perte silencieuse.
        this._userDirtied = true;
        if (!this._history) return;
        // Try/catch défensif : si _captureState throw (structuredClone
        // sur un type non-cloneable, cycle inattendu, mémoire saturée),
        // on logue un warning et on skip le push plutôt que de propager
        // l'exception qui casserait l'action user en cours.
        try {
            this._history.push(this._captureState());
        } catch (e) {
            if (typeof console !== 'undefined' && console.warn) {
                console.warn('[iris-grid] _pushHistory skip:', e && e.message);
            }
            return;
        }
        // Notify workbook-level history
        if (typeof this._options.onSnapshot === 'function') this._options.onSnapshot();
        this._updateUndoRedoButtons();
    };

    SqlResultGrid.prototype._updateUndoRedoButtons = function() {
        // If workbook-level undo is wired, buttons are managed by TabManager
        if (typeof this._options.onUndo === 'function') return;
        if (this._copilotUndoBtn) this._copilotUndoBtn.disabled = !this._history || !this._history.canUndo();
        if (this._copilotRedoBtn) this._copilotRedoBtn.disabled = !this._history || !this._history.canRedo();
    };

    SqlResultGrid.prototype._copilotUndo = function() {
        // Delegate to workbook-level undo if available
        if (typeof this._options.onUndo === 'function') {
            this._options.onUndo();
            return;
        }
        if (!this._history) return;
        var state = this._history.undo();
        if (state) this._restoreFromState(state);
    };

    SqlResultGrid.prototype._copilotRedo = function() {
        // Delegate to workbook-level redo if available
        if (typeof this._options.onRedo === 'function') {
            this._options.onRedo();
            return;
        }
        if (!this._history) return;
        var state = this._history.redo();
        if (state) this._restoreFromState(state);
    };

    // ── Copilot — Send request & apply result ──

    SqlResultGrid.prototype._setCopilotProcessing = function(active) {
        if (!this._copilotBar) return;
        // Compteur global des runs copilot en cours, utilis\u00e9 par le guard
        // ``beforeunload`` pour d\u00e9cider de pr\u00e9venir l'utilisateur. Compteur
        // (et non boolean) car plusieurs grilles peuvent avoir un copilot
        // actif simultan\u00e9ment (multi-onglet workbook). Idempotence via
        // ``this._copilotProcessingActive`` : un appelant qui re-set
        // ``active=true`` deux fois ne doit pas double-incr\u00e9menter.
        try {
            var prevActive = !!this._copilotProcessingActive;
            var nextActive = !!active;
            if (prevActive !== nextActive) {
                this._copilotProcessingActive = nextActive;
                if (typeof window !== 'undefined') {
                    var cur = window.__copilotRunsActive;
                    if (typeof cur !== 'number' || !isFinite(cur) || cur < 0) cur = 0;
                    cur += (nextActive ? 1 : -1);
                    if (cur < 0) cur = 0; // floor d\u00e9fensif
                    window.__copilotRunsActive = cur;
                }
            }
        } catch (e) { /* defensive */ }
        if (active) {
            this._copilotBar.classList.add('grid-copilot-processing');
            this._copilotInput.disabled = true;
            // Le sendBtn reste ACTIF mais bascule en mode Stop. C'est le
            // seul contr\u00f4le qui permet d'annuler le run c\u00f4t\u00e9 serveur ;
            // le d\u00e9sactiver br\u00fblerait $$$ pour rien si l'user veut stopper.
            this._copilotSendBtn.disabled = false;
            this._copilotSendBtn.classList.add('grid-copilot-stop');
            this._copilotSendBtn.title = 'Annuler le run';
            this._copilotSendBtn.setAttribute('aria-label', 'Annuler le run du copilot');
            this._copilotSendBtn.innerHTML = '&#9632;'; // U+25A0 BLACK SQUARE
            this._copilotStatus.textContent = 'Modification en cours\u2026';
            this._copilotStatus.className = 'grid-copilot-status';
            // Démarrer le polling de la todo-list. Si le LLM n'en crée
            // jamais, le texte reste "Modification en cours…" — silence.
            this._startCopilotProgressPoll();
        } else {
            this._copilotBar.classList.remove('grid-copilot-processing');
            this._copilotInput.disabled = false;
            this._copilotSendBtn.classList.remove('grid-copilot-stop');
            this._copilotSendBtn.title = 'Envoyer';
            this._copilotSendBtn.setAttribute('aria-label', 'Envoyer la demande au copilot');
            this._copilotSendBtn.innerHTML = '&#10148;'; // U+27A4
            this._copilotSendBtn.disabled = !this._copilotInput.value.trim();
            this._stopCopilotProgressPoll();
            // Si le status est encore "Annulation…" (race rare entre Stop
            // et fin naturelle du run), on le neutralise pour ne pas
            // laisser l'utilisateur avec un message qui ne reflète plus
            // l'état réel.
            if (this._copilotStatus &&
                this._copilotStatus.textContent === 'Annulation…') {
                this._copilotStatus.textContent = '';
            }
        }
    };

    // ── Cancel d'un run copilot en cours ──
    //
    // Appelé quand l'utilisateur clique sur le bouton Stop (qui remplace
    // visuellement Send pendant un run). Double action :
    //   1) POST /api/iris/result-cancel pour que le serveur arrête sa
    //      boucle LLM. Indispensable : abort() côté client ne signale
    //      RIEN au serveur, qui continuerait à brûler $$$ jusqu'au bout.
    //   2) abort() du fetch local pour libérer l'attente de la réponse.
    //      Le .catch du fetch verra AbortError, le caller saura ignorer.
    SqlResultGrid.prototype._cancelCopilotRun = function() {
        var runId = this._copilotRunId;
        // Stop le polling IMMÉDIATEMENT — sinon un dernier tick (≤1s
        // après le clic Stop) lit `tool_in_use` du store et écrase
        // "Annulation…" puis "Annulé." avec un label stale, donnant
        // l'impression que Stop n'a pas fonctionné. Review adv High #1.
        this._stopCopilotProgressPoll();
        // Feedback immédiat : status + bouton désactivé pour éviter le
        // double-clic. Le serveur peut prendre 1-2s pour propager le
        // CancelledError au tour LLM en cours (inévitable, c'est le coût
        // du tour en vol).
        this._copilotSendBtn.disabled = true;
        if (this._copilotStatus) {
            this._copilotStatus.textContent = 'Annulation…';
            this._copilotStatus.className = 'grid-copilot-status';
        }
        if (runId) {
            // POST best-effort. Pas de retry : si le serveur ne répond
            // pas, abort() local + on_connection_close côté serveur
            // prendront le relais (le serveur détectera la fermeture
            // socket à la prochaine write).
            try {
                fetch('/api/iris/result-cancel', {
                    method: 'POST',
                    credentials: 'same-origin',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-Xsrftoken': _getXsrfCookie(),
                    },
                    body: JSON.stringify({ run_id: runId }),
                }).catch(function() {
                    // Silent : le abort local suffit côté UX. Serveur
                    // verra on_connection_close via le abort du fetch
                    // result-modify ci-dessous.
                });
            } catch (e) { /* defensive */ }
        }
        // Abort le fetch result-modify (libère le .then en attente côté
        // client). Le serveur recevra la fermeture socket → cancel via
        // on_connection_close (defense-in-depth si le POST cancel a raté).
        if (this._copilotAbort) {
            try { this._copilotAbort.abort(); } catch (e) { /* defensive */ }
        }
    };

    // ── Copilot — Polling de la todo-list pendant le run ──
    //
    // Le backend expose /api/iris/task-progress?run_id=X qui retourne la
    // task in_progress courante (s'il y en a). On polle toutes les 1s
    // pendant le run et on remplace "Modification en cours…" par le
    // subject de la task si une in_progress existe. Si aucune, on remet
    // le défaut. Fin du run : clearInterval.

    SqlResultGrid.prototype._startCopilotProgressPoll = function() {
        var self = this;
        if (!this._copilotRunId) return;  // Pas d'id → pas de polling
        // Évite doublon si appelé deux fois d'affilée.
        if (this._copilotPollInterval) return;
        var url = '/api/iris/task-progress?run_id=' + encodeURIComponent(this._copilotRunId);
        var tick = function() {
            fetch(url, { credentials: 'same-origin' })
                .then(function(resp) {
                    if (!resp.ok) return null;
                    return resp.json();
                })
                .then(function(data) {
                    // Garde-fou : ne pas update si le run est fini entre-temps.
                    if (!self._copilotPollInterval) return;
                    if (!data) return;
                    var inProgress = data.task_in_progress;
                    // Règle d'affichage :
                    //   task in_progress → subject seul (pas de préfixe)
                    //   pas d'in_progress → "Modification en cours…" défaut
                    // Guard d'\u00e9galit\u00e9 : sans \u00e7a le polling 1s r\u00e9-\u00e9crit
                    // textContent \u00e0 chaque tick m\u00eame quand la valeur est
                    // identique. Avec role="status" (aria-live polite),
                    // certains lecteurs d'\u00e9cran (NVDA notamment) r\u00e9-annoncent
                    // \u00e0 chaque write \u2192 spam SR insupportable pendant un
                    // run de 30s avec un subject stable.
                    // Cumul plan + tool pour transparence maximale :
                    //   subject + tool  \u2192 "Construire ventes \u2014 Lecture onglet"
                    //   subject seul    \u2192 "Construire ventes"
                    //   tool seul       \u2192 "Lecture onglet"
                    //   rien            \u2192 "Modification en cours\u2026"
                    // L'em-dash s\u00e9pare "ce que je veux faire" (plan) de
                    // "ce que je fais" (outil courant). Les meta tools
                    // (plan_*, done, abandon) sont filtr\u00e9s c\u00f4t\u00e9 backend.
                    var toolInUse = (typeof data.tool_in_use === 'string'
                        && data.tool_in_use) ? data.tool_in_use : null;
                    var subject = (inProgress && inProgress.subject) || '';
                    var nextText;
                    if (subject && toolInUse) {
                        nextText = subject + ' \u2014 ' + toolInUse;
                    } else if (subject) {
                        nextText = subject;
                    } else if (toolInUse) {
                        nextText = toolInUse;
                    } else {
                        nextText = 'Modification en cours\u2026';
                    }
                    if (self._copilotStatus.textContent !== nextText) {
                        self._copilotStatus.textContent = nextText;
                    }
                })
                .catch(function() {
                    // Silencieux : erreurs réseau ponctuelles ne doivent pas
                    // spammer la console ni casser l'UX. La prochaine tick
                    // retentera. Le status reste sur sa valeur précédente.
                });
        };
        // Premier tick immédiat (sinon on attend 1s pour voir la 1ère task).
        tick();
        this._copilotPollInterval = setInterval(tick, 1000);
    };

    SqlResultGrid.prototype._stopCopilotProgressPoll = function() {
        if (this._copilotPollInterval) {
            clearInterval(this._copilotPollInterval);
            this._copilotPollInterval = null;
        }
        this._copilotRunId = null;
    };

    // Génère un identifiant unique pour un run copilot. Utilise
    // crypto.randomUUID() si disponible (évergreen 2022+), sinon fallback
    // timestamp+random — c'est juste un id de polling, pas de la crypto.
    SqlResultGrid.prototype._newCopilotRunId = function() {
        if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
            return crypto.randomUUID();
        }
        return 'run_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 10);
    };

    // ── Anonymisation pilotée utilisateur ───────────────────────────────
    // Le backend (``app/services/anonymization/extract.py``) est la source
    // de vérité pour la logique de tokenisation / auto-décide / validation.
    // Le miroir CÔTÉ CLIENT vit désormais dans
    // ``static/js/anonymization/tokenizer.js`` (window.AnonTokenizer),
    // chargé AVANT ce fichier par les templates ``iris.html``,
    // ``datastore.html``, ``automations/edit.html``.
    //
    // En cas de divergence Py↔JS, le backend gagne (il renvoie
    // 409 ANON_PENDING_REVIEW avec son state réconcilié, qui écrase
    // alors le cache local). Les fixtures contractuelles
    // ``tests/fixtures/anon_tokenizer_contract.json`` et
    // ``anon_auto_pseudo_contract.json`` sont exécutées par
    // ``test_anon_terms.py`` (Python) ET ``test_anon_tokenizer_js.py``
    // (Node) pour bloquer le drift en CI.

    //: Helper interne : retourne le module partagé ou un fallback fail-CLOSED.
    //: Si ``window.AnonTokenizer`` n'est pas chargé (script manquant en
    //: template, race rare) on log un warning UNE fois et retourne un stub
    //: conservateur :
    //:   - ``tokenizeValue`` → ``[]`` : aucun nouveau terme détecté localement,
    //:     ``_anonExtractTerms`` retournera vide. Le backend reprendra la main
    //:     au prochain send (gate 409 ANON_PENDING_REVIEW).
    //:   - ``isAutoDecidable`` → ``false`` : si un caller direct atteint cette
    //:     fonction, on traite comme "user doit trancher" (jamais d'auto-confirm
    //:     silencieux). Cohérent avec la doctrine fail-closed du CLAUDE.md.
    //:   - ``autoPseudoMiddle`` → ``''`` : preview vide plutôt que faux pseudo.
    //:
    //: Le vrai module est mis en cache au premier hit pour éviter des milliers
    //: de lookups ``window.AnonTokenizer`` sur les classeurs lourds (20K+
    //: cellules × _anonTokenize = hot path).
    var _anonModuleCache = null;
    var _anonFallbackWarned = false;
    function _anonModule() {
        if (_anonModuleCache) return _anonModuleCache;
        if (typeof window !== 'undefined' && window.AnonTokenizer) {
            _anonModuleCache = window.AnonTokenizer;
            return _anonModuleCache;
        }
        if (!_anonFallbackWarned) {
            _anonFallbackWarned = true;
            // eslint-disable-next-line no-console
            console.warn(
                'iris-grid: window.AnonTokenizer absent — ' +
                'le tokenize local est désactivé (le backend reprendra). ' +
                'Vérifier que /static/js/anonymization/tokenizer.js est chargé ' +
                'avant /static/js/iris-grid.js dans le template.'
            );
        }
        // NOTE : on ne MET PAS en cache le fallback. Si ``tokenizer.js`` se
        // charge en retard (futur defer/async), un prochain appel pourra
        // trouver le vrai module sans être bloqué sur le stub.
        return {
            tokenizeValue: function() { return []; },
            isAutoDecidable: function() { return false; },
            autoPseudoMiddle: function() { return ''; }
        };
    }

    SqlResultGrid.prototype._anonTokenize = function(value) {
        return _anonModule().tokenizeValue(value);
    };

    SqlResultGrid.prototype._anonAutoPseudoMiddle = function(term, category) {
        // ``category`` (optionnel) permet à `autoPseudoMiddle` de produire un
        // label sémantique (EMAIL/NAME/PHONE/IBAN/…) plutôt que TXT/NUM.
        // Le state du modal Confidentialité l'expose via ``entry.category``
        // (propagé depuis le backend dans :meth:`repository.get_state_for_user`).
        return _anonModule().autoPseudoMiddle(term, category);
    };

    SqlResultGrid.prototype._anonIsAutoDecidable = function(token) {
        return _anonModule().isAutoDecidable(token);
    };

    SqlResultGrid.prototype._anonExtractTerms = function() {
        // Miroir de ``anon_terms.extract_terms`` — même champs scannés.
        var self = this;
        var out = Object.create(null); // Set-like (plus rapide que Set pour grosse cardinalité)
        function addV(v) {
            var toks = self._anonTokenize(v);
            for (var i = 0; i < toks.length; i++) out[toks[i]] = 1;
        }
        function addMatch(m) {
            if (!m || typeof m !== 'object') return;
            for (var k in m) {
                if (!Object.prototype.hasOwnProperty.call(m, k)) continue;
                var v = m[k];
                if (Array.isArray(v)) {
                    for (var i = 0; i < v.length; i++) addV(v[i]);
                } else {
                    addV(v);
                }
            }
        }
        function addRowsArray(rows) {
            if (!Array.isArray(rows)) return;
            for (var r = 0; r < rows.length; r++) {
                var row = rows[r];
                if (Array.isArray(row)) {
                    for (var c = 0; c < row.length; c++) addV(row[c]);
                } else if (row && typeof row === 'object') {
                    for (var k in row) {
                        if (Object.prototype.hasOwnProperty.call(row, k)) addV(row[k]);
                    }
                }
            }
        }
        function addCellDetails(cd) {
            if (!cd || typeof cd !== 'object') return;
            for (var ck in cd) {
                if (!Object.prototype.hasOwnProperty.call(cd, ck)) continue;
                var cell = cd[ck];
                if (!cell || typeof cell !== 'object') continue;
                addV(cell.label);
                addV(cell.description);
                addMatch(cell.match);
                addRowsArray(cell.rows);
            }
        }

        // Active sheet rows
        addRowsArray(this.allRows);
        // cellDetails de l'onglet actif
        addCellDetails(this._cellDetails);

        // Autres onglets via getTabsContext (même source que le payload)
        var tabs = null;
        if (typeof this._options.getTabsContext === 'function') {
            try { tabs = this._options.getTabsContext(); } catch (e) { tabs = null; }
        }
        if (Array.isArray(tabs)) {
            for (var ti = 0; ti < tabs.length; ti++) {
                var tab = tabs[ti];
                if (!tab || typeof tab !== 'object') continue;
                addV(tab.label);
                addRowsArray(tab.rows);
                if (Array.isArray(tab.sheet_content)) {
                    for (var si = 0; si < tab.sheet_content.length; si++) {
                        var entry = tab.sheet_content[si];
                        if (!entry) continue;
                        addV(entry.value);
                        addV(entry.label);
                        addMatch(entry.match);
                    }
                }
                if (tab.col_distinct && typeof tab.col_distinct === 'object') {
                    for (var cn in tab.col_distinct) {
                        if (!Object.prototype.hasOwnProperty.call(tab.col_distinct, cn)) continue;
                        var info = tab.col_distinct[cn];
                        if (info && Array.isArray(info.values)) {
                            for (var vi = 0; vi < info.values.length; vi++) addV(info.values[vi]);
                        }
                    }
                }
                addCellDetails(tab.cellDetails);
            }
        }

        return Object.keys(out);
    };

    SqlResultGrid.prototype._reconcileAnonymizationState = function() {
        // Miroir de ``anon_terms.reconcile_state`` v2 : PRÉSERVE les termes
        // stockés absents du classeur courant (ils viennent potentiellement
        // d'autres classeurs de l'user). Seul le job cleanup serveur a la
        // vue cross-classeur pour supprimer.
        var current = this._anonExtractTerms();
        var currentSet = Object.create(null);
        for (var i = 0; i < current.length; i++) currentSet[current[i]] = 1;

        var state = (this._anonymizationState && typeof this._anonymizationState === 'object')
            ? this._anonymizationState : { version: 1, terms: {} };
        var storedTerms = (state.terms && typeof state.terms === 'object') ? state.terms : {};

        var newTerms = {};
        // 1. Recopie TOUS les termes stockés (cross-classeur) — normalisés.
        //    Préserve ``id`` (BDD) et ``auto_pseudo`` (calculé serveur) sinon
        //    le modal perd la capacité d'appeler les endpoints scopés-id
        //    (DELETE /terms/:id, GET .../coverage) à chaque reconcile. C'est
        //    ce que ``_openAnonymizationPanel`` exécute en première ligne,
        //    donc tout `id` perdu ici = boutons « Voir détail / Supprimer »
        //    silencieusement masqués.
        for (var st in storedTerms) {
            if (!Object.prototype.hasOwnProperty.call(storedTerms, st)) continue;
            if (typeof st !== 'string' || !st) continue;
            var e = storedTerms[st] || {};
            newTerms[st] = {
                enabled: !!e.enabled,
                confirmed: !!e.confirmed
            };
            if (typeof e.pseudo === 'string' && e.pseudo) {
                newTerms[st].pseudo = e.pseudo;
            }
            if (typeof e.id === 'number' && e.id > 0) {
                newTerms[st].id = e.id;
            }
            if (typeof e.auto_pseudo === 'string' && e.auto_pseudo) {
                newTerms[st].auto_pseudo = e.auto_pseudo;
            }
        }
        // 2. Ajoute les tokens du classeur courant absents en state
        var added = [];
        for (var j = 0; j < current.length; j++) {
            var tok = current[j];
            if (newTerms[tok]) continue;
            newTerms[tok] = {
                enabled: false,
                confirmed: this._anonIsAutoDecidable(tok)
            };
            added.push(tok);
            // Track les nouveaux "non-auto-décidables" pour affichage du
            // badge NOUVEAU et tri dans le panneau. Les auto-décidables
            // (dates, courts numériques) ne sont pas signalés — ils ne
            // valent pas l'attention de l'user.
            if (!newTerms[tok].confirmed) {
                this._anonNewTokensPending[tok] = 1;
            }
        }
        // 3. ``vanished`` = informationnel (PAS appliqué). Ces tokens ne
        // sont PAS dans le classeur courant mais restent dans le state
        // car ils peuvent venir d'autres classeurs de l'user. Seul le
        // cleanup serveur (union cross-classeur) peut réellement supprimer.
        var vanished = [];
        for (var st2 in storedTerms) {
            if (!Object.prototype.hasOwnProperty.call(storedTerms, st2)) continue;
            if (!(st2 in currentSet)) vanished.push(st2);
        }

        this._anonymizationState = { version: 1, terms: newTerms };
        return {
            state: this._anonymizationState,
            added: added.sort(),
            vanished: vanished.sort()
        };
    };

    // Retourne un dict à 3 scopes :
    //   {
    //     __active__:  { colName: [tokens] },   // onglet ACTIF uniquement
    //     __otherTabs__: [tokens],              // autres onglets du classeur ouvert
    //     __otherWorkbooks__: [tokens]          // state BDD, absent du classeur ouvert
    //   }
    //
    // L'onglet actif = cette instance ``SqlResultGrid`` (sa ``allRows`` +
    // ``_cellDetails``). Les autres onglets sont accessibles via
    // ``_options.getTabsContext()`` (liste des tabs avec rows / sheet_content
    // / cellDetails). Les termes en state qui ne sont dans AUCUN onglet
    // ouvert viennent d'autres classeurs BDD.
    //
    // **Cellules fusionnées** : un merge `{r1,c1,r2,c2}` est représenté par
    // UNE cellule anchor (r1,c1) qui porte la valeur ; les cellules "hidden"
    // du merge peuvent contenir la même valeur dupliquée OU être vides. On
    // attribue le terme à la colonne `this.columns[c1]` (anchor) — sémantique
    // naturelle : c'est "la colonne du label" du merge.
    SqlResultGrid.prototype._extractTermsByColumn = function() {
        var self = this;
        var result = { __active__: {}, __otherTabs__: [], __otherWorkbooks__: [] };
        // Map colName → Object(token→1) pour dedup par colonne (onglet actif)
        var colMap = Object.create(null);
        // Set des tokens de l'onglet actif (tous colonnes confondues)
        var activeTokens = Object.create(null);
        // Set des tokens des AUTRES onglets du classeur ouvert
        var otherTabsTokens = Object.create(null);

        function add(col, tok) {
            if (!col) col = '(sans colonne)';
            if (!colMap[col]) colMap[col] = Object.create(null);
            colMap[col][tok] = 1;
            activeTokens[tok] = 1;
        }

        // Cellules fusionnées : pour un merge {r1,c1,r2,c2}, seule l'anchor
        // (r1,c1) porte sémantiquement la valeur. Les cellules couvertes
        // (hidden) peuvent contenir des valeurs résiduelles qui ne doivent
        // pas créer de fausses entrées dans les colonnes qu'elles occupent
        // visuellement. On construit un Set des "hidden merged positions"
        // à skipper et on traite l'anchor sur sa colonne de base.
        var hiddenMerged = Object.create(null);
        var merges = Array.isArray(this._merges) ? this._merges : [];
        for (var mi = 0; mi < merges.length; mi++) {
            var m = merges[mi];
            if (!m) continue;
            for (var rr = m.r1; rr <= m.r2; rr++) {
                for (var cc = m.c1; cc <= m.c2; cc++) {
                    if (rr === m.r1 && cc === m.c1) continue; // anchor gardé
                    hiddenMerged[rr + ',' + cc] = 1;
                }
            }
        }

        var cols = this.columns || [];
        var isArr = this.isArrayFormat;
        var rows = this.allRows || [];
        for (var r = 0; r < rows.length; r++) {
            var row = rows[r];
            if (!row) continue;
            if (isArr && Array.isArray(row)) {
                for (var c = 0; c < row.length; c++) {
                    if (hiddenMerged[r + ',' + c]) continue; // skip non-anchor du merge
                    var colName = cols[c] || ('col_' + c);
                    var toks = self._anonTokenize(row[c]);
                    for (var ti = 0; ti < toks.length; ti++) add(colName, toks[ti]);
                }
            } else if (typeof row === 'object') {
                for (var k in row) {
                    if (!Object.prototype.hasOwnProperty.call(row, k)) continue;
                    var toks2 = self._anonTokenize(row[k]);
                    for (var tj = 0; tj < toks2.length; tj++) add(k, toks2[tj]);
                }
            }
        }
        // cellDetails : chaque cellule drill-down peut contenir ses propres
        // rows — on les rattache à la colonne de la cellule anchor.
        if (this._cellDetails) {
            for (var key in this._cellDetails) {
                if (!Object.prototype.hasOwnProperty.call(this._cellDetails, key)) continue;
                var parts = key.split(',');
                var cIdx = parseInt(parts[1], 10);
                if (isNaN(cIdx)) continue;
                var anchorCol = cols[cIdx] || ('col_' + cIdx);
                var cd = this._cellDetails[key] || {};
                if (Array.isArray(cd.rows)) {
                    for (var ri2 = 0; ri2 < cd.rows.length; ri2++) {
                        var subrow = cd.rows[ri2];
                        if (Array.isArray(subrow)) {
                            for (var ci2 = 0; ci2 < subrow.length; ci2++) {
                                var sub_toks = self._anonTokenize(subrow[ci2]);
                                for (var si2 = 0; si2 < sub_toks.length; si2++) {
                                    // On garde la colonne de l'anchor, pas la
                                    // colonne interne du drill-down (qui peut
                                    // n'exister que dans ce drill précis).
                                    add(anchorCol, sub_toks[si2]);
                                }
                            }
                        }
                    }
                }
            }
        }

        // Dedup intra-onglet-actif : un même token présent dans plusieurs
        // colonnes (ex: "DUPONT" dans nom_client ET nom_fournisseur) ne
        // doit apparaître QU'UNE FOIS dans l'UI. On l'attache à sa
        // colonne primaire = première par ordre alphabétique. Les autres
        // colonnes "perdent" ce token (mais comptent dans le badge "+N
        // autres colonnes" exposé via ``_anonTokenColumnCount``).
        var sortedColNames = Object.keys(colMap).sort();
        var primaryCol = Object.create(null);  // token → première col où vu
        var colCount = Object.create(null);    // token → nombre de cols
        for (var sci = 0; sci < sortedColNames.length; sci++) {
            var scn = sortedColNames[sci];
            for (var stok in colMap[scn]) {
                if (!Object.prototype.hasOwnProperty.call(colMap[scn], stok)) continue;
                colCount[stok] = (colCount[stok] || 0) + 1;
                if (!primaryCol[stok]) primaryCol[stok] = scn;
            }
        }
        // Rebuild colMap dédupliqué : chaque token uniquement dans sa col primaire
        var dedupColMap = Object.create(null);
        for (var dtok in primaryCol) {
            if (!Object.prototype.hasOwnProperty.call(primaryCol, dtok)) continue;
            var dcn = primaryCol[dtok];
            if (!dedupColMap[dcn]) dedupColMap[dcn] = Object.create(null);
            dedupColMap[dcn][dtok] = 1;
        }
        // Stash compte de colonnes pour badge UI (rendu dans renderColumnSection)
        self._anonTokenColumnCount = colCount;

        // Flatten en listes triées — section "onglet actif par colonne"
        var activeByCol = {};
        for (var cn in dedupColMap) {
            if (!Object.prototype.hasOwnProperty.call(dedupColMap, cn)) continue;
            activeByCol[cn] = Object.keys(dedupColMap[cn]).sort();
        }
        result.__active__ = activeByCol;

        // Collecte les tokens des AUTRES onglets du classeur ouvert via
        // ``getTabsContext`` (exposé par le parent — TabManager / workbook
        // runtime). Un onglet qui s'auto-détecte comme l'actif (même label)
        // est skippé pour ne pas le compter 2× dans "autres onglets".
        // Note : le tokenizer respecte les mêmes règles que pour l'actif
        // (cellDetails inclus), sans le détail "par colonne" — ici on
        // présente juste une liste plate.
        var tabsCtx = null;
        if (typeof this._options.getTabsContext === 'function') {
            try { tabsCtx = this._options.getTabsContext(); } catch (e) { tabsCtx = null; }
        }
        var activeLabel = (this._options && this._options.activeTabLabel)
            ? String(this._options.activeTabLabel) : null;
        if (Array.isArray(tabsCtx)) {
            for (var ti = 0; ti < tabsCtx.length; ti++) {
                var tab = tabsCtx[ti];
                if (!tab || typeof tab !== 'object') continue;
                // Skip l'onglet actif : il est déjà couvert par activeByCol.
                // Heuristique : on identifie l'actif soit par label (si
                // fourni via options) soit par ``is_active: true``.
                if (tab.is_active) continue;
                if (activeLabel !== null && tab.label === activeLabel) continue;

                // Tokens des rows de l'onglet
                if (Array.isArray(tab.rows)) {
                    for (var tr = 0; tr < tab.rows.length; tr++) {
                        var trow = tab.rows[tr];
                        if (Array.isArray(trow)) {
                            for (var tc = 0; tc < trow.length; tc++) {
                                var tToks = self._anonTokenize(trow[tc]);
                                for (var tti = 0; tti < tToks.length; tti++) otherTabsTokens[tToks[tti]] = 1;
                            }
                        } else if (trow && typeof trow === 'object') {
                            for (var tk in trow) {
                                if (!Object.prototype.hasOwnProperty.call(trow, tk)) continue;
                                var tToks2 = self._anonTokenize(trow[tk]);
                                for (var ttj = 0; ttj < tToks2.length; ttj++) otherTabsTokens[tToks2[ttj]] = 1;
                            }
                        }
                    }
                }
                // sheet_content (format sparse) + match
                if (Array.isArray(tab.sheet_content)) {
                    for (var sci = 0; sci < tab.sheet_content.length; sci++) {
                        var entry = tab.sheet_content[sci];
                        if (!entry) continue;
                        [entry.value, entry.label].forEach(function(v) {
                            var toks_ = self._anonTokenize(v);
                            for (var xi = 0; xi < toks_.length; xi++) otherTabsTokens[toks_[xi]] = 1;
                        });
                        if (entry.match && typeof entry.match === 'object') {
                            for (var mk in entry.match) {
                                var mv = entry.match[mk];
                                if (Array.isArray(mv)) {
                                    for (var mli = 0; mli < mv.length; mli++) {
                                        var mToks = self._anonTokenize(mv[mli]);
                                        for (var mii = 0; mii < mToks.length; mii++) otherTabsTokens[mToks[mii]] = 1;
                                    }
                                } else {
                                    var mToks2 = self._anonTokenize(mv);
                                    for (var mii2 = 0; mii2 < mToks2.length; mii2++) otherTabsTokens[mToks2[mii2]] = 1;
                                }
                            }
                        }
                    }
                }
                // cellDetails de chaque onglet
                if (tab.cellDetails && typeof tab.cellDetails === 'object') {
                    for (var ck in tab.cellDetails) {
                        var cdt = tab.cellDetails[ck];
                        if (!cdt || !Array.isArray(cdt.rows)) continue;
                        for (var cri = 0; cri < cdt.rows.length; cri++) {
                            var csubrow = cdt.rows[cri];
                            if (Array.isArray(csubrow)) {
                                for (var cci = 0; cci < csubrow.length; cci++) {
                                    var cToks = self._anonTokenize(csubrow[cci]);
                                    for (var cti = 0; cti < cToks.length; cti++) otherTabsTokens[cToks[cti]] = 1;
                                }
                            }
                        }
                    }
                }
            }
        }
        // Retire de "other tabs" les tokens qui sont déjà dans l'actif
        // (doublon : un même terme peut être dans plusieurs onglets).
        var otherTabsList = [];
        for (var otk in otherTabsTokens) {
            if (!Object.prototype.hasOwnProperty.call(otherTabsTokens, otk)) continue;
            if (activeTokens[otk]) continue;
            otherTabsList.push(otk);
        }
        otherTabsList.sort();
        result.__otherTabs__ = otherTabsList;

        // Termes du state qui ne sont NI dans l'actif NI dans les autres
        // onglets ouverts → viennent d'autres classeurs (BDD cross-classeur).
        var state = this._anonymizationState || { version: 1, terms: {} };
        var others = [];
        if (state.terms) {
            for (var term in state.terms) {
                if (!Object.prototype.hasOwnProperty.call(state.terms, term)) continue;
                if (activeTokens[term] || otherTabsTokens[term]) continue;
                others.push(term);
            }
        }
        others.sort();
        result.__otherWorkbooks__ = others;

        return result;
    };

    SqlResultGrid.prototype._anonPendingTerms = function() {
        var state = this._anonymizationState;
        if (!state || !state.terms) return [];
        var out = [];
        for (var t in state.terms) {
            if (!Object.prototype.hasOwnProperty.call(state.terms, t)) continue;
            var e = state.terms[t];
            if (e && !e.confirmed) out.push(t);
        }
        return out.sort();
    };

    SqlResultGrid.prototype._updateAnonymizationBadge = function() {
        if (!this._copilotAnonBadge) return;
        var pending = this._anonPendingTerms();
        if (pending.length === 0) {
            this._copilotAnonBadge.style.display = 'none';
            this._copilotAnonBadge.textContent = '';
            if (this._copilotAnonBtn) {
                this._copilotAnonBtn.title = 'Confidentialité — choisir les termes à anonymiser';
            }
        } else {
            this._copilotAnonBadge.style.display = 'inline-flex';
            this._copilotAnonBadge.textContent = pending.length > 99 ? '99+' : String(pending.length);
            if (this._copilotAnonBtn) {
                this._copilotAnonBtn.title = pending.length + ' terme(s) à confirmer avant envoi au copilot';
            }
        }
    };

    SqlResultGrid.prototype._notifyAnonymizationStateChange = function() {
        // Callback optionnel vers le parent (iris.js / page hôte) qui peut
        // persister le state (localStorage, export .afz.json, etc.).
        if (typeof this._options.onAnonymizationStateChange === 'function') {
            try { this._options.onAnonymizationStateChange(this._anonymizationState); }
            catch (e) { /* defensive */ }
        }
    };

    // ── Fetch / persist state vers la BDD serveur ──

    // Adopte un nouveau state (retourné par GET/PUT ou gate 409) et met à
    // jour tous les observables dérivés : badge, marqueurs de cellules,
    // callback parent. Centralise la séquence qui était dupliquée 4 fois
    // (fetch success, persist success, gate 409 response, success response
    // dans _sendCopilotRequest). Un seul chemin = un seul test mental.
    SqlResultGrid.prototype._setAnonymizationState = function(state) {
        if (!state || typeof state !== 'object') return;
        this._anonymizationState = state;
        this._updateAnonymizationBadge();
        this._applyAnonymizationCellMarkers();
        this._notifyAnonymizationStateChange();
        // Broadcast cross-tab — sauf si on est précisément en train
        // d'appliquer un state reçu via le channel (sinon cascade entre
        // N tabs ouverts). Le flag est posé/levé par le listener.
        if (this._anonBroadcastChannel && !this._anonBroadcastSuppress) {
            try {
                this._anonBroadcastChannel.postMessage({
                    type: 'anon_state_changed',
                    source_session: this._anonBroadcastSessionId,
                    state: state,
                    ts: Date.now(),
                });
            } catch (e) {
                // postMessage peut throw si state contient des refs non-
                // clonables (DOM nodes, fonctions). Le state anon ne
                // devrait contenir que primitives + objets simples mais
                // garde-fou par sécurité.
            }
        }
    };

    // Compteur monotone des mutations LOCALES du state anonymisation.
    // Appelé par les chemins qui font une vraie modification utilisateur
    // (toggle, panel Save). Utilisé pour détecter les réponses serveur
    // obsolètes : si un PUT part avec seq=3 et que l'utilisateur toggle
    // entre-temps (seq→4), la réponse du PUT à seq=3 est « périmée » et
    // ne doit pas écraser le state local qui reflète la dernière intention.
    SqlResultGrid.prototype._bumpAnonStateSeq = function() {
        this._anonStateSeq = (this._anonStateSeq || 0) + 1;
        return this._anonStateSeq;
    };

    // SSoT d'invalidation du cache de state anonymisation (fix 2026-06-11,
    // tâche #13). Les sites qui forcent un resync (409, conflation refusée,
    // DELETE backend, refresh inter-grilles) doivent passer par ICI : reset
    // des 3 champs ensemble, y compris le backoff post-échec réseau — une
    // invalidation EXPLICITE doit toujours autoriser un fetch immédiat.
    SqlResultGrid.prototype._invalidateAnonymizationCache = function() {
        this._anonymizationFetched = false;
        this._anonymizationFetchPromise = null;
        this._anonymizationFetchFailedAt = 0;
    };

    SqlResultGrid.prototype._fetchAnonymizationState = function() {
        // Charge le state d'anonymisation du user courant depuis le
        // serveur. Promise cachée : fetch 1× par cycle de vie de la grille
        // (évite le bruit réseau si la grille est rebuild plusieurs fois).
        // Les callers peuvent await pour savoir quand le state est prêt.
        //
        // Guard contre le race « fetch stale écrase state plus récent » :
        // on capture le ``_anonStateSeq`` à l'envoi. Si une mutation locale
        // est intervenue entre-temps (toggle, panel Save), on IGNORE la
        // réponse — le state local est plus récent et sera pushé au
        // prochain flush du debouncer.
        var self = this;
        if (this._anonymizationFetched) {
            return Promise.resolve(this._anonymizationState);
        }
        if (this._anonymizationFetchPromise) {
            return this._anonymizationFetchPromise;
        }
        // Backoff post-échec réseau (fix 2026-06-11, tâche #13) : les
        // renders/markers peuvent appeler en rafale — sans backoff, un
        // serveur down déclencherait une tempête de retries. Une
        // invalidation EXPLICITE (cf. _invalidateAnonymizationCache)
        // remet ce timestamp à 0 et bypass le backoff.
        if (this._anonymizationFetchFailedAt
            && (Date.now() - this._anonymizationFetchFailedAt) < ANON_FETCH_RETRY_BACKOFF_MS) {
            return Promise.resolve(this._anonymizationState);
        }
        var capturedSeq = this._anonStateSeq || 0;
        this._anonymizationFetchPromise = fetch('/api/anonymization/terms', {
            method: 'GET',
            headers: { 'Accept': 'application/json' },
            credentials: 'same-origin'
        }).then(function(resp) {
            if (!resp.ok) {
                // 401/403 : utilisateur non autorisé → on reste sur state
                // local vide. Pas de blocage dur.
                return null;
            }
            return resp.json();
        }).then(function(data) {
            self._anonymizationFetched = true;
            self._anonymizationFetchFailedAt = 0;
            self._anonymizationLastFetchTs = Date.now();
            // Révision adoptée SANS garde seq (eXamine 2026-06-10) : c'est
            // le jeton serveur le plus frais connu — même si le STATE local
            // est plus récent (toggle pendant le fetch), le prochain PUT
            // doit présenter CE jeton. Le garder sous le seq guard créait
            // une boucle 409 sous toggles continus (révision périmée rejouée
            // à chaque save). Cohérent avec l'adoption post-PUT (sans seq).
            if (data && typeof data.revision === 'string') {
                self._anonRevision = data.revision;
            }
            // Adopter le STATE uniquement si aucune mutation locale n'est
            // intervenue depuis le début du fetch.
            if ((self._anonStateSeq || 0) !== capturedSeq) {
                return self._anonymizationState;
            }
            if (data && data.anonymization_state) {
                self._setAnonymizationState(data.anonymization_state);
            }
            return self._anonymizationState;
        }).catch(function() {
            // Échec réseau (fix 2026-06-11, tâche #13) : ne PAS latcher le
            // cache « fetched » sur un état vide — le panneau resterait
            // vide (0 terme affiché alors que la BDD en a des milliers)
            // jusqu'au reload de la page, et c'est exactement le scénario
            // qui produisait les 409 MASS_DELETE vécus. On libère le cache
            // pour retry au prochain appelant, borné par le backoff
            // ci-dessus (anti-tempête).
            self._anonymizationFetched = false;
            self._anonymizationFetchPromise = null;
            self._anonymizationFetchFailedAt = Date.now();
            return self._anonymizationState;
        });
        return this._anonymizationFetchPromise;
    };

    SqlResultGrid.prototype._persistAnonymizationState = function(state) {
        // Sauvegarde le state vers la BDD serveur (PUT idempotent, semantique
        // replace). Le backend normalise + renvoie le state après upsert +
        // delete des termes absents, qu'on adopte comme cache local.
        //
        // Instrumenté avec le SyncStatusIndicator (via callbacks du parent)
        // pour que l'utilisateur voie qu'une sync est en cours — évite
        // l'impression de lag inexpliqué.
        var self = this;
        var payload = { anonymization_state: state };
        // Verrou optimiste (fix lost update 2026-06-10) : renvoie la révision
        // connue du GET — un autre onglet//data-privacy/scan qui a écrit
        // entre-temps fait refuser ce PUT (409 STATE_REVISION_MISMATCH) au
        // lieu d'écraser silencieusement ses modifications.
        if (typeof this._anonRevision === 'string' && this._anonRevision) {
            payload.expected_revision = this._anonRevision;
        }
        var syncToken = this._beginSync('Synchronisation anonymisation…');
        // Capture le seq AU MOMENT de l'envoi. Si une mutation locale
        // arrive pendant le PUT, la réponse serveur (qui ne reflète que
        // le state envoyé) est périmée — l'ignorer pour ne pas écraser.
        var capturedSeq = this._anonStateSeq || 0;
        return fetch('/api/anonymization/terms', {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'X-Xsrftoken': _getXsrfCookie()
            },
            credentials: 'same-origin',
            body: JSON.stringify(payload)
        }).then(function(resp) {
            // Lecture SÛRE : ne plante pas sur le HTML d'une erreur passerelle
            // (413 mapping volumineux, 429, 502/504). ``ctx.data`` reste le
            // JSON parsé quand il y en a, ``ctx.status`` est toujours fiable.
            return _readJsonSafe(resp).then(function(r) {
                return { status: r.status, data: r.data || {} };
            });
        }).then(function(ctx) {
            var data = ctx.data || {};
            if (ctx.status === 200 && data.success) {
                // Adopter la révision post-write SANS condition de seq : elle
                // reflète l'état serveur après NOTRE écriture — le prochain
                // PUT (même conflaté avec des mutations locales plus
                // récentes) doit la présenter, sinon il 409-erait sur sa
                // propre écriture.
                if (typeof data.revision === 'string') {
                    self._anonRevision = data.revision;
                }
                // N'écrase le cache local QUE si aucune mutation locale
                // n'est intervenue depuis l'envoi — sinon la réponse est
                // stale par rapport à l'intention la plus récente de l'user.
                if (data.anonymization_state &&
                    (self._anonStateSeq || 0) === capturedSeq) {
                    self._setAnonymizationState(data.anonymization_state);
                }
                self._endSync(syncToken, false);
                // Propage ``state_errors`` éventuels au caller (panel Save)
                // pour qu'il puisse afficher un toast warning si le backend
                // a sanitizé certains termes en passing. Fix CRITICAL
                // 2026-05-20 : avant, ces erreurs étaient logguées côté
                // serveur mais jamais exposées côté UI.
                // ``state_errors_truncated_count`` = signal "+N invisibles"
                // quand le backend cap à 10 (R3 MED 2026-05-20).
                return {
                    ok: true,
                    state: self._anonymizationState,
                    state_errors: Array.isArray(data.state_errors) ? data.state_errors : null,
                    state_errors_truncated_count: Number.isFinite(data.state_errors_truncated_count)
                        ? data.state_errors_truncated_count : 0
                };
            }
            // 400 ANON_STATE_INVALID ou autre : on remonte la réponse pour
            // que le panneau affiche les state_errors.
            self._endSync(syncToken, true);
            return { ok: false, status: ctx.status, data: data };
        }).catch(function(err) {
            self._endSync(syncToken, true);
            return { ok: false, error: (err && err.message) || 'network' };
        });
    };

    // ── Debounce + flush pour les PUT anonymisation ──
    //
    // Les toggles rapides (clic droit "Anonymiser" sur 3 cellules en 1s)
    // déclenchaient autant de PUTs sériels (50-200ms chacun), bloquant
    // l'UI à chaque coup. Maintenant :
    //   - ``_schedulePersistAnonymization()`` conflate via un timer de
    //     300ms : seul le DERNIER state est envoyé au serveur.
    //   - La promise rendue résout quand le PUT effectif répond.
    //   - En cas d'échec, on refetch le state serveur (source de vérité)
    //     et on affiche un toast. Le revert local précédent avait une
    //     sémantique fragile avec les conflations multiples — refetch est
    //     atomique et correct peu importe combien de toggles ont transité.
    //   - ``_flushAnonymizationPersist()`` force l'envoi immédiat du
    //     pending (utilisé par ``beforeunload`` + panel Save).

    SqlResultGrid.prototype._schedulePersistAnonymization = function() {
        var self = this;
        clearTimeout(this._anonPersistTimer);
        if (!this._anonPersistPending) {
            var resolveFn;
            var promise = new Promise(function(resolve) { resolveFn = resolve; });
            this._anonPersistPending = { promise: promise, resolve: resolveFn };
        }
        var pending = this._anonPersistPending;
        this._anonPersistTimer = setTimeout(function() {
            self._anonPersistTimer = null;
            self._anonPersistPending = null;
            self._persistAnonymizationState(self._anonymizationState).then(function(res) {
                if (res && !res.ok) {
                    // Refetch pour récupérer l'état serveur autoritatif puis
                    // toast. Les conflations multiples rendaient un revert
                    // local ambigu (on reverte à quoi exactement ?) — refetch
                    // est déterministe.
                    //
                    // Pour les 409 MASS_DELETE_REFUSED / REVISION_MISMATCH,
                    // _showAnonymizationError fait DÉJÀ invalidate+refetch :
                    // doubler ici relançait un 2e GET concurrent pendant que
                    // le 1er était en vol (review globale 2026-06-11, FAIBLE).
                    // Tout autre statut (incl. 409 d'un autre error_code)
                    // garde le refetch amont.
                    var ec = (res.data || {}).error_code;
                    var handledBy409 = res.status === 409
                        && (ec === 'MASS_DELETE_REFUSED'
                            || ec === 'STATE_REVISION_MISMATCH');
                    if (!handledBy409) {
                        self._invalidateAnonymizationCache();
                        self._fetchAnonymizationState();
                    }
                    self._showAnonymizationError(res);
                }
                pending.resolve(res);
            });
        }, ANON_PERSIST_DEBOUNCE_MS);
        return pending.promise;
    };

    SqlResultGrid.prototype._flushAnonymizationPersist = function(useBeacon) {
        if (!this._anonPersistPending) return null;
        var self = this;
        var pending = this._anonPersistPending;
        clearTimeout(this._anonPersistTimer);
        this._anonPersistTimer = null;
        this._anonPersistPending = null;
        if (useBeacon && typeof navigator !== 'undefined') {
            // Sur ``beforeunload`` / ``pagehide`` : fetch classique peut
            // être annulé par le browser. On utilise ``fetch`` + ``keepalive``
            // — mécanisme équivalent à ``sendBeacon`` mais autorisant le
            // header custom ``X-Xsrftoken`` (sendBeacon ne permet pas les
            // headers custom). Guard empty xsrf : sans cookie, pas la peine
            // d'envoyer, le backend rejettera en 403.
            var xsrf = _getXsrfCookie();
            if (xsrf) {
                try {
                    fetch('/api/anonymization/terms', {
                        method: 'PUT',
                        headers: {
                            'Content-Type': 'application/json',
                            'Accept': 'application/json',
                            'X-Xsrftoken': xsrf,
                        },
                        credentials: 'same-origin',
                        body: JSON.stringify({ anonymization_state: self._anonymizationState }),
                        keepalive: true,
                    });
                } catch (e) { /* best-effort pendant unload */ }
            }
            // Resolution shape : ok:null pour éviter qu'un caller qui
            // check `res.ok` truthy ne pense que le serveur a confirmé —
            // le mode keepalive ne permet pas d'observer la réponse.
            var beaconRes = { ok: null, flushed: true, keptAlive: !!xsrf };
            pending.resolve(beaconRes);
            return Promise.resolve(beaconRes);
        }
        return this._persistAnonymizationState(this._anonymizationState).then(function(res) {
            pending.resolve(res);
            return res;
        });
    };

    SqlResultGrid.prototype._cancelAnonymizationPersist = function() {
        // Annule un PUT pending (utilisé avant un PUT direct qui va
        // écraser le state — panel Save).
        if (!this._anonPersistPending) return;
        clearTimeout(this._anonPersistTimer);
        this._anonPersistTimer = null;
        this._anonPersistPending.resolve({ ok: true, superseded: true });
        this._anonPersistPending = null;
    };

    // Helpers pour signaler les syncs au GridTabManager (qui pilote le
    // SyncStatusIndicator). Si la grille est standalone (pas embed dans un
    // TabManager), les callbacks sont absents → no-op silencieux.
    SqlResultGrid.prototype._beginSync = function(label) {
        if (typeof this._options.onSyncBegin !== 'function') return null;
        try { return this._options.onSyncBegin(label); } catch (e) { return null; }
    };

    SqlResultGrid.prototype._endSync = function(token, errored) {
        if (token == null || typeof this._options.onSyncEnd !== 'function') return;
        try {
            this._options.onSyncEnd(token, errored ? { error: true } : undefined);
        } catch (e) { /* defensive */ }
    };

    SqlResultGrid.prototype._showAnonymizationError = function(res) {
        var data = (res && res.data) || {};
        var status = res && res.status;
        var errorMessage = data.error || 'Échec enregistrement anonymisation.';

        // Cas particulier 413 STATE_TOO_LARGE : message trop long pour le
        // status discret de la grille + l'utilisateur doit AGIR (aller
        // purger /data/privacy). On escalade en toast global persistant.
        if (status === 413 && data.error_code === 'STATE_TOO_LARGE'
            && typeof showToast === 'function') {
            showToast(errorMessage, 'error', 12000);
            return;
        }

        // 409 MASS_DELETE_REFUSED (save auto/debounced hors panneau) : liste
        // locale désynchronisée — message humain (pas le texte API backend) +
        // resync automatique du state pour que le prochain save reparte d'une
        // base fraîche. Jamais de confirm_mass_delete automatique.
        if (status === 409
            && (data.error_code === 'MASS_DELETE_REFUSED'
                || data.error_code === 'STATE_REVISION_MISMATCH')) {
            var resyncMsg = data.error_code === 'STATE_REVISION_MISMATCH'
                ? ('Enregistrement refusé : tes termes ont été modifiés '
                   + 'entre-temps (autre onglet ou scan). Rien n\'a été écrasé '
                   + '— état rechargé, réessaie.')
                : ('Enregistrement refusé : ta liste de termes était '
                   + 'désynchronisée du serveur. Rien n\'a été supprimé — état '
                   + 'rechargé, réessaie.');
            this._invalidateAnonymizationCache();
            this._fetchAnonymizationState();
            if (typeof showToast === 'function') {
                showToast(resyncMsg, 'error', 12000);
                return;
            }
            errorMessage = resyncMsg; // fallback : statut discret ci-dessous
        }

        if (this._copilotStatus) {
            this._copilotStatus.textContent = errorMessage;
            this._copilotStatus.className = 'grid-copilot-status error';
            var self = this;
            // clearTimeout AVANT de ré-armer (fix 2026-06-11, tâche #13) :
            // sans handle, le timer d'une erreur A (t0) effaçait l'erreur B
            // affichée à t0+3s après seulement 1s de visibilité (le guard
            // « className contient error » est vrai pour B aussi).
            if (this._anonStatusErrTimer) {
                clearTimeout(this._anonStatusErrTimer);
            }
            this._anonStatusErrTimer = setTimeout(function() {
                self._anonStatusErrTimer = null;
                if (self._copilotStatus && self._copilotStatus.className.indexOf('error') !== -1) {
                    self._copilotStatus.textContent = '';
                    self._copilotStatus.className = 'grid-copilot-status';
                }
            }, ANON_ERROR_TOAST_MS);
        }
    };

    // ── Indicateurs visuels discrets sur les cellules ──
    //
    // Un seul parcours de ``tbody`` par render. Pour chaque td, on tokenise
    // son texte et on vérifie la présence de termes ``enabled=True`` ou
    // ``confirmed=False`` dans le state. Classe CSS ajoutée → styling via
    // les règles inline ci-dessous (pas besoin de fichier CSS séparé).

    // FNV-1a 32 bits (Math.imul = multiplication exacte mod 2^32, supporté
    // par les 2 dernières versions de Chrome/Firefox/Safari/Edge). Hash PAR
    // TERME, combiné par ADDITION dans le caller : commutatif, donc
    // insensible à l'ordre d'énumération de ``state.terms`` (non garanti
    // identique entre navigateurs). Pas un hash crypto — juste un signal
    // « le contenu du dictionnaire a bougé » (fix 2026-06-11, tâche #24).
    function _anonFnv1a(str) {
        var h = 0x811c9dc5;
        for (var i = 0; i < str.length; i++) {
            h ^= str.charCodeAt(i);
            h = Math.imul(h, 0x01000193) >>> 0;
        }
        return h;
    }

    SqlResultGrid.prototype._applyAnonymizationCellMarkers = function() {
        if (!this.tbodyEl) return;
        var state = this._anonymizationState;
        if (!state || !state.terms) return;
        // Debounce + cache (fix perf 2026-04-23) : le marker re-apply peut
        // être déclenché à chaque render, chaque toggle, chaque PUT serveur.
        // Sur une grille 5000 cellules × 100 termes on parlait de millions
        // de comparaisons par cycle. Deux optimisations :
        //  1. Fingerprint du state (hash rapide) + fingerprint du tbody
        //     (rowCount+cellCount) : skip si inchangés.
        //  2. rAF pour coalescer les triggers en rafale.
        var self = this;
        if (this._anonMarkerRaf) return;  // déjà planifié ce frame
        this._anonMarkerRaf = (window.requestAnimationFrame || function(f) { return setTimeout(f, 16); })(function() {
            self._anonMarkerRaf = null;
            self._applyAnonymizationCellMarkersSync();
        });
    };

    SqlResultGrid.prototype._applyAnonymizationCellMarkersSync = function() {
        if (!this.tbodyEl) return;
        var state = this._anonymizationState;
        if (!state || !state.terms) return;

        var activeTokens = Object.create(null);
        var pendingTokens = Object.create(null);
        var activeCount = 0, pendingCount = 0;
        var termsHash = 0;
        for (var t in state.terms) {
            if (!Object.prototype.hasOwnProperty.call(state.terms, t)) continue;
            var e = state.terms[t] || {};
            // Le préfixe ('p:'/'a:') entre dans le hash : un même terme qui
            // passe de pending → actif change le fingerprint même à counts
            // égaux par ailleurs.
            if (!e.confirmed) {
                pendingTokens[t] = 1; pendingCount++;
                termsHash = (termsHash + _anonFnv1a('p:' + t)) >>> 0;
            } else if (e.enabled) {
                activeTokens[t] = 1; activeCount++;
                termsHash = (termsHash + _anonFnv1a('a:' + t)) >>> 0;
            }
        }

        // Fingerprint : counts + hash additif du CONTENU des termes + nb de
        // rows. L'ancien fingerprint (counts seuls) ne bougeait pas quand un
        // terme était REMPLACÉ par un autre à count égal → marquage visuel
        // figé/FAUX après édition du dictionnaire (fix 2026-06-11, #24).
        var fp = activeCount + '|' + pendingCount + '|' + termsHash.toString(36) +
            '|' + this.tbodyEl.childElementCount;
        if (this._anonMarkerFingerprint === fp && this._anonMarkerTbody === this.tbodyEl) {
            return; // rien à faire, même state + même tbody
        }
        this._anonMarkerFingerprint = fp;
        this._anonMarkerTbody = this.tbodyEl;

        this._ensureAnonCellStyles();

        // Short-circuit : pas de tokens enabled/pending → juste nettoyer
        // les classes éventuellement posées avant (transition active → clear).
        if (activeCount === 0 && pendingCount === 0) {
            var dirty = this.tbodyEl.querySelectorAll(
                '.grid-cell-anon-active, .grid-cell-anon-pending'
            );
            for (var di = 0; di < dirty.length; di++) {
                dirty[di].classList.remove('grid-cell-anon-active', 'grid-cell-anon-pending');
            }
            return;
        }

        var cells = this.tbodyEl.querySelectorAll('td[data-row][data-col]');
        for (var i = 0; i < cells.length; i++) {
            var td = cells[i];
            td.classList.remove('grid-cell-anon-active', 'grid-cell-anon-pending');
            var text = td.textContent || '';
            if (text.length === 0) continue;
            // Délègue au tokenizer partagé pour éviter le drift Py↔JS — la
            // regex /[^\s,;:]+/gu, le cap MAX_VALUE_LEN et le filtre
            // tok.length < 2 vivent uniquement dans
            // ``static/js/anonymization/tokenizer.js``. Si le module est
            // absent (template incomplet), ``_anonTokenize`` retourne ``[]``
            // (fail-closed) — la cellule restera non marquée plutôt que
            // d'utiliser une regex locale qui pourrait diverger du backend.
            var tokens = this._anonTokenize(text);
            if (tokens.length === 0) continue;
            var hasActive = false;
            var hasPending = false;
            for (var ti = 0; ti < tokens.length; ti++) {
                var tok = tokens[ti];
                if (pendingTokens[tok]) { hasPending = true; break; }
                if (activeTokens[tok]) hasActive = true;
            }
            if (hasPending) td.classList.add('grid-cell-anon-pending');
            else if (hasActive) td.classList.add('grid-cell-anon-active');
        }
    };

    SqlResultGrid.prototype._ensureAnonCellStyles = function() {
        if (document.getElementById('anon-cell-styles')) return;
        var st = document.createElement('style');
        st.id = 'anon-cell-styles';
        st.textContent = [
            /* Cellule qui contient un terme anonymisé (enabled=True) :
               fine ligne pointillée indigo sous le texte. Discret mais
               visible à l'œil formé. */
            '.grid-cell-anon-active {',
            '  text-decoration: underline dotted rgba(99, 102, 241, 0.55);',
            '  text-underline-offset: 2px;',
            '}',
            /* Cellule qui contient un terme pending (confirmed=False) :
               fond rouge très léger, plus fort que l'autre. Invite à
               ouvrir le panneau. */
            '.grid-cell-anon-pending {',
            '  background-color: rgba(220, 38, 38, 0.06);',
            '  box-shadow: inset 2px 0 0 rgba(220, 38, 38, 0.35);',
            '}',
            /* Menu contextuel custom pour ajouter un terme depuis une cell. */
            '.anon-context-menu {',
            /* 1995 = au-dessus des modaux iris-grid inline (1990) mais sous
               OverlayManager.modal (2000). Cf. overlay-layers.css. */
            '  position: fixed; z-index: 1995;',
            '  background: var(--bg-surface, #fff); color: var(--text-primary, #111827);',
            '  border: 1px solid var(--border, #d1d5db); border-radius: 0.5rem;',
            '  box-shadow: var(--shadow-lg, 0 10px 40px rgba(0,0,0,0.2));',
            '  padding: 0.25rem 0; min-width: 220px; max-height: 360px; overflow-y: auto;',
            '  font-size: 0.8125rem;',
            '}',
            '.anon-context-menu .anon-ctx-item {',
            '  padding: 0.4rem 0.75rem; cursor: pointer; white-space: nowrap;',
            '  display: flex; align-items: center; gap: 0.5rem;',
            '}',
            '.anon-context-menu .anon-ctx-item:hover { background: rgba(0,0,0,0.04); }',
            '.anon-context-menu .anon-ctx-sep {',
            '  height: 1px; background: var(--border, #e5e7eb); margin: 0.25rem 0;',
            '}',
            '.anon-context-menu .anon-ctx-header {',
            '  padding: 0.3rem 0.75rem; font-size: 0.6875rem; font-weight: 600;',
            '  color: var(--text-muted, #6b7280); text-transform: uppercase; letter-spacing: 0.05em;',
            '}',
        ].join('\n');
        document.head.appendChild(st);
    };

    // ── Menu contextuel : ajouter un terme depuis une cell ──

    SqlResultGrid.prototype._attachAnonContextMenu = function() {
        // No-op depuis le merge 2026-05-15 : la section "Confidentialité"
        // est maintenant intégrée comme Section 0 du menu contextuel
        // principal (cf. ``_showContextMenu``). Avant : ce handler attachait
        // un 2e listener ``contextmenu`` qui créait un menu standalone
        // ``.anon-context-menu`` se superposant visuellement au menu
        // principal sur le même right-click. La fonction est gardée
        // (et toujours appelée au mount) pour ne pas casser les call sites
        // existants — bascule en no-op safe. À supprimer dans un futur
        // cleanup (avec son call site et le CSS .anon-context-menu).
        return;
        // ↓↓↓ DEAD CODE (gardé pour traçabilité du diff, à retirer) ↓↓↓
        // eslint-disable-next-line no-unreachable
        if (!this.tbodyEl || this._anonCtxAttached) return;
        this._anonCtxAttached = true;
        var self = this;
        this.tbodyEl.addEventListener('contextmenu', function(e) {
            var td = e.target.closest('td[data-row][data-col]');
            if (!td) return;
            // Ne pas hijacker le menu natif si l'utilisateur Shift+clic
            // droit (escape hatch pour inspection / paste URL).
            if (e.shiftKey) return;

            // Lecture raw depuis ``displayRows`` via ``data-row``/``data-col``.
            // ``data-row`` est un index dans displayRows (vue triée/filtrée),
            // PAS dans allRows. Indexer allRows directement quand un filtre/tri
            // est actif anonymise la mauvaise cellule silencieusement (l'user
            // voit anne mais le system anonymise didier, par exemple).
            // Préféré au ``td.textContent`` qui contient la valeur FORMATÉE
            // (ex: "1 234,56" en FR) — la tokenisation casserait dessus
            // alors que l'user veut anonymiser la valeur canonique "1234.56".
            var rAttr = td.getAttribute('data-row');
            var cAttr = td.getAttribute('data-col');
            var raw = null;
            if (rAttr !== null && cAttr !== null) {
                var r = parseInt(rAttr, 10);
                var c = parseInt(cAttr, 10);
                if (!isNaN(r) && !isNaN(c) && self.displayRows[r]) {
                    raw = self.isArrayFormat
                        ? self.displayRows[r][c]
                        : self.displayRows[r][self.columns[c]];
                }
            }

            var tokens = [];
            if (typeof raw === 'number' && isFinite(raw)) {
                // Cellule numérique : un seul "token" = la valeur canonique
                // stringifiée. L'user a bien le choix d'anonymiser "42"
                // même si la UI l'affiche "42,00 €" après formattage.
                var canon = String(raw);
                if (canon.length >= 2) tokens.push(canon);
            } else if (typeof raw === 'string' && raw) {
                // String : tokenisation standard (même règles que backend).
                tokens = self._anonTokenize ? self._anonTokenize(raw) : [];
            } else {
                // Fallback sur textContent si raw non accessible (cell édité,
                // cellDetails drill-down, etc.).
                var text = (td.textContent || '').trim();
                if (!text) return;
                tokens = self._anonTokenize ? self._anonTokenize(text) : [];
            }

            if (tokens.length === 0) return;
            e.preventDefault();
            self._showAnonContextMenu(e.clientX, e.clientY, tokens);
        });
    };

    SqlResultGrid.prototype._showAnonContextMenu = function(x, y, tokens) {
        var self = this;
        // Cleanup si un menu était déjà ouvert
        var prev = document.querySelector('.anon-context-menu');
        if (prev) prev.remove();

        var menu = document.createElement('div');
        menu.className = 'anon-context-menu';
        menu.style.left = x + 'px';
        menu.style.top = y + 'px';

        var header = document.createElement('div');
        header.className = 'anon-ctx-header';
        header.textContent = 'Confidentialité';
        menu.appendChild(header);

        // Pour chaque token distinct de la cell, proposer d'anonymiser
        var seen = Object.create(null);
        var uniq = [];
        for (var i = 0; i < tokens.length; i++) {
            if (!seen[tokens[i]]) { seen[tokens[i]] = 1; uniq.push(tokens[i]); }
        }
        uniq.forEach(function(tok) {
            var state = (self._anonymizationState && self._anonymizationState.terms) || {};
            var existing = state[tok];
            var label;
            if (existing && existing.enabled) {
                label = 'Ne plus anonymiser « ' + tok + ' »';
            } else {
                label = 'Anonymiser « ' + tok + ' »';
            }
            var item = document.createElement('div');
            item.className = 'anon-ctx-item';
            item.textContent = label;
            item.addEventListener('click', function() {
                menu.remove();
                self._toggleAnonTerm(tok);
            });
            menu.appendChild(item);
        });

        // Séparateur + ouvrir panneau complet
        var sep = document.createElement('div');
        sep.className = 'anon-ctx-sep';
        menu.appendChild(sep);
        var openAll = document.createElement('div');
        openAll.className = 'anon-ctx-item';
        openAll.textContent = 'Gérer la liste complète…';
        openAll.addEventListener('click', function() {
            menu.remove();
            self._openAnonymizationPanel();
        });
        menu.appendChild(openAll);

        document.body.appendChild(menu);
        // OverlayManager (layer=dropdown). Z-index 1000+N×10, conflict
        // dismiss-previous → un autre dropdown ouvert sera fermé.
        if (window.OverlayManager && typeof window.OverlayManager.open === 'function') {
            window.OverlayManager.open(menu, {
                layer: 'dropdown',
                onClose: function() {
                    if (menu.parentNode) menu.remove();
                    document.removeEventListener('mousedown', dismiss, true);
                    document.removeEventListener('keydown', onKey, true);
                },
            });
        }

        // Auto-dismiss : click ailleurs, Escape
        function dismiss(ev) {
            if (!menu.contains(ev.target)) {
                if (window.OverlayManager) {
                    try { window.OverlayManager.close(menu); } catch (e) {}
                }
                if (menu.parentNode) menu.remove();
                document.removeEventListener('mousedown', dismiss, true);
                document.removeEventListener('keydown', onKey, true);
            }
        }
        function onKey(ev) {
            // Escape : géré par OverlayManager (LIFO).
        }
        setTimeout(function() {
            document.addEventListener('mousedown', dismiss, true);
        }, 0);

        // Clamp à la fenêtre (si menu déborde à droite)
        var rect = menu.getBoundingClientRect();
        var vw = window.innerWidth, vh = window.innerHeight;
        if (rect.right > vw - 8) menu.style.left = (vw - rect.width - 8) + 'px';
        if (rect.bottom > vh - 8) menu.style.top = (vh - rect.height - 8) + 'px';
    };

    SqlResultGrid.prototype._toggleAnonTerm = function(term) {
        // Toggle enabled/disabled pour un terme via menu contextuel.
        // Pattern optimistic : on mute le state local, on rend l'UI tout
        // de suite, on planifie un PUT debouncé (300ms). Si l'utilisateur
        // toggle plusieurs termes rapidement, les PUTs sont conflatés
        // (seul le dernier state part au serveur).
        //
        // En cas d'échec serveur, ``_schedulePersistAnonymization`` refetch
        // le state autoritatif + toast (pas de revert local manuel — avec
        // conflations multiples, la sémantique du revert était ambiguë).
        var state = this._anonymizationState || { version: 1, terms: {} };
        if (!state.terms) state.terms = {};
        var existing = state.terms[term];
        if (existing && existing.enabled) {
            existing.enabled = false;
            existing.confirmed = true;
        } else {
            state.terms[term] = {
                enabled: true,
                confirmed: true,
                // pseudo absent = auto-gen côté backend
            };
            if (existing && existing.pseudo) state.terms[term].pseudo = existing.pseudo;
        }
        this._setAnonymizationState(state);
        this._bumpAnonStateSeq(); // mutation locale = la réponse des PUTs en vol devient stale
        this._schedulePersistAnonymization();
    };

    SqlResultGrid.prototype._openAnonymizationPanel = function(opts) {
        // Panneau modal pour choisir les termes à anonymiser. Pattern dérivé
        // de ``_openSaveSqlModal`` (même z-index, même style overlay+card).
        //
        // ``opts.consentCallbacks`` (optionnel) — si défini, ce panneau est
        // ouvert dans le contexte du flow ``data_read_consent`` (cf.
        // ``static/js/iris.js::openConsentAnonymizationPanel``) au lieu du
        // contexte habituel (clic cadenas dans la grille). Les 3 callbacks
        // ``onSave``/``onCancel``/``onAbandon`` permettent au flow consent
        // de savoir comment l'user a fermé le panneau et de répondre au
        // gate backend en conséquence :
        //   - Enregistrer → onSave   → backend ``approved=true``
        //   - Annuler     → onCancel → réouvre le prompt OUI/NON
        //   - Esc/backdrop→ onAbandon→ backend ``abandoned=true``
        // Pas de raccourci à un panneau allégé : le but de cette voie
        // est d'avoir EXACTEMENT le même modal (stats, filtres, bulk
        // actions, bouton Améliorer, liste complète des termes user) que
        // celui ouvert par le cadenas du classeur. Single source of truth.
        opts = opts || {};
        if (document.getElementById('anon-terms-modal')) {
            // Modal déjà ouvert (autre instance / clic répété). On invoque
            // ``onAbandon`` du caller s'il en a fourni : sans ça, le caller
            // resterait avec ``_copilotConsentInProgress=true`` à jamais et
            // une future soumission verrait le bail-out "Des termes restent
            // à confirmer" alors qu'aucun consent n'est en cours côté caller.
            // ``onAbandon`` est la sémantique correcte ("rien n'a été fait
            // par ce caller") plutôt que ``onCancel`` (utilisateur a refusé).
            if (opts.consentCallbacks
                && typeof opts.consentCallbacks.onAbandon === 'function') {
                try { opts.consentCallbacks.onAbandon(); } catch (e) {}
            }
            return;
        }
        var self = this;
        var _consentCallbacks = (opts.consentCallbacks && typeof opts.consentCallbacks === 'object')
            ? opts.consentCallbacks
            : null;
        // ``_consentExitReason`` = sentinelle pour close() afin d'appeler la
        // bonne callback. null par défaut = abandon (Esc/backdrop). Set à
        // 'save' juste avant close() dans la branche success de btnSave,
        // et à 'cancel' juste avant close() dans le handler btnCancel.
        var _consentExitReason = null;

        // Réconcilie juste avant d'afficher : le classeur a pu changer entre
        // deux ouvertures du panneau.
        this._reconcileAnonymizationState();
        var state = this._anonymizationState;
        var terms = state.terms || {};

        // **Ouverture = vu = LLM débloqué** (v6). Le contrat user :
        // "une fois que l'utilisateur les a vu donc a ouvert Confidentialité,
        // il n'y a plus de nouveaux et les LLM sont débloqués".
        //
        // 1. Snapshot les tokens "nouveaux depuis la dernière ouverture"
        //    pour afficher badge NOUVEAU + les trier en premier — uniquement
        //    pour CETTE session du panneau.
        // 2. Marque tous les pending comme `confirmed=true` (l'user les voit).
        // 3. Persist async : le backend enregistre confirmed=true → le gate
        //    ne bloquera plus au prochain send. Si l'user coche des termes
        //    ensuite, le save applique aussi `enabled=true`.
        var newShownThisOpen = Object.assign({}, this._anonNewTokensPending);
        this._anonNewTokensPending = Object.create(null);

        var pendingMarkedConfirmed = false;
        for (var _pt in terms) {
            if (!Object.prototype.hasOwnProperty.call(terms, _pt)) continue;
            if (terms[_pt] && !terms[_pt].confirmed) {
                terms[_pt].confirmed = true;
                pendingMarkedConfirmed = true;
            }
        }
        if (pendingMarkedConfirmed) {
            // Persist debouncé — débloque le gate backend au prochain send.
            // Ne fire PAS un PUT immédiat : si l'user clique rapidement OK/annuler
            // dans le panel, on évite un PUT puis Save qui ré-override.
            this._bumpAnonStateSeq();
            this._schedulePersistAnonymization();
            this._updateAnonymizationBadge();
            this._applyAnonymizationCellMarkers();
        }

        var overlay = document.createElement('div');
        overlay.id = 'anon-terms-modal';
        // z-index délégué à OverlayManager (layer='modal' = 2000+N×10). Cela
        // garantit que ce panneau passe AU-DESSUS de tout — y compris du modal
        // classeur sur /datastore qui était une cause connue de bug "panneau
        // s'ouvre derrière" (fix 2026-05-20).
        overlay.style.cssText =
            'position:fixed;inset:0;background:var(--bg-overlay, rgba(0,0,0,0.5));' +
            'display:flex;align-items:center;justify-content:center;';

        var card = document.createElement('div');
        // overflow:hidden (fix 2026-06-10, bug vécu « boutons dans la zone
        // d'erreur ») : sans clip, quand le contenu dépasse max-height:86vh
        // (petit écran + message d'erreur long + progressBox visible), le
        // footer (Annuler/Enregistrer/Voir tous) était RENDU HORS du
        // rectangle de la card, superposé visuellement au contenu derrière.
        card.style.cssText =
            'background:var(--bg-surface, #fff);color:var(--text-primary, #111827);' +
            'border-radius:0.75rem;box-shadow:var(--shadow-lg, 0 10px 40px rgba(0,0,0,0.2));' +
            'border:1px solid var(--border, transparent);' +
            'width:min(720px, 94vw);max-height:86vh;overflow:hidden;' +
            'display:flex;flex-direction:column;padding:1.25rem;gap:0.75rem;';

        var title = document.createElement('h2');
        title.textContent = 'Confidentialité — termes à anonymiser';
        title.style.cssText = 'font-size:1rem;font-weight:600;margin:0;';

        // ── Stats badges (cohérence visuelle avec /data/privacy) ──
        // 3 cartes inline pour le scope "classeur courant" : total détectés,
        // en attente de revue, anonymisés. ``critical_visible`` (présent sur
        // /data/privacy) est volontairement omis ici : c'est une métrique
        // globale (nb critiques visibles dans TOUS les contextes envoyés au
        // LLM), pas scopable au workbook ouvert. Le badge de chiffrer/total
        // dans la sub legend reste sous forme texte pour le filtre actif.
        var statsRow = document.createElement('div');
        statsRow.style.cssText =
            'display:flex;flex-wrap:wrap;gap:0.5rem;font-size:0.75rem;';

        function _mkStatCard(label, valueRef, accentColor) {
            var c = document.createElement('div');
            c.style.cssText =
                'flex:1;min-width:110px;padding:0.45rem 0.7rem;' +
                'border:1px solid var(--border, #e5e7eb);border-radius:0.4rem;' +
                'background:var(--bg-surface, #fff);display:flex;flex-direction:column;gap:0.1rem;';
            var lab = document.createElement('span');
            lab.textContent = label;
            lab.style.cssText = 'color:var(--text-muted, #6b7280);font-size:0.7rem;';
            var val = document.createElement('span');
            val.id = valueRef;
            val.setAttribute('aria-live', 'polite');
            val.textContent = '0';
            val.style.cssText =
                'font-weight:600;font-size:0.95rem;' +
                'color:' + (accentColor || 'var(--text-primary, #111827)') + ';';
            c.appendChild(lab);
            c.appendChild(val);
            return c;
        }
        // IDs avec préfixe ``anon-modal-`` pour éviter toute collision avec
        // les IDs de /data/privacy (``stat-total`` etc.) si les deux UIs se
        // retrouvaient dans le même document (cas Theory : modal ouvert sur
        // une page qui aurait aussi inclu privacy.html).
        var statCardTotal = _mkStatCard('Détectés', 'anon-modal-stat-total');
        var statCardPending = _mkStatCard('À confirmer', 'anon-modal-stat-pending', 'var(--status-warning, #d97706)');
        var statCardEnabled = _mkStatCard('Anonymisés', 'anon-modal-stat-enabled', 'var(--status-success, #059669)');
        statsRow.appendChild(statCardTotal);
        statsRow.appendChild(statCardPending);
        statsRow.appendChild(statCardEnabled);

        // ``sub`` reste utilisé pour la legend du filtre actif (ex: "101
        // affichés (filtre : nouveaux)"). Stats principales = ``statsRow``.
        var sub = document.createElement('p');
        sub.style.cssText = 'font-size:0.75rem;color:var(--text-muted, #6b7280);margin:0;';

        // Outils du haut : recherche + filtre
        var toolsRow = document.createElement('div');
        toolsRow.style.cssText = 'display:flex;gap:0.5rem;align-items:center;';

        var search = document.createElement('input');
        search.type = 'text';
        search.placeholder = 'Rechercher un terme…';
        search.style.cssText =
            'flex:1;padding:0.45rem 0.7rem;border:1px solid var(--border, #d1d5db);' +
            'border-radius:0.375rem;background:var(--bg-surface, #fff);' +
            'color:var(--text-primary, #111827);font-size:0.875rem;';

        var filterSel = document.createElement('select');
        filterSel.style.cssText =
            'padding:0.45rem 0.7rem;border:1px solid var(--border, #d1d5db);' +
            'border-radius:0.375rem;background:var(--bg-surface, #fff);' +
            'color:var(--text-primary, #111827);font-size:0.875rem;';
        var opts_ = [
            ['all', 'Tous'],
            ['new', 'Nouveaux'],
            ['enabled', 'Anonymisés'],
            ['clear', 'En clair']
        ];
        opts_.forEach(function(o) {
            var opt = document.createElement('option');
            opt.value = o[0]; opt.textContent = o[1];
            filterSel.appendChild(opt);
        });
        // Si on a des nouveaux tokens ce tour-ci, auto-filtre dessus pour
        // focaliser l'attention. Sinon, vue complète par défaut.
        var hasAnyNew = Object.keys(newShownThisOpen).length > 0;
        filterSel.value = hasAnyNew ? 'new' : 'all';

        // Filtre type de valeur (numérique / non-numérique). Miroir client
        // du ``_is_pure_numeric`` Python (auto_anonymizer.py) : un token
        // est "purement numérique" si chaque caractère est chiffre ou
        // séparateur autorisé (espace, ``,``, ``.``, ``+``, ``-``, ``_``,
        // ``/``, ``:``) ET qu'il contient au moins un chiffre. Les
        // téléphones FR sans lettres (06.12…) tombent dans "numérique"
        // — connu, l'utilisateur peut les flagger manuellement.
        var numFilterSel = document.createElement('select');
        numFilterSel.style.cssText = filterSel.style.cssText;
        [
            ['all', 'Tous types'],
            ['non-numeric', 'Texte uniquement'],
            ['numeric', 'Numériques uniquement']
        ].forEach(function(o) {
            var opt = document.createElement('option');
            opt.value = o[0]; opt.textContent = o[1];
            numFilterSel.appendChild(opt);
        });
        numFilterSel.value = 'all';

        toolsRow.appendChild(search);
        toolsRow.appendChild(filterSel);
        toolsRow.appendChild(numFilterSel);

        // Bulk actions (au-dessus de la liste)
        var bulkRow = document.createElement('div');
        bulkRow.style.cssText = 'display:flex;gap:0.5rem;flex-wrap:wrap;';
        function mkBtn(label, handler, bgColor) {
            var b = document.createElement('button');
            b.type = 'button';
            b.textContent = label;
            b.style.cssText =
                'padding:0.35rem 0.75rem;border:1px solid var(--border, #d1d5db);' +
                'background:' + (bgColor || 'var(--bg-surface, #fff)') + ';' +
                'color:' + (bgColor ? '#fff' : 'var(--text-secondary, #374151)') + ';' +
                'border-radius:0.375rem;font-size:0.8125rem;cursor:pointer;';
            b.addEventListener('click', handler);
            return b;
        }
        bulkRow.appendChild(mkBtn('Tout anonymiser', function() { bulkSet({enabled: true, confirmed: true}); }));
        bulkRow.appendChild(mkBtn('Rien anonymiser', function() { bulkSet({enabled: false, confirmed: true}); }));
        bulkRow.appendChild(mkBtn('Confirmer visibles sans anonymiser', function() { bulkConfirmVisible(false); }));
        bulkRow.appendChild(mkBtn('Anonymiser visibles', function() { bulkConfirmVisible(true); }));

        // Bouton « Améliorer l'anonymisation » (2026-05-19, fix David) —
        // remplace l'ancien « Détecter automatiquement » (qui faisait de
        // l'auto-classification PII via Ollama). Désormais on délègue au
        // même flow que /data/privacy : ``PrivacyImprovePseudos.openAndStartImprove``
        // appelle ``POST /api/anonymization/improve-pseudo`` qui demande au
        // LLM local de proposer un LABEL sémantique (NOM_FAMILLE, CODE_CLIENT…)
        // au lieu du ``TXT_4b3a`` opaque auto-généré.
        //
        // Avantages vs runAutoClassify (auto-classification PII) :
        //   - Améliore aussi la LISIBILITÉ du placeholder pour le LLM
        //     (NOM_FAMILLE_4b3a > TXT_4b3a > nn_e3f).
        //   - Ne touche PAS aux toggles ``enabled`` de l'user (préserve
        //     les choix manuels) — l'auto-classify les écrasait.
        //   - Préserve les pseudos personnalisés saisis par l'user (regex
        //     anti-écrasement côté backend handler).
        //
        // ``runAutoClassify`` reste en place comme code dormant (réactivable
        // via injection si besoin de la classification PII) mais n'est plus
        // exposé via UI.
        //
        // ALIGNEMENT COMPORTEMENTAL (2026-05-20, demande user) — ce bouton
        // doit « reprendre le code » de ``#action-improve-pseudos`` côté
        // ``privacy-page.js`` (l'action déclenchée par le clic), sans
        // changer le visuel (rouge brand, comme les autres bulk actions).
        // Concrètement on ajoute :
        //   - Auto-flush du state pending AVANT l'improve (parité avec
        //     ``privacy-page.js#_persistDirtyTerms``). Sans ça, un terme
        //     toggle ON puis clic immédiat tombe en ``skipped_disabled``
        //     côté backend (la BDD n'a pas reçu le PUT debouncé 300ms).
        //   - Désactivation du bouton pendant tout le flow (anti double-
        //     clic + parité ``actImprove.disabled = true`` autour du flow
        //     côté /data/privacy).
        //   - ``await`` sur ``openAndStartImprove`` pour garder le bouton
        //     désactivé jusqu'à la fin du traitement (success / abort /
        //     empty).
        // Le test ``test_anonymization_panel_alignment.py::TestImproveAnonymizationButtonBehavior``
        // verrouille ces 3 garanties.
        //
        // Les markers ``IMPROVE_BUTTON_BLOCK_*`` (sentinels commentaire,
        // ne pas les retirer) délimitent le handler pour le test —
        // résistants aux reformats Prettier.
        // ─── IMPROVE_BUTTON_BLOCK_START ───────────────────────────────
        var btnImprove = mkBtn("Améliorer l'anonymisation", async function() {
            // ── Handler aligné sur ``privacy-page.js#action-improve-pseudos``
            //    (demande user 2026-05-20 « doit reprendre le code, ils sont
            //    censés faire la même chose à des échelles différentes »).
            //
            // Échelle privacy-page = global (state.terms, state.dirtyTerms).
            // Échelle iris-grid modal = classeur courant ouvert (draft local).
            //
            // Source de vérité visuelle du modal = ``draft`` (closure ci-dessous
            // ligne 6356, hoisted donc accessible ici). L'user toggle des termes
            // dans le modal → mute draft mais PAS ``_anonymizationState`` tant
            // que « Enregistrer » n'est pas cliqué. Si on lit _anonymizationState
            // ici, on rate les toggles draft → message "Aucun terme activé"
            // alors que l'user en a activés (bug observé 2026-05-20).
            if (!window.PrivacyImprovePseudos
                || typeof window.PrivacyImprovePseudos.openAndStartImprove !== 'function') {
                // eslint-disable-next-line no-console
                if (window.console && console.error) {
                    console.error(
                        '[iris-grid] PrivacyImprovePseudos.openAndStartImprove indisponible — '
                        + 'improve-pseudos.js a-t-il bien été chargé ?'
                    );
                }
                if (typeof window.showToast === 'function') {
                    window.showToast(
                        "Module d'amélioration indisponible. Recharge la page (Ctrl+F5).",
                        'error'
                    );
                }
                return;
            }
            // ``self`` capture le SqlResultGrid courant.
            var grid = self;
            // Auto-commit du draft AVANT amélioration (parité privacy-page.js
            // qui flush state.dirtyTerms avant improve). Sans ce commit, les
            // toggles non-sauvés du modal ne sont pas persistés en BDD →
            // l'improve opérerait sur des termes en BDD avec enabled=false →
            // 0 mapping retenu.
            //
            // ``draft`` peut être ``undefined`` si btnImprove est cliqué AVANT
            // que la ligne 6356 ait été exécutée (race théorique) — on guard.
            var hasDraftDirty = false;
            try {
                hasDraftDirty = (typeof draft !== 'undefined')
                    && (JSON.stringify(draft) !== JSON.stringify(
                        (grid._anonymizationState && grid._anonymizationState.terms) || {}
                    ));
            } catch (_e) { hasDraftDirty = false; }

            if (hasDraftDirty) {
                if (typeof window.showToast === 'function') {
                    window.showToast(
                        "Enregistrement avant amélioration…",
                        'info'
                    );
                }
                btnImprove.disabled = true;
                try {
                    // Commit le draft → PUT vers BDD. Pattern identique au
                    // bouton « Enregistrer » du modal (ligne 7088+).
                    var newState = { version: 1, terms: draft };
                    if (typeof grid._cancelAnonymizationPersist === 'function') {
                        grid._cancelAnonymizationPersist();
                    }
                    if (typeof grid._bumpAnonStateSeq === 'function') {
                        grid._bumpAnonStateSeq();
                    }
                    var saveRes = await grid._persistAnonymizationState(newState);
                    if (!saveRes || !saveRes.ok) {
                        var errMsg = (saveRes && saveRes.data && saveRes.data.error)
                            || 'inconnue';
                        throw new Error(errMsg);
                    }
                } catch (err) {
                    if (typeof window.showToast === 'function') {
                        window.showToast(
                            "Échec enregistrement (" + ((err && err.message) || 'inconnue')
                                + "). Amélioration annulée pour éviter un state "
                                + "incohérent. Recharge la page si le problème persiste.",
                            'error'
                        );
                    }
                    return;
                } finally {
                    btnImprove.disabled = false;
                }
            } else if (!!(grid && grid._anonPersistPending)) {
                // Pas de modif draft local, mais un flush debouncé en attente
                // (modifs faites HORS modal). Flusher pour s'assurer que la
                // BDD est cohérente avant l'improve.
                btnImprove.disabled = true;
                try {
                    if (typeof grid._flushAnonymizationPersist === 'function') {
                        await grid._flushAnonymizationPersist(false);
                    }
                } catch (_e) { /* best-effort */ }
                finally { btnImprove.disabled = false; }
            }
            // Ferme le modal Confidentialité parent AVANT d'ouvrir improve.
            // Fix bug 2026-05-20 (user) : sinon 2 modaux empilés (Confidentialité +
            // Improve), backdrop visuel doublé, et au close du Improve le state
            // OverlayManager pouvait rester corrompu → app bloquée (refresh
            // page nécessaire). Pattern aligné sur privacy-page.js qui ouvre
            // Improve depuis la page elle-même, pas depuis un autre modal.
            // ``close`` est hoisted depuis la function declaration ligne 7076 de
            // cette closure ``_openAnonymizationPanel`` (function declarations
            // sont hoisted, function expressions ne le sont pas).
            //
            // ⚠️ Flow consent : si on close sans set ``_consentExitReason``,
            // le dispatch (cf. ``close()``) appelle ``onAbandon`` → backend
            // reçoit ``abandoned=true`` → Iris reçoit "lecture refusée"
            // SILENCIEUSEMENT. L'user clique « Améliorer » en pensant juste
            // enrichir ses pseudos, et perd le flow Iris sans feedback.
            // Adversarial review HIGH 2026-05-20.
            //
            // Améliorer = sortie distincte de Annuler. Dispatch préfère
            // ``onImprove`` (caller veut guider l'user post-improve, ex:
            // copilot affiche "Cliquez Envoyer pour reprendre"). Fallback
            // sur ``onCancel`` si le caller n'expose pas onImprove → Iris
            // conserve son comportement historique (Améliorer ré-ouvre le
            // prompt OUI/NON via onCancel). Branche no-op hors flow consent
            // (``_consentCallbacks=null``, _consentExitReason ignoré).
            // ``_consentExitReason`` est hoisted (var) au top du scope, donc
            // accessible ici.
            _consentExitReason = 'improve';
            if (typeof close === 'function') {
                try { close(); } catch (_e) { /* defensive */ }
            }
            // Fire-and-forget (pas d'await) — parité privacy-page.js. La modal
            // gère son propre lifecycle via AbortController + OverlayManager.
            window.PrivacyImprovePseudos.openAndStartImprove({
                    getXsrf: _getXsrfCookie,
                    getEligibleTerms: function() {
                        // Lit ``draft`` (= source de vérité visuelle du modal,
                        // muté par les toggles user). Fix bug 2026-05-20 :
                        // avant on lisait ``_anonymizationState.terms`` qui ne
                        // reflète pas les toggles non-sauvés → "Aucun terme
                        // activé" alors que l'user en avait coché dans le modal.
                        var src = (typeof draft !== 'undefined' && draft)
                            ? draft
                            : ((grid && grid._anonymizationState && grid._anonymizationState.terms) || {});
                        var out = [];
                        Object.keys(src).forEach(function(tok) {
                            var entry = src[tok];
                            if (!entry || !entry.enabled) return;
                            out.push({
                                term: tok,
                                enabled: true,
                                pseudo_middle: (typeof entry.pseudo === 'string' && entry.pseudo)
                                    ? entry.pseudo : null,
                            });
                        });
                        return out;
                    },
                    refreshTerm: function(term, newPseudoMiddle) {
                        // Update inline + ré-applique via ``_setAnonymizationState``
                        // (méthode prototype canonique, ligne 4956) qui pilote
                        // le re-render du panneau ouvert + broadcast cross-tab
                        // via ``_anonBroadcastChannel``. Fix review adversariale
                        // BLOCKING J 2026-05-19 : les méthodes
                        // ``_renderAnonymizationList`` / ``_reloadAnonymizationState``
                        // n'existaient PAS sur ``SqlResultGrid.prototype`` →
                        // le panneau n'était jamais rafraîchi après l'improve.
                        var st = (grid && grid._anonymizationState) || null;
                        if (!st || !st.terms || !st.terms[term]) return;
                        // Clone shallow pour respecter immutability conceptuelle
                        // côté listeners du broadcast (autre tab applique le
                        // state reçu — doit pas être muté par ref).
                        var nextTerms = {};
                        Object.keys(st.terms).forEach(function(k) {
                            nextTerms[k] = st.terms[k];
                        });
                        nextTerms[term] = Object.assign({}, st.terms[term],
                            { pseudo: newPseudoMiddle });
                        var nextState = Object.assign({}, st, { terms: nextTerms });
                        if (typeof grid._setAnonymizationState === 'function') {
                            try { grid._setAnonymizationState(nextState); } catch (e) {}
                        }
                    },
                    onComplete: function() {
                        // Refetch BDD canonique (un autre tab a peut-être amélioré
                        // d'autres termes aussi). ``_setAnonymizationState`` re-render
                        // + broadcast les modifications aux autres tabs ouverts.
                        fetch('/api/anonymization/terms', {
                            credentials: 'same-origin',
                            headers: { 'X-Requested-With': 'XMLHttpRequest' },
                        }).then(function(resp) {
                            return resp.ok ? resp.json() : null;
                        }).then(function(data) {
                            if (!data) return;
                            var newState = data.anonymization_state;
                            if (newState && typeof grid._setAnonymizationState === 'function') {
                                try { grid._setAnonymizationState(newState); } catch (e) {}
                            }
                        }).catch(function() { /* best-effort */ });
                    },
                });
        }, 'var(--brand, #2563eb)');
        bulkRow.appendChild(btnImprove);
        // ─── IMPROVE_BUTTON_BLOCK_END ─────────────────────────────────

        // L'ancien sélecteur de scope (active vs workbook) servait à
        // l'auto-classify PII. Le bouton « Améliorer l'anonymisation »
        // traite tous les termes ``enabled`` du panneau (cross-classeur
        // dans /data/privacy, scoped-state ici dans iris-grid). Pas de
        // notion de scope côté UI → le ``scopeSelect`` est construit pour
        // compatibilité avec ``runAutoClassify`` mais masqué via display:none.
        var scopeSelect = document.createElement('select');
        scopeSelect.id = 'anon-auto-scope';
        scopeSelect.title = 'Périmètre de l\'analyse automatique';
        // Masqué depuis le retrait du bouton « Détecter automatiquement »
        // (2026-05-19, fix David). Le select reste construit pour
        // compatibilité avec ``runAutoClassify`` (code dormant) mais
        // n'apparaît plus dans la barre d'actions UI.
        scopeSelect.style.cssText =
            'display:none;'
            + 'padding:0.35rem 0.6rem;border:1px solid var(--border, #d1d5db);'
            + 'background:var(--bg-surface, #fff);color:var(--text-secondary, #374151);'
            + 'border-radius:0.375rem;font-size:0.8125rem;cursor:pointer;';
        [
            ['active', 'Onglet actif'],
            ['workbook', 'Classeur actif'],
        ].forEach(function(o) {
            var opt = document.createElement('option');
            opt.value = o[0];
            opt.textContent = o[1];
            scopeSelect.appendChild(opt);
        });
        // Default : classeur actif (le maximum dans le scope autorisé)
        scopeSelect.value = 'workbook';
        bulkRow.appendChild(scopeSelect);

        // Container progression (créé masqué, affiché pendant le run)
        var progressBox = document.createElement('div');
        progressBox.style.cssText =
            'display:none;flex-direction:column;gap:0.4rem;' +
            'padding:0.6rem 0.8rem;border-radius:0.5rem;' +
            'background:var(--bg-surface-2, #f3f4f6);' +
            'border:1px solid var(--border, #d1d5db);' +
            'font-size:0.8rem;color:var(--text-secondary, #374151);';
        var progressLabel = document.createElement('div');
        progressLabel.style.cssText = 'display:flex;justify-content:space-between;gap:0.5rem;align-items:center;';
        var progressLabelText = document.createElement('span');
        var progressEta = document.createElement('span');
        progressEta.style.cssText = 'color:var(--text-muted, #6b7280);font-variant-numeric:tabular-nums;';
        progressLabel.appendChild(progressLabelText);
        progressLabel.appendChild(progressEta);

        var progressTrack = document.createElement('div');
        progressTrack.style.cssText =
            'height:6px;background:var(--border, #d1d5db);border-radius:3px;overflow:hidden;';
        var progressFill = document.createElement('div');
        progressFill.style.cssText =
            'height:100%;width:0%;background:var(--brand, #2563eb);transition:width 0.3s;';
        progressTrack.appendChild(progressFill);

        var progressFooter = document.createElement('div');
        progressFooter.style.cssText = 'display:flex;justify-content:space-between;gap:0.5rem;align-items:center;';
        var progressDetails = document.createElement('span');
        progressDetails.style.cssText = 'color:var(--text-muted, #6b7280);font-variant-numeric:tabular-nums;';
        var btnCancel2 = document.createElement('button');
        btnCancel2.type = 'button';
        btnCancel2.textContent = 'Annuler';
        btnCancel2.style.cssText =
            'padding:0.25rem 0.65rem;border:1px solid var(--border, #d1d5db);' +
            'background:var(--bg-surface, #fff);color:var(--text-secondary, #374151);' +
            'border-radius:0.375rem;font-size:0.75rem;cursor:pointer;';
        progressFooter.appendChild(progressDetails);
        progressFooter.appendChild(btnCancel2);

        progressBox.appendChild(progressLabel);
        progressBox.appendChild(progressTrack);
        progressBox.appendChild(progressFooter);
        // Insertion DOM différée : ``bulkRow`` n'est appendChild dans
        // ``card`` que plus bas (~ligne 5278). On utilise ``card`` direct
        // qui existe déjà à ce stade.

        var cancelRequested = false;
        var currentAbortCtrl = null;
        btnCancel2.addEventListener('click', function() {
            cancelRequested = true;
            btnCancel2.disabled = true;
            btnCancel2.textContent = 'Annulation…';
            // Abort le fetch en cours pour cancel < 1s perçu (review CRITICAL #4)
            if (currentAbortCtrl) {
                try { currentAbortCtrl.abort(); } catch (e) {}
            }
        });

        function fmtDuration(ms) {
            if (ms < 1000) return Math.round(ms) + ' ms';
            var s = Math.round(ms / 100) / 10;
            if (s < 60) return s + ' s';
            var m = Math.floor(s / 60), rs = Math.round(s - m * 60);
            return m + ' min ' + rs + ' s';
        }

        // URL utilisée pour les POST chunks. Bascule du LLM local vers le
        // fallback regex si /probe retourne 503 (parité avec /data/privacy
        // via scan-progress.js). Stateful local à ``runAutoClassify`` —
        // déclaré sur la closure du modal pour rester accessible aux
        // event-listeners du chunk loop.
        var classifyUrl = '/api/anonymization/auto-classify';
        function postChunk(tokensChunk) {
            currentAbortCtrl = new AbortController();
            return fetch(classifyUrl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Xsrftoken': _getXsrfCookie()
                },
                body: JSON.stringify({ tokens: tokensChunk }),
                signal: currentAbortCtrl.signal
            });
        }

        async function runAutoClassify() {
            // Bouton "Détecter automatiquement" = REFAIRE LA LISTE.
            // Le LLM décide pour CHAQUE terme (sensible ou pas). Cela
            // écrase les choix précédents (humains ou auto antérieur).
            // L'utilisateur peut toujours modifier après dans le panneau.
            //
            // Scope filtre la liste analysée :
            //  - active   : termes de l'onglet actif uniquement
            //  - workbook : onglet actif + autres onglets du classeur ouvert
            //  - all      : tous (cross-classeurs BDD)
            var scope = scopeSelect.value || 'workbook';
            var byCol = self._extractTermsByColumn();
            var activeByCol = byCol.__active__ || {};
            var otherTabsTerms = byCol.__otherTabs__ || [];
            var inScope = Object.create(null);
            // Onglet actif (toutes colonnes)
            Object.keys(activeByCol).forEach(function(col) {
                (activeByCol[col] || []).forEach(function(t) { inScope[t] = true; });
            });
            if (scope === 'workbook') {
                otherTabsTerms.forEach(function(t) { inScope[t] = true; });
            }
            var allTokens = Object.keys(draft).filter(function(t) {
                return inScope[t];
            });
            if (allTokens.length === 0) {
                var scopeLabel = ({
                    active: 'l\'onglet actif',
                    workbook: 'le classeur actif'
                })[scope] || 'ce périmètre';
                setErr('Aucun terme dans ' + scopeLabel + ' à analyser.', 'muted');
                return;
            }

            var prevText = btnAuto.textContent;
            btnAuto.disabled = true;
            btnAuto.innerHTML = '<i class="bi bi-hourglass-split"></i> Calibrage…';
            setErr('', 'muted');
            cancelRequested = false;
            btnCancel2.disabled = false;
            btnCancel2.textContent = 'Annuler';

            // PHASE 1 — Probe pour estimer le temps total. Sur 503 (LLM
            // local indisponible/non-configuré), bascule sur le fallback
            // regex au lieu de bail out : parité avec /data/privacy qui
            // fait pareil via scan-progress.js::performAutoClassify('regex').
            var batchSize = 200;
            var avgMs = null;
            classifyUrl = '/api/anonymization/auto-classify';
            try {
                // signal abortable (fix 2026-06-11, tâche #13) : la
                // calibration appelle le LLM local — si celui-ci est wedgé,
                // le probe peut pendre longtemps. Sans signal, « Annuler »
                // restait bloqué sur « Annulation… » toute la durée du probe.
                currentAbortCtrl = new AbortController();
                var probeRes = await fetch('/api/anonymization/auto-classify/probe', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-Xsrftoken': _getXsrfCookie()
                    },
                    signal: currentAbortCtrl.signal
                });
                if (probeRes.status === 503) {
                    // LLM local indisponible (non configuré ou down). Fallback
                    // automatique sur regex : pas de probe nécessaire (regex
                    // est instantané), juste un message informatif puis run.
                    classifyUrl = '/api/anonymization/auto-classify/regex';
                    avgMs = null; // pas de calibration en regex (rapide)
                    setErr('LLM local indisponible — détection via patterns regex (PII built-in).', 'muted');
                } else if (probeRes.ok) {
                    var probeData = await probeRes.json();
                    if (probeData.duration_ms) avgMs = probeData.duration_ms;
                    if (probeData.batch_size) batchSize = probeData.batch_size;
                }
            } catch (e) {
                if (e && e.name === 'AbortError') {
                    // Annulation user pendant la calibration — pas une erreur.
                    setErr('Annulé.', 'muted');
                } else {
                    setErr('Erreur calibration : ' + (e && e.message ? e.message : 'inconnue'));
                }
                btnAuto.disabled = false;
                btnAuto.textContent = prevText;
                return;
            }

            // PHASE 2 — Run chunked avec progression
            var totalChunks = Math.ceil(allTokens.length / batchSize);
            var estimatedMs = avgMs ? Math.round(avgMs * totalChunks) : null;
            progressLabelText.textContent = 'Analyse de ' + allTokens.length + ' termes…';
            progressEta.textContent = estimatedMs ? '~' + fmtDuration(estimatedMs) + ' restant' : '';
            progressDetails.textContent = '0 / ' + totalChunks + ' lots • 0 termes flaggés';
            progressFill.style.width = '0%';
            progressBox.style.display = 'flex';
            btnAuto.innerHTML = '<i class="bi bi-hourglass-split"></i> Analyse en cours…';

            var totalApplied = 0;       // tokens marqués sensibles par le LLM
            var totalNotSensitive = 0;  // tokens marqués non-sensibles par le LLM
            var startTime = Date.now();
            var observedTimings = [];

            for (var i = 0; i < totalChunks; i++) {
                if (cancelRequested) break;
                var chunk = allTokens.slice(i * batchSize, (i + 1) * batchSize);
                var chunkStart = Date.now();
                try {
                    var res = await postChunk(chunk);
                    if (res.status === 503 && classifyUrl.indexOf('/regex') === -1) {
                        // LLM local désactivé en cours de run (admin a save).
                        // Bascule transparente sur regex : retry du même chunk
                        // pour ne pas perdre les classifications déjà faites.
                        classifyUrl = '/api/anonymization/auto-classify/regex';
                        setErr('LLM local indisponible — bascule sur regex.', 'muted');
                        i--; // retry ce chunk avec la nouvelle URL
                        continue;
                    }
                    if (res.status === 503) {
                        // Déjà en mode regex et 503 — vrai problème serveur.
                        setErr('Service de détection indisponible (lot ' + (i + 1) + '/' + totalChunks + ').');
                        break;
                    }
                    if (!res.ok) {
                        setErr('Erreur ' + res.status + ' au lot ' + (i + 1) + '/' + totalChunks + '.');
                        break;
                    }
                    var data = await res.json();
                    observedTimings.push(Date.now() - chunkStart);
                    var flaggedSet = {};
                    if (Array.isArray(data.flagged)) {
                        data.flagged.forEach(function(token) { flaggedSet[token] = true; });
                    }
                    // Refaire la liste : décision binaire LLM pour CHAQUE
                    // token du chunk (sensible OU pas sensible).
                    chunk.forEach(function(token) {
                        if (!draft[token]) return;
                        if (flaggedSet[token]) {
                            draft[token].enabled = true;
                            draft[token].confirmed = true;
                            totalApplied++;
                        } else {
                            draft[token].enabled = false;
                            draft[token].confirmed = true;
                            totalNotSensitive++;
                        }
                    });
                } catch (e) {
                    if (e && e.name === 'AbortError') {
                        // Annulation user — break sans afficher d'erreur
                        cancelRequested = true;
                        break;
                    }
                    setErr('Erreur réseau au lot ' + (i + 1) + ' : ' +
                        (e && e.message ? e.message : 'inconnue'));
                    break;
                }

                var processed = i + 1;
                var pct = Math.round((processed / totalChunks) * 100);
                progressFill.style.width = pct + '%';
                var remaining = totalChunks - processed;
                if (observedTimings.length > 0 && remaining > 0) {
                    var avgObs = observedTimings.reduce(function(a, b) { return a + b; }, 0) / observedTimings.length;
                    progressEta.textContent = '~' + fmtDuration(Math.round(avgObs * remaining)) + ' restant';
                } else if (remaining === 0) {
                    progressEta.textContent = 'Terminé';
                }
                progressDetails.textContent =
                    processed + ' / ' + totalChunks + ' lots • ' +
                    totalApplied + ' termes flaggés';

                renderList();
                updateSubtitle();
            }

            var totalTime = Date.now() - startTime;
            progressBox.style.display = 'none';
            btnAuto.disabled = false;
            btnAuto.textContent = prevText;

            // Auto-persist : décisions LLM commit directement en BDD.
            // L'utilisateur peut modifier dans le panneau s'il veut.
            function mergeAndPersistAutoFlags() {
                var totalProcessed = totalApplied + totalNotSensitive;
                if (totalProcessed === 0) return Promise.resolve();
                var liveTerms = self._anonymizationState.terms || {};
                Object.keys(draft).forEach(function(token) {
                    var d = draft[token];
                    if (!d || !d.confirmed) return;
                    if (!liveTerms[token]) liveTerms[token] = {};
                    liveTerms[token].enabled = !!d.enabled;
                    liveTerms[token].confirmed = true;
                    if (d.pseudo && !liveTerms[token].pseudo) {
                        liveTerms[token].pseudo = d.pseudo;
                    }
                });
                self._anonymizationState.terms = liveTerms;
                self._bumpAnonStateSeq();
                return self._persistAnonymizationState(self._anonymizationState);
            }

            var totalProcessed = totalApplied + totalNotSensitive;
            if (cancelRequested) {
                setErr('Annulé. ' + totalApplied + ' terme(s) anonymisé(s) avant arrêt.', 'muted');
                if (totalProcessed > 0) mergeAndPersistAutoFlags();
                return;
            }
            if (totalProcessed === 0) {
                setErr('Analyse non aboutie en ' + fmtDuration(totalTime) +
                    '. Sélection manuelle possible si nécessaire.', 'muted');
                return;
            }
            setErr(totalApplied + ' terme(s) anonymisé(s), ' +
                totalNotSensitive + ' laissé(s) en clair (analyse en ' +
                fmtDuration(totalTime) + '). Modifiable dans la liste si besoin.', 'success');
            try {
                await mergeAndPersistAutoFlags();
                self._updateAnonymizationBadge && self._updateAnonymizationBadge();
                self._applyAnonymizationCellMarkers && self._applyAnonymizationCellMarkers();
            } catch (e) {
                setErr('Détection OK mais persist échouée : ' +
                    (e && e.message ? e.message : 'inconnue') +
                    '. Cliquer « Enregistrer » pour réessayer.');
            }
            // NB : l'ancien ``setTimeout`` qui re-forçait err en ROUGE après
            // 6s a été SUPPRIMÉ (fix 2026-06-11, tâche #13) — il recolorait
            // en rouge le message de succès encore affiché (bug vécu).
            // setErr pose désormais la couleur atomiquement à chaque message,
            // le « reset au rouge par défaut » n'a plus de raison d'être.
        }

        // Container scrollable de la liste. min-height:0 (fix 2026-06-10) :
        // l'idiome flex pour qu'un enfant flex:1 scrollable puisse SE
        // COMPRESSER sous la contrainte du parent — l'ancien plancher rigide
        // 200px forçait le débordement de la card sur petit écran.
        var listWrap = document.createElement('div');
        listWrap.style.cssText =
            'flex:1;min-height:0;overflow-y:auto;border:1px solid var(--border, #e5e7eb);' +
            'border-radius:0.5rem;padding:0.25rem;background:var(--bg-surface-2, #f9fafb);';

        // Zone d'erreur : flex-shrink:0 (jamais compressée par le layout) +
        // max-height + scroll interne pour les messages longs (ex: 409
        // verbeux) — au lieu de pousser le footer hors de la card.
        var err = document.createElement('div');
        err.style.cssText =
            'font-size:0.8125rem;color:var(--status-error,#dc2626);min-height:1rem;' +
            'flex-shrink:0;max-height:6em;overflow-y:auto;overflow-wrap:anywhere;';

        // SSoT d'affichage du statut du panneau (fix 2026-06-11, tâche #13) :
        // TOUT message passe par setErr — texte + couleur posés ATOMIQUEMENT.
        // Supprime deux classes de bugs vécus : « succès recoloré en rouge »
        // (l'ancien timer 6s re-forçait le rouge sur un message encore
        // affiché) et « message héritant de la couleur du précédent » (writer
        // qui posait le texte sans la couleur). kind: 'error' (défaut, rouge)
        // | 'muted' (info discrète) | 'success' (vert).
        var _ERR_KIND_COLORS = {
            error: 'var(--status-error,#dc2626)',
            muted: 'var(--text-muted, #6b7280)',
            success: 'var(--status-success, #059669)'
        };
        function setErr(text, kind) {
            err.textContent = text;
            err.style.color = _ERR_KIND_COLORS[kind] || _ERR_KIND_COLORS.error;
        }

        // Footer : flex-shrink:0 — les boutons d'action gardent toujours
        // leur taille et leur place EN BAS DE LA CARD (pattern modal
        // standard : tout est shrink:0 sauf la zone scrollable listWrap).
        var footer = document.createElement('div');
        footer.style.cssText =
            'display:flex;justify-content:flex-end;gap:0.5rem;align-items:center;flex-shrink:0;';

        // Lien vers la page de gestion globale ``/data/privacy``. La page
        // est la single source of truth pour la liste complète des termes
        // (cross-classeur, groupé par provenance). Le modal reste utile
        // pour les gates 409 ANON_PENDING_REVIEW déclenchés par un send
        // Iris en plein flow — il édite la même table BDD via la même API
        // (``/api/anonymization/terms``) donc tout changement ici est
        // immédiatement visible dans l'autre, et inversement.
        // ``target=_blank`` + ``rel=noopener noreferrer`` : préserve l'état
        // local du modal (draft non sauvé) et bloque le tabnabbing.
        // ``margin-right:auto`` pousse les actions Annuler/Enregistrer à
        // droite du flex container malgré ce 1er enfant.
        var btnViewAll = document.createElement('a');
        btnViewAll.textContent = 'Voir tous les termes →';
        btnViewAll.href = '/data/privacy';
        btnViewAll.target = '_blank';
        btnViewAll.rel = 'noopener noreferrer';
        btnViewAll.title =
            'Ouvrir la page Confidentialité — vue cross-classeur ' +
            'groupée par provenance.';
        btnViewAll.style.cssText =
            'margin-right:auto;padding:0.4rem 0.6rem;' +
            'color:var(--brand, #2563eb);font-size:0.8125rem;' +
            'text-decoration:none;border-radius:0.375rem;' +
            'border:1px solid transparent;cursor:pointer;';

        var btnCancel = document.createElement('button');
        btnCancel.type = 'button';
        btnCancel.textContent = 'Annuler';
        btnCancel.style.cssText =
            'padding:0.45rem 1rem;border:1px solid var(--border, #d1d5db);' +
            'background:var(--bg-surface, #fff);color:var(--text-secondary, #374151);' +
            'border-radius:0.375rem;font-size:0.8125rem;cursor:pointer;';
        var btnSave = document.createElement('button');
        btnSave.type = 'button';
        btnSave.textContent = 'Enregistrer';
        btnSave.style.cssText =
            'padding:0.45rem 1rem;border:none;background:var(--brand, var(--brand));color:#fff;' +
            'border-radius:0.375rem;font-size:0.8125rem;font-weight:500;cursor:pointer;';
        footer.appendChild(btnViewAll);
        footer.appendChild(btnCancel);
        footer.appendChild(btnSave);

        card.appendChild(title);
        card.appendChild(statsRow);
        card.appendChild(sub);
        card.appendChild(toolsRow);
        card.appendChild(bulkRow);
        // progressBox juste après bulkRow (visible au-dessus de la liste
        // pendant le run auto-classify, masqué par défaut).
        card.appendChild(progressBox);
        card.appendChild(listWrap);
        card.appendChild(err);
        card.appendChild(footer);
        overlay.appendChild(card);
        document.body.appendChild(overlay);
        // Enregistre dans OverlayManager : z-index dynamique (2000 + N×10 du
        // layer modal), gestion Escape LIFO, scroll-lock, onClose callback.
        // Garantit que ce panneau s'affiche TOUJOURS devant les autres
        // modaux (datastore wb-dialog, iris-grid fullscreen, etc.).
        if (window.OverlayManager && typeof window.OverlayManager.open === 'function') {
            window.OverlayManager.open(overlay, {
                layer: 'modal',
                lockScroll: true,
                onClose: function() { close(); },
            });
        }

        // Draft local (on ne mute pas this._anonymizationState avant save)
        var draft = JSON.parse(JSON.stringify(terms));

        function updateSubtitle() {
            // Stats scopées au classeur courant : ne compte que les termes
            // du workbook ouvert (onglet actif + autres onglets). Les
            // termes d'autres classeurs en BDD existent dans le draft pour
            // permettre un replace-state intact, mais ne sont pas comptés
            // dans le header du modal qui annonce le scope "classeur".
            var wbSet = _workbookTermsSet();
            var total = 0, pending = 0, enabled = 0, matchingFilter = 0;
            for (var k in draft) {
                if (!Object.prototype.hasOwnProperty.call(draft, k)) continue;
                if (!wbSet[k]) continue;
                total++;
                if (!draft[k].confirmed) pending++;
                if (draft[k].enabled) enabled++;
                if (filterMatch(k, draft[k])) matchingFilter++;
            }
            // Maj des 3 stat-cards. ``getElementById`` plutôt qu'une capture
            // locale : robuste si le modal est ré-ouvert (les anciennes refs
            // pointent vers du DOM removed). Coût ~3 lookups en O(1).
            var elTotal = document.getElementById('anon-modal-stat-total');
            var elPending = document.getElementById('anon-modal-stat-pending');
            var elEnabled = document.getElementById('anon-modal-stat-enabled');
            if (elTotal) elTotal.textContent = String(total);
            if (elPending) elPending.textContent = String(pending);
            if (elEnabled) elEnabled.textContent = String(enabled);

            // Sub-text : juste la legend du filtre actif (les stats principales
            // sont au-dessus dans statsRow). Affiche si le filtre réduit la
            // liste vs total — sinon vide pour ne pas surcharger.
            var filterLabels = {
                'new': 'nouveaux',
                'enabled': 'anonymisés',
                'clear': 'en clair',
            };
            var filterLabel = filterLabels[filterSel.value];
            if (filterLabel && matchingFilter !== total) {
                sub.textContent = matchingFilter + ' terme(s) affiché(s) (filtre : ' + filterLabel + ').';
            } else {
                sub.textContent = '';
            }
        }

        // Délégué à ``window.AnonTokenizer.isPureNumeric`` — single source
        // of truth Py↔JS partagée avec /data/privacy et le backend
        // ``auto_classify._is_pure_numeric``. Le fallback inline ci-dessous
        // n'est sollicité que si tokenizer.js n'est pas chargé (anomalie :
        // tokenizer.js est chargé AVANT iris-grid.js dans tous les
        // templates qui montent le modal — iris.html, datastore.html,
        // automations/edit.html). Defense-in-depth pour ne pas casser le
        // filtre type si tokenizer.js était CSP-blocked.
        var NUMERIC_ALLOWED = ' \t\u00A00123456789+-_.,/:';
        function isPureNumericClient(t) {
            if (typeof window !== 'undefined'
                && window.AnonTokenizer
                && typeof window.AnonTokenizer.isPureNumeric === 'function') {
                return window.AnonTokenizer.isPureNumeric(t);
            }
            if (t === null || t === undefined) return false;
            var s = String(t).trim();
            if (!s) return false;
            var hasDigit = false;
            for (var ix = 0; ix < s.length; ix++) {
                var ch = s.charAt(ix);
                if (ch >= '0' && ch <= '9') { hasDigit = true; continue; }
                if (NUMERIC_ALLOWED.indexOf(ch) === -1) return false;
            }
            return hasDigit;
        }

        function filterMatch(term, entry) {
            var q = search.value.trim().toLowerCase();
            if (q && term.toLowerCase().indexOf(q) === -1) return false;
            // Filtre type (numérique / non-numérique)
            var nv = numFilterSel.value;
            if (nv === 'numeric' && !isPureNumericClient(term)) return false;
            if (nv === 'non-numeric' && isPureNumericClient(term)) return false;
            switch (filterSel.value) {
                case 'new':      return !!newShownThisOpen[term];
                case 'enabled':  return !!entry.enabled;
                case 'clear':    return !entry.enabled && entry.confirmed;
                default:         return true;
            }
        }

        function renderList() {
            listWrap.innerHTML = '';
            var frag = document.createDocumentFragment();

            // 2 scopes distincts au sein du classeur courant :
            //  1. Onglet actif → groupé par colonne d'origine
            //  2. Autres onglets du classeur ouvert → liste plate
            // La section « Autres classeurs » a été retirée : la vision
            // user est "result area = classeur courant" — les termes
            // cross-classeurs se gèrent via le bouton "Voir tous les
            // termes →" qui ouvre /data/privacy.
            var byCol = self._extractTermsByColumn();
            var activeByCol = byCol.__active__ || {};
            var otherTabsTerms = byCol.__otherTabs__ || [];

            // Tri des colonnes de l'onglet actif : d'abord celles avec au
            // moins 1 terme NOUVEAU, puis alpha.
            var colNames = Object.keys(activeByCol);
            colNames.sort(function(a, b) {
                var aNew = activeByCol[a].some(function(t) {
                    return !!newShownThisOpen[t] && filterMatch(t, draft[t] || {});
                });
                var bNew = activeByCol[b].some(function(t) {
                    return !!newShownThisOpen[t] && filterMatch(t, draft[t] || {});
                });
                if (aNew !== bNew) return aNew ? -1 : 1;
                return a.localeCompare(b);
            });

            var totalRendered = 0;
            // Section 1 : onglet actif, par colonne
            for (var ci = 0; ci < colNames.length; ci++) {
                var cn = colNames[ci];
                var colTerms = activeByCol[cn].filter(function(t) {
                    var e = draft[t];
                    return e && filterMatch(t, e);
                });
                if (colTerms.length === 0) continue;
                var section = renderColumnSection(cn, colTerms, 'active');
                frag.appendChild(section);
                totalRendered += colTerms.length;
            }

            // Section 2 : autres onglets du classeur ouvert
            if (otherTabsTerms.length > 0) {
                var visibleOtherTabs = otherTabsTerms.filter(function(t) {
                    var e = draft[t];
                    return e && filterMatch(t, e);
                });
                if (visibleOtherTabs.length > 0) {
                    var otherTabsSection = renderColumnSection(
                        'Autres onglets de ce classeur', visibleOtherTabs, 'otherTabs'
                    );
                    frag.appendChild(otherTabsSection);
                    totalRendered += visibleOtherTabs.length;
                }
            }

            listWrap.appendChild(frag);
            if (totalRendered === 0) {
                var empty = document.createElement('div');
                empty.style.cssText = 'padding:1rem;text-align:center;color:var(--text-muted, #6b7280);font-size:0.875rem;';
                // Total scopé au classeur courant : nb termes du workbook
                // (pas le draft global qui peut contenir d'autres classeurs).
                var totalInWb = _workbookTermsCount();
                empty.textContent = totalInWb === 0
                    ? 'Aucun terme détecté dans ce classeur. Pour les termes d\'autres classeurs, cliquez « Voir tous les termes → » en bas.'
                    : 'Aucun terme ne correspond au filtre actuel.';
                listWrap.appendChild(empty);
            }
            updateSubtitle();
        }

        // Computed à chaque appel pour refléter d'éventuels changements
        // d'onglet actif. Retourne le Set des termes (cleartext) du
        // workbook courant : onglet actif + autres onglets.
        function _workbookTermsSet() {
            var byCol = self._extractTermsByColumn();
            var set = Object.create(null);
            var act = byCol.__active__ || {};
            Object.keys(act).forEach(function(col) {
                (act[col] || []).forEach(function(t) { set[t] = true; });
            });
            (byCol.__otherTabs__ || []).forEach(function(t) { set[t] = true; });
            return set;
        }
        function _workbookTermsCount() {
            var set = _workbookTermsSet();
            return Object.keys(set).length;
        }

        // Render d'une section colonne : header cliquable + checkbox
        // "Anonymiser toute la colonne" + liste des termes.
        // ``scope`` ∈ { 'active', 'otherTabs', 'otherWorkbooks' } — préfixe
        // visuel et titre de section pilotés par cette valeur (plutôt que
        // l'ancien booléen ``isOther`` qui ne distinguait que 2 cas).
        // Persist l'état collapsed/expanded des sections entre les
        // renderList() (sinon chaque tick de la barre de progression
        // auto-classify réinitialise toutes les sections à expanded).
        // Map clé "scope:colName" → bool (true = collapsed).
        if (!self._anonSectionCollapsed) {
            self._anonSectionCollapsed = Object.create(null);
        }
        var sectionStateMap = self._anonSectionCollapsed;

        function renderColumnSection(colName, terms, scope) {
            var sectionKey = scope + ':' + colName;
            var section = document.createElement('div');
            section.style.cssText =
                'border:1px solid var(--border, #e5e7eb);border-radius:0.375rem;' +
                'margin-bottom:0.5rem;background:var(--bg-surface, #fff);overflow:hidden;';

            // Compute stats de la section
            var totalInCol = terms.length;
            var enabledInCol = 0, pendingInCol = 0;
            for (var i = 0; i < terms.length; i++) {
                var e = draft[terms[i]];
                if (!e) continue;
                if (e.enabled) enabledInCol++;
                if (!e.confirmed) pendingInCol++;
            }

            var header = document.createElement('div');
            header.style.cssText =
                'display:flex;align-items:center;gap:0.5rem;padding:0.45rem 0.6rem;' +
                'background:' + (pendingInCol > 0 ? 'var(--status-error-bg, rgba(220, 38, 38, 0.08))' : 'var(--bg-hover, rgba(0,0,0,0.03))') + ';' +
                'cursor:pointer;user-select:none;border-bottom:1px solid var(--border, #e5e7eb);';

            // Chevron expand/collapse
            var chevron = document.createElement('span');
            chevron.textContent = '▾';
            chevron.style.cssText = 'display:inline-block;font-size:0.75rem;color:var(--text-muted, #6b7280);width:10px;transition:transform 150ms;';

            // Bulk-checkbox "toute la colonne"
            var bulk = document.createElement('input');
            bulk.type = 'checkbox';
            bulk.title = 'Anonymiser toute la colonne';
            var allEnabled = enabledInCol === totalInCol;
            var someEnabled = enabledInCol > 0 && enabledInCol < totalInCol;
            bulk.checked = allEnabled;
            bulk.indeterminate = someEnabled;
            bulk.style.cssText = 'flex-shrink:0;';
            bulk.addEventListener('click', function(e) { e.stopPropagation(); });
            bulk.addEventListener('change', function() {
                var newVal = bulk.checked;
                for (var j = 0; j < terms.length; j++) {
                    var e2 = draft[terms[j]];
                    if (!e2) continue;
                    e2.enabled = newVal;
                    e2.confirmed = true;
                }
                renderList();  // re-render pour refléter
            });

            var label = document.createElement('span');
            label.style.cssText = 'flex:1;font-size:0.8125rem;font-weight:600;color:var(--text-primary, #111827);';
            // Préfixe visuel par scope : colonne d'onglet actif (▸),
            // autres onglets du classeur (⊞), autres classeurs (⌘).
            // Choix de glyphes Unicode simples pour rester cohérent avec
            // "pas d'emoji" — les glyphes géométriques se rendent uniformément.
            var icon;
            if (scope === 'otherWorkbooks') icon = '⌘ ';
            else if (scope === 'otherTabs') icon = '⊞ ';
            else icon = '▸ ';
            label.textContent = icon + colName;

            var stats = document.createElement('span');
            stats.style.cssText = 'font-size:0.75rem;color:var(--text-muted, #6b7280);flex-shrink:0;';
            var parts = [totalInCol + ' terme' + (totalInCol > 1 ? 's' : '')];
            if (enabledInCol > 0) parts.push(enabledInCol + ' anonymisé' + (enabledInCol > 1 ? 's' : ''));
            if (pendingInCol > 0) parts.push(pendingInCol + ' à confirmer');
            stats.textContent = parts.join(' • ');

            header.appendChild(chevron);
            header.appendChild(bulk);
            header.appendChild(label);
            header.appendChild(stats);
            section.appendChild(header);

            // Body : liste des termes (collapsible par clic sur header).
            // Tri : NOUVEAUX (`newShownThisOpen`) d'abord, puis alphabétique.
            // Priorise visuellement ce qui demande l'attention de l'user.
            var sortedTerms = terms.slice().sort(function(a, b) {
                var na = newShownThisOpen[a] ? 0 : 1;
                var nb = newShownThisOpen[b] ? 0 : 1;
                if (na !== nb) return na - nb;
                return a.localeCompare(b);
            });
            var body = document.createElement('div');
            body.style.cssText = 'background:var(--bg-surface, #fff);';
            for (var k = 0; k < sortedTerms.length; k++) {
                body.appendChild(renderRow(sortedTerms[k], draft[sortedTerms[k]]));
            }
            section.appendChild(body);

            header.addEventListener('click', function() {
                var collapsed = body.style.display === 'none';
                body.style.display = collapsed ? '' : 'none';
                chevron.style.transform = collapsed ? 'rotate(0deg)' : 'rotate(-90deg)';
                // Persist le nouvel état (vs valeur par défaut héritée des
                // règles ci-dessous). Permet aux re-render successifs de
                // ce panneau (ex: tick auto-classify) de respecter le
                // choix utilisateur — sans ça, chaque renderList efface tout.
                sectionStateMap[sectionKey] = !collapsed;
            });

            // État initial : (1) si l'utilisateur a déjà fait un choix
            // explicite sur cette section, on le respecte ; (2) sinon
            // règles par défaut — section pending-only ouverte, longue
            // section all-confirmed collapsed.
            var explicitState = sectionStateMap[sectionKey];
            var startCollapsed;
            if (typeof explicitState === 'boolean') {
                startCollapsed = explicitState;
            } else {
                startCollapsed = pendingInCol === 0 && totalInCol > 20;
            }
            if (startCollapsed) {
                body.style.display = 'none';
                chevron.style.transform = 'rotate(-90deg)';
            }

            return section;
        }

        function renderRow(term, entry) {
            // ``isNew`` = ajouté depuis la dernière ouverture du panneau.
            // Pilote : badge NOUVEAU (déclaré plus bas) + fond légèrement
            // rouge pour attirer l'œil. ``confirmed`` est déjà true (posé
            // à l'ouverture), donc on n'utilise plus ce flag pour le visuel.
            var isNew = !!newShownThisOpen[term];
            var row = document.createElement('div');
            row.style.cssText =
                'display:flex;align-items:center;gap:0.5rem;' +
                'padding:0.4rem 0.5rem;border-bottom:1px solid var(--border, #e5e7eb);' +
                'background:' + (isNew ? 'var(--status-error-bg, rgba(220, 38, 38, 0.06))' : 'transparent') + ';';

            var chk = document.createElement('input');
            chk.type = 'checkbox';
            chk.checked = !!entry.enabled;
            chk.title = 'Anonymiser ce terme';
            chk.style.cssText = 'flex-shrink:0;';
            chk.addEventListener('change', function() {
                entry.enabled = chk.checked;
                entry.confirmed = true;
                row.style.background = 'transparent';
                // ⚠️ NE PAS clearer ``pseudoInput.value`` si l'user décoche :
                // il peut vouloir conserver son pseudo personnalisé pour le
                // ré-activer plus tard. Le re-style via _applyPseudoStyle()
                // donne le signal visuel (grisé/italique quand inactif).
                // L'input reste toujours éditable (cf. ligne ~6836) — user
                // feedback 2026-05-20 « il faut cocher je ne savais pas,
                // vaut mieux ne pas avoir besoin de cocher ».
                _applyPseudoStyle();
                updateSubtitle();
                newBadge.style.display = 'none';
            });

            var termEl = document.createElement('span');
            termEl.textContent = term.length > 60 ? term.slice(0, 57) + '…' : term;
            termEl.title = term;
            termEl.style.cssText =
                'flex:1;min-width:0;font-family:monospace;font-size:0.8125rem;' +
                'color:var(--text-primary, #111827);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;';

            // Badge NOUVEAU : affiché pour les termes arrivés SINCE la
            // dernière ouverture du panneau (snapshot dans newShownThisOpen).
            // Purement visuel — le ``confirmed=true`` a déjà été posé à
            // l'ouverture du panneau, donc le gate backend ne bloque plus.
            // Le badge disparaîtra à la prochaine ouverture (fresh snapshot).
            // BLOCKING #1 review iris-grid : ``isNew`` est déjà déclaré
            // ligne 5663 ; on réutilise sans redéclarer (var permet la
            // redéclaration silencieuse, ce qui masquait l'intention).
            isNew = !!newShownThisOpen[term];
            var newBadge = document.createElement('span');
            newBadge.textContent = 'NOUVEAU';
            newBadge.style.cssText =
                'flex-shrink:0;font-size:0.6875rem;font-weight:600;padding:0.1rem 0.4rem;' +
                'border-radius:9999px;background:#dc2626;color:#fff;' +
                'display:' + (isNew ? 'inline-block' : 'none') + ';';

            // Valeur anonymisée affichée dans le champ :
            //  - si l'utilisateur a un pseudo custom → on l'affiche tel quel
            //  - sinon on affiche l'auto_pseudo fourni par le backend (via
            //    reconcile_state / get_state_for_user)
            //  - en dernier recours (token tout juste détecté localement,
            //    jamais passé par le backend), on calcule le même middle
            //    côté JS — algorithme identique (MD5 + consonnes).
            var pseudoInput = document.createElement('input');
            pseudoInput.type = 'text';
            var hasCustom = typeof entry.pseudo === 'string' && entry.pseudo;
            // Le fallback JS reçoit ``entry.category`` (propagée par le
            // backend via repository.get_state_for_user) pour produire le
            // même label sémantique que le backend (EMAIL/NAME/PHONE/IBAN
            // si catégorisé, sinon detect runtime via regex, sinon TXT/NUM).
            var autoPseudo = (typeof entry.auto_pseudo === 'string' && entry.auto_pseudo)
                ? entry.auto_pseudo
                : self._anonAutoPseudoMiddle(term, entry.category);
            pseudoInput.value = hasCustom ? entry.pseudo : autoPseudo;
            pseudoInput.dataset.autoValue = autoPseudo;
            // ⚠️ Input TOUJOURS éditable (même si la checkbox n'est pas
            // cochée). User feedback 2026-05-20 : « il faut cocher je ne
            // savais pas, vaut mieux ne pas avoir besoin de cocher ».
            // Si l'user édite le pseudo d'un terme non coché, on auto-coche
            // au input event (cf. plus bas) — sinon la valeur n'aurait
            // aucun effet et le pseudo serait perdu visuellement.
            pseudoInput.title = hasCustom
                ? 'Pseudonyme personnalisé — ce que le LLM voit'
                : 'Valeur anonymisée auto-générée. Modifiez pour utiliser un pseudonyme sémantique (ex: CLIENT_A). Cocher non requis.';
            pseudoInput.maxLength = 128;
            // Couleur grisée tant que c'est la valeur auto par défaut, passe
            // en couleur normale dès que l'user customise — donne un signal
            // visuel clair "c'est ta valeur" vs "c'est la valeur par défaut".
            var _baseCss =
                'width:180px;flex-shrink:0;padding:0.3rem 0.5rem;' +
                'border:1px solid var(--border, #d1d5db);border-radius:0.25rem;' +
                'background:var(--bg-surface, #fff);' +
                'font-family:monospace;font-size:0.8125rem;';
            function _applyPseudoStyle() {
                // Grisé+italique dans 2 cas :
                //  1. Pseudo absent → valeur auto par défaut (état originel)
                //  2. Pseudo défini MAIS terme non activé (checkbox uncheck)
                //     → l'user a tapé une valeur qui ne s'applique pas pour
                //        l'instant. Signal visuel "inactif" pour éviter
                //        confusion (sinon on croit que ça s'applique).
                // Normal seulement si pseudo custom ET terme activé.
                var isAuto = !entry.pseudo;
                var isInactive = !isAuto && !chk.checked;
                var muted = isAuto || isInactive;
                pseudoInput.style.cssText = _baseCss +
                    'color:' + (muted ? 'var(--text-muted, #6b7280)' : 'var(--text-primary, #111827)') + ';' +
                    'font-style:' + (muted ? 'italic' : 'normal') + ';';
            }
            _applyPseudoStyle();
            pseudoInput.addEventListener('input', function() {
                var v = pseudoInput.value.trim();
                // Si l'user revient à la valeur auto identique → on retire
                // le pseudo custom pour que le backend auto-génère à nouveau
                // (économise une entrée en BDD, restore behavior par défaut).
                if (!v || v === pseudoInput.dataset.autoValue) {
                    delete entry.pseudo;
                } else {
                    entry.pseudo = v;
                }
                // Auto-coche la checkbox enabled si l'user saisit un pseudo
                // sur un terme non encore activé. Sans ça, l'user customise
                // un pseudo qui ne s'appliquera jamais (terme not enabled =
                // aucune anonymisation appliquée côté backend) — comportement
                // surprenant. User feedback 2026-05-20.
                // Le check ``v !== ''`` évite d'auto-cocher si l'user clear
                // le champ (intent : "retirer le pseudo custom", pas activer).
                if (v && !chk.checked) {
                    chk.checked = true;
                    entry.enabled = true;
                    entry.confirmed = true;
                    row.style.background = 'transparent';
                    newBadge.style.display = 'none';
                    updateSubtitle();
                }
                _applyPseudoStyle();
            });

            // ── Actions par rangée (alignement avec /data/privacy) ──
            // "Voir détail" : ouvre le modal PrivacyDetailPanel (coverage
            // cross-classeur + audit récent) — utile pour comprendre où ce
            // terme apparaît avant de décider de l'anonymiser ou non.
            // "Supprimer" : DELETE BDD avec confirmation inline. Termine
            // par retirer la rangée du DOM (le draft.term est aussi retiré
            // pour qu'un Enregistrer subsequent ne le ré-insère pas).
            // Les 2 boutons sont gated sur ``_hasBackendId(entry)`` : un
            // terme tout juste détecté localement (jamais passé par le
            // backend) n'a pas encore d'id BDD — les actions sont alors
            // masquées. Helper plus strict que ``!!entry.id`` pour rejeter
            // les sentinels ``0`` / ``''`` / ``null`` qu'un futur refactor
            // pourrait introduire silencieusement.
            function _hasBackendId(e) {
                return e != null
                    && typeof e.id === 'number'
                    && Number.isFinite(e.id)
                    && e.id > 0;
            }
            var actionBtns = document.createElement('div');
            actionBtns.style.cssText =
                'display:flex;align-items:center;gap:0.3rem;flex-shrink:0;';

            var btnDetail = document.createElement('button');
            btnDetail.type = 'button';
            btnDetail.title = 'Voir où ce terme apparaît + historique';
            btnDetail.setAttribute('aria-label', 'Voir détail de ' + term);
            // Icône SVG info (pas d'emoji — règle codebase). Tracé statique
            // basique, taille 14×14 pour matcher la hauteur des autres
            // contrôles inline de la rangée.
            btnDetail.innerHTML =
                '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" ' +
                'stroke="currentColor" stroke-width="2" stroke-linecap="round" ' +
                'stroke-linejoin="round" aria-hidden="true">' +
                '<circle cx="12" cy="12" r="10"></circle>' +
                '<line x1="12" y1="16" x2="12" y2="12"></line>' +
                '<line x1="12" y1="8" x2="12.01" y2="8"></line>' +
                '</svg>';
            btnDetail.style.cssText =
                'background:transparent;border:1px solid var(--border, #d1d5db);' +
                'color:var(--text-muted, #6b7280);border-radius:0.25rem;' +
                'padding:0.2rem 0.35rem;cursor:pointer;display:inline-flex;align-items:center;';
            btnDetail.addEventListener('click', function() {
                if (!_hasBackendId(entry)) return;
                if (!window.PrivacyDetailPanel
                    || typeof window.PrivacyDetailPanel.loadCoverage !== 'function') {
                    setErr('Module détail indisponible (rechargez la page).');
                    return;
                }
                window.PrivacyDetailPanel.loadCoverage(entry.id, {
                    fetchJson: _anonModalFetchJson,
                    localTerm: { term: term, id: entry.id, pseudo_middle: entry.pseudo },
                });
            });

            var btnDelete = document.createElement('button');
            btnDelete.type = 'button';
            btnDelete.title = 'Supprimer ce terme de la base';
            btnDelete.setAttribute('aria-label', 'Supprimer ' + term);
            // Icône SVG poubelle (pas d'emoji — règle codebase).
            var _DELETE_ICON_SVG =
                '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" ' +
                'stroke="currentColor" stroke-width="2" stroke-linecap="round" ' +
                'stroke-linejoin="round" aria-hidden="true">' +
                '<polyline points="3 6 5 6 21 6"></polyline>' +
                '<path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"></path>' +
                '<path d="M10 11v6"></path>' +
                '<path d="M14 11v6"></path>' +
                '<path d="M9 6V4a2 2 0 0 1 2-2h2a2 2 0 0 1 2 2v2"></path>' +
                '</svg>';
            btnDelete.innerHTML = _DELETE_ICON_SVG;
            btnDelete.style.cssText =
                'background:transparent;border:1px solid var(--border, #d1d5db);' +
                'color:var(--status-error,#dc2626);border-radius:0.25rem;' +
                'padding:0.2rem 0.35rem;cursor:pointer;display:inline-flex;align-items:center;';
            var deletePending = false;
            btnDelete.addEventListener('click', function() {
                if (!_hasBackendId(entry)) return;
                if (!deletePending) {
                    // Premier clic : passer en mode confirmation inline.
                    deletePending = true;
                    btnDelete.innerHTML = '';
                    btnDelete.textContent = 'Confirmer ?';
                    btnDelete.style.background = 'var(--status-error,#dc2626)';
                    btnDelete.style.color = '#fff';
                    btnDelete.style.borderColor = 'var(--status-error,#dc2626)';
                    btnDelete.style.padding = '0.2rem 0.55rem';
                    btnDelete.style.fontSize = '0.75rem';
                    // Auto-revert après 4s pour éviter une confirmation
                    // par erreur si l'utilisateur s'éloigne du bouton.
                    setTimeout(function() {
                        if (!deletePending) return;
                        deletePending = false;
                        btnDelete.textContent = '';
                        btnDelete.innerHTML = _DELETE_ICON_SVG;
                        btnDelete.style.background = 'transparent';
                        btnDelete.style.color = 'var(--status-error,#dc2626)';
                        btnDelete.style.borderColor = 'var(--border, #d1d5db)';
                        btnDelete.style.padding = '0.2rem 0.35rem';
                        btnDelete.style.fontSize = '';
                    }, 4000);
                    return;
                }
                // Second clic : exécute le DELETE backend.
                btnDelete.disabled = true;
                btnDelete.textContent = '...';
                _anonModalFetchJson(
                    '/api/anonymization/terms/' + encodeURIComponent(entry.id),
                    { method: 'DELETE' }
                ).then(function() {
                    // Retire du draft + state vivant (sinon un PUT subsequent
                    // ré-injecterait le terme via replace-state).
                    delete draft[term];
                    if (self._anonymizationState && self._anonymizationState.terms) {
                        delete self._anonymizationState.terms[term];
                    }
                    self._bumpAnonStateSeq && self._bumpAnonStateSeq();
                    // Race anti-multi-onglet : après un DELETE backend, on
                    // ne sait plus si le draft local est consistent avec la
                    // BDD (un autre onglet a pu insérer/modifier). Désactive
                    // Save et invite à refermer/rouvrir le panneau pour un
                    // refresh propre. Sans ça : un PUT subsequent avec le
                    // draft stale ferait un replace_state qui pourrait
                    // ré-effacer des termes que l'autre onglet a insérés.
                    btnSave.disabled = true;
                    btnSave.title =
                        'Refermez et rouvrez le panneau pour appliquer d\'autres modifications ' +
                        '(état rafraîchi depuis le serveur).';
                    setErr('Terme supprimé. Refermez le panneau pour appliquer '
                        + 'd\'autres modifications.', 'muted');
                    // Refresh asynchrone du state autoritatif — pas bloquant
                    // pour la UI courante, mais aligne les autres composants
                    // (badge, cell markers) avec la BDD. Invalidation du
                    // cache OBLIGATOIRE avant (fix 2026-06-11, tâche #13) :
                    // sans elle, _anonymizationFetched=true court-circuitait
                    // le fetch → le « refresh » était un no-op et la révision
                    // optimiste restait périmée (409 au PUT suivant).
                    if (typeof self._fetchAnonymizationState === 'function') {
                        self._invalidateAnonymizationCache();
                        self._fetchAnonymizationState();
                    }
                    renderList();
                    updateSubtitle();
                    self._updateAnonymizationBadge && self._updateAnonymizationBadge();
                    self._applyAnonymizationCellMarkers && self._applyAnonymizationCellMarkers();
                }).catch(function(e) {
                    setErr('Suppression échouée : ' +
                        ((e && e.message) || 'inconnue'));
                    btnDelete.disabled = false;
                    btnDelete.textContent = '';
                    btnDelete.innerHTML = _DELETE_ICON_SVG;
                    btnDelete.style.background = 'transparent';
                    btnDelete.style.color = 'var(--status-error,#dc2626)';
                    btnDelete.style.borderColor = 'var(--border, #d1d5db)';
                    btnDelete.style.padding = '0.2rem 0.35rem';
                    btnDelete.style.fontSize = '';
                    deletePending = false;
                });
            });

            if (_hasBackendId(entry)) {
                actionBtns.appendChild(btnDetail);
                actionBtns.appendChild(btnDelete);
            }

            row.appendChild(chk);
            row.appendChild(termEl);
            row.appendChild(newBadge);
            row.appendChild(pseudoInput);
            row.appendChild(actionBtns);
            return row;
        }

        // Mini fetchJson local au modal : taxonomie 4-cas légère sans
        // dépendance à privacy-page.js (pas chargé sur /iris). Réutilisé
        // par les actions par rangée (DELETE) et le coverage. CSRF via le
        // cookie ``_xsrf`` (cf. ``_getXsrfCookie`` déjà défini dans iris-grid).
        function _anonModalFetchJson(url, options) {
            options = options || {};
            var headers = options.headers || {};
            if (options.method && options.method !== 'GET' && options.method !== 'HEAD') {
                headers['X-Xsrftoken'] = _getXsrfCookie();
                if (!headers['Content-Type']) headers['Content-Type'] = 'application/json';
            }
            options.headers = headers;
            options.credentials = 'same-origin';
            return fetch(url, options).then(function(resp) {
                return resp.json().catch(function() { return null; }).then(function(data) {
                    if (!resp.ok) {
                        var msg = (data && data.error)
                            ? data.error
                            : (resp.status === 401 ? 'Session expirée. Reconnectez-vous.'
                                : (resp.status === 429 ? 'Trop de requêtes. Patientez.'
                                    : (resp.status >= 500 ? 'Erreur serveur (' + resp.status + ').'
                                        : 'Erreur (' + resp.status + ').')));
                        var e = new Error(msg);
                        e.status = resp.status;
                        e.data = data;
                        throw e;
                    }
                    return data || {};
                });
            });
        }

        function bulkSet(patch) {
            // Restreint au classeur courant : "Tout/Rien anonymiser" doit
            // refléter le scope du panneau ("result area = classeur
            // courant"). Les termes d'autres classeurs en BDD restent
            // intacts dans le draft et seront repersistés tels quels via
            // le PUT replace-state (cf. _persistAnonymizationState).
            var wbSet = _workbookTermsSet();
            for (var k in draft) {
                if (!Object.prototype.hasOwnProperty.call(draft, k)) continue;
                if (!wbSet[k]) continue;
                if (patch.enabled !== undefined) draft[k].enabled = patch.enabled;
                if (patch.confirmed !== undefined) draft[k].confirmed = patch.confirmed;
            }
            renderList();
        }
        function bulkConfirmVisible(enable) {
            // "Visibles" = termes du classeur courant qui passent le
            // filtre actuel. Les termes d'autres classeurs ne sont jamais
            // rendus, donc jamais touchés ici (defense in depth via wbSet).
            var wbSet = _workbookTermsSet();
            var keys = Object.keys(draft);
            for (var i = 0; i < keys.length; i++) {
                var k = keys[i];
                if (!wbSet[k]) continue;
                if (!filterMatch(k, draft[k])) continue;
                draft[k].enabled = enable;
                draft[k].confirmed = true;
            }
            renderList();
        }

        // Debounce 200ms sur la recherche — task #9 : pour des classeurs
        // avec > 1000 termes, renderList() à chaque keystroke crée du lag
        // perceptible (chaque caractère re-tokenise + re-render toute la
        // liste). 200ms = sweet spot UX (immédiat perçu côté user, gros
        // gain quand on tape rapidement plusieurs caractères d'affilée).
        // Les filtres select/change restent immédiats (1 clic, pas de spam).
        var _searchDebounceTimer = null;
        search.addEventListener('input', function() {
            if (_searchDebounceTimer) clearTimeout(_searchDebounceTimer);
            _searchDebounceTimer = setTimeout(function() {
                _searchDebounceTimer = null;
                renderList();
                updateSubtitle();
            }, 200);
        });
        filterSel.addEventListener('change', function() {
            renderList();
            updateSubtitle();
        });
        numFilterSel.addEventListener('change', function() {
            renderList();
            updateSubtitle();
        });

        var closed = false;
        function close() {
            if (closed) return;
            closed = true;
            // Flush forcé : à l'ouverture, tous les pending sont marqués
            // confirmed=true (contrat "vu = débloque LLM") et persistance
            // debouncée à 300ms. Sans ce flush, un refresh de page entre
            // close() et le PUT envoyé perd les confirmed=true → les
            // termes redeviennent "nouveaux" à la prochaine ouverture.
            if (typeof self._flushAnonymizationPersist === 'function') {
                try { self._flushAnonymizationPersist(false); } catch (e) {}
            }
            // Désenregistre du manager — idempotent. Si la fermeture est
            // déclenchée PAR le manager (Escape), il ne re-rentre pas grâce
            // au guard ``closed`` ci-dessus.
            if (window.OverlayManager && typeof window.OverlayManager.close === 'function') {
                try { window.OverlayManager.close(overlay); } catch (e) {}
            }
            if (overlay.parentNode) overlay.parentNode.removeChild(overlay);
            // Dispatch des callbacks consent (mode "flow consent"). Toujours
            // appelé APRÈS le cleanup DOM pour que le panneau soit fermé
            // visuellement avant que le flow consent ne déclenche une
            // éventuelle ré-ouverture (cas onCancel → openConsentPromptModal).
            // try/catch défensif : une exception dans une callback ne doit
            // jamais ré-ouvrir le modal ou laisser un overlay résiduel.
            if (_consentCallbacks) {
                try {
                    if (_consentExitReason === 'save'
                        && typeof _consentCallbacks.onSave === 'function') {
                        _consentCallbacks.onSave();
                    } else if (_consentExitReason === 'improve'
                        && typeof _consentCallbacks.onImprove === 'function') {
                        // Améliorer pseudos : sémantique propre pour les
                        // callers qui veulent guider l'user post-improve
                        // (ex: copilot affiche "Cliquez Envoyer pour
                        // reprendre"). Si le caller n'a pas d'onImprove,
                        // fallback sur onCancel (préserve l'UX Iris où
                        // Améliorer ré-ouvre le prompt OUI/NON via cancel).
                        _consentCallbacks.onImprove();
                    } else if (_consentExitReason === 'improve'
                        && typeof _consentCallbacks.onCancel === 'function') {
                        _consentCallbacks.onCancel();
                    } else if (_consentExitReason === 'cancel'
                        && typeof _consentCallbacks.onCancel === 'function') {
                        _consentCallbacks.onCancel();
                    } else if (typeof _consentCallbacks.onAbandon === 'function') {
                        // null reason (Esc/backdrop/programmatique) = abandon.
                        _consentCallbacks.onAbandon();
                    }
                } catch (cbErr) {
                    if (window.console && window.console.error) {
                        window.console.error(
                            '[iris-grid] consentCallbacks dispatch failed: ',
                            cbErr
                        );
                    }
                }
            }
        }
        // Escape : géré par OverlayManager.open ci-dessus (LIFO, ferme le
        // top-most). Pas de listener keydown manuel ici — sinon double-fire.
        btnCancel.addEventListener('click', function() {
            // Set le reason AVANT close() pour que le dispatch des
            // callbacks consent (cf. close() ci-dessus) appelle onCancel.
            // Sans flow consent (_consentCallbacks=null), aucun effet.
            _consentExitReason = 'cancel';
            close();
        });
        overlay.addEventListener('click', function(e) { if (e.target === overlay) close(); });

        btnSave.addEventListener('click', function() {
            setErr('');
            // Validation côté client : collisions pseudo + sentinelles +
            // cross-term + trim. Source de vérité unique dans
            // ``window.AnonymizationSaveHelpers`` (cf.
            // ``static/js/anonymization/save-helpers.js``).
            //
            // Pas de fallback inline (adversarial CRITICAL 2026-05-20) :
            // un fallback divergeait silencieusement du helper et
            // réintroduisait la duplication que ce refactor visait à
            // éliminer. L'ordre de chargement est verrouillé par le test
            // ``test_helper_loaded_before_iris_grid``. Si le helper
            // n'est pas chargé, c'est une régression du template — fail
            // visible plutôt que silent divergence.
            if (!window.AnonymizationSaveHelpers
                || typeof window.AnonymizationSaveHelpers.validatePseudoMap !== 'function') {
                setErr('Erreur interne : module de validation indisponible. '
                    + 'Rechargez la page (Ctrl+F5). Si le problème persiste, '
                    + 'utilisez « Signaler un problème ».');
                if (window.console && console.error) {
                    console.error(
                        '[iris-grid] AnonymizationSaveHelpers manquant — '
                        + 'save-helpers.js a-t-il été chargé avant iris-grid.js ?'
                    );
                }
                return;
            }
            var validation = window.AnonymizationSaveHelpers.validatePseudoMap(draft);
            if (validation.errors.length) {
                setErr(validation.errors[0]
                    + (validation.errors.length > 1 ? ' (+' + (validation.errors.length - 1) + ' autre(s))' : ''));
                return;
            }
            // Commit du draft — persist vers la BDD serveur. Tant que le
            // PUT n'a pas répondu, on désactive le bouton pour éviter un
            // double-submit. Cancel le debounce pending : sinon un PUT
            // antérieur (state out-of-date) pourrait écraser ce save.
            var newState = { version: 1, terms: draft };
            self._cancelAnonymizationPersist();
            // Bump le seq : un PUT précédent déjà en vol (la cancel ci-dessus
            // ne fait qu'annuler un TIMER, pas une requête fetch déjà partie)
            // verra son captured seq devenir stale et sa réponse sera ignorée.
            // Le PUT qui part maintenant capture le nouveau seq et sa réponse
            // sera correctement adoptée.
            self._bumpAnonStateSeq();
            btnSave.disabled = true;
            btnSave.textContent = 'Enregistrement…';
            self._persistAnonymizationState(newState).then(function(res) {
                // ⚠️ Ne pas ré-activer btnSave AVANT le confirm consent
                // (R3 HIGH 2026-05-20). Le confirm() est bloquant 30s+
                // possible, pendant lequel l'user peut re-cliquer le
                // bouton si on l'a déjà ré-activé — double-PUT.
                // On restaure le bouton dans CHAQUE branche après que
                // toute logique synchrone soit terminée.
                if (res && res.ok) {
                    // Invalide le badge global Komptia (cross-page) — sinon
                    // le badge affiche un compteur stale jusqu'au prochain
                    // refresh. Parité avec privacy-page.js _persistDirtyTerms.
                    // Garde typeof : badge optionnel si template ne le charge pas.
                    if (window.KomptiaPrivacyBadge
                        && typeof window.KomptiaPrivacyBadge.invalidate === 'function') {
                        try { window.KomptiaPrivacyBadge.invalidate(); } catch (_e) { /* defensive */ }
                    }
                    // Backend a sanitizé certains termes (collision pseudo,
                    // pseudo invalide, etc.). ``state_errors`` est propagé
                    // par ``_persistAnonymizationState`` (cf. ligne ~5096)
                    // depuis la response 200 du backend qui les a strippés
                    // silencieusement. Sans ce signal, "Enregistrer" affiche
                    // success alors qu'une partie est perdue.
                    var warningErrors = Array.isArray(res.state_errors)
                        ? res.state_errors
                        : null;

                    // ⚠️ FLOW CONSENT + state_errors = risque confidentialité
                    // (adversarial HIGH #2 2026-05-20). Si on est en flow
                    // consent (panel ouvert depuis "Configurer l'anonymisation"
                    // → _consentCallbacks set) ET que le backend a strippé
                    // des termes, Iris est sur le point de reprendre avec
                    // un mapping incomplet : un terme PII enabled=true mais
                    // pseudo strippé → le LLM peut voir la valeur réelle.
                    // Bloquer avec une confirm explicite plutôt qu'auto-
                    // dispatch onSave silencieux.
                    if (warningErrors && warningErrors.length && _consentCallbacks) {
                        var warnDetailConsent = window.AnonymizationSaveHelpers.formatStateErrors(
                            warningErrors,
                            res.state_errors_truncated_count
                        );
                        var confirmMsg =
                            'Attention : ' + warningErrors.length
                            + ' modification(s) n\'ont PAS été sauvées :\n\n'
                            + (warnDetailConsent || 'Erreurs de validation backend.')
                            + '\n\nSi tu continues, Iris reprendra avec un dictionnaire '
                            + 'd\'anonymisation incomplet — certaines valeurs sensibles '
                            + 'pourront être visibles par le LLM.\n\n'
                            + 'OK = continuer quand même (Iris reprend).\n'
                            + 'Annuler = corriger les erreurs (le panneau reste ouvert).';
                        // ``confirm()`` synchrone (bloque l'event loop UI mais
                        // c'est exactement ce qu'on veut : empêcher Iris de
                        // reprendre sans décision utilisateur explicite). Pour
                        // un modal Komptia plus propre, utiliser OverlayManager
                        // dans une itération future — confirm() suffit pour
                        // fermer ce risque PII immédiatement.
                        //
                        // ⚠️ Browser dialog suppression (Firefox/Safari "Block
                        // this site from showing more dialogs") fait que
                        // ``confirm()`` retourne ``false`` instantanément sans
                        // dialog visible. Sans détection, on tombe sur
                        // "Annuler" et l'user croit avoir validé alors qu'Iris
                        // reste bloqué jusqu'au timeout backend (5min).
                        // Détection : mesurer le temps avant/après — un user
                        // qui lit + clique met >50ms ; un suppression renvoie
                        // false en <5ms. R3 HIGH 2026-05-20.
                        var _confirmStart = Date.now();
                        var _confirmResult = window.confirm(confirmMsg);
                        var _confirmElapsedMs = Date.now() - _confirmStart;
                        if (!_confirmResult && _confirmElapsedMs < 50) {
                            // Dialog probablement supprimé par le browser.
                            // Toast 'error' explicite (sticky) + ne PAS
                            // dispatch onSave → l'user voit le problème.
                            if (typeof window.showToast === 'function') {
                                window.showToast(
                                    'Confirmation bloquée par votre navigateur. '
                                    + 'Autorisez les dialogs sur cette page, ou '
                                    + 'corrigez les erreurs sur /data/privacy.',
                                    'error'
                                );
                            }
                            setErr('Confirmation requise pour continuer — '
                                + 'autorisez les dialogs et réessayez.');
                            // Restore le bouton (modal reste ouvert).
                            btnSave.disabled = false;
                            btnSave.textContent = 'Enregistrer';
                            return;
                        }
                        if (!_confirmResult) {
                            // L'user a explicitement cliqué Annuler. Ne pas
                            // close, ne pas dispatch onSave. Le panel reste
                            // ouvert avec ``draft`` intact pour qu'il puisse
                            // fixer les termes en cause puis re-cliquer
                            // Enregistrer. Backend a partiellement sauvé —
                            // l'user verra au prochain save les corrections
                            // (idempotent replace-state).
                            setErr((warnDetailConsent || ('Erreurs : ' + warningErrors.length))
                                + ' — corrige avant de continuer.');
                            btnSave.disabled = false;
                            btnSave.textContent = 'Enregistrer';
                            return;
                        }
                        // L'user a explicitement validé "continuer quand même".
                        // On tombe dans le flow normal (toast warning + close
                        // + onSave dispatch). Pas besoin de restore le bouton :
                        // close() va retirer l'overlay du DOM.
                    }

                    // Warning toast hors flow consent OU après confirm OK :
                    // signaler à l'user que tout n'a pas été sauvé. Sans flow
                    // consent, juste un toast (l'user reste sur la grille,
                    // peut réouvrir le panel pour corriger).
                    if (warningErrors && warningErrors.length
                        && typeof window.showToast === 'function') {
                        var warnMsg = window.AnonymizationSaveHelpers.formatStateErrors(
                            warningErrors,
                            res.state_errors_truncated_count
                        );
                        window.showToast(
                            warnMsg
                                ? warnMsg + ' — modifications partiellement sauvées.'
                                : 'Certaines modifications n\'ont pas été sauvées '
                                  + '(' + warningErrors.length + ' erreur(s)).',
                            'warning'
                        );
                    }
                    // Set le reason AVANT close() pour le dispatch des
                    // callbacks consent (cf. close() plus haut). Sans flow
                    // consent, aucun effet (just close).
                    _consentExitReason = 'save';
                    close();
                    return;
                }
                // Backend a refusé (status non-200). Montrer state_errors
                // via helper partagé (single source of truth — pas de
                // fallback inline, cf. CRITICAL 2026-05-20).
                // Restore le bouton pour que l'user puisse retenter (modal
                // reste ouvert avec draft intact).
                btnSave.disabled = false;
                btnSave.textContent = 'Enregistrer';
                var data = (res && res.data) || {};
                // 409 MASS_DELETE_REFUSED : la liste locale est désynchronisée
                // du serveur (cas résiduel post-fix delete_scope 2026-06-10 :
                // dico ACTIF réellement tronqué côté client, ex. fetch initial
                // échoué → state vide). JAMAIS de confirm_mass_delete
                // automatique (= purge aveugle). Recovery in-place : re-fetch
                // l'état serveur, reconstruit draft + liste — le panneau et le
                // flow consent restent ouverts, l'user refait ses modifs sur
                // une base fraîche. Message HUMAIN (pas le texte API backend
                // qui mentionne confirm_mass_delete, inactionnable depuis l'UI).
                if (data.error_code === 'MASS_DELETE_REFUSED'
                    || data.error_code === 'STATE_REVISION_MISMATCH') {
                    setErr(data.error_code === 'STATE_REVISION_MISMATCH'
                        ? ('Tes termes ont été modifiés entre-temps (autre onglet, '
                           + 'page Confidentialité ou scan). Rien n\'a été écrasé. '
                           + 'Rechargement en cours…')
                        : ('Ta liste affichée était désynchronisée du serveur ('
                           + (data.count_delete != null ? data.count_delete : '?')
                           + ' termes manquants sur '
                           + (data.count_before != null ? data.count_before : '?')
                           + '). Rien n\'a été supprimé. Rechargement en cours…'));
                    // Bouton verrouillé jusqu'à la fin du re-fetch (eXamine
                    // 2026-06-10 finding c) : sinon un re-clic re-PUT le draft
                    // périmé → re-409 + entrelacement de renders.
                    btnSave.disabled = true;
                    // Compte des termes actifs AVANT resync — pour détecter en
                    // flow consent un dico qui a RÉTRÉCI côté serveur (finding
                    // e : ne jamais relancer Iris avec moins d'anonymisation
                    // que ce que l'user croyait avoir, sans le prévenir).
                    var enabledBefore409 = 0;
                    for (var k409 in draft) {
                        if (Object.prototype.hasOwnProperty.call(draft, k409)
                            && draft[k409] && draft[k409].enabled) { enabledBefore409++; }
                    }
                    self._invalidateAnonymizationCache();
                    // NB (finding d, rare) : si un toggle local bump le seq
                    // pendant ce fetch, le guard seq de _fetchAnonymizationState
                    // ignore la réponse serveur et ``fresh`` peut être périmé.
                    // Convergence garantie sans perte : le prochain save
                    // re-prend un 409 (le backend refuse, ne supprime jamais)
                    // et re-déclenche cette recovery.
                    self._fetchAnonymizationState().then(function(st) {
                        var fresh = (st && st.terms) || {};
                        // Invariant : toute réassignation de ``draft`` DOIT être
                        // suivie de renderList() — les rows existantes capturent
                        // les anciens objets entry et doivent être reconstruites.
                        draft = JSON.parse(JSON.stringify(fresh));
                        renderList();
                        updateSubtitle();
                        var enabledAfter409 = 0;
                        for (var k2 in draft) {
                            if (Object.prototype.hasOwnProperty.call(draft, k2)
                                && draft[k2] && draft[k2].enabled) { enabledAfter409++; }
                        }
                        if (_consentCallbacks && enabledAfter409 < enabledBefore409) {
                            setErr('Liste rechargée — attention : le serveur a MOINS '
                                + 'de termes actifs (' + enabledAfter409 + ' vs '
                                + enabledBefore409 + ' affichés avant). Vérifie '
                                + 'ton anonymisation avant d\'enregistrer (Iris '
                                + 'reprendra avec ce dictionnaire).');
                        } else {
                            setErr('Liste rechargée — vérifie puis refais tes '
                                + 'modifications.', 'muted');
                        }
                        btnSave.disabled = false;
                    }).catch(function() {
                        // Réseau down : draft inchangé, on rend la main.
                        setErr('Rechargement impossible (réseau). Réessaie plus tard.');
                        btnSave.disabled = false;
                    });
                    return;
                }
                var stErrs = Array.isArray(data.state_errors) ? data.state_errors : [];
                var msg = window.AnonymizationSaveHelpers.formatStateErrors(stErrs);
                if (msg) {
                    setErr(msg);
                } else {
                    setErr(data.error || 'Échec de l\'enregistrement.');
                }
            });
        });

        updateSubtitle();
        renderList();

        // Focus la recherche pour taper directement
        setTimeout(function() { search.focus(); }, 0);
    };

    SqlResultGrid.prototype._sendCopilotRequest = function(instruction) {
        var self = this;

        // Ajoute le prompt à l'historique localStorage (navigation ↑/↓).
        // Dédup adjacent et cap 20 entrées géré par le helper. Stocké
        // device-only, JAMAIS envoyé au serveur. Reset l'index de
        // navigation pour que le prochain ↑ reparte du dernier.
        _pushCopilotPromptToHistory(instruction);
        self._copilotPromptHistoryIdx = null;

        // ── Pre-gate d'anonymisation ──
        // Réconcilie le state local avec les tokens actuels du classeur. Si
        // des termes ne sont pas encore confirmés, on ouvre le panneau et
        // on ne part pas au backend (évite un aller-retour 409 inutile).
        //
        // Quand le gate déclenche l'ouverture du panneau, on passe des
        // ``consentCallbacks`` pour que la fermeture du modal nettoie le
        // status copilot et relance automatiquement la soumission après
        // un Save (sinon : l'user voit l'erreur "Des termes sont à
        // confirmer…" persister après avoir justement sauvegardé, et doit
        // ressoumettre manuellement). Le flag ``_copilotConsentInProgress``
        // borne la récursion à UNE seule re-tentative pour éviter une
        // boucle si le workbook change entre l'open et le save.
        try {
            var reconciled = this._reconcileAnonymizationState();
            this._updateAnonymizationBadge();
            if (reconciled.added.length > 0 || this._anonPendingTerms().length > 0) {
                if (this._copilotConsentInProgress) {
                    // Gate refire dans le même flow consent (typiquement parce
                    // que le run précédent a matérialisé un onglet contenant
                    // de nouveaux tokens : noms, codes, IDs qui n'étaient pas
                    // dans le scan initial). L'ancien comportement affichait
                    // « Des termes restent à confirmer. Vérifiez puis
                    // renvoyez. » et obligeait l'user à re-cliquer Envoyer →
                    // ouvre encore le modal → re-save → re-submit. Trois
                    // clics pour une action qui devrait en demander un.
                    //
                    // Nouveau comportement (2026-05-22) : message actionnable
                    // qui montre QUI est nouveau + 2 boutons. L'user choisit
                    // entre revoir en détail (modal) ou tout valider d'un
                    // coup (bulk confirm + re-submit immédiat).
                    this._copilotConsentInProgress = false;
                    var pending = this._anonPendingTerms();
                    var pendingCount = pending.length;
                    var statusEl = this._copilotStatus;
                    // Vide le contenu existant (textContent / appendChild
                    // précédent) avant de reconstruire.
                    while (statusEl.firstChild) {
                        statusEl.removeChild(statusEl.firstChild);
                    }
                    statusEl.className = 'grid-copilot-status error';

                    // Sample : 3 premiers + "+N autres". Tronqué visuellement
                    // pour rester lisible sur classeurs avec 100+ tokens.
                    // textContent garantit l'échappement HTML (les tokens
                    // sont des données workbook, potentiellement <script>).
                    var sample = pending.slice(0, 3);
                    var moreCount = Math.max(0, pendingCount - sample.length);
                    var sampleStr = sample.join(', ');
                    if (moreCount > 0) {
                        sampleStr += ' +' + moreCount + ' autre' +
                            (moreCount > 1 ? 's' : '');
                    }
                    var plural = pendingCount > 1;
                    var msgText =
                        pendingCount + ' nouveau' + (plural ? 'x' : '') +
                        ' terme' + (plural ? 's' : '') + ' détecté' +
                        (plural ? 's' : '') + ' dans le dernier résultat (' +
                        sampleStr + '). ';
                    statusEl.appendChild(document.createTextNode(msgText));

                    // Capture l'instruction dans la closure des 2 boutons —
                    // ``instruction`` est le paramètre de _sendCopilotRequest,
                    // référencé tel quel par les handlers click ci-dessous.
                    var instructionCapture = instruction;
                    var selfRefire = this;

                    var btnVerify = document.createElement('button');
                    btnVerify.type = 'button';
                    btnVerify.textContent = 'Vérifier les nouveaux';
                    // Inline style minimal pour rester dans le flow texte
                    // du status (pas de design system dédié pour ce
                    // micro-cas ; inline préférable à une nouvelle classe
                    // CSS pour 2 boutons localisés).
                    btnVerify.style.cssText =
                        'margin-left:.4em;padding:.1em .55em;cursor:pointer;' +
                        'font-size:0.72rem;border:1px solid currentColor;' +
                        'background:transparent;color:inherit;border-radius:3px;';
                    btnVerify.addEventListener('click', function() {
                        // Re-ouvre le panneau qui auto-marquera confirmed=true
                        // à l'ouverture (cf. l. 6128-6135). onSave re-soumet
                        // automatiquement. _copilotConsentInProgress remis
                        // à true pour réactiver la garde anti-boucle.
                        selfRefire._copilotConsentInProgress = true;
                        var clearStatus = function() {
                            while (statusEl.firstChild) {
                                statusEl.removeChild(statusEl.firstChild);
                            }
                            statusEl.className = 'grid-copilot-status';
                        };
                        selfRefire._openAnonymizationPanel({
                            reason: 'pending',
                            consentCallbacks: {
                                onSave: function() {
                                    clearStatus();
                                    selfRefire._sendCopilotRequest(
                                        instructionCapture
                                    );
                                },
                            },
                        });
                    });
                    statusEl.appendChild(btnVerify);

                    var btnConfirmAll = document.createElement('button');
                    btnConfirmAll.type = 'button';
                    btnConfirmAll.textContent = 'Tout valider et renvoyer';
                    btnConfirmAll.style.cssText =
                        'margin-left:.4em;padding:.1em .55em;cursor:pointer;' +
                        'font-size:0.72rem;border:1px solid currentColor;' +
                        'background:transparent;color:inherit;border-radius:3px;';
                    btnConfirmAll.addEventListener('click', function() {
                        // Bulk-marque tous les termes pending confirmed=true
                        // (équivalent à ouvrir le modal + Save, sans l'étape
                        // visuelle). Persiste async via le helper standard.
                        var state = selfRefire._anonymizationState;
                        if (state && state.terms) {
                            var touched = false;
                            for (var t in state.terms) {
                                if (!Object.prototype.hasOwnProperty.call(
                                    state.terms, t
                                )) continue;
                                if (state.terms[t] && !state.terms[t].confirmed) {
                                    state.terms[t].confirmed = true;
                                    touched = true;
                                }
                            }
                            if (touched) {
                                if (typeof selfRefire._bumpAnonStateSeq === 'function') {
                                    selfRefire._bumpAnonStateSeq();
                                }
                                if (typeof selfRefire._schedulePersistAnonymization === 'function') {
                                    selfRefire._schedulePersistAnonymization();
                                }
                                if (typeof selfRefire._updateAnonymizationBadge === 'function') {
                                    selfRefire._updateAnonymizationBadge();
                                }
                            }
                        }
                        while (statusEl.firstChild) {
                            statusEl.removeChild(statusEl.firstChild);
                        }
                        statusEl.className = 'grid-copilot-status';
                        selfRefire._sendCopilotRequest(instructionCapture);
                    });
                    statusEl.appendChild(btnConfirmAll);

                    return;
                }
                this._copilotConsentInProgress = true;
                // Aucun toast pendant que le modal est ouvert : le modal
                // EST le message. On clear toute trace d'erreur précédente.
                this._copilotStatus.textContent = '';
                this._copilotStatus.className = 'grid-copilot-status';

                var instructionCapture = instruction;
                var clearCopilotStatus = function() {
                    self._copilotStatus.textContent = '';
                    self._copilotStatus.className = 'grid-copilot-status';
                };
                this._openAnonymizationPanel({
                    reason: 'pending',
                    consentCallbacks: {
                        onSave: function() {
                            // L'user a confirmé/sauvegardé. On relance la
                            // soumission. _copilotConsentInProgress reste true :
                            // si le gate refire (cas rare workbook modifié),
                            // la branche anti-boucle ci-dessus stoppe le scénario.
                            clearCopilotStatus();
                            self._sendCopilotRequest(instructionCapture);
                        },
                        onImprove: function() {
                            // L'user clique « Améliorer pseudos » : l'improve
                            // modal va s'ouvrir, et l'user pourra revenir
                            // soumettre. On guide explicitement sinon le
                            // contexte se perd.
                            self._copilotStatus.textContent =
                                'Améliorez vos pseudonymes puis cliquez Envoyer pour reprendre.';
                            self._copilotStatus.className = 'grid-copilot-status';
                            self._copilotConsentInProgress = false;
                        },
                        onCancel: function() {
                            clearCopilotStatus();
                            self._copilotConsentInProgress = false;
                        },
                        onAbandon: function() {
                            clearCopilotStatus();
                            self._copilotConsentInProgress = false;
                        },
                    },
                });
                return;
            }
            // Gate passe : reset le flag pour les futures soumissions.
            this._copilotConsentInProgress = false;
        } catch (e) {
            // Defensive : si le reconcile plante, on laisse partir. Le
            // backend tranchera (409 si nécessaire).
        }

        // Nouveau run_id AVANT _setCopilotProcessing(true) pour que le
        // polling puisse démarrer avec le bon id dès activation.
        this._copilotRunId = this._newCopilotRunId();
        this._setCopilotProcessing(true);

        // Cancel previous in-flight copilot request
        if (this._copilotAbort) this._copilotAbort.abort();
        this._copilotAbort = new AbortController();
        var thisAbort = this._copilotAbort; // Capture for stale-response check

        // Collect display state
        var displayState = {
            hiddenCols: Array.from(this.hiddenCols),
            sortColIndex: this.sortColIndex,
            sortDirection: this.sortDirection,
            visibleColumns: this._getVisibleColNames()
        };

        // Collect all tabs context (SQL only, no cell values)
        var tabsContext = null;
        if (typeof this._options.getTabsContext === 'function') {
            tabsContext = this._options.getTabsContext();
        }

        // Envoyer le contenu de la feuille active au LLM dès qu'elle est "structurée"
        // (feuille dashboard, xlsx importé, ou tout tableau sans SQL auto-généré).
        //
        // Tronquage SÉLECTIF par rôle sémantique (générique, marche pour
        // n'importe quel classeur) :
        //
        // 1. Cellules AVEC cellDetails (drill-down SQL, match, label sémantique)
        //    → structure porteuse d'info métier, TOUJOURS gardées (pas de cap).
        //    Cas typique : les valeurs numériques d'un onglet dashboard déjà
        //    rempli (chaque cellule a sa source SQL). Cap les tronquer casserait
        //    la navigation drill-down.
        //
        // 2. Cellules string non-numériques (labels, catégories, mois) →
        //    portent la STRUCTURE que le LLM reproduit quand on lui demande
        //    « clone ce template ». Cap 2000 (safety payload, rarement atteint
        //    — un xlsx humainement interprétable a au plus ~1000 labels).
        //
        // 3. Cellules purement numériques sans cellDetails (data brute d'un
        //    xlsx import) → échantillon suffit au LLM. Cap 500.
        //
        // Ancien comportement (cap unique 500 toutes cellules confondues) :
        // un template comme MODELE RATIO2 (729 cellules, beaucoup de labels)
        // perdait la dernière section de labels → clone_structure_from
        // reconstruisait une grille incomplète. Voir bug 2026-04-19.
        var MAX_LABEL_CELLS = 2000;
        var MAX_NUMERIC_CELLS = 500;
        var isStructuredNonSqlSheet =
            this._isDashboardSheet
            || (!this.sql && this.allRows && this.allRows.length > 0);
        var sheetContent = null;
        if (isStructuredNonSqlSheet) {
            sheetContent = [];
            var labelCount = 0;
            var numericCount = 0;
            var labelTruncated = false;
            var numericTruncated = false;
            for (var r = 0; r < this.allRows.length; r++) {
                for (var c = 0; c < this.columns.length; c++) {
                    var v = this.isArrayFormat ? this.allRows[r][c] : this.allRows[r][this.columns[c]];
                    if (!v && v !== 0) continue;
                    var strV = String(v);
                    var trimmed = strV.trim();
                    if (!trimmed) continue;
                    var detailKey = r + ',' + c;
                    var detail = this._cellDetails ? this._cellDetails[detailKey] : null;
                    var hasDetail = !!(detail && (detail.sql || detail.match || detail.label || detail.description));
                    // Classification : isNumeric = string parsable en nombre fini
                    // ET pas un nombre "magique" comme NaN/Infinity.
                    var numVal = Number(trimmed);
                    var isNumeric = (typeof v === 'number') ||
                        (trimmed !== '' && !isNaN(numVal) && isFinite(numVal));
                    // Priorité : cellules avec cellDetails = toujours gardées.
                    // Sinon cap séparé label vs numeric.
                    if (!hasDetail) {
                        if (isNumeric) {
                            if (numericCount >= MAX_NUMERIC_CELLS) {
                                numericTruncated = true;
                                continue;
                            }
                            numericCount++;
                        } else {
                            if (labelCount >= MAX_LABEL_CELLS) {
                                labelTruncated = true;
                                continue;
                            }
                            labelCount++;
                        }
                    }
                    var cellEntry = {
                        row: r + 1,
                        col: this.columns[c],
                        value: strV
                    };
                    if (detail) {
                        if (detail.sql) cellEntry.source_sql = detail.sql;
                        if (detail.match) cellEntry.match = detail.match;
                        cellEntry.label = detail.label || detail.description || null;
                    }
                    sheetContent.push(cellEntry);
                }
            }
            if (labelTruncated || numericTruncated) {
                var parts = [];
                if (labelTruncated) parts.push('labels > ' + MAX_LABEL_CELLS);
                if (numericTruncated) parts.push('valeurs numériques > ' + MAX_NUMERIC_CELLS);
                sheetContent.push({
                    row: 0, col: '_meta',
                    value: '(tronqué — ' + parts.join(', ') +
                        '). Les cellules avec cellDetails ont été préservées.'
                });
            }
        }

        // Si l'utilisateur a sélectionné des cellules au moment du clic
        // Send, on les passe au backend pour que le copilot voie le scope
        // de la demande sans énumération verbale. Cap 200 cells (anti-bruit
        // si Ctrl+A sur grille géante) ; coords 0-based, dédupliquées par
        // (row,col) car la sélection DOM peut contenir des doublons via
        // double-clic ou drag chevauchant.
        //
        // GARDE : `data-row` reflète l'index dans `displayRows` (vue triée/
        // filtrée), PAS dans `allRows` — alors que `sheet_content` envoyé
        // au backend est buildé depuis `allRows` (lignes ~6697). Si un tri
        // ou filtre frontend est actif, envoyer des coords display
        // produirait un drift silencieux côté LLM (référence la mauvaise
        // row). Même pattern que `__finalizeMoveCells:2204` qui refuse le
        // déplacement dans le même cas. On ne passe `selected_cells` que
        // si l'ordre brut est intact.
        var selectedCells = null;
        var sortActiveSel = typeof this.sortColIndex === 'number' && this.sortColIndex >= 0;
        var filtersActiveSel = false;
        if (this.filters) {
            for (var fkSel in this.filters) {
                if (!this.filters.hasOwnProperty(fkSel)) continue;
                var fSel = this.filters[fkSel];
                if (fSel && ((fSel.excluded && fSel.excluded.size > 0) || fSel.excludeNull)) {
                    filtersActiveSel = true;
                    break;
                }
            }
        }
        if (this._selectedCells && this._selectedCells.length > 0
            && !sortActiveSel && !filtersActiveSel) {
            var seen = Object.create(null);
            var cells = [];
            for (var sci = 0; sci < this._selectedCells.length && cells.length < 200; sci++) {
                var td = this._selectedCells[sci];
                var rAttr = td && td.getAttribute ? td.getAttribute('data-row') : null;
                var cAttr = td && td.getAttribute ? td.getAttribute('data-col') : null;
                if (rAttr == null || cAttr == null) continue;
                var rNum = parseInt(rAttr, 10);
                var cNum = parseInt(cAttr, 10);
                if (isNaN(rNum) || isNaN(cNum) || rNum < 0 || cNum < 0) continue;
                var key = rNum + ',' + cNum;
                if (seen[key]) continue;
                seen[key] = true;
                cells.push({ r: rNum, c: cNum });
            }
            if (cells.length > 0) selectedCells = cells;
        }

        var payload = {
            sql: this.sql,
            instruction: instruction,
            columns: this.columns,
            display_state: displayState,
            tabs_context: tabsContext,
            sheet_content: sheetContent,
            run_id: this._copilotRunId,
            anonymization_state: this._anonymizationState,
            copilot_memory: this._getCopilotMemory() || ''
        };
        if (selectedCells) payload.selected_cells = selectedCells;

        // Mode "workbook by reference" : si le classeur est sauvé dans le
        // datastore (path connu), on déclenche un save synchrone puis on
        // passe `workbook_path` au backend. Celui-ci lira le `.afz.json`
        // depuis le disque (pas de cap réseau), ce qui permet de gérer
        // des classeurs gigantesques. Le backend ignorera `tabs_context`/
        // `sheet_content` du payload quand `workbook_path` est fourni —
        // mais on les garde dans le payload pour le fallback (legacy
        // clients ou classeur jamais sauvé).
        var doSendCopilotRequest = function(finalPayload) {
            return fetch('/api/iris/result-modify', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Xsrftoken': _getXsrfCookie()
                },
                body: JSON.stringify(finalPayload),
                signal: thisAbort.signal
            });
        };

        var workbookPath = (typeof this._options.getWorkbookPath === 'function')
            ? this._options.getWorkbookPath() : null;
        var saveBeforeCopilot = (typeof this._options.saveWorkbookBeforeCopilot === 'function')
            ? this._options.saveWorkbookBeforeCopilot : null;

        var fetchPromise;
        if (saveBeforeCopilot) {
            // On sauve d'abord — la promise résout avec le `filePath` final
            // (qui peut différer de `workbookPath` si c'était la première
            // sauvegarde — saveWorkbookBeforeCopilot crée un nom horodaté).
            fetchPromise = saveBeforeCopilot()
                .then(function(savedPath) {
                    payload.workbook_path = savedPath;
                    return doSendCopilotRequest(payload);
                })
                .catch(function(err) {
                    // Save échoué → fallback sur l'envoi inline (les
                    // tabs_context/sheet_content du payload restent valides).
                    console.warn('[Copilot] save before copilot failed, fallback inline:', err);
                    return doSendCopilotRequest(payload);
                });
        } else if (workbookPath) {
            // Pas de saveWorkbookBeforeCopilot mais on a un path → on envoie
            // tel quel (état stale potentiel mais OK si l'utilisateur a sauvé
            // récemment).
            payload.workbook_path = workbookPath;
            fetchPromise = doSendCopilotRequest(payload);
        } else {
            // Aucun path connu (classeur jamais sauvé) → mode legacy
            // tabs_context inline.
            fetchPromise = doSendCopilotRequest(payload);
        }

        fetchPromise
        .then(function(resp) {
            // Lecture SÛRE (fix 2026-06-10) : resp.json() brut rejette en
            // SyntaxError sur un body non-JSON (page HTML d'un proxy 502/504,
            // crash avant handler) → l'user voyait « Erreur réseau :
            // Unexpected token… ». _readJsonSafe (SSoT komptiaReadJson) ne
            // throw jamais et normalise en message lisible.
            return _readJsonSafe(resp).then(function(res) {
                var d = res.data;
                if (!d || typeof d !== 'object') {
                    // Préserver error_code si le helper l'a extrait (eXamine
                    // 2026-06-10) : un 409/400 renvoyé en HTML par un proxy
                    // garde ainsi ses branches error_code fonctionnelles.
                    d = res.error
                        ? { error: res.error, error_code: res.errorCode || undefined }
                        : {};
                }
                return {status: res.status, data: d};
            });
        })
        .then(function(ctx) {
            // Ignore stale response if a newer request has been fired
            if (self._copilotAbort !== thisAbort) return;
            self._setCopilotProcessing(false);
            var data = ctx.data || {};

            // Gate d'anonymisation : le backend a détecté des termes qui ne
            // sont pas confirmés côté serveur (ex: front périmé OU nouveaux
            // termes apparus côté serveur). On adopte le state renvoyé et
            // on ouvre le panneau.
            //
            // Pas d'anti-loop par flag ici : chaque 409 traduit une
            // découverte serveur LÉGITIME de termes que le front ne
            // connaissait pas encore (progressive discovery). Le pré-gate
            // synchrone garde son flag pour éviter les vraies boucles
            // client. On reset le flag avant d'ouvrir pour repartir
            // sur un cycle propre.
            if (ctx.status === 409 && data.error_code === 'ANON_PENDING_REVIEW') {
                if (data.anonymization_state) {
                    self._setAnonymizationState(data.anonymization_state);
                }
                self._copilotConsentInProgress = false;
                self._copilotStatus.textContent = '';
                self._copilotStatus.className = 'grid-copilot-status';
                var instructionCapture409 = instruction;
                var clearStatus409 = function() {
                    self._copilotStatus.textContent = '';
                    self._copilotStatus.className = 'grid-copilot-status';
                };
                self._openAnonymizationPanel({
                    reason: 'pending',
                    consentCallbacks: {
                        onSave: function() {
                            clearStatus409();
                            self._sendCopilotRequest(instructionCapture409);
                        },
                        onImprove: function() {
                            self._copilotStatus.textContent =
                                'Améliorez vos pseudonymes puis cliquez Envoyer pour reprendre.';
                            self._copilotStatus.className = 'grid-copilot-status';
                        },
                        onCancel: clearStatus409,
                        onAbandon: clearStatus409,
                    },
                });
                return;
            }

            // Validation shape échouée côté backend — on laisse l'utilisateur
            // ouvrir le panneau pour corriger manuellement. Les erreurs
            // détaillées sont dans data.state_errors mais on affiche juste
            // un message simple (le détail est déjà dans les logs + panneau
            // qui re-validera au save). Même UX que le 409 : la fermeture
            // par Save nettoie le toast et relance automatiquement.
            if (ctx.status === 400 && data.error_code === 'ANON_STATE_INVALID') {
                self._copilotConsentInProgress = false;
                self._copilotStatus.textContent = '';
                self._copilotStatus.className = 'grid-copilot-status';
                var instructionCapture400 = instruction;
                var clearStatus400 = function() {
                    self._copilotStatus.textContent = '';
                    self._copilotStatus.className = 'grid-copilot-status';
                };
                self._openAnonymizationPanel({
                    reason: 'invalid',
                    consentCallbacks: {
                        onSave: function() {
                            clearStatus400();
                            self._sendCopilotRequest(instructionCapture400);
                        },
                        onImprove: function() {
                            self._copilotStatus.textContent =
                                'Améliorez vos pseudonymes puis cliquez Envoyer pour reprendre.';
                            self._copilotStatus.className = 'grid-copilot-status';
                        },
                        onCancel: clearStatus400,
                        onAbandon: clearStatus400,
                    },
                });
                return;
            }

            // Cancellation côté serveur : type="cancelled" arrive quand le
            // serveur a propagé asyncio.CancelledError (Stop button OU client
            // ferme l'onglet). Pas une erreur — c'est volontaire. Status
            // neutre "Annulé", pas de toast rouge.
            if (data.type === 'cancelled') {
                self._copilotStatus.textContent = 'Annulé.';
                self._copilotStatus.className = 'grid-copilot-status';
                // Anti-stale : ne pas écraser le status d'un run plus récent
                // qui aurait pris le relai entre-temps.
                var abortRef = thisAbort;
                setTimeout(function() {
                    if (self._copilotAbort === abortRef &&
                        self._copilotStatus &&
                        self._copilotStatus.textContent === 'Annulé.') {
                        self._copilotStatus.textContent = '';
                    }
                }, 3000);
                return;
            }

            if (data.error) {
                self._copilotStatus.textContent = data.error;
                self._copilotStatus.className = 'grid-copilot-status error';
                // Axe 5 du contrat (fix 2026-06-11, tâche #19) : bouton
                // « Signaler » UNIQUEMENT sur les erreurs 5xx (bug serveur,
                // LLM down, budget run épuisé). Doctrine partagée avec
                // iris-widget : pas de bouton sur les erreurs métier/4xx —
                // une session expirée ou un rate-limit noierait le canal
                // bug-report. SSoT du signalement = feedback-reporter.js
                // (window.komptiaReportFeedback, capture console+réseau).
                if (ctx.status >= 500
                    && typeof window.komptiaReportFeedback === 'function') {
                    var reportBtn = document.createElement('button');
                    reportBtn.type = 'button';
                    reportBtn.className = 'copilot-report-btn';
                    reportBtn.textContent = 'Signaler';
                    reportBtn.setAttribute(
                        'aria-label', 'Signaler cette erreur au support');
                    // Snapshot du contexte AU MOMENT de l'erreur (le run_id
                    // courant peut changer si l'user relance avant de
                    // cliquer Signaler).
                    var reportPayload = {
                        context: 'copilot_grid',
                        message: String(data.error),
                        error_kind: data.error_kind || null,
                        http_status: ctx.status,
                        run_id: self._copilotRunId || null,
                        timestamp: new Date().toISOString(),
                        page: window.location.pathname,
                    };
                    reportBtn.addEventListener('click', function() {
                        try { window.komptiaReportFeedback(reportPayload); }
                        catch (e) { /* defensive — reporter optionnel */ }
                    });
                    self._copilotStatus.appendChild(reportBtn);
                }
                return;
            }
            if (data.skipped) {
                self._copilotStatus.textContent = 'Requête ignorée (identique à la précédente).';
                self._copilotStatus.className = 'grid-copilot-status';
                return;
            }

            // Le backend peut renvoyer un state réconcilié dans un résultat
            // succès (nouveaux termes ajoutés avec confirmed=false, ou
            // normalisation). On synchronise le cache local pour ne pas
            // renvoyer un état périmé au prochain tour.
            if (data.anonymization_state) {
                self._setAnonymizationState(data.anonymization_state);
            }

            // Mémoire copilot : le backend retourne `copilot_memory_new`
            // (avec tokens §…§ intacts) en fin de run réussi. On notifie
            // l'owner (onCopilotMemoryChange) qui owne la source de vérité
            // sur le TabManager et la persistera au prochain save. Si le
            // backend n'émet pas ce champ (run échoué, compact LLM KO),
            // l'owner garde l'ancienne mémoire intacte.
            if (typeof data.copilot_memory_new === 'string' &&
                data.copilot_memory_new.length > 0 &&
                data.copilot_memory_new !== self._getCopilotMemory()) {
                if (typeof self._options.onCopilotMemoryChange === 'function') {
                    try { self._options.onCopilotMemoryChange(data.copilot_memory_new); }
                    catch (e) { /* ne casse pas le flux si owner lève */ }
                }
            }

            var outcome = self._applyCopilotResult(data);
            self._copilotInput.value = '';
            self._copilotInput.style.height = 'auto';
            self._copilotSendBtn.disabled = true;
            // Fix faux succès (2026-06-10, bug vécu) : ne plus écraser
            // inconditionnellement le statut par « Succès : Modification
            // appliquée » —
            //  * max_turns_reached : _handleMultiActionResult vient de poser
            //    le message info/warning (invitation à reprendre ou 0-action),
            //    l'ancien code le détruisait à l'instant où il apparaissait ;
            //  * applied === 0 (ex: fill_sql dont toutes les cellules étaient
            //    null/hors-grille) : avertissement honnête au lieu d'un
            //    succès sur un classeur inchangé.
            if (outcome && outcome.statusHandled) {
                // Statut déjà posé par le handler — rien à faire.
            } else if (outcome && outcome.applied === 0) {
                self._copilotStatus.textContent =
                    (outcome.errorsTotal > 0
                        ? outcome.errorsTotal + ' erreur(s) — ' : '')
                    + 'aucune cellule modifiée. Reformule ou précise ta demande.';
                self._copilotStatus.className = 'grid-copilot-status warning';
            } else {
                self._copilotStatus.textContent = data.description || 'Modification appliquée';
                self._copilotStatus.className = 'grid-copilot-status success';
                setTimeout(function() {
                    if (self._copilotStatus.className.indexOf('success') !== -1) {
                        self._copilotStatus.textContent = '';
                    }
                }, 4000);
            }
        })
        .catch(function(err) {
            if (err && err.name === 'AbortError') {
                // Abort déclenché par _cancelCopilotRun (user a cliqué Stop)
                // OU par un nouveau run qui supplante celui-ci. Le serveur
                // recevra la fermeture socket → cancel via on_connection_close.
                // On reset l'UI proprement (le .then() ne s'exécutera pas).
                if (self._copilotAbort === thisAbort) {
                    self._setCopilotProcessing(false);
                    if (self._copilotStatus) {
                        self._copilotStatus.textContent = 'Annulé.';
                        self._copilotStatus.className = 'grid-copilot-status';
                        setTimeout(function() {
                            if (self._copilotStatus &&
                                self._copilotStatus.textContent === 'Annulé.') {
                                self._copilotStatus.textContent = '';
                            }
                        }, 3000);
                    }
                }
                return;
            }
            self._setCopilotProcessing(false);
            // err.message peut être undefined (coupure réseau brutale) —
            // fallback lisible plutôt que « Erreur réseau : undefined ».
            self._copilotStatus.textContent = 'Erreur réseau : '
                + ((err && err.message) || 'connexion interrompue')
                + '. Vérifie ta connexion puis réessaie.';
            self._copilotStatus.className = 'grid-copilot-status error';
        });
    };

    SqlResultGrid.prototype._getVisibleColNames = function() {
        var names = [];
        for (var i = 0; i < this.columnOrder.length; i++) {
            var idx = this.columnOrder[i];
            if (!this.hiddenCols.has(idx)) names.push(this.columns[idx]);
        }
        return names;
    };

    SqlResultGrid.prototype._applyCopilotResult = function(result) {
        // Outcome optionnel remonté au caller (fix faux succès 2026-06-10) :
        // {applied: n, errorsTotal: n, statusHandled: bool}. undefined pour
        // les branches qui n'ont pas (encore) de comptage — le caller garde
        // alors le statut succès historique.
        var outcome;
        if (result.type === 'sql' && result.columns && result.rows) {
            // Force new tab on blank sheets (never destroy user content)
            var forceNewTab = result.new_tab || this._isBlankSheet;
            if (forceNewTab && typeof this._options.onNewTab === 'function') {
                var label = result.description || 'Résultat';
                var count = result.row_count || result.rows.length;
                if (count) label += ' (' + count + ')';
                this._options.onNewTab(label, result.columns, result.rows, result.sql || '', count);
                return;
            }

            // Replace current tab — save state for undo first
            this._pushHistory();
            this._isBlankSheet = false; // Exit blank mode on real data
            this._truncated = !!result.truncated;
            this.sql = result.sql || this.sql;
            this.columns = result.columns;
            this.allRows = result.rows;
            this.totalRowCount = result.row_count || result.rows.length;
            this.isArrayFormat = this.allRows.length > 0 && Array.isArray(this.allRows[0]);
            this.columnMetadata = null;
            this.hiddenCols = new Set();
            this.columnOrder = this.columns.map(function(_, i) { return i; });
            this.sortColIndex = -1;
            this.sortDirection = null;
            this.filters = {};
            this.displayRows = this.allRows.slice();
            this._detectTypes();
            this._build();
            // Re-analyze columns for drill-down on the new SQL
            if (this.sql && /GROUP\s+BY/i.test(this.sql)) {
                this._fetchColumnMetadata();
            }
        } else if (result.type === 'fill' && result.cells) {
            // Fill multiple cells at once — save state for undo
            this._pushHistory();
            for (var i = 0; i < result.cells.length; i++) {
                var cell = result.cells[i];
                var rowIdx = (typeof cell.row === 'number' ? cell.row : parseInt(cell.row, 10)) - 1;
                // Resolve column: letter name or index
                var colIdx;
                if (typeof cell.col === 'number') {
                    colIdx = cell.col;
                } else {
                    colIdx = this.columns.indexOf(cell.col);
                    if (colIdx === -1) colIdx = parseInt(cell.col, 10) || 0;
                }
                // Expand grid if needed (add rows/cols)
                while (rowIdx >= this.allRows.length && this.allRows.length < 500) {
                    var newRow = [];
                    for (var x = 0; x < this.columns.length; x++) newRow.push('');
                    this.allRows.push(newRow);
                }
                // Write value
                if (rowIdx < this.allRows.length && colIdx >= 0 && colIdx < this.columns.length) {
                    if (this.isArrayFormat) {
                        this.allRows[rowIdx][colIdx] = cell.value;
                    } else {
                        this.allRows[rowIdx][this.columns[colIdx]] = cell.value;
                    }
                }
            }
            this.displayRows = this.allRows.slice();
            this.totalRowCount = this.allRows.length;
            this._detectTypes();
            this._rebuildBody();
            this._updateHeaderInfo();
        } else if (result.type === 'fill_sql' && result.cells) {
            // Fill cells with SQL-computed values + drill-down details
            this._pushHistory();
            var filledCount = 0;
            var detailCount = 0;
            for (var i = 0; i < result.cells.length; i++) {
                var cell = result.cells[i];
                // Skip failed cells
                if (cell.value === null || cell.value === undefined) continue;
                var rowIdx = (typeof cell.row === 'number' ? cell.row : parseInt(cell.row, 10)) - 1;
                var colIdx;
                if (typeof cell.col === 'number') {
                    colIdx = cell.col;
                } else {
                    colIdx = this.columns.indexOf(cell.col);
                    if (colIdx === -1) {
                        var parsed = parseInt(cell.col, 10);
                        colIdx = isNaN(parsed) ? -1 : parsed;
                    }
                }
                if (colIdx < 0 || colIdx >= this.columns.length) continue;
                // Expand grid if needed
                while (rowIdx >= this.allRows.length && this.allRows.length < 500) {
                    var newRow = [];
                    for (var x = 0; x < this.columns.length; x++) newRow.push('');
                    this.allRows.push(newRow);
                }
                // Write value
                if (rowIdx < this.allRows.length) {
                    if (this.isArrayFormat) {
                        this.allRows[rowIdx][colIdx] = cell.value;
                    } else {
                        this.allRows[rowIdx][this.columns[colIdx]] = cell.value;
                    }
                    filledCount++;
                    // Store drill-down detail if available
                    if (cell.detail && cell.detail.columns && cell.detail.rows) {
                        var cellKey = rowIdx + ',' + colIdx;
                        this._cellDetails[cellKey] = {
                            sql: cell.detail.sql || '',
                            columns: cell.detail.columns,
                            rows: cell.detail.rows,
                            row_count: cell.detail.row_count || cell.detail.rows.length,
                            description: cell.detail.description || cell.label || ''
                        };
                        detailCount++;
                    }
                }
            }
            this.displayRows = this.allRows.slice();
            this.totalRowCount = this.allRows.length;
            this._detectTypes();
            this._rebuildBody();
            this._updateHeaderInfo();
            // Outcome remonté au caller (fix faux succès 2026-06-10) : avec
            // filledCount=0 (toutes cellules null/hors-grille), la barre de
            // statut affichait quand même « Succès : Modification appliquée ».
            outcome = {
                applied: filledCount,
                errorsTotal: result.errors_count || 0,
            };
            // Show feedback toast
            if (typeof this._showSaveToast === 'function') {
                var msg = filledCount + ' cellule' + (filledCount > 1 ? 's' : '') + ' remplie' + (filledCount > 1 ? 's' : '');
                if (detailCount > 0) msg += ' (' + detailCount + ' avec détails)';
                if (result.errors_count > 0) msg += ' — ' + result.errors_count + ' erreur' + (result.errors_count > 1 ? 's' : '');
                this._showSaveToast(msg, (result.errors_count > 0 || filledCount === 0) ? 'warning' : 'success');
            }
        } else if (result.type === 'display' && result.actions) {
            // Display-only modifications — save state for undo
            this._pushHistory();
            for (var i = 0; i < result.actions.length; i++) {
                this._applyDisplayAction(result.actions[i]);
            }
        } else if (result.type === 'clone_sheet') {
            this._handleCloneSheet(result);
        } else if (result.type === 'emit_tab') {
            this._handleEmitTab(result);
        } else if (result.type === 'patch_tab') {
            this._handlePatchTab(result);
        } else if (result.type === 'rename_tab') {
            this._handleRenameTab(result);
        } else if (result.type === 'delete_tab') {
            this._handleDeleteTab(result);
        } else if (result.type === 'modify_tab_sql') {
            this._handleModifyTabSql(result);
        } else if (result.type === 'done' || result.type === 'max_turns_reached') {
            // Format multi-actions : N emits + M modifications produits dans
            // un seul run du copilot. On les applique séquentiellement comme
            // des actions individuelles. ``max_turns_reached`` partage le même
            // shape (emits + modifications) mais signale en plus le message
            // d'invitation à reprendre via le chat.
            outcome = this._handleMultiActionResult(result);
        } else if (result.type === 'multi_action') {
            // Alias historique potentiel (au cas où un retour custom le pose).
            outcome = this._handleMultiActionResult(result);
        }

        this._updateUndoRedoButtons();

        // Filet de sécurité centralisé : pour TOUS les types qui modifient
        // l'état du classeur, on déclenche onSnapshot → snapshotWorkbook
        // (debounced 500ms) → setDirty + scheduleIdleAutosave +
        // _writeAutoRecover. Idempotent : les handlers spécialisés
        // (_handleEmitTab, _handlePatchTab, _handleRenameTab,
        // _handleDeleteTab) appellent déjà onSnapshot ; le debounce 500ms
        // collapse les appels multiples en un seul snapshot.
        //
        // Couvre les branches inline (sql, fill, fill_sql, clone_sheet)
        // qui n'avaient pas leur propre onSnapshot. Sans ce filet, un
        // résultat copilot type='fill_sql' ou type='sql' (cas auto-fill,
        // ou conversation post-modification) restait en mémoire JS sans
        // déclencher l'autosave → perte au browser-back.
        // ``display`` exclu : purement informationnel, ne mute rien.
        var stateMutatingTypes = [
            'sql', 'fill', 'fill_sql', 'clone_sheet',
            'emit_tab', 'patch_tab', 'rename_tab', 'delete_tab',
            'modify_tab_sql',
            'done', 'max_turns_reached', 'multi_action',
        ];
        if (
            result && stateMutatingTypes.indexOf(result.type) !== -1
            && this._options
            && typeof this._options.onSnapshot === 'function'
        ) {
            try {
                this._options.onSnapshot();
            } catch (_e) {
                // Defense-in-depth : ne casse jamais le rendu si snapshot
                // utilisateur lève. Logué pour audit.
                try { console.error('[copilot] onSnapshot threw :', _e); } catch (__e) { /* noop */ }
            }
        }
        return outcome;
    };

    // Format ``{type: "done"|"max_turns_reached", emits: [...],
    // modifications: [...]}`` — applique chaque action dans l'ordre. Chaque
    // emit est un dict ``{type: "emit_tab", tab, ...}`` que ``_handleEmitTab``
    // sait déjà traiter ; les modifications sont des dicts au format des
    // ``patch_tab``/``rename_tab``/``delete_tab`` standalone, on dispatche
    // sur le ``type`` interne.
    SqlResultGrid.prototype._handleMultiActionResult = function(result) {
        var emits = Array.isArray(result.emits) ? result.emits : [];
        var modifications = Array.isArray(result.modifications) ? result.modifications : [];
        var appliedCount = 0;
        var errorsTotal = 0;

        for (var i = 0; i < emits.length; i++) {
            var emit = emits[i];
            if (!emit || typeof emit !== 'object') { errorsTotal++; continue; }
            // ``emit`` a déjà le shape attendu par _handleEmitTab (type/tab/...).
            // _handleEmitTab retourne false sur structure invalide (eXamine
            // 2026-06-10) — ne pas compter un emit raté comme « appliqué »,
            // sinon le caller affiche un succès sur un classeur inchangé.
            if (this._handleEmitTab(emit) !== false) {
                appliedCount++;
            } else {
                errorsTotal++;
            }
        }
        for (var j = 0; j < modifications.length; j++) {
            var mod = modifications[j];
            if (!mod || typeof mod !== 'object') continue;
            switch (mod.type) {
                case 'patch_tab':
                    this._handlePatchTab(mod);
                    appliedCount++;
                    break;
                case 'rename_tab':
                    this._handleRenameTab(mod);
                    appliedCount++;
                    break;
                case 'delete_tab':
                    this._handleDeleteTab(mod);
                    appliedCount++;
                    break;
                case 'modify_tab_sql':
                    this._handleModifyTabSql(mod);
                    appliedCount++;
                    break;
                default:
                    // Type inconnu — on l'ignore plutôt que de planter
                    // l'application d'autres actions valides.
                    break;
            }
        }

        // Pour ``max_turns_reached`` : afficher le message d'invitation à
        // reprendre. NB (eXamine 2026-06-10) : le hook ``onCopilotMessage``
        // n'a AUCUNE implémentation dans la codebase à ce jour — l'appel
        // ci-dessous est un point d'extension pour un futur manager qui
        // voudrait pousser le message dans un chat persistant ; aujourd'hui
        // le fallback _copilotStatus est TOUJOURS le chemin effectif.
        // Fix faux succès 2026-06-10 : si AUCUNE action n'a été appliquée
        // (le LLM a bouclé sur des done rejetés jusqu'au budget), le dire
        // en avertissement — l'ancien code laissait le caller afficher
        // « Succès : Modification appliquée » sur un classeur inchangé.
        if (result.type === 'max_turns_reached') {
            var mtMsg = (typeof result.message === 'string' && result.message)
                ? result.message
                : 'Budget de l\'agent épuisé.';
            var mtSeverity = 'info';
            if (appliedCount === 0) {
                mtMsg = 'Budget de l\'agent épuisé — AUCUNE modification n\'a été '
                    + 'appliquée au classeur. Reformule ta demande ou relance avec '
                    + '« continue ».';
                mtSeverity = 'warning';
            }
            if (typeof this._options.onCopilotMessage === 'function') {
                try {
                    this._options.onCopilotMessage(mtMsg, mtSeverity);
                } catch (e) {
                    // Hook utilisateur cassé : on retombe sur _copilotStatus
                    // sans casser l'application des actions ci-dessus.
                }
            }
            if (this._copilotStatus) {
                this._copilotStatus.textContent = mtMsg;
                this._copilotStatus.className = 'grid-copilot-status ' + mtSeverity;
            }
        }

        // statusHandled : pour max_turns_reached, le statut vient d'être posé
        // ici (info reprise ou warning 0-action) — le caller ne doit PAS
        // l'écraser avec le succès générique (fix faux succès 2026-06-10).
        return {
            applied: appliedCount,
            errorsTotal: errorsTotal,
            statusHandled: result.type === 'max_turns_reached',
        };
    };

    // ── emit_tab: the LLM returns a complete new tab (label, columns, rows,
    // merges, cellDetails). Used for offline transformations from sibling tabs
    // already in the workbook (ratios, clones with filters, etc.). cellDetails
    // carry per-cell SQL + match for drill-down.
    SqlResultGrid.prototype._handleEmitTab = function(result) {
        var tab = result && result.tab;
        if (!tab || !Array.isArray(tab.columns) || !Array.isArray(tab.rows)) {
            if (this._copilotStatus) {
                this._copilotStatus.textContent = 'emit_tab: structure invalide';
                this._copilotStatus.className = 'grid-copilot-status error';
            }
            // false = échec signalé au caller (_handleMultiActionResult ne
            // compte pas cet emit comme appliqué — fix faux succès 2026-06-10).
            return false;
        }
        var label = tab.label || result.description || 'Onglet émis';
        var columns = tab.columns;
        var rows = tab.rows;
        var merges = Array.isArray(tab.merges) ? tab.merges : [];
        var cellDetails = (tab.cellDetails && typeof tab.cellDetails === 'object') ? tab.cellDetails : {};
        var newTabFlag = (result.new_tab !== false); // default true
        var count = rows.length;
        var metrics = result.metrics || {};

        // is_sql_result=true → onglet matérialisé par ask_iris (résultat SQL pur).
        // On conserve le sql d'origine et on NE force PAS isDashboardSheet=true,
        // sinon l'onglet est classé "dashboard" et perd ses capabilities SQL.
        // is_sql_result absent/false → comportement legacy (transformation Copilot
        // avec cellDetails+merges, qui sera reclassé dashboard ssi merges ≠ []).
        var isSqlResult = !!result.is_sql_result;
        var applyToGrid = function(targetGrid) {
            if (!targetGrid) return;
            targetGrid.sql = isSqlResult ? (tab.sql || '') : '';
            targetGrid.columns = columns.slice();
            targetGrid.allRows = rows;
            targetGrid.totalRowCount = count;
            targetGrid.isArrayFormat = count > 0 && Array.isArray(rows[0]);
            targetGrid.columnMetadata = null;
            targetGrid.hiddenCols = new Set();
            targetGrid.columnOrder = columns.map(function(_, i) { return i; });
            targetGrid.sortColIndex = -1;
            targetGrid.sortDirection = null;
            targetGrid.filters = {};
            targetGrid.displayRows = rows.slice();
            targetGrid._cellDetails = cellDetails;
            // Dashboard = vraies cellules fusionnées. cellDetails seuls (drill-downs)
            // peuvent vivre sur un sql_result sans le transformer en dashboard.
            targetGrid._isDashboardSheet = !isSqlResult && merges.length > 0;
            targetGrid._isBlankSheet = false;
            // Block the auto-fill ghost from re-filling None cells the user
            // explicitly wants empty.
            targetGrid._autoFillCompleted = true;
            if (typeof targetGrid.setMerges === 'function') {
                targetGrid.setMerges(merges);
            }
            if (typeof targetGrid._detectTypes === 'function') {
                targetGrid._detectTypes();
            }
            if (typeof targetGrid._build === 'function') {
                targetGrid._build();
            } else {
                if (typeof targetGrid._rebuildBody === 'function') targetGrid._rebuildBody();
                if (typeof targetGrid._updateHeaderInfo === 'function') targetGrid._updateHeaderInfo();
            }
        };

        if (newTabFlag && typeof this._options.onNewTab === 'function') {
            // Create empty tab first; onNewTab returns the new tab index.
            var createdIdx = this._options.onNewTab(label, columns, [], '', 0);
            var newGrid = null;
            if (typeof createdIdx === 'number' && createdIdx >= 0
                && typeof this._options.getTabGrid === 'function') {
                newGrid = this._options.getTabGrid(createdIdx);
            }
            if (!newGrid) {
                if (this._copilotStatus) {
                    this._copilotStatus.textContent = 'emit_tab: onglet créé mais grille introuvable';
                    this._copilotStatus.className = 'grid-copilot-status error';
                }
                return;
            }
            applyToGrid(newGrid);
        } else {
            // Overwrite the active tab
            this._pushHistory();
            applyToGrid(this);
        }

        if (this._copilotStatus) {
            var msg = 'Onglet émis — ' + count + ' ligne' + (count > 1 ? 's' : '');
            if (metrics.recomputed) {
                msg += ', ' + metrics.recomputed + ' recalculée' + (metrics.recomputed > 1 ? 's' : '') + ' côté serveur';
            }
            if (metrics.total_ms) {
                msg += ' · ' + (metrics.total_ms / 1000).toFixed(1) + 's';
            }
            this._copilotStatus.textContent = msg;
            this._copilotStatus.className = 'grid-copilot-status success';
        }

        // Trigger snapshot → setDirty → autosave (cohérent avec _handleRenameTab,
        // _handlePatchTab, _handleDeleteTab). Sans cet appel, un emit_tab reste
        // en mémoire JS sans déclencher le système autosave existant (60s
        // périodique + 10s idle + localStorage AutoRecover) → résultat copilot
        // de 30 min perdu si l'utilisateur fait browser-back / refresh / crash
        // navigateur avant le prochain trigger manuel. Bug 2026-04-27.
        if (typeof this._options.onSnapshot === 'function') this._options.onSnapshot();
    };

    // ── rename_tab / delete_tab / patch_tab ──
    //
    // Ces trois terminaux sont émis par `run_copilot_agent` (backend) quand le
    // LLM appelle les outils du même nom. Ils mutent respectivement le label,
    // la liste des onglets, ou un sous-ensemble de cellules d'un onglet — et
    // sont aussi undoable que `emit_tab` (snapshot workbook avant/après).

    SqlResultGrid.prototype._handleRenameTab = function(result) {
        var targetIdx = result && result.target_tab_index;
        var newLabel = result && result.new_label;
        if (typeof targetIdx !== 'number' || typeof newLabel !== 'string') {
            if (this._copilotStatus) {
                this._copilotStatus.textContent = 'rename_tab: réponse invalide';
                this._copilotStatus.className = 'grid-copilot-status error';
            }
            return;
        }
        if (typeof this._options.onRenameTab !== 'function') {
            if (this._copilotStatus) {
                this._copilotStatus.textContent = 'rename_tab: non supporté par ce contexte';
                this._copilotStatus.className = 'grid-copilot-status error';
            }
            return;
        }
        // Snapshot APRÈS succès — évite une entrée undoable "vide" si le
        // manager refuse (index OOB, label vide…). La mutation label est
        // idempotente : un snapshot tardif capture le bon état.
        var ok = this._options.onRenameTab(targetIdx, newLabel);
        if (ok && typeof this._options.onSnapshot === 'function') {
            this._options.onSnapshot();
        }
        if (this._copilotStatus) {
            if (ok) {
                this._copilotStatus.textContent = 'Onglet renommé en « ' + newLabel.trim() + ' »';
                this._copilotStatus.className = 'grid-copilot-status success';
            } else {
                this._copilotStatus.textContent = 'rename_tab: index ou label invalide';
                this._copilotStatus.className = 'grid-copilot-status error';
            }
        }
    };

    SqlResultGrid.prototype._handleDeleteTab = function(result) {
        var targetIdx = result && result.target_tab_index;
        var targetLabel = (result && result.target_label) || '';
        if (typeof targetIdx !== 'number') {
            if (this._copilotStatus) {
                this._copilotStatus.textContent = 'delete_tab: réponse invalide';
                this._copilotStatus.className = 'grid-copilot-status error';
            }
            return;
        }
        if (typeof this._options.onDeleteTab !== 'function') {
            if (this._copilotStatus) {
                this._copilotStatus.textContent = 'delete_tab: non supporté par ce contexte';
                this._copilotStatus.className = 'grid-copilot-status error';
            }
            return;
        }
        // Snapshot APRÈS succès du callback — même motif que _handleRenameTab.
        var ok = this._options.onDeleteTab(targetIdx);
        if (ok && typeof this._options.onSnapshot === 'function') {
            this._options.onSnapshot();
        }
        if (this._copilotStatus) {
            if (ok) {
                var msg = 'Onglet supprimé';
                if (targetLabel) msg += ' : « ' + targetLabel + ' »';
                this._copilotStatus.textContent = msg;
                this._copilotStatus.className = 'grid-copilot-status success';
            } else {
                this._copilotStatus.textContent = 'delete_tab: suppression refusée (actif, dernier onglet ou index invalide)';
                this._copilotStatus.className = 'grid-copilot-status error';
            }
        }
    };

    // modify_tab_sql : mute le SQL d'un onglet existant. Le payload
    // backend a déjà fait l'appel Iris + récupéré les nouvelles données.
    // Côté frontend, on délègue au TabManager (callback ``onReplaceTabContent``)
    // qui écrase le contenu de l'onglet à ``target_tab_index`` SANS le
    // supprimer/recréer (préserve scroll, position dans la barre, focus).
    SqlResultGrid.prototype._handleModifyTabSql = function(result) {
        var targetIdx = result && result.target_tab_index;
        var sql = result && result.sql;
        var columns = result && result.columns;
        var rows = result && result.rows;
        var rowCount = result && result.row_count;
        var label = result && result.label;
        if (typeof targetIdx !== 'number'
            || typeof sql !== 'string'
            || !Array.isArray(columns)
            || !Array.isArray(rows)) {
            if (this._copilotStatus) {
                this._copilotStatus.textContent = 'modify_tab_sql: réponse invalide';
                this._copilotStatus.className = 'grid-copilot-status error';
            }
            return;
        }
        if (typeof this._options.onReplaceTabContent !== 'function') {
            if (this._copilotStatus) {
                this._copilotStatus.textContent =
                    'modify_tab_sql: non supporté par ce contexte';
                this._copilotStatus.className = 'grid-copilot-status error';
            }
            return;
        }
        var ok = this._options.onReplaceTabContent(targetIdx, {
            sql: sql,
            columns: columns,
            rows: rows,
            row_count: typeof rowCount === 'number' ? rowCount : rows.length,
            label: label || null,
        });
        if (ok && typeof this._options.onSnapshot === 'function') {
            this._options.onSnapshot();
        }
        if (this._copilotStatus) {
            if (ok) {
                this._copilotStatus.textContent =
                    'SQL de l\'onglet « ' + (label || '#' + targetIdx)
                    + ' » mis à jour (' + rows.length + ' lignes).';
                this._copilotStatus.className = 'grid-copilot-status success';
            } else {
                this._copilotStatus.textContent =
                    'modify_tab_sql: index ' + targetIdx + ' invalide ou onglet introuvable';
                this._copilotStatus.className = 'grid-copilot-status error';
            }
        }
    };

    // patch_tab : mutation granulaire. `patches` = { "R,C": scalar |
    // {value?, cellDetail?} }. Les R,C sont 0-based (convention copilot_agent).
    // Pour chaque patch : si value fourni → écrit dans la grille ; si
    // cellDetail fourni → merge dans grid._cellDetails[R,C]. La grille cible
    // peut ne pas être `this` — un LLM peut patcher un onglet non-actif.
    SqlResultGrid.prototype._handlePatchTab = function(result) {
        var targetIdx = result && result.target_tab_index;
        var patches = result && result.patches;
        var targetLabel = (result && result.target_label) || '';
        if (typeof targetIdx !== 'number' || !patches || typeof patches !== 'object') {
            if (this._copilotStatus) {
                this._copilotStatus.textContent = 'patch_tab: réponse invalide';
                this._copilotStatus.className = 'grid-copilot-status error';
            }
            return;
        }
        if (typeof this._options.getTabGrid !== 'function') {
            if (this._copilotStatus) {
                this._copilotStatus.textContent = 'patch_tab: non supporté par ce contexte';
                this._copilotStatus.className = 'grid-copilot-status error';
            }
            return;
        }
        var grid = this._options.getTabGrid(targetIdx);
        if (!grid) {
            if (this._copilotStatus) {
                this._copilotStatus.textContent = 'patch_tab: onglet ' + targetIdx + ' introuvable';
                this._copilotStatus.className = 'grid-copilot-status error';
            }
            return;
        }
        // Fail-closed sur grille sans colonnes : le `while` d'extension créerait
        // des lignes `[]`, puis `c >= grid.columns.length` rejetterait tous les
        // patches silencieusement → grille gonflée à 500 lignes vides + 0
        // cellule écrite = corruption. On refuse net.
        if (!Array.isArray(grid.columns) || grid.columns.length === 0) {
            if (this._copilotStatus) {
                this._copilotStatus.textContent = 'patch_tab: onglet ' + targetIdx + ' sans colonnes';
                this._copilotStatus.className = 'grid-copilot-status error';
            }
            return;
        }
        // Snapshot workbook AVANT la mutation (les checks bloquants ont été
        // passés ; undo unifié avec emit_tab).
        if (typeof this._options.onSnapshot === 'function') this._options.onSnapshot();

        var applied = 0;
        var rejected = 0;
        var keys = Object.keys(patches);
        if (!grid._cellDetails || typeof grid._cellDetails !== 'object') {
            grid._cellDetails = {};
        }
        for (var i = 0; i < keys.length; i++) {
            var key = keys[i];
            // Parse "R,C" — refuse tout ce qui ne matche pas strictement.
            var m = /^\s*(\d+)\s*,\s*(\d+)\s*$/.exec(key);
            if (!m) { rejected++; continue; }
            var r = parseInt(m[1], 10);
            var c = parseInt(m[2], 10);
            if (r < 0 || c < 0) { rejected++; continue; }
            var patch = patches[key];
            var newValue;
            var newDetail = null;
            var hasValue = false;
            if (patch && typeof patch === 'object' && !Array.isArray(patch)) {
                if ('value' in patch) { newValue = patch.value; hasValue = true; }
                if (patch.cellDetail && typeof patch.cellDetail === 'object') {
                    newDetail = patch.cellDetail;
                }
            } else {
                // scalaire direct
                newValue = patch;
                hasValue = true;
            }

            // Étend la grille si R dépasse l'existant, borné à 500 comme `fill`.
            while (r >= grid.allRows.length && grid.allRows.length < 500) {
                var newRow = [];
                for (var x = 0; x < grid.columns.length; x++) newRow.push('');
                grid.allRows.push(newRow);
            }
            if (r >= grid.allRows.length || c >= grid.columns.length) { rejected++; continue; }

            if (hasValue) {
                if (grid.isArrayFormat) {
                    grid.allRows[r][c] = newValue;
                } else {
                    grid.allRows[r][grid.columns[c]] = newValue;
                }
            }
            if (newDetail) {
                var cellKey = r + ',' + c;
                var existing = grid._cellDetails[cellKey] || {};
                // Merge shallow : les champs fournis écrasent, les autres
                // restent (le LLM peut ne fournir que `match` pour refaire le
                // SUM sans toucher à `label`).
                for (var k in newDetail) {
                    if (Object.prototype.hasOwnProperty.call(newDetail, k)) {
                        existing[k] = newDetail[k];
                    }
                }
                grid._cellDetails[cellKey] = existing;
            }
            applied++;
        }

        grid.displayRows = grid.allRows.slice();
        grid.totalRowCount = grid.allRows.length;
        if (typeof grid._detectTypes === 'function') grid._detectTypes();
        if (typeof grid._rebuildBody === 'function') grid._rebuildBody();
        if (typeof grid._updateHeaderInfo === 'function') grid._updateHeaderInfo();

        if (this._copilotStatus) {
            var msg = applied + ' cellule' + (applied > 1 ? 's' : '') + ' patchée' + (applied > 1 ? 's' : '');
            if (targetLabel) msg += ' dans « ' + targetLabel + ' »';
            if (rejected) msg += ' — ' + rejected + ' rejetée' + (rejected > 1 ? 's' : '');
            this._copilotStatus.textContent = msg;
            this._copilotStatus.className = rejected ? 'grid-copilot-status warning' : 'grid-copilot-status success';
        }
    };

    // ── Auto-fill ghost system (Copilot-like) ──────────────────────

    SqlResultGrid.prototype._triggerAutoFill = function() {
        var self = this;
        if (!this._isDashboardSheet || this._autoFillPending) return;
        if (this._autoFillCompleted) return;
        // Ne pas trigger si une cellule est en cours d'édition
        // (allRows n'a pas encore la nouvelle valeur → données stale)
        if (this.tbodyEl && this.tbodyEl.querySelector('input.grid-cell-input')) return;

        // Need tabs with SQL data
        var tabsContext = null;
        if (typeof this._options.getTabsContext === 'function') {
            tabsContext = this._options.getTabsContext();
        }
        if (!tabsContext) return;
        var hasSqlTabs = false;
        for (var t = 0; t < tabsContext.length; t++) {
            if (tabsContext[t].sql && !tabsContext[t].is_active) { hasSqlTabs = true; break; }
        }
        if (!hasSqlTabs) return;

        // Need at least 1 filled cell
        var filledCount = 0;
        for (var r = 0; r < this.allRows.length && filledCount < 1; r++) {
            for (var c = 0; c < this.columns.length; c++) {
                var v = this.isArrayFormat ? this.allRows[r][c] : this.allRows[r][this.columns[c]];
                if (v && String(v).trim()) filledCount++;
            }
        }
        if (filledCount < 1) return;

        // Build sheet snapshot with ONLY filled cells (no empty cells)
        var sheetContent = [];
        for (var r2 = 0; r2 < Math.min(this.allRows.length, 20); r2++) {
            for (var c2 = 0; c2 < this.columns.length; c2++) {
                var v2 = this.isArrayFormat ? this.allRows[r2][c2] : this.allRows[r2][this.columns[c2]];
                if (v2 && String(v2).trim()) {
                    var cellEntry = {
                        row: r2 + 1,
                        col: this.columns[c2],
                        value: String(v2)
                    };
                    // Annotate with detail info if available (same format as fill_sql)
                    var detailKey = r2 + ',' + c2;
                    var detail = this._cellDetails ? this._cellDetails[detailKey] : null;
                    if (detail) {
                        if (detail.sql) cellEntry.source_sql = detail.sql;
                        if (detail.match) cellEntry.match = detail.match;
                        // label: explicit label > description > nothing
                        cellEntry.label = detail.label || detail.description || null;
                    }
                    sheetContent.push(cellEntry);
                }
            }
        }

        // Deduplicate: skip if sheet content hasn't changed since last auto-fill
        var contentHash = sheetContent.map(function(c) { return c.row + c.col + c.value; }).join('|');
        if (this._lastAutoFillHash && this._lastAutoFillHash === contentHash) return;
        this._lastAutoFillHash = contentHash;

        this._autoFillPending = true;
        // Annuler la requête précédente si elle est encore en cours
        if (this._autoFillAbort) this._autoFillAbort.abort();
        this._autoFillAbort = new AbortController();

        if (this._copilotStatus) {
            this._copilotStatus.textContent = 'Analyse des cellules…';
            this._copilotStatus.className = 'grid-copilot-status';
        }

        var payload = {
            sql: this.sql,
            instruction: "Remplis toutes les cellules vides avec les valeurs numériques appropriées " +
                "à partir des données des autres onglets. Analyse les labels (en-têtes de lignes " +
                "et colonnes) pour comprendre quelle valeur va dans quelle cellule.",
            columns: this.columns,
            display_state: { hiddenCols: [], sortColIndex: -1, sortDirection: null, visibleColumns: this._getVisibleColNames() },
            tabs_context: tabsContext,
            sheet_content: sheetContent,
            is_auto_fill: true
        };

        fetch('/api/iris/result-modify', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Xsrftoken': _getXsrfCookie()
            },
            body: JSON.stringify(payload),
            signal: this._autoFillAbort.signal
        })
        .then(function(resp) { return resp.json(); })
        .then(function(data) {
            self._autoFillPending = false;
            // Auto-fill ghost : si l'IA n'est pas configurée, on n'affiche
            // PAS de toast pour chaque trigger d'auto-fill (un user qui
            // édite la feuille déclencherait N toasts spammeurs). Le banner
            // global suffit pour informer. On nettoie juste l'UI status.
            if (data && data.reason === 'not_configured') {
                if (self._copilotStatus) self._copilotStatus.textContent = '';
                return;
            }
            if (data.error || !data.cells) {
                if (self._copilotStatus) self._copilotStatus.textContent = '';
                return;
            }
            // Dismiss anciens ghosts MAINTENANT (les nouveaux arrivent)
            self._dismissGhosts();
            // Store as ghost values (only in empty cells)
            self._ghostValues = {};
            var count = 0;
            for (var i = 0; i < data.cells.length; i++) {
                var cell = data.cells[i];
                if (cell.value === null || cell.value === undefined) continue;
                var rowIdx = (typeof cell.row === 'number' ? cell.row : parseInt(cell.row, 10)) - 1;
                var colIdx;
                if (typeof cell.col === 'number') {
                    colIdx = cell.col;
                } else {
                    colIdx = self.columns.indexOf(cell.col);
                    if (colIdx === -1) {
                        var p = parseInt(cell.col, 10);
                        colIdx = isNaN(p) ? -1 : p;
                    }
                }
                if (colIdx < 0 || colIdx >= self.columns.length) continue;
                if (rowIdx < 0 || rowIdx >= self.allRows.length) continue;
                // Only ghost empty cells
                var existing = self.isArrayFormat
                    ? self.allRows[rowIdx][colIdx]
                    : self.allRows[rowIdx][self.columns[colIdx]];
                if (existing && String(existing).trim()) continue;
                self._ghostValues[rowIdx + ',' + colIdx] = {
                    value: cell.value,
                    detail: cell.detail || null,
                    label: cell.label || null,
                    match: cell.match || null
                };
                count++;
            }
            if (count > 0) {
                self._renderGhosts();
                if (self._copilotStatus) {
                    self._copilotStatus.textContent = count + ' suggestion' + (count > 1 ? 's' : '') +
                        ' — Tab pour accepter, Échap pour ignorer';
                    self._copilotStatus.className = 'grid-copilot-status success';
                }
            } else {
                if (self._copilotStatus) self._copilotStatus.textContent = '';
            }
        })
        .catch(function(err) {
            self._autoFillPending = false;
            // AbortError = requête annulée volontairement (feuille modifiée) → silencieux
            if (err && err.name === 'AbortError') return;
            if (self._copilotStatus) self._copilotStatus.textContent = '';
        });
    };

    // Apply ghost display to a single td (shared by _renderGhosts and ghost restore)
    // Template detection: find a sibling sheet with matching name pattern
    // Returns { templateGrid, oldVar, newVar } or null
    // Handle clone_sheet response: clone a sibling sheet with substitutions.
    //
    // Behavior:
    //   - Substitutions are applied to text cells uniformly (word-boundary, case-insensitive).
    //   - Substitutions that also appear in the source cells' SQL are considered "SQL-affecting"
    //     → the corresponding numeric values are SKIPPED and left to the auto-fill (which will
    //     recompute with the substituted SQL). This prevents silent data corruption
    //     (e.g., values computed for person A displayed under person B's row).
    //   - Substitutions that are purely cosmetic (don't appear in any SQL) → all numeric
    //     values AND their _cellDetails (source_sql, match, label, drill-down rows) are
    //     copied as-is. This is the correct answer when the source already matches the
    //     user's perimeter — no recalculation needed.
    //   - An empty substitutions list ([]) means a pure transfer: all cells copied verbatim.
    SqlResultGrid.prototype._handleCloneSheet = function(result) {
        var sourceIdx = result.source_tab_index;
        var subs = Array.isArray(result.substitutions) ? result.substitutions : [];
        var wantsNewTab = result.new_tab === true;
        // Reset l'état auto-fill AVANT toute chose : si le clone ajoute des
        // cellules vides ou si des valeurs doivent être recalculées, l'auto-fill
        // doit pouvoir se relancer. Ne pas reset cet état bloque silencieusement
        // l'auto-fill sur les onglets où il avait déjà tourné une fois.
        this._autoFillCompleted = false;
        this._lastAutoFillHash = null;
        if (!this._options || !this._options.getTabGrid) {
            if (this._copilotStatus) {
                this._copilotStatus.textContent = 'Clone impossible (API onglets indisponible)';
                this._copilotStatus.className = 'grid-copilot-status error';
            }
            if (typeof this._showSaveToast === 'function') {
                this._showSaveToast('Clone impossible (API onglets indisponible)', true);
            }
            return;
        }

        var sourceGrid = this._options.getTabGrid(sourceIdx);
        if (!sourceGrid || !sourceGrid.allRows || sourceGrid.allRows.length === 0) {
            var msgSrcMissing = 'Onglet source introuvable (index ' + sourceIdx + ')';
            if (this._copilotStatus) {
                this._copilotStatus.textContent = msgSrcMissing;
                this._copilotStatus.className = 'grid-copilot-status error';
            }
            if (typeof this._showSaveToast === 'function') {
                this._showSaveToast(msgSrcMissing, true);
            }
            return;
        }

        // Si le LLM (ou le fallback backend) a demandé un nouvel onglet,
        // on délègue la création à l'hôte et on ré-exécute le clone sur la
        // NOUVELLE grille (qui ne sera plus == this). Ça résout deux cas :
        //   1. L'utilisateur veut "dans une autre feuille"
        //   2. source_tab_index == onglet actif (auto-clone impossible)
        if (wantsNewTab) {
            if (typeof this._options.onNewTab !== 'function') {
                var msgNoTabApi = 'Impossible de créer un nouvel onglet (pas de callback dispo)';
                if (this._copilotStatus) {
                    this._copilotStatus.textContent = msgNoTabApi;
                    this._copilotStatus.className = 'grid-copilot-status error';
                }
                if (typeof this._showSaveToast === 'function') {
                    this._showSaveToast(msgNoTabApi, true);
                }
                return;
            }
            // Label du nouvel onglet : description LLM tronquée, fallback "Clone de <source>"
            var srcLabelForTab = (sourceGrid._options && sourceGrid._options.tabLabel)
                || ('onglet ' + sourceIdx);
            var desc = result.description || '';
            var newTabLabel = desc
                ? (desc.length > 50 ? desc.substring(0, 50) + '…' : desc)
                : ('Clone de ' + srcLabelForTab);
            // Créer un onglet VIERGE qui a la MÊME largeur (columns) que la source,
            // pour éviter que le clone tronque les colonnes > H (SqlResultGrid
            // génère par défaut A-H quand columns est vide). Si source.columns
            // existe, on le passe ; sinon on tombe sur le défaut A-H.
            var newCols = (sourceGrid.columns && sourceGrid.columns.length > 0)
                ? sourceGrid.columns.slice()
                : [];
            var createdIdx = this._options.onNewTab(newTabLabel, newCols, [], '', 0);
            // Récupérer la nouvelle grille (si onNewTab retourne l'index)
            var newGrid = null;
            if (typeof createdIdx === 'number') {
                newGrid = this._options.getTabGrid(createdIdx);
            } else {
                // Fallback : pas d'index retourné, on prend le dernier onglet ajouté
                var guessIdx = 0;
                while (this._options.getTabGrid(guessIdx)) guessIdx++;
                newGrid = this._options.getTabGrid(guessIdx - 1);
            }
            if (!newGrid) {
                var msgNoGrid = 'Nouvel onglet créé mais introuvable — action annulée';
                if (this._copilotStatus) {
                    this._copilotStatus.textContent = msgNoGrid;
                    this._copilotStatus.className = 'grid-copilot-status error';
                }
                if (typeof this._showSaveToast === 'function') {
                    this._showSaveToast(msgNoGrid, true);
                }
                return;
            }
            // Copier la référence au statut du copilot source pour que le
            // message final apparaisse dans la barre d'origine (UX plus claire
            // que "rien ne se passe sur l'onglet actif, regardez dans le nouveau").
            newGrid._copilotStatus = this._copilotStatus;
            newGrid._showSaveToast = this._showSaveToast
                ? this._showSaveToast.bind(this) : newGrid._showSaveToast;
            // Appliquer le clone en désactivant new_tab pour éviter une boucle
            // infinie (sinon ça recréerait un autre onglet à chaque appel).
            var resultNoNewTab = Object.assign({}, result, { new_tab: false });
            newGrid._handleCloneSheet(resultNoNewTab);
            return;
        }

        // Guard: source tab must not be the current tab (would create a self-referential clone).
        // Normalement déjà couvert par le fallback backend (new_tab=true forcé), mais on
        // garde la défense en profondeur pour les appels legacy.
        if (sourceGrid === this) {
            var msgSelf = 'Onglet source = onglet actif — clone annulé (utilisez new_tab=true)';
            if (this._copilotStatus) {
                this._copilotStatus.textContent = msgSelf;
                this._copilotStatus.className = 'grid-copilot-status error';
            }
            if (typeof this._showSaveToast === 'function') {
                this._showSaveToast(msgSelf, true);
            }
            return;
        }

        // Pre-compile substitution regexes (word-boundary, case-insensitive).
        // IMPORTANT : `String.prototype.replace` interprète `$&`, `$1`, `$'`, `` $` ``
        // dans la valeur de remplacement comme des métacaractères. Un `newVal`
        // fourni par le LLM peut donc, involontairement ou malicieusement, contenir
        // ces séquences et produire une substitution SILENCIEUSEMENT fausse
        // (ex: `$&` duplique la valeur matchée). On double chaque `$` littéral
        // pour le neutraliser → `$$` est interprété comme un `$` simple.
        var compiledSubs = [];
        for (var si = 0; si < subs.length; si++) {
            var oldVal = subs[si] && subs[si].old;
            var newVal = (subs[si] && subs[si]['new']) || '';
            if (!oldVal) continue;
            var escaped = String(oldVal).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
            var safeNewVal = String(newVal).replace(/\$/g, '$$$$');
            compiledSubs.push({
                re: new RegExp('\\b' + escaped + '\\b', 'gi'),
                reBare: new RegExp(escaped, 'gi'),  // no word boundary — for SQL detection
                newVal: safeNewVal
            });
        }

        var replaceAll = function(str) {
            if (!str) return str;
            var s = String(str);
            for (var i = 0; i < compiledSubs.length; i++) {
                s = s.replace(compiledSubs[i].re, compiledSubs[i].newVal);
            }
            return s;
        };

        var replaceAllBare = function(str) {
            if (!str) return str;
            var s = String(str);
            for (var i = 0; i < compiledSubs.length; i++) {
                s = s.replace(compiledSubs[i].reBare, compiledSubs[i].newVal);
            }
            return s;
        };

        // Check: do any substitutions appear in the source cells' SQL?
        // If yes, numeric values from those cells cannot be trusted (silent data corruption risk)
        // and must be recomputed.
        var subsAffectSQL = (function() {
            if (compiledSubs.length === 0) return false;
            var det = sourceGrid._cellDetails || {};
            for (var key in det) {
                if (!det.hasOwnProperty(key)) continue;
                var sqlText = det[key] && det[key].sql;
                if (!sqlText) continue;
                for (var i = 0; i < compiledSubs.length; i++) {
                    compiledSubs[i].reBare.lastIndex = 0;  // reset regex state
                    if (compiledSubs[i].reBare.test(sqlText)) return true;
                }
            }
            return false;
        })();

        // Ensure grid has enough rows to accommodate the source
        while (this.allRows.length < sourceGrid.allRows.length && this.allRows.length < 500) {
            var newRow = [];
            for (var x = 0; x < this.columns.length; x++) newRow.push('');
            this.allRows.push(newRow);
        }
        this.displayRows = this.allRows.slice();
        this.totalRowCount = this.allRows.length;

        var count = 0;
        var numericCopied = 0;
        var numericSkipped = 0;

        for (var r = 0; r < sourceGrid.allRows.length && r < this.allRows.length; r++) {
            for (var c = 0; c < sourceGrid.columns.length && c < this.columns.length; c++) {
                var srcVal = sourceGrid.isArrayFormat
                    ? sourceGrid.allRows[r][c]
                    : sourceGrid.allRows[r][sourceGrid.columns[c]];
                if (srcVal === null || srcVal === undefined || !String(srcVal).trim()) continue;

                // Skip if destination cell already has data
                var myVal = this.isArrayFormat
                    ? this.allRows[r][c]
                    : this.allRows[r][this.columns[c]];
                if (myVal && String(myVal).trim()) continue;

                var sVal = String(srcVal);
                var isNumeric = !isNaN(Number(sVal)) && isFinite(Number(sVal));
                var srcKey = r + ',' + c;
                var srcDetail = sourceGrid._cellDetails ? sourceGrid._cellDetails[srcKey] : null;

                if (isNumeric) {
                    if (subsAffectSQL) {
                        // Substitutions change the SQL context → value is stale.
                        // Leave blank so auto-fill recomputes with the substituted SQL.
                        numericSkipped++;
                        continue;
                    }
                    // Substitutions are cosmetic (don't touch SQL) — or substitutions=[].
                    // Copy the value AND its drill-down detail as-is.
                    var ghostCopy = {
                        value: sVal,
                        detail: null,
                        label: srcDetail ? (srcDetail.label || srcDetail.description || null) : null,
                        match: srcDetail ? (srcDetail.match || null) : null
                    };
                    if (srcDetail && srcDetail.columns && srcDetail.rows) {
                        ghostCopy.detail = {
                            sql: srcDetail.sql || '',
                            columns: srcDetail.columns,
                            rows: srcDetail.rows,
                            row_count: srcDetail.row_count || srcDetail.rows.length,
                            description: srcDetail.description || ''
                        };
                    }
                    this._ghostValues[r + ',' + c] = ghostCopy;
                    numericCopied++;
                } else {
                    // Text cell: apply substitution. Keep any sibling detail (sql may carry
                    // useful context for drill-down) — the SQL is left untouched on the
                    // "subst cosmetic" path (subsAffectSQL=false). On the "subst SQL" path,
                    // apply the substitution to the SQL so drill-downs stay coherent.
                    var txtGhost = {
                        value: replaceAll(sVal),
                        detail: null,
                        label: srcDetail ? (srcDetail.label || srcDetail.description || null) : null,
                        match: srcDetail ? (srcDetail.match || null) : null
                    };
                    if (srcDetail && srcDetail.columns && srcDetail.rows) {
                        txtGhost.detail = {
                            sql: subsAffectSQL ? replaceAllBare(srcDetail.sql || '') : (srcDetail.sql || ''),
                            columns: srcDetail.columns,
                            rows: srcDetail.rows,
                            row_count: srcDetail.row_count || srcDetail.rows.length,
                            description: srcDetail.description || ''
                        };
                    }
                    this._ghostValues[r + ',' + c] = txtGhost;
                }
                count++;
            }
        }

        // Appliquer les valeurs piochées par le backend dans value_source_tabs
        // (lookup multi-onglets). Ces cellules ne sont ajoutées qu'aux positions
        // qui sont ENCORE vides après le clone structurel (pas d'écrasement).
        var reusedCount = 0;
        var reusedCells = Array.isArray(result.reused_cells) ? result.reused_cells : [];
        for (var rc = 0; rc < reusedCells.length; rc++) {
            var rCell = reusedCells[rc];
            if (rCell.value === null || rCell.value === undefined || rCell.value === '') continue;
            var rRow = (typeof rCell.row === 'number' ? rCell.row : parseInt(rCell.row, 10)) - 1;
            var rCol;
            if (typeof rCell.col === 'number') {
                rCol = rCell.col;
            } else {
                rCol = this.columns.indexOf(rCell.col);
                if (rCol === -1) {
                    var rParsed = parseInt(rCell.col, 10);
                    rCol = isNaN(rParsed) ? -1 : rParsed;
                }
            }
            if (rRow < 0 || rCol < 0 || rCol >= this.columns.length) continue;
            // Agrandir si besoin (dans la limite de 500 lignes)
            while (rRow >= this.allRows.length && this.allRows.length < 500) {
                var rNew = [];
                for (var rx = 0; rx < this.columns.length; rx++) rNew.push('');
                this.allRows.push(rNew);
            }
            if (rRow >= this.allRows.length) continue;
            // Ne pas écraser une cellule déjà remplie (ni en valeur réelle, ni en ghost)
            var rExisting = this.isArrayFormat
                ? this.allRows[rRow][rCol]
                : this.allRows[rRow][this.columns[rCol]];
            if (rExisting && String(rExisting).trim()) continue;
            if (this._ghostValues && this._ghostValues[rRow + ',' + rCol]) continue;
            this._ghostValues[rRow + ',' + rCol] = {
                value: rCell.value,
                detail: null,
                label: rCell.label || null,
                match: rCell.match || null
            };
            reusedCount++;
        }
        this.displayRows = this.allRows.slice();
        this.totalRowCount = this.allRows.length;

        if (count > 0 || reusedCount > 0) {
            // Ne bloquer l'auto-fill que quand tout est déjà clone-copié et qu'il
            // n'y a rien à recalculer. Si des valeurs doivent être recalculées
            // (substitutions affectant le SQL) ou si des cellules restent vides
            // après lookup, on laisse l'auto-fill se relancer.
            if (numericSkipped === 0 && reusedCount === 0) {
                this._autoFillCompleted = true;
            } else {
                this._autoFillCompleted = false;
                this._lastAutoFillHash = null;
            }
            this._rebuildBody();
            var srcLabel = sourceGrid._options ? sourceGrid._options.tabLabel : ('onglet ' + sourceIdx);
            var msg = count + ' cellule' + (count > 1 ? 's' : '') + ' clonée' + (count > 1 ? 's' : '') +
                ' depuis "' + (srcLabel || 'source') + '"';
            if (reusedCount > 0) {
                msg += ' + ' + reusedCount + ' valeur' + (reusedCount > 1 ? 's' : '') +
                    ' récupérée' + (reusedCount > 1 ? 's' : '') + ' des autres onglets';
            }
            if (numericCopied > 0 && numericSkipped === 0 && compiledSubs.length === 0 && reusedCount === 0) {
                msg += ' (transfert complet — source identique au besoin)';
            } else if (numericCopied > 0 && numericSkipped === 0 && reusedCount === 0) {
                msg += ' (substitutions cosmétiques — valeurs copiées)';
            } else if (numericSkipped > 0) {
                msg += ' (' + numericSkipped + ' valeur' + (numericSkipped > 1 ? 's' : '') +
                    ' à recalculer via auto-fill)';
            }
            // Métriques backend (durée totale) si fournies
            var metrics = result.metrics || {};
            if (metrics.total_ms) {
                msg += ' · ' + (metrics.total_ms / 1000).toFixed(1) + 's';
            }
            msg += ' — Tab pour accepter, Échap pour ignorer';
            if (this._copilotStatus) {
                this._copilotStatus.textContent = msg;
                this._copilotStatus.className = 'grid-copilot-status success';
            }
        } else {
            // Aucune cellule écrite — toast visible (pas juste un micro-message
            // dans la barre copilot) pour que l'utilisateur comprenne que la
            // requête n'a rien produit. Cas typiques :
            //  - source vide
            //  - cible déjà intégralement remplie
            //  - excludes trop restrictifs
            //  - value_source_tabs vide
            var nothingMsg = 'Rien à cloner — la feuille source est vide ou la cible est déjà remplie';
            if (this._copilotStatus) {
                this._copilotStatus.textContent = nothingMsg;
                this._copilotStatus.className = 'grid-copilot-status';
            }
            if (typeof this._showSaveToast === 'function') {
                this._showSaveToast(nothingMsg, true);
            }
        }

        // Warnings backend (ex: "le plan a confondu source_tabs et value_source_tabs",
        // "new_tab forcé automatiquement", "exclusions n'ont rien éliminé")
        // → afficher en secondaire pour que l'utilisateur comprenne les écarts
        // entre ce qu'il a demandé et ce qui a été fait.
        var warnings = Array.isArray(result.warnings) ? result.warnings : [];
        if (warnings.length > 0) {
            if (this._copilotStatus) {
                // On affiche le premier warning en plus du message de succès (les suivants
                // restent dans la réponse JSON pour un éventuel panneau détaillé futur).
                var primaryWarning = warnings[0];
                var prev = this._copilotStatus.textContent;
                this._copilotStatus.textContent = prev + ' ⚠ ' + primaryWarning;
            }
            // Toast pour rendre le warning visible même si la barre a été masquée
            if (typeof this._showSaveToast === 'function') {
                this._showSaveToast('⚠ ' + warnings[0], false);
            }
        }
    };

    SqlResultGrid.prototype._applyGhostToCell = function(td, ghost) {
        var ghn = Number(ghost.value);
        var formattedValue = (!isNaN(ghn) && isFinite(ghn)) ? formatNumber(ghn) : String(ghost.value);
        var isValue = !!(ghost.match || ghost.label || ghost.detail);

        var displayText = formattedValue;
        var tooltipText = formattedValue;

        if (isValue) {
            var ghostLabel = this.__buildGhostLabel(ghost);
            if (ghostLabel) {
                displayText = ghostLabel.short;
                tooltipText = formattedValue + ' — ' + ghostLabel.long;
            }
        }

        td.textContent = displayText;
        td.setAttribute('title', tooltipText);
        td.classList.add('grid-cell-ghost');
        td.classList.add(isValue ? 'grid-cell-ghost-value' : 'grid-cell-ghost-label');
    };

    SqlResultGrid.prototype._renderGhosts = function() {
        for (var key in this._ghostValues) {
            var parts = key.split(',');
            var td = this.tbodyEl.querySelector(
                'td[data-row="' + parts[0] + '"][data-col="' + parts[1] + '"]'
            );
            if (td && !td.textContent.trim() && !td.querySelector('input')) {
                this._applyGhostToCell(td, this._ghostValues[key]);
            }
        }
    };

    // Build a human-readable label from ghost match/label
    // Returns { short: "BILAN · 2023/2024", long: "lfaCodeStatistique:BILAN · exercice:2023/2024" }
    SqlResultGrid.prototype.__buildGhostLabel = function(ghost) {
        // 1. Use LLM-provided label if available
        if (ghost.label && String(ghost.label).trim()) {
            return { short: String(ghost.label).trim(), long: String(ghost.label).trim() };
        }
        // 2. Build from match keys (dimension values)
        if (ghost.match && typeof ghost.match === 'object') {
            var shortParts = [];
            var longParts = [];
            for (var k in ghost.match) {
                var v = ghost.match[k];
                if (v !== null && v !== undefined && String(v).trim()) {
                    shortParts.push(String(v).trim());
                    longParts.push(k + ':' + String(v).trim());
                }
            }
            if (shortParts.length > 0) {
                return { short: shortParts.join(' · '), long: longParts.join(' · ') };
            }
        }
        // 3. No label available (fill type or no match) → null (show raw value)
        return null;
    };

    SqlResultGrid.prototype._acceptGhosts = function() {
        if (Object.keys(this._ghostValues).length === 0) return;
        this._history.push(this._captureState());
        var count = 0, detailCount = 0;
        for (var key in this._ghostValues) {
            var ghost = this._ghostValues[key];
            var parts = key.split(',');
            var rowIdx = parseInt(parts[0], 10);
            var colIdx = parseInt(parts[1], 10);
            while (rowIdx >= this.allRows.length && this.allRows.length < 500) {
                var newRow = [];
                for (var x = 0; x < this.columns.length; x++) newRow.push('');
                this.allRows.push(newRow);
            }
            if (rowIdx < this.allRows.length) {
                if (this.isArrayFormat) {
                    this.allRows[rowIdx][colIdx] = ghost.value;
                } else {
                    this.allRows[rowIdx][this.columns[colIdx]] = ghost.value;
                }
                count++;
                if (ghost.detail && ghost.detail.columns && ghost.detail.rows) {
                    this._cellDetails[key] = {
                        sql: ghost.detail.sql || '',
                        columns: ghost.detail.columns,
                        rows: ghost.detail.rows,
                        row_count: ghost.detail.row_count || ghost.detail.rows.length,
                        description: ghost.detail.description || '',
                        match: ghost.match || null,
                        label: ghost.label || null
                    };
                    detailCount++;
                }
            }
        }
        this._ghostValues = {};
        this.displayRows = this.allRows.slice();
        this.totalRowCount = this.allRows.length;
        this._detectTypes();
        this._rebuildBody();
        this._updateHeaderInfo();

        // Check if there are still empty cells → allow re-trigger for progressive fill
        var emptyCells = 0;
        for (var er = 0; er < this.allRows.length && emptyCells === 0; er++) {
            for (var ec = 0; ec < this.columns.length; ec++) {
                var ev = this.isArrayFormat ? this.allRows[er][ec] : this.allRows[er][this.columns[ec]];
                if (!ev || !String(ev).trim()) { emptyCells++; break; }
            }
        }
        if (emptyCells > 0) {
            // Still empty cells → allow one more auto-fill round
            this._autoFillCompleted = false;
            this._lastAutoFillHash = null;  // force re-trigger
        } else {
            this._autoFillCompleted = true;
        }

        if (this._copilotStatus) {
            var msg = count + ' cellule' + (count > 1 ? 's' : '') + ' remplie' + (count > 1 ? 's' : '');
            if (detailCount > 0) msg += ' (' + detailCount + ' avec détails)';
            if (emptyCells > 0) msg += ' — suggestions suivantes en cours…';
            this._copilotStatus.textContent = msg;
            this._copilotStatus.className = 'grid-copilot-status success';
            var self = this;
            setTimeout(function() {
                if (self._copilotStatus.className.indexOf('success') !== -1)
                    self._copilotStatus.textContent = '';
            }, 4000);
        }
    };

    // Accept only ghosts in selected cells, dismiss the rest
    SqlResultGrid.prototype._acceptSelectedGhosts = function() {
        if (Object.keys(this._ghostValues).length === 0) return;
        if (!this._selectedCells || this._selectedCells.length === 0) return;

        // Build set of selected cell keys
        var selectedKeys = {};
        for (var i = 0; i < this._selectedCells.length; i++) {
            var td = this._selectedCells[i];
            var r = td.getAttribute('data-row');
            var c = td.getAttribute('data-col');
            if (r !== null && c !== null) selectedKeys[r + ',' + c] = true;
        }

        // Split ghosts: keep selected, dismiss rest
        var toAccept = {};
        var toDismiss = {};
        for (var key in this._ghostValues) {
            if (selectedKeys[key]) {
                toAccept[key] = this._ghostValues[key];
            } else {
                toDismiss[key] = this._ghostValues[key];
            }
        }

        if (Object.keys(toAccept).length === 0) {
            // No ghosts in selected cells — do nothing
            return;
        }

        // Accept selected ghosts
        this._history.push(this._captureState());
        var count = 0, detailCount = 0;
        for (var key in toAccept) {
            var ghost = toAccept[key];
            var parts = key.split(',');
            var rowIdx = parseInt(parts[0], 10);
            var colIdx = parseInt(parts[1], 10);

            while (rowIdx >= this.allRows.length && this.allRows.length < 500) {
                var newRow = [];
                for (var x = 0; x < this.columns.length; x++) newRow.push('');
                this.allRows.push(newRow);
            }

            if (rowIdx < this.allRows.length) {
                if (this.isArrayFormat) {
                    this.allRows[rowIdx][colIdx] = ghost.value;
                } else {
                    this.allRows[rowIdx][this.columns[colIdx]] = ghost.value;
                }
                count++;

                if (ghost.detail && ghost.detail.columns && ghost.detail.rows) {
                    this._cellDetails[key] = {
                        sql: ghost.detail.sql || '',
                        columns: ghost.detail.columns,
                        rows: ghost.detail.rows,
                        row_count: ghost.detail.row_count || ghost.detail.rows.length,
                        description: ghost.detail.description || '',
                        match: ghost.match || null,
                        label: ghost.label || null
                    };
                    detailCount++;
                }
            }
        }

        // Keep only non-accepted ghosts
        this._ghostValues = toDismiss;

        // If no ghosts left, mark auto-fill as completed
        if (Object.keys(this._ghostValues).length === 0) {
            this._autoFillCompleted = true;
        }

        // Rebuild
        this.displayRows = this.allRows.slice();
        this.totalRowCount = this.allRows.length;
        this._detectTypes();
        this._rebuildBody();
        this._updateHeaderInfo();
        this._clearSelection();

        if (this._copilotStatus) {
            var remaining = Object.keys(this._ghostValues).length;
            var msg = count + ' suggestion' + (count > 1 ? 's' : '') + ' acceptée' + (count > 1 ? 's' : '');
            if (detailCount > 0) msg += ' (' + detailCount + ' avec détails)';
            if (remaining > 0) msg += ' — ' + remaining + ' restante' + (remaining > 1 ? 's' : '');
            this._copilotStatus.textContent = msg;
            this._copilotStatus.className = 'grid-copilot-status success';
            var self = this;
            setTimeout(function() {
                if (self._copilotStatus.className.indexOf('success') !== -1) {
                    if (Object.keys(self._ghostValues).length > 0) {
                        self._copilotStatus.textContent = Object.keys(self._ghostValues).length + ' suggestion(s) — Tab pour accepter, Échap pour ignorer';
                        self._copilotStatus.className = 'grid-copilot-status';
                    } else {
                        self._copilotStatus.textContent = '';
                    }
                }
            }, 3000);
        }
    };

    SqlResultGrid.prototype._dismissGhosts = function() {
        if (Object.keys(this._ghostValues).length === 0) return;
        this._ghostValues = {};
        var ghostCells = this.tbodyEl.querySelectorAll('.grid-cell-ghost');
        for (var i = 0; i < ghostCells.length; i++) {
            if (ghostCells[i].querySelector('input')) continue;
            ghostCells[i].textContent = '';
            ghostCells[i].removeAttribute('title');
            ghostCells[i].classList.remove('grid-cell-ghost', 'grid-cell-ghost-label', 'grid-cell-ghost-value');
        }
        if (this._copilotStatus) this._copilotStatus.textContent = '';
    };

    // ── end auto-fill ghost ─────────────────────────────────────

    SqlResultGrid.prototype._applyDisplayAction = function(action) {
        switch (action.action) {
            case 'hide_column':
                var hideIdx = this.columns.indexOf(action.column);
                if (hideIdx !== -1) this.hiddenCols.add(hideIdx);
                this._rebuildThead();
                this._rebuildBody();
                this._updateHeaderInfo();
                break;

            case 'show_column':
                var showIdx = this.columns.indexOf(action.column);
                if (showIdx !== -1) this.hiddenCols.delete(showIdx);
                this._rebuildThead();
                this._rebuildBody();
                this._updateHeaderInfo();
                break;

            case 'sort':
                var sortIdx = this.columns.indexOf(action.column);
                if (sortIdx !== -1) {
                    this.sortColIndex = sortIdx;
                    this.sortDirection = action.direction || 'asc';
                    this._refreshView();
                    this._updateSortIndicators();
                }
                break;

            case 'rename_column':
                var renIdx = this.columns.indexOf(action.column);
                if (renIdx !== -1) {
                    this.columns[renIdx] = action.new_name;
                    this._rebuildThead();
                }
                break;
        }
    };

    // ── Sort ──

    SqlResultGrid.prototype._onHeaderClick = function(colIndex) {
        // Silent no-op si le tri n'est pas supporté (feuille blank/dashboard,
        // fusions présentes). Plus de toast intrusif — l'arrow de tri est
        // caché dans ces contextes, l'user ne s'attend pas à un feedback.
        if (!this._sheetSupports('sort')) return;
        this._pushHistory();
        if (this.sortColIndex === colIndex) {
            if (this.sortDirection === 'asc') {
                this.sortDirection = 'desc';
            } else if (this.sortDirection === 'desc') {
                this.sortColIndex = -1;
                this.sortDirection = null;
            }
        } else {
            this.sortColIndex = colIndex;
            this.sortDirection = 'asc';
        }

        this._refreshView();
        this._updateSortIndicators();
    };

    SqlResultGrid.prototype._showLayoutLockedMessage = function(action) {
        var msg = (action || 'Action') + ' impossible : des cellules fusionnées sont présentes. '
            + 'Utilisez « Retirer les fusions » pour la débloquer.';
        if (typeof window !== 'undefined' && typeof window.alert === 'function') {
            window.alert(msg);
        } else {
            try { console.warn(msg); } catch (e) {}
        }
    };

    SqlResultGrid.prototype._applySort = function() {
        if (this.sortColIndex < 0 || !this.sortDirection) return;

        var colIndex = this.sortColIndex;
        var colName = this.columns[colIndex];
        var type = this.columnTypes[colIndex];
        var isArr = this.isArrayFormat;
        var dir = this.sortDirection === 'asc' ? 1 : -1;

        this.displayRows.sort(function(a, b) {
            var va = isArr ? a[colIndex] : a[colName];
            var vb = isArr ? b[colIndex] : b[colName];
            return dir * compareValues(va, vb, type);
        });
    };

    SqlResultGrid.prototype._updateSortIndicators = function() {
        if (!this.theadEl) return;
        var ths = this.theadEl.querySelectorAll('.grid-sortable-th');
        for (var i = 0; i < ths.length; i++) {
            var th = ths[i];
            var arrow = th.querySelector('.grid-sort-arrow');
            var idx = parseInt(th.getAttribute('data-col'), 10);
            th.classList.remove('grid-sorted-asc', 'grid-sorted-desc');
            if (idx === this.sortColIndex && this.sortDirection) {
                th.classList.add(this.sortDirection === 'asc' ? 'grid-sorted-asc' : 'grid-sorted-desc');
                arrow.textContent = this.sortDirection === 'asc' ? ' ▲' : ' ▼';
            } else {
                arrow.textContent = '';
            }
        }
    };

    // ── Value helper ──

    SqlResultGrid.prototype._getVal = function(row, colIndex) {
        return this.isArrayFormat ? row[colIndex] : row[this.columns[colIndex]];
    };

    // ── Filters ──

    SqlResultGrid.prototype._collectDistinct = function(colIndex, limit) {
        limit = limit || 500;
        var vals = new Map(); // displayValue → count
        var hasNull = false;
        for (var i = 0; i < this.allRows.length; i++) {
            var v = this._getVal(this.allRows[i], colIndex);
            if (v == null) { hasNull = true; continue; }
            var s = String(v);
            vals.set(s, (vals.get(s) || 0) + 1);
            if (vals.size >= limit) break;
        }
        var sorted = Array.from(vals.keys()).sort(function(a, b) {
            return a.localeCompare(b, 'fr', { sensitivity: 'base' });
        });
        return { values: sorted, counts: vals, hasNull: hasNull };
    };

    // #46 (suite GRID-2) — collecteur de valeurs distinctes FILTRÉ par une
    // sous-chaîne (insensible à la casse). Sert au popup de filtre sur colonne à
    // forte cardinalité : la liste statique est cappée aux 500 premières valeurs,
    // donc la recherche doit pouvoir RETROUVER une valeur au-delà en re-scannant
    // tout. Même balayage O(N) que _collectDistinct, mais ne retient que les
    // valeurs contenant `query`. `limit` borne le nombre de correspondances
    // distinctes (perf : on n'affiche pas 10 000 cases). `truncated` signale au
    // popup que la recherche elle-même a atteint le cap → « affinez ».
    SqlResultGrid.prototype._collectDistinctMatching = function(colIndex, query, limit) {
        limit = limit || 500;
        var q = String(query == null ? '' : query).toLowerCase();
        var vals = new Map();
        var hasNull = false;
        var truncated = false;
        for (var i = 0; i < this.allRows.length; i++) {
            var v = this._getVal(this.allRows[i], colIndex);
            if (v == null) { hasNull = true; continue; }
            var s = String(v);
            if (q !== '' && s.toLowerCase().indexOf(q) === -1) continue;
            if (!vals.has(s)) {
                if (vals.size >= limit) { truncated = true; continue; }
                vals.set(s, 0);
            }
            vals.set(s, vals.get(s) + 1);
        }
        var sorted = Array.from(vals.keys()).sort(function(a, b) {
            return a.localeCompare(b, 'fr', { sensitivity: 'base' });
        });
        return { values: sorted, counts: vals, hasNull: hasNull, truncated: truncated };
    };

    SqlResultGrid.prototype._applyFilters = function() {
        var self = this;
        var filterKeys = Object.keys(this.filters);
        if (filterKeys.length === 0) {
            this.displayRows = this.allRows.slice();
        } else {
            this.displayRows = this.allRows.filter(function(row) {
                for (var k = 0; k < filterKeys.length; k++) {
                    var ci = parseInt(filterKeys[k], 10);
                    var f = self.filters[ci];
                    var v = self._getVal(row, ci);
                    if (v == null) {
                        if (f.excludeNull) return false;
                    } else {
                        if (f.excluded && f.excluded.has(String(v))) return false;
                    }
                }
                return true;
            });
        }
    };

    SqlResultGrid.prototype._refreshView = function() {
        this._applyFilters();
        this._applySort();
        // La sélection est indexée par POSITION dans displayRows. Réordonner
        // (tri) ou réduire (filtre) displayRows invalide les keys d'une sélection
        // PARTIELLE (elles pointeraient d'autres lignes → Σ FAUSSE silencieuse,
        // Q5 — review adversariale). Donc :
        //   - colonne ENTIÈRE (_entireColumnSelected) : on RE-DÉRIVE les keys sur
        //     la nouvelle vue → toujours toute la colonne → Σ correcte ;
        //   - sélection partielle : on CLEAR (fail-closed) — jamais de Σ sur des
        //     lignes que l'utilisateur n'a pas choisies.
        if (this._entireColumnSelected !== null && this._entireColumnSelected !== undefined) {
            var ec = this._entireColumnSelected;
            this._selectedKeys = new Set();
            var nn = this.displayRows ? this.displayRows.length : 0;
            for (var rr = 0; rr < nn; rr++) {
                this._selectedKeys.add(rr + ',' + ec);
            }
            // (le rebuild ci-dessous re-surligne + recalcule le résumé)
        } else if (this._selectedKeys && this._selectedKeys.size > 0) {
            this._clearSelection();
        }
        this._rebuildBody();
        this._updateHeaderInfo();
        this._updateFilterIndicators();
    };

    SqlResultGrid.prototype._updateFilterIndicators = function() {
        if (!this.theadEl) return;
        var hasAny = Object.keys(this.filters).length > 0;
        var ths = this.theadEl.querySelectorAll('.grid-sortable-th');
        for (var i = 0; i < ths.length; i++) {
            var idx = parseInt(ths[i].getAttribute('data-col'), 10);
            if (this.filters[idx]) {
                ths[i].classList.add('grid-filtered');
            } else {
                ths[i].classList.remove('grid-filtered');
            }
        }
        if (this.btnClearFilters) {
            this.btnClearFilters.style.display = hasAny ? '' : 'none';
        }
    };

    SqlResultGrid.prototype._clearAllFilters = function() {
        if (!this.filters || Object.keys(this.filters).length === 0) return;
        this._pushHistory();
        this.filters = {};
        this._refreshView();
    };

    SqlResultGrid.prototype._filterByValue = function(colIndex, value, exclude) {
        this._pushHistory();
        var f = this.filters[colIndex] || { excluded: new Set(), excludeNull: false };

        if (value == null) {
            if (exclude) {
                f.excludeNull = true;
            } else {
                // Keep only nulls: exclude everything else. GRID-1 — distinct
                // COMPLET (pas le cap 500 réservé au popup) : sinon des valeurs
                // non-null au-delà du cap ne seraient pas exclues → elles
                // passeraient le filtre à tort (donnée silencieusement fausse).
                var d = this._collectDistinct(colIndex, Number.MAX_SAFE_INTEGER);
                f.excluded = new Set(d.values);
                f.excludeNull = false;
            }
        } else {
            var strVal = String(value);
            if (exclude) {
                f.excluded.add(strVal);
            } else {
                // Keep only this value: exclude everything else. GRID-1 — on
                // collecte TOUTES les valeurs distinctes (pas le cap 500 réservé
                // au popup) : sinon les valeurs au-delà du cap ne sont pas
                // exclues → des lignes ≠ X passent le filtre silencieusement.
                var d2 = this._collectDistinct(colIndex, Number.MAX_SAFE_INTEGER);
                f.excluded = new Set(d2.values);
                f.excluded.delete(strVal);
                f.excludeNull = true;
            }
        }

        if (f.excluded.size === 0 && !f.excludeNull) {
            delete this.filters[colIndex];
        } else {
            this.filters[colIndex] = f;
        }
        this._refreshView();
    };

    // ── Filter popup ──

    SqlResultGrid.prototype._openFilterPopup = function(colIndex, anchorEl) {
        // Note : on autorise l'ouverture du popup même avec des merges.
        // Raison : bloquer d'emblée empêchait l'utilisateur d'ANNULER un
        // filtre déjà appliqué — classeur effectivement inutilisable. Le
        // popup sait désactiver sélectivement ses actions mutantes selon
        // ``_canModifyLayout`` (bandeau + disable) ; l'action ``Clear
        // filter`` reste active pour sortir d'un état cassé.
        this._closeFilterPopup();
        var self = this;
        var colName = this.columns[colIndex];
        var currentFilter = this.filters[colIndex];
        // GRID-2 — on probe 501 valeurs distinctes pour DÉTECTER une troncature
        // sans la confondre avec « exactement 500 ». Si >500, on n'affiche que
        // les 500 premières + on AVERTIT (sinon cases manquantes / recherche
        // aveugle, et l'user croit filtrer sur toute la colonne).
        var _distinctProbe = this._collectDistinct(colIndex, 501);
        var _distinctTruncated = _distinctProbe.values.length > 500;
        var distinct = _distinctTruncated
            ? {
                values: _distinctProbe.values.slice(0, 500),
                counts: _distinctProbe.counts,
                hasNull: _distinctProbe.hasNull,
            }
            : _distinctProbe;

        var popup = document.createElement('div');
        popup.className = 'grid-filter-popup';

        // Bandeau warning : quand les actions mutantes ne sont pas
        // supportées (merges actifs, type d'onglet non data-grille),
        // on désactive tri + apply mais on garde "Supprimer le filtre"
        // actif pour permettre à l'utilisateur de sortir d'un état cassé.
        var canMutate = this._sheetSupports('filter_apply');
        if (!canMutate) {
            var warn = document.createElement('div');
            warn.className = 'grid-fp-merge-warn';
            warn.style.cssText =
                'padding:0.4rem 0.6rem;margin:-0.25rem -0.25rem 0.35rem;' +
                'background:rgba(251, 191, 36, 0.12);' +
                'border-left:3px solid rgb(217, 119, 6);' +
                'color:var(--text-primary, #111827);font-size:0.75rem;line-height:1.35;';
            warn.textContent =
                'Tri et nouveau filtre désactivés pour ce type d\'onglet ' +
                '(ou tant que des fusions existent). « Supprimer le filtre » ' +
                'reste possible pour revenir à un état normal.';
            popup.appendChild(warn);
        }

        // Sort links (désactivés si merges — voir bandeau ci-dessus)
        var sortAsc = document.createElement('a');
        sortAsc.className = 'grid-fp-sort-link';
        sortAsc.textContent = '↑ Trier A → Z';
        if (!canMutate) sortAsc.style.cssText = 'opacity:0.4;pointer-events:none;cursor:not-allowed;';
        sortAsc.addEventListener('click', function() {
            if (!canMutate) return;
            self.sortColIndex = colIndex; self.sortDirection = 'asc';
            // Passe par _refreshView (SSoT du tri, comme _onHeaderClick) : applique
            // la logique de sélection (re-dérive colonne entière / clear partielle)
            // sinon une sélection partielle sommerait de mauvaises lignes après tri
            // (review adversariale Q5). _applySort+_rebuildBody en direct la
            // contournait.
            self._refreshView(); self._updateSortIndicators();
            self._closeFilterPopup();
        });
        popup.appendChild(sortAsc);

        var sortDesc = document.createElement('a');
        sortDesc.className = 'grid-fp-sort-link';
        sortDesc.textContent = '↓ Trier Z → A';
        if (!canMutate) sortDesc.style.cssText = 'opacity:0.4;pointer-events:none;cursor:not-allowed;';
        sortDesc.addEventListener('click', function() {
            if (!canMutate) return;
            self.sortColIndex = colIndex; self.sortDirection = 'desc';
            // SSoT du tri (cf. lien « Trier A → Z » ci-dessus + _onHeaderClick).
            self._refreshView(); self._updateSortIndicators();
            self._closeFilterPopup();
        });
        popup.appendChild(sortDesc);

        // Clear filter link
        if (currentFilter) {
            var clearLink = document.createElement('a');
            clearLink.className = 'grid-fp-clear-link';
            clearLink.textContent = '✕ Supprimer le filtre';
            clearLink.addEventListener('click', function() {
                delete self.filters[colIndex];
                self._refreshView();
                self._closeFilterPopup();
            });
            popup.appendChild(clearLink);
        }

        // Separator
        var sep = document.createElement('div');
        sep.className = 'grid-fp-separator';
        popup.appendChild(sep);

        // Search
        var search = document.createElement('input');
        search.type = 'text';
        search.className = 'grid-fp-search';
        search.placeholder = 'Rechercher...';
        popup.appendChild(search);

        if (_distinctTruncated) {
            // GRID-2 — colonne à forte cardinalité : la liste de cases (et la
            // recherche) ne couvre que les 500 premières valeurs. Avertir
            // honnêtement + orienter vers le clic-droit « Filtrer par » sur une
            // cellule (exact et non cappé — cf. GRID-1).
            var truncWarn = document.createElement('div');
            truncWarn.className = 'grid-fp-trunc-warn';
            truncWarn.style.cssText =
                'padding:0.4rem 0.6rem;margin:0.25rem 0;' +
                'background:rgba(251, 191, 36, 0.12);' +
                'border-left:3px solid rgb(217, 119, 6);' +
                'color:var(--text-primary, #111827);font-size:0.72rem;line-height:1.35;';
            truncWarn.textContent =
                'Colonne à forte cardinalité : seules les 500 premières valeurs ' +
                'sont listées. Utilisez la recherche ci-dessous pour retrouver et ' +
                'cocher une valeur au-delà, ou clic-droit sur une cellule → « Filtrer par ».';
            popup.appendChild(truncWarn);
        }

        // Checkbox list
        var listWrap = document.createElement('div');
        listWrap.className = 'grid-fp-list';

        var allItems = []; // { el, value, label }

        // "(Tout sélectionner)" checkbox
        var checkAllLabel = document.createElement('label');
        checkAllLabel.className = 'grid-fp-item grid-fp-item-all';
        var checkAll = document.createElement('input');
        checkAll.type = 'checkbox';
        checkAllLabel.appendChild(checkAll);
        checkAllLabel.appendChild(document.createTextNode(' (Tout sélectionner)'));
        listWrap.appendChild(checkAllLabel);

        // Null item
        if (distinct.hasNull) {
            var nullLabel = document.createElement('label');
            nullLabel.className = 'grid-fp-item';
            var nullCb = document.createElement('input');
            nullCb.type = 'checkbox';
            nullCb.checked = !(currentFilter && currentFilter.excludeNull);
            nullLabel.appendChild(nullCb);
            nullLabel.appendChild(document.createTextNode(' (vide)'));
            listWrap.appendChild(nullLabel);
            allItems.push({ el: nullLabel, cb: nullCb, value: null, label: '(vide)' });
        }

        // Value items
        for (var i = 0; i < distinct.values.length; i++) {
            (function(val) {
                var lbl = document.createElement('label');
                lbl.className = 'grid-fp-item';
                var cb = document.createElement('input');
                cb.type = 'checkbox';
                cb.checked = !(currentFilter && currentFilter.excluded && currentFilter.excluded.has(val));
                lbl.appendChild(cb);
                var displayVal = val === '' ? '(texte vide)' : val;
                if (displayVal.length > 40) displayVal = displayVal.substring(0, 40) + '…';
                lbl.appendChild(document.createTextNode(' ' + displayVal));
                listWrap.appendChild(lbl);
                allItems.push({ el: lbl, cb: cb, value: val, label: displayVal });
            })(distinct.values[i]);
        }

        popup.appendChild(listWrap);

        // Update "select all" state
        function updateCheckAll() {
            var total = 0, checked = 0;
            for (var j = 0; j < allItems.length; j++) {
                if (allItems[j].el.style.display !== 'none') {
                    total++;
                    if (allItems[j].cb.checked) checked++;
                }
            }
            checkAll.checked = total > 0 && checked === total;
            checkAll.indeterminate = checked > 0 && checked < total;
        }
        updateCheckAll();

        checkAll.addEventListener('change', function() {
            var state = checkAll.checked;
            for (var j = 0; j < allItems.length; j++) {
                if (allItems[j].el.style.display !== 'none') {
                    allItems[j].cb.checked = state;
                }
            }
        });

        // #46 (fix revue adversariale) — mémoire vivante de l'état coché des cases
        // DYNAMIQUES (injectées par la recherche). Ces cases sont détruites/recréées
        // à chaque ré-injection (frappe suivante) ; sans mémoire, une valeur que
        // l'utilisateur vient de décocher reviendrait cochée (dérivée du seul
        // currentFilter) → réincluse en silence dans le filtre = donnée FAUSSE.
        // Clé = valeur ; valeur = état coché voulu par l'utilisateur. Vidée quand
        // la recherche est effacée (q==='').
        var dynChecked = new Map();

        // Note de troncature des correspondances de recherche (#46) — créée à la
        // demande quand une recherche ramène plus de valeurs que le cap.
        var searchTruncNote = null;
        function _setSearchTruncNote(show) {
            // Défense : si le popup a été fermé entre-temps (listWrap détaché),
            // ne rien faire — insertBefore sur un parentNode null crasherait.
            if (!listWrap.parentNode) return;
            if (show && !searchTruncNote) {
                searchTruncNote = document.createElement('div');
                searchTruncNote.className = 'grid-fp-search-trunc';
                searchTruncNote.style.cssText =
                    'padding:0.3rem 0.6rem;font-size:0.7rem;line-height:1.3;'
                    + 'color:var(--text-secondary, #6b7280);font-style:italic;';
                searchTruncNote.textContent =
                    'Beaucoup de correspondances — seules les premières sont affichées. Affinez la recherche.';
                listWrap.parentNode.insertBefore(searchTruncNote, listWrap);
            } else if (!show && searchTruncNote) {
                searchTruncNote.parentNode.removeChild(searchTruncNote);
                searchTruncNote = null;
            }
        }

        // Retire les cases injectées dynamiquement par la recherche (#46) → liste
        // canonique (500 premières). À appeler quand la recherche est vidée.
        function _clearDynamicMatches() {
            for (var j = allItems.length - 1; j >= 0; j--) {
                var el = allItems[j].el;
                if (el && el.classList && el.classList.contains('grid-fp-dynamic')) {
                    if (el.parentNode) el.parentNode.removeChild(el);
                    allItems.splice(j, 1);
                }
            }
        }

        // #46 — sur colonne tronquée, injecte les valeurs distinctes (au-delà des
        // 500 listées) qui correspondent à `q`, en cases cochables, pour que la
        // recherche les TROUVE réellement. Dédup vs items déjà présents.
        function _injectMatches(q) {
            _clearDynamicMatches();
            var already = Object.create(null);
            for (var j = 0; j < allItems.length; j++) {
                if (allItems[j].value != null) already[allItems[j].value] = true;
            }
            var matched = self._collectDistinctMatching(colIndex, q, 500);
            for (var i = 0; i < matched.values.length; i++) {
                (function(val) {
                    if (already[val]) return;
                    var lbl = document.createElement('label');
                    lbl.className = 'grid-fp-item grid-fp-dynamic';
                    var cb = document.createElement('input');
                    cb.type = 'checkbox';
                    // État coché : priorité à la mémoire vivante (toggle utilisateur
                    // qui doit survivre aux ré-injections), sinon dérivé du filtre
                    // courant. Sans ça, décocher puis affiner la recherche réincluait
                    // silencieusement la valeur.
                    cb.checked = dynChecked.has(val)
                        ? dynChecked.get(val)
                        : !(currentFilter && currentFilter.excluded && currentFilter.excluded.has(val));
                    cb.addEventListener('change', function() { dynChecked.set(val, cb.checked); });
                    lbl.appendChild(cb);
                    var displayVal = val === '' ? '(texte vide)' : val;
                    if (displayVal.length > 40) displayVal = displayVal.substring(0, 40) + '…';
                    lbl.appendChild(document.createTextNode(' ' + displayVal));
                    listWrap.appendChild(lbl);
                    allItems.push({ el: lbl, cb: cb, value: val, label: displayVal });
                })(matched.values[i]);
            }
            _setSearchTruncNote(matched.truncated);
        }

        // Search filtering
        search.addEventListener('input', function() {
            var q = search.value.trim().toLowerCase();
            // 1) Filtre rapide des items déjà rendus. On matche sur la valeur
            //    COMPLÈTE (pas le label tronqué à 40 car) pour ne pas masquer à
            //    tort une valeur dont le fragment recherché est au-delà du 40e car.
            for (var j = 0; j < allItems.length; j++) {
                var hay = (allItems[j].value != null ? String(allItems[j].value) : allItems[j].label).toLowerCase();
                var show = q === '' || hay.indexOf(q) !== -1;
                allItems[j].el.style.display = show ? '' : 'none';
            }
            // 2) Colonne tronquée : la liste statique n'a que 500 valeurs. On
            //    re-scanne tout (débounce) pour faire apparaître les correspondances
            //    au-delà — sinon la recherche est aveugle au reste de la colonne.
            if (_distinctTruncated) {
                clearTimeout(self._fpSearchTimer);
                if (q === '') {
                    _clearDynamicMatches();
                    dynChecked.clear(); // nouvelle recherche → on repart propre
                    _setSearchTruncNote(false);
                    updateCheckAll();
                } else {
                    self._fpSearchTimer = setTimeout(function() {
                        _injectMatches(q);
                        updateCheckAll();
                    }, 160);
                }
            }
            updateCheckAll();
        });

        // Buttons
        var btnRow = document.createElement('div');
        btnRow.className = 'grid-fp-buttons';

        var btnOk = document.createElement('button');
        btnOk.type = 'button';
        btnOk.className = 'grid-fp-btn-ok';
        btnOk.textContent = 'OK';
        if (!canMutate) {
            btnOk.disabled = true;
            btnOk.title = 'Désactivé tant que des fusions existent';
            btnOk.style.cssText = 'opacity:0.4;cursor:not-allowed;';
        }
        btnOk.addEventListener('click', function() {
            if (!canMutate) return;
            // #46 (fix race débounce↔OK) : une injection de correspondances peut
            // être EN ATTENTE (l'utilisateur a tapé puis cliqué OK avant les 160ms).
            // Si on calcule le filtre maintenant, les valeurs au-delà du cap ne sont
            // pas encore dans allItems → sur colonne tronquée elles seraient TOUTES
            // exclues (0 ligne) ou le mauvais sous-ensemble gardé. On matérialise donc
            // l'injection SYNCHRONEMENT avant tout calcul.
            if (_distinctTruncated && search.value.trim() !== '') {
                clearTimeout(self._fpSearchTimer);
                _injectMatches(search.value.trim().toLowerCase());
            }
            var searchActive = search.value.trim() !== '';
            var excluded = new Set();
            var excludeNull = false;

            if (searchActive) {
                // Recherche active = « ne garder QUE les valeurs cochées visibles » :
                // on EXCLUT tout le reste, puis on ré-inclut les cochées visibles.
                if (_distinctTruncated) {
                    // Colonne tronquée : la liste (même augmentée par la recherche
                    // #46) ne contient PAS toutes les valeurs distinctes. N'exclure
                    // que `allItems` laisserait passer les valeurs non listées → le
                    // filtre « ne garder que X » serait silencieusement FAUX (trappe
                    // GRID-1). On matérialise donc le distinct COMPLET (uncapped),
                    // exactement comme le clic-droit « Filtrer par «X» ».
                    var full = self._collectDistinct(colIndex, Number.MAX_SAFE_INTEGER);
                    for (var fi = 0; fi < full.values.length; fi++) excluded.add(full.values[fi]);
                    if (full.hasNull) excludeNull = true;
                } else {
                    for (var j = 0; j < allItems.length; j++) {
                        if (allItems[j].value == null) excludeNull = true;
                        else excluded.add(allItems[j].value);
                    }
                }
                for (var j = 0; j < allItems.length; j++) {
                    if (allItems[j].el.style.display !== 'none' && allItems[j].cb.checked) {
                        if (allItems[j].value == null) excludeNull = false;
                        else excluded.delete(allItems[j].value);
                    }
                }
            } else {
                // No search: standard — unchecked = excluded
                for (var j = 0; j < allItems.length; j++) {
                    if (!allItems[j].cb.checked) {
                        if (allItems[j].value == null) excludeNull = true;
                        else excluded.add(allItems[j].value);
                    }
                }
            }
            if (excluded.size === 0 && !excludeNull) {
                delete self.filters[colIndex];
            } else {
                self.filters[colIndex] = { excluded: excluded, excludeNull: excludeNull };
            }
            self._refreshView();
            self._closeFilterPopup();
        });
        btnRow.appendChild(btnOk);

        var btnCancel = document.createElement('button');
        btnCancel.type = 'button';
        btnCancel.className = 'grid-fp-btn-cancel';
        btnCancel.textContent = 'Annuler';
        btnCancel.addEventListener('click', function() { self._closeFilterPopup(); });
        btnRow.appendChild(btnCancel);

        popup.appendChild(btnRow);

        // Position popup under the header cell
        var rect = anchorEl.getBoundingClientRect();
        var containerRect = this.container.getBoundingClientRect();
        popup.style.position = 'absolute';
        popup.style.top = (rect.bottom - containerRect.top) + 'px';
        popup.style.left = Math.max(0, rect.left - containerRect.left) + 'px';

        this.container.style.position = 'relative';
        this.container.appendChild(popup);
        this._activePopup = popup;

        // Close on outside click
        var closeOnOutside = function(e) {
            if (!popup.contains(e.target) && !anchorEl.contains(e.target)) {
                self._closeFilterPopup();
                document.removeEventListener('mousedown', closeOnOutside);
            }
        };
        setTimeout(function() { document.addEventListener('mousedown', closeOnOutside); }, 0);
        this._popupOutsideHandler = closeOnOutside;

        search.focus();
    };

    SqlResultGrid.prototype._closeFilterPopup = function() {
        // #46 — annuler le débounce de recherche en vol : sinon il s'exécuterait
        // sur un popup détaché du DOM (insertBefore sur parentNode null → crash).
        clearTimeout(this._fpSearchTimer);
        if (this._activePopup) {
            this._activePopup.remove();
            this._activePopup = null;
        }
        if (this._popupOutsideHandler) {
            document.removeEventListener('mousedown', this._popupOutsideHandler);
            this._popupOutsideHandler = null;
        }
    };

    // ── Export CSV ──

    SqlResultGrid.prototype._exportCSV = function(opts) {
        opts = opts || {};
        // ``opts.columns`` : en-têtes anonymisés renvoyés par le serveur (cas
        // pivot où une colonne EST une valeur métier). Sans cet override, le
        // header CSV reprendrait ``this.columns`` EN CLAIR → fuite (re-review it.11).
        var cols = opts.columns || this.columns;
        // ``opts.rows`` : lignes déjà anonymisées par le serveur
        // (``/api/iris/anonymize-tabs``). Le formatage CSV reste IDENTIQUE au
        // clair (même séparateur ``;``, même BOM) — seules les valeurs changent.
        var rows = opts.rows || this.displayRows;
        var anonymized = !!opts.anonymized;
        // A5-F3 : avertir quand le résultat SQL a été TRONQUÉ côté serveur (cap
        // max_rows) — l'export CSV ne porte alors que sur les lignes chargées,
        // pas sur l'intégralité. Sans ce signal, un user croit exporter tout le
        // résultat (données fausses silencieuses). L'export serveur complet
        // (« Excel — version complète ») reste la voie pour tout récupérer.
        if (this._truncated && typeof window.showToast === 'function') {
            // A5-F3 (adversarial) : signal d'INTÉGRITÉ DONNÉES → toast STICKY
            // ('error', persistant jusqu'au dismiss) et message centré sur le
            // total serveur (pas un compte d'affichage potentiellement filtré).
            window.showToast(
                'Export CSV partiel : le résultat SQL complet compte '
                + (this.totalRowCount || rows.length) + ' lignes mais a été tronqué côté serveur '
                + '(cap d\'affichage). Pour tout exporter, utilisez « Excel — version complète (serveur) ».',
                'error'
            );
        }
        var isArr = this.isArrayFormat;
        var visible = this._getVisibleColIndices();
        var lines = [];

        // Header
        lines.push(visible.map(function(ci) { return csvEscape(cols[ci]); }).join(';'));

        // Rows
        for (var i = 0; i < rows.length; i++) {
            var row = rows[i];
            var cells = [];
            for (var k = 0; k < visible.length; k++) {
                var j = visible[k];
                var val = isArr ? row[j] : row[cols[j]];
                cells.push(csvEscape(val));
            }
            lines.push(cells.join(';'));
        }

        var csv = lines.join('\n');
        var blob = new Blob(['\uFEFF' + csv], { type: 'text/csv;charset=utf-8;' }); // BOM for Excel
        var url = URL.createObjectURL(blob);
        var a = document.createElement('a');
        a.href = url;
        a.download = (anonymized ? 'resultats_anonymise_' : 'resultats_') + Date.now() + '.csv';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    };

    // ── Copy to clipboard ──

    SqlResultGrid.prototype._copyToClipboard = function(btnEl) {
        var cols = this.columns;
        var rows = this.displayRows;
        var isArr = this.isArrayFormat;
        var visible = this._getVisibleColIndices();
        var lines = [];

        // Header
        lines.push(visible.map(function(ci) { return cols[ci]; }).join('\t'));

        // Rows
        for (var i = 0; i < rows.length; i++) {
            var row = rows[i];
            var cells = [];
            for (var k = 0; k < visible.length; k++) {
                var j = visible[k];
                var val = isArr ? row[j] : row[cols[j]];
                cells.push(val == null ? '' : String(val));
            }
            lines.push(cells.join('\t'));
        }

        var tsv = lines.join('\n');
        navigator.clipboard.writeText(tsv).then(function() {
            var origHTML = btnEl.innerHTML;
            btnEl.textContent = '✓';
            setTimeout(function() { btnEl.innerHTML = origHTML; }, 3000);
        }).catch(function() {
            btnEl.textContent = '✗';
            setTimeout(function() { btnEl.innerHTML = '<i class="bi bi-clipboard"></i>'; }, 3000);
        });
    };

    // ── Fullscreen ──

    SqlResultGrid.prototype._toggleFullscreen = function() {
        this.isFullscreen = !this.isFullscreen;
        // Use fullscreenTarget from options (tab manager parent) or fall back to own container
        var target = this._options.fullscreenTarget || this.container;
        if (this.isFullscreen) {
            target.classList.add('grid-fullscreen');
            this.btnFullscreen.textContent = '✕';
            this.btnFullscreen.title = 'Quitter le plein écran (Escape)';
            this._escHandler = this._handleEscape.bind(this);
            this._fullscreenTarget = target;
            document.addEventListener('keydown', this._escHandler);
        } else {
            target.classList.remove('grid-fullscreen');
            this.btnFullscreen.textContent = '⛶';
            this.btnFullscreen.title = 'Plein écran (Escape pour quitter)';
            this._fullscreenTarget = null;
            if (this._escHandler) {
                document.removeEventListener('keydown', this._escHandler);
                this._escHandler = null;
            }
        }
    };

    SqlResultGrid.prototype._handleEscape = function(e) {
        if (e.key === 'Escape' && this.isFullscreen) {
            this._toggleFullscreen();
        }
    };

    // ── Context menu (right-click on cells) ──

    SqlResultGrid.prototype._initContextMenu = function() {
        if (!this.tbodyEl) return;
        var self = this;
        this.tbodyEl.addEventListener('contextmenu', function(e) {
            var td = e.target.closest('td');
            if (!td || td.classList.contains('grid-row-num')) return;
            e.preventDefault();

            // Read row/col from data attributes (correct even with rowspan/colspan)
            var colIndex = parseInt(td.getAttribute('data-col'), 10);
            var rowIndex = parseInt(td.getAttribute('data-row'), 10);
            if (isNaN(colIndex) || isNaN(rowIndex)) return;
            if (rowIndex < 0 || rowIndex >= self.displayRows.length) return;
            if (colIndex < 0 || colIndex >= self.columns.length) return;

            var rawValue = self._getVal(self.displayRows[rowIndex], colIndex);
            self._showContextMenu(e.clientX, e.clientY, colIndex, rowIndex, rawValue);
        });
    };

    SqlResultGrid.prototype._showContextMenu = function(x, y, colIndex, rowIndex, value) {
        this._closeContextMenu();
        var self = this;
        var menu = document.createElement('div');
        menu.className = 'grid-context-menu';

        function addItem(label, callback, icon) {
            var item = document.createElement('div');
            item.className = 'grid-ctx-item';
            item.innerHTML = (icon || '') + ' ' + _escHtml(label);
            item.addEventListener('click', function() {
                callback();
                self._closeContextMenu();
            });
            menu.appendChild(item);
        }

        function addDisabledItem(label, icon) {
            var item = document.createElement('div');
            item.className = 'grid-ctx-item grid-ctx-disabled';
            item.innerHTML = (icon || '') + ' ' + _escHtml(label);
            menu.appendChild(item);
        }

        function addSep() {
            var sep = document.createElement('div');
            sep.className = 'grid-ctx-separator';
            menu.appendChild(sep);
        }

        var displayVal = value == null ? 'null' : String(value);
        var shortVal = displayVal.length > 25 ? displayVal.substring(0, 25) + '…' : displayVal;
        var sourceCellKey = rowIndex + ',' + colIndex;

        // ── Section 0 : Confidentialité (intégrée 2026-05-15) ──
        // Avant : un 2e menu standalone ``_showAnonContextMenu`` se
        // superposait visuellement au menu principal sur le même
        // right-click → 2 menus à la même position. Maintenant on
        // intègre la section "Confidentialité" comme 1ère section ici.
        // Logique de tokenisation alignée sur l'ancien
        // ``_attachAnonContextMenu`` (raw value > textContent).
        var anonTokens = [];
        if (typeof self._anonTokenize === 'function') {
            if (typeof value === 'number' && isFinite(value)) {
                // Cellule numérique : un seul "token" = la valeur canonique.
                var canon = String(value);
                if (canon.length >= 2) anonTokens.push(canon);
            } else if (typeof value === 'string' && value) {
                anonTokens = self._anonTokenize(value);
            } else if (value != null) {
                anonTokens = self._anonTokenize(String(value));
            }
        }
        // Dédup tokens (l'utilisateur n'a pas besoin de voir 2× le même).
        var anonSeen = Object.create(null);
        var anonUniq = [];
        for (var ai = 0; ai < anonTokens.length; ai++) {
            if (!anonSeen[anonTokens[ai]]) {
                anonSeen[anonTokens[ai]] = 1;
                anonUniq.push(anonTokens[ai]);
            }
        }
        if (anonUniq.length > 0 && typeof self._toggleAnonTerm === 'function') {
            // Header section (style inline pour rester self-contained, pas
            // besoin d'ajouter une classe CSS .grid-ctx-header dans iris-grid.css).
            var anonHdr = document.createElement('div');
            anonHdr.className = 'grid-ctx-section-header';
            anonHdr.style.cssText = 'padding:0.3rem 0.75rem;font-size:0.6875rem;font-weight:600;color:var(--text-muted,#6b7280);text-transform:uppercase;letter-spacing:0.05em;';
            anonHdr.textContent = 'Confidentialité';
            menu.appendChild(anonHdr);
            anonUniq.forEach(function(tok) {
                var state = (self._anonymizationState && self._anonymizationState.terms) || {};
                var existing = state[tok];
                var label = (existing && existing.enabled)
                    ? 'Ne plus anonymiser « ' + tok + ' »'
                    : 'Anonymiser « ' + tok + ' »';
                addItem(label, function() {
                    self._toggleAnonTerm(tok);
                });
            });
            if (typeof self._openAnonymizationPanel === 'function') {
                addItem('Gérer la liste complète…', function() {
                    self._openAnonymizationPanel();
                });
            }
            addSep();
        }

        // ── Section 1: Clipboard ──
        addItem('Copier « ' + shortVal + ' »', function() {
            // Single-cell copy via context menu → store as 1×1 clipboard
            var textVal = value == null ? '' : String(value);
            navigator.clipboard.writeText(textVal).catch(function() {});
            SqlResultGrid._clearClipboardAnts();

            var details = self._cellDetails[sourceCellKey] || null;
            var drilldownCtx = null;
            if (!details && self._isDrillable(colIndex) && self.sql) {
                var row = self.displayRows[rowIndex];
                var rowValues = {};
                for (var ci = 0; ci < self.columns.length; ci++) {
                    var v = self.isArrayFormat ? row[ci] : row[self.columns[ci]];
                    rowValues[self.columns[ci]] = v;
                }
                drilldownCtx = { original_sql: self.sql, col_index: colIndex, row_values: rowValues };
            }
            SqlResultGrid._clipboard = {
                cells: [[{ value: textVal, details: details, drilldownCtx: drilldownCtx }]],
                rows: 1, cols: 1, tsv: textVal
            };

            // Marching ants on the copied cell
            var td = self.tbodyEl.querySelector('td[data-row="' + rowIndex + '"][data-col="' + colIndex + '"]');
            if (td) { td.classList.add('grid-cell-clipboard'); SqlResultGrid._clipboardAnts = [td]; }
        });

        addItem('Copier la ligne', function() {
            var row = self.displayRows[rowIndex];
            var parts = [];
            for (var j = 0; j < self.columns.length; j++) {
                var v = self._getVal(row, j);
                parts.push(v == null ? '' : String(v));
            }
            navigator.clipboard.writeText(parts.join('\t')).catch(function() {});
        });

        // Paste (supports single and multi-cell)
        var clip = SqlResultGrid._clipboard;
        if (clip) {
            var pasteLabel = clip.rows === 1 && clip.cols === 1
                ? 'Coller « ' + (clip.cells[0][0].value.length > 20 ? clip.cells[0][0].value.substring(0, 20) + '…' : clip.cells[0][0].value) + ' »'
                : 'Coller (' + clip.rows + '×' + clip.cols + ')';
            addItem(pasteLabel, function() {
                self._pasteClipboardAt(rowIndex, colIndex);
            });
        }

        // Clear cell + edit : via helper ``_sheetSupports('edit')``.
        // Élargit l'édition via context menu aux onglets importés et SQL
        // (ancien comportement limité aux blank/dashboard seulement).
        if (this._sheetSupports('edit')) {
            addSep();
            // Chemin d'édition explicite : utile surtout pour les cellules
            // avec cellDetails (où le dblclick ouvre le drill au lieu d'éditer).
            // La saisie manuelle supprimera automatiquement le cellDetails
            // (doCommit) pour préserver la cohérence valeur↔SQL.
            addItem('Modifier la cellule', function() {
                var targetTd = self.tbodyEl.querySelector(
                    'td[data-row="' + rowIndex + '"][data-col="' + colIndex + '"]'
                );
                if (targetTd) self._startCellEdit(targetTd);
            }, '✎');
            addItem('Effacer la cellule', function() {
                // Push ici (pas dans _clearCellAt) car _clearSelectedCells
                // batch-push lui-même pour éviter le N-push multi-cellules.
                self._pushHistory();
                self._clearCellAt(rowIndex, colIndex);
            });
        }

        // ── Section 2: Detail (unified — works for both drillable AND AI-detail cells) ──
        // On NE propose l'item "Voir le détail" que si le detail est vraiment
        // drillable (contrat _cellHasRealDetail) OU si la colonne est
        // structurellement drillable via /api/drilldown.
        var hasAIDetail = this._cellHasRealDetail(this._cellDetails[sourceCellKey]);
        var isDrillable = this._isDrillable(colIndex);
        if (hasAIDetail || isDrillable) {
            addSep();
            addItem('Voir le détail', function() {
                if (hasAIDetail) {
                    var detail = self._cellDetails[sourceCellKey];
                    var lbl = (detail.description || 'Détail').substring(0, 30);
                    if (detail.row_count) lbl += ' (' + detail.row_count + ')';
                    var openTab = self._options.onDetailTab || self._options.onNewTab;
                    if (detail.rows && detail.rows.length > 0 && typeof openTab === 'function') {
                        openTab(lbl, detail.columns, detail.rows, detail.sql, detail.row_count);
                    } else if (detail.sql) {
                        // Lazy load: rows stripped after save → re-execute SQL
                        self._fetchCellDetailRows(detail, lbl);
                    }
                } else if (isDrillable) {
                    self._drillDown(rowIndex, colIndex);
                }
            }, '<i class="bi bi-search"></i>');
        }

        // ── Section 3: Filters (only if there's actual data) ──
        // **Root fix 2026-04-24** : ces items contournaient ``_canModifyLayout``
        // et permettaient d'appliquer un filtre même sur une feuille mergée
        // → classeur coincé (popup header bloquait mais context menu non).
        // On gate via ``_sheetSupports`` pour cohérence globale.
        var hasData = this.displayRows.length > 0;
        var canFilterApply = this._sheetSupports('filter_apply');
        var canFilterClear = this._sheetSupports('filter_clear');
        if (hasData && canFilterApply) {
            addSep();
            addItem('Filtrer par « ' + shortVal + ' »', function() {
                self._filterByValue(colIndex, value, false);
            });
            addItem('Exclure « ' + shortVal + ' »', function() {
                self._filterByValue(colIndex, value, true);
            });
        }
        // "Supprimer tous les filtres" reste dispo même quand apply bloqué
        // (merges) — sortie d'un état coincé.
        if (canFilterClear && Object.keys(this.filters).length > 0) {
            addSep();
            addItem('Supprimer tous les filtres', function() {
                self._clearAllFilters();
            });
        }

        // ── Section 4: Cell merging ──
        var existingMerge = this._findMergeContaining(rowIndex, colIndex);
        if (existingMerge) {
            addSep();
            addItem('Annuler la fusion', function() {
                self.unmergeCells(rowIndex, colIndex);
            });
        } else {
            var selectionRect = this._getSelectionRect();
            if (selectionRect && (selectionRect.rMax > selectionRect.rMin
                || selectionRect.cMax > selectionRect.cMin)) {
                var rectCount = (selectionRect.rMax - selectionRect.rMin + 1)
                              * (selectionRect.cMax - selectionRect.cMin + 1);
                var isContiguous = this._selectedCells.length === rectCount;
                addSep();
                if (isContiguous) {
                    addItem('Fusionner les cellules sélectionnées', function() {
                        self.mergeCells(
                            selectionRect.rMin, selectionRect.cMin,
                            selectionRect.rMax, selectionRect.cMax
                        );
                    });
                } else {
                    addDisabledItem('Fusionner (sélection non rectangulaire)');
                }
            }
        }

        // ── Position and display ──
        menu.style.left = x + 'px';
        menu.style.top = y + 'px';
        document.body.appendChild(menu);
        if (window.OverlayManager && typeof window.OverlayManager.open === 'function') {
            window.OverlayManager.open(menu, { layer: 'dropdown' });
        }
        this._activeContextMenu = menu;

        var menuRect = menu.getBoundingClientRect();
        if (menuRect.right > window.innerWidth) {
            menu.style.left = (x - menuRect.width) + 'px';
        }
        if (menuRect.bottom > window.innerHeight) {
            menu.style.top = (y - menuRect.height) + 'px';
        }

        var closeHandler = function(e) {
            if (!menu.contains(e.target)) {
                self._closeContextMenu();
                document.removeEventListener('mousedown', closeHandler);
            }
        };
        setTimeout(function() { document.addEventListener('mousedown', closeHandler); }, 0);
        this._ctxOutsideHandler = closeHandler;
    };

    SqlResultGrid.prototype._closeContextMenu = function() {
        if (this._activeContextMenu) {
            if (window.OverlayManager && typeof window.OverlayManager.close === 'function') {
                try { window.OverlayManager.close(this._activeContextMenu); } catch (e) {}
            }
            this._activeContextMenu.remove();
            this._activeContextMenu = null;
        }
        if (this._ctxOutsideHandler) {
            document.removeEventListener('mousedown', this._ctxOutsideHandler);
            this._ctxOutsideHandler = null;
        }
    };

    // ── Paste cell (from context menu) ──

    SqlResultGrid.prototype._pasteCellAt = function(rowIndex, colIndex, copiedCell) {
        var value = copiedCell.value;

        // Update data model
        if (rowIndex < this.allRows.length) {
            if (this.isArrayFormat) {
                this.allRows[rowIndex][colIndex] = value;
            } else {
                this.allRows[rowIndex][this.columns[colIndex]] = value;
            }
            this.displayRows = this.allRows.slice();
        }

        // Update DOM
        var td = this.tbodyEl.querySelector(
            'td[data-row="' + rowIndex + '"][data-col="' + colIndex + '"]'
        );
        if (td) {
            var nv = Number(value);
            td.textContent = (value && !isNaN(nv) && isFinite(nv)) ? formatNumber(nv) : (value || '');
            td.classList.add('grid-cell-editable');
            // Le paste mute td.textContent hors _rebuildBody : la valeur collée
            // peut contenir (ou retirer) un terme d'anonymisation → re-marquage
            // (rAF-coalescé) sinon marquage stale (review adversariale tâche #24).
            this._anonMarkerFingerprint = null;
            this._applyAnonymizationCellMarkers();
            // Green flash feedback
            td.classList.add('grid-cell-copied');
            setTimeout(function() { td.classList.remove('grid-cell-copied'); }, 400);
        }

        // Copy details if the source cell had any (AI detail or drill-down)
        var targetKey = rowIndex + ',' + colIndex;
        var self = this;

        if (copiedCell.details) {
            // Source had AI-generated detail → copy directly
            this._cellDetails[targetKey] = copiedCell.details;
            if (td && this._cellHasRealDetail(copiedCell.details)) {
                td.classList.add('grid-cell-has-detail');
            }

            // Open detail in a new background tab
            if (typeof this._options.onNewTab === 'function') {
                var d = copiedCell.details;
                var label = (d.description || '').substring(0, 30);
                if (d.row_count) label += ' (' + d.row_count + ')';
                this._options.onNewTab(label, d.columns, d.rows, d.sql, d.row_count);
            }
        } else if (copiedCell.drilldownCtx) {
            // Source was a drillable cell → fetch drill-down detail via API
            var ctx = copiedCell.drilldownCtx;
            var xsrf = _getXsrfCookie();
            var drillToken = self._beginSync('Chargement du détail…');
            fetch('/api/drilldown', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-Xsrftoken': xsrf },
                body: JSON.stringify({
                    original_sql: ctx.original_sql,
                    col_index: ctx.col_index,
                    row_values: ctx.row_values
                })
            })
            .then(function(r) { return r.json(); })
            .then(function(data) {
                self._endSync(drillToken, !!(data && data.error));
                if (data.error || data.unchanged) return;

                // Store the fetched detail for this cell
                var detailData = {
                    sql: data.sql || ctx.original_sql,
                    columns: data.columns || [],
                    rows: data.rows || [],
                    row_count: data.row_count || 0,
                    description: data.breadcrumb || 'Détail'
                };
                self._cellDetails[targetKey] = detailData;

                // Mark cell and update DOM (uniquement si detail réellement drillable)
                var targetTd = self.tbodyEl.querySelector(
                    'td[data-row="' + rowIndex + '"][data-col="' + colIndex + '"]'
                );
                if (targetTd && self._cellHasRealDetail(detailData)) {
                    targetTd.classList.add('grid-cell-has-detail');
                }

                // Open detail in background tab
                if (typeof self._options.onNewTab === 'function') {
                    var lbl = (detailData.description || '').substring(0, 30);
                    if (detailData.row_count) lbl += ' (' + detailData.row_count + ')';
                    self._options.onNewTab(lbl, detailData.columns, detailData.rows, detailData.sql, detailData.row_count);
                }
            })
            .catch(function(err) {
                self._endSync(drillToken, true);
                console.warn('[Grid] Drill-down fetch for paste failed:', err);
            });
        } else {
            delete this._cellDetails[targetKey];
            if (td) td.classList.remove('grid-cell-has-detail');
        }
    };

    SqlResultGrid.prototype._clearCellAt = function(rowIndex, colIndex) {
        if (rowIndex < 0 || rowIndex >= this.allRows.length) return;
        // Clear data
        if (this.isArrayFormat) {
            this.allRows[rowIndex][colIndex] = '';
        } else {
            this.allRows[rowIndex][this.columns[colIndex]] = '';
        }
        this.displayRows = this.allRows.slice();
        // Clear detail if any
        var cellKey = rowIndex + ',' + colIndex;
        delete this._cellDetails[cellKey];
        // Update DOM
        var td = this.tbodyEl.querySelector(
            'td[data-row="' + rowIndex + '"][data-col="' + colIndex + '"]'
        );
        if (td) {
            td.textContent = '';
            td.classList.remove('grid-cell-has-detail');
            td.className = 'grid-cell-editable';
            td.setAttribute('data-row', rowIndex);
            td.setAttribute('data-col', colIndex);
        }
        // Notify state change
        if (this._options && typeof this._options.onStateChange === 'function') {
            this._options.onStateChange();
        }
        // Une cellule vidée change la valeur affichée → le résumé de sélection
        // (Σ/moyenne) doit se recalculer, sinon il resterait FIGÉ non nul sur des
        // cellules désormais vides (review adversariale, Q5). Respecte
        // _suppressSelectionRefresh → en batch (_clearSelectedCells), on ne
        // recalcule qu'une fois après la boucle.
        this._refreshSelectionSummary();
    };

    SqlResultGrid.prototype._clearSelectedCells = function() {
        if (!this._selectedCells || this._selectedCells.length === 0) return;
        // Snapshot UNIQUE pour la batch (vs un par cellule sinon spam).
        // `_clearCellAt` n'a pas son propre push pour éviter le N-push.
        this._pushHistory();
        this._suppressSelectionRefresh = true;
        try {
            for (var i = 0; i < this._selectedCells.length; i++) {
                var td = this._selectedCells[i];
                var r = parseInt(td.getAttribute('data-row'), 10);
                var c = parseInt(td.getAttribute('data-col'), 10);
                this._clearCellAt(r, c);
            }
        } finally {
            this._suppressSelectionRefresh = false;
        }
        // Recalcule une SEULE fois après la batch (les cellules vidées doivent se
        // refléter dans la Σ — sinon total figé non nul sur cellules vidées, Q5).
        this._refreshSelectionSummary();
    };

    // ── Paste clipboard (multi-cell) at target position ──

    SqlResultGrid.prototype._pasteClipboardAt = function(startRow, startCol) {
        var clip = SqlResultGrid._clipboard;
        if (!clip || !clip.cells.length) return;
        this._pushHistory();

        for (var r = 0; r < clip.cells.length; r++) {
            var rowIdx = startRow + r;
            // Extend rows if needed (blank sheets)
            while (rowIdx >= this.allRows.length && this._isBlankSheet && this.allRows.length < 500) {
                var newRow = [];
                for (var x = 0; x < this.columns.length; x++) newRow.push('');
                this.allRows.push(newRow);
            }
            if (rowIdx >= this.allRows.length) break;

            for (var c = 0; c < clip.cells[r].length; c++) {
                var colIdx = startCol + c;
                if (colIdx >= this.columns.length) break;

                var cell = clip.cells[r][c];

                // Write value
                if (this.isArrayFormat) {
                    this.allRows[rowIdx][colIdx] = cell.value;
                } else {
                    this.allRows[rowIdx][this.columns[colIdx]] = cell.value;
                }

                // Copy details
                var targetKey = rowIdx + ',' + colIdx;
                if (cell.details) {
                    this._cellDetails[targetKey] = cell.details;
                } else if (cell.drilldownCtx) {
                    // Async drill-down fetch for this cell
                    this._fetchDrilldownForCell(targetKey, cell.drilldownCtx);
                }
            }
        }

        this.displayRows = this.allRows.slice();
        this._rebuildBody();
        this._updateHeaderInfo();

        // Green flash on pasted area
        for (var pr = 0; pr < clip.cells.length; pr++) {
            for (var pc = 0; pc < clip.cells[pr].length; pc++) {
                var td = this.tbodyEl.querySelector(
                    'td[data-row="' + (startRow + pr) + '"][data-col="' + (startCol + pc) + '"]'
                );
                if (td) td.classList.add('grid-cell-copied');
            }
        }
        var self = this;
        setTimeout(function() {
            var all = self.tbodyEl.querySelectorAll('.grid-cell-copied');
            for (var i = 0; i < all.length; i++) all[i].classList.remove('grid-cell-copied');
        }, 400);

        // Clear marching ants after paste
        SqlResultGrid._clearClipboardAnts();

        // Trigger auto-fill après paste — annuler toute requête en cours
        if (this._isDashboardSheet) {
            if (this._autoFillAbort) this._autoFillAbort.abort();
            this._autoFillCompleted = false;
            this._autoFillPending = false;
            clearTimeout(this._autoFillTimer);
            this._autoFillTimer = setTimeout(function() {
                self._triggerAutoFill();
            }, 3000);
        }
    };

    // Fetch drill-down detail for a pasted cell (async, background)
    SqlResultGrid.prototype._fetchDrilldownForCell = function(targetKey, ctx) {
        var self = this;
        // Snapshot de la valeur au moment du fetch : si l'utilisateur édite la
        // cellule pendant que la requête est en vol, on ne doit PAS poser le
        // cellDetails au retour (le drill pointerait sur une donnée qui ne
        // correspond plus à la valeur affichée).
        var parts0 = targetKey.split(',');
        var snapR = parseInt(parts0[0], 10);
        var snapC = parseInt(parts0[1], 10);
        var readCell = function() {
            if (!self.allRows[snapR]) return null;
            return self.isArrayFormat
                ? self.allRows[snapR][snapC]
                : self.allRows[snapR][self.columns[snapC]];
        };
        var snapshotVal = readCell();
        var xsrf = _getXsrfCookie();
        var bgDrillToken = this._beginSync('Mise à jour détail cellule…');
        fetch('/api/drilldown', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-Xsrftoken': xsrf },
            body: JSON.stringify({ original_sql: ctx.original_sql, col_index: ctx.col_index, row_values: ctx.row_values })
        })
        .then(function(r) { return r.json(); })
        .then(function(data) {
            self._endSync(bgDrillToken, !!(data && data.error));
            if (data.error || data.unchanged) return;
            // Abandonner si la cellule a été éditée entre-temps.
            if (readCell() !== snapshotVal) return;
            var newDetail = {
                sql: data.sql || ctx.original_sql,
                columns: data.columns || [],
                rows: data.rows || [],
                row_count: data.row_count || 0,
                description: data.breadcrumb || 'Détail'
            };
            self._cellDetails[targetKey] = newDetail;
            var parts = targetKey.split(',');
            var td = self.tbodyEl.querySelector('td[data-row="' + parts[0] + '"][data-col="' + parts[1] + '"]');
            if (td && self._cellHasRealDetail(newDetail)) {
                td.classList.add('grid-cell-has-detail');
            }
        })
        .catch(function() { self._endSync(bgDrillToken, true); });
    };

    // ── Column resize ──

    SqlResultGrid.prototype._startResize = function(e, th) {
        var self = this;
        var startX = e.clientX;
        var startWidth = th.offsetWidth;

        document.body.classList.add('grid-resizing');

        function onMove(ev) {
            var newWidth = Math.max(50, Math.min(500, startWidth + (ev.clientX - startX)));
            th.style.width = newWidth + 'px';
            th.style.minWidth = newWidth + 'px';
            th.style.maxWidth = newWidth + 'px';
        }

        function onUp() {
            document.removeEventListener('mousemove', onMove);
            document.removeEventListener('mouseup', onUp);
            document.body.classList.remove('grid-resizing');
        }

        document.addEventListener('mousemove', onMove);
        document.addEventListener('mouseup', onUp);
    };

    // ── Hide/show columns ──

    SqlResultGrid.prototype._getVisibleColIndices = function() {
        var result = [];
        for (var k = 0; k < this.columnOrder.length; k++) {
            var i = this.columnOrder[k];
            if (!this.hiddenCols.has(i)) result.push(i);
        }
        return result;
    };

    SqlResultGrid.prototype._openColumnsDialog = function() {
        // Note : la visibilité du bouton est pilotée par ``_updateHeaderInfo``
        // → le bouton n'est visible QUE pour les feuilles SQL sans fusion.
        // Donc ce handler n'est jamais invoqué dans un contexte où
        // ``_canModifyLayout()`` serait faux — pas de message d'erreur à
        // afficher ici.
        this._closeFilterPopup();
        var self = this;

        var popup = document.createElement('div');
        popup.className = 'grid-filter-popup grid-col-dialog';

        var titleRow = document.createElement('div');
        titleRow.className = 'grid-col-title-row';

        var title = document.createElement('div');
        title.className = 'grid-fp-sort-link';
        title.style.fontWeight = '600';
        title.style.cursor = 'default';
        title.textContent = 'Colonnes visibles';
        titleRow.appendChild(title);

        var closeBtn = document.createElement('button');
        closeBtn.type = 'button';
        closeBtn.className = 'grid-col-close-btn';
        closeBtn.textContent = '\u00d7';
        closeBtn.title = 'Fermer';
        closeBtn.addEventListener('click', function() {
            self._closeColDialog();
        });
        titleRow.appendChild(closeBtn);

        popup.appendChild(titleRow);

        var sep = document.createElement('div');
        sep.className = 'grid-fp-separator';
        popup.appendChild(sep);

        // ── Search input ──
        var searchWrap = document.createElement('div');
        searchWrap.className = 'grid-search-wrap';
        var searchInput = document.createElement('input');
        searchInput.type = 'text';
        searchInput.className = 'grid-col-search';
        searchInput.placeholder = 'Rechercher une colonne\u2026';
        searchWrap.appendChild(searchInput);
        var clearBtn = document.createElement('button');
        clearBtn.type = 'button';
        clearBtn.className = 'grid-search-clear';
        clearBtn.textContent = '×';
        clearBtn.title = 'Effacer';
        clearBtn.addEventListener('click', function() {
            searchInput.value = '';
            searchInput.dispatchEvent(new Event('input'));
        });
        searchWrap.appendChild(clearBtn);
        popup.appendChild(searchWrap);

        var listWrap = document.createElement('div');
        listWrap.className = 'grid-fp-list';
        listWrap.style.maxHeight = '250px';

        var items = [];

        // Check all
        var checkAllLabel = document.createElement('label');
        checkAllLabel.className = 'grid-fp-item grid-fp-item-all';
        var checkAll = document.createElement('input');
        checkAll.type = 'checkbox';
        checkAllLabel.appendChild(checkAll);
        checkAllLabel.appendChild(document.createTextNode(' (Tout afficher)'));
        listWrap.appendChild(checkAllLabel);

        // Working copy of columnOrder for reordering inside the dialog
        var dialogOrder = this.columnOrder.slice();

        // Build column items in current columnOrder
        for (var k = 0; k < dialogOrder.length; k++) {
            (function(ci) {
                var lbl = document.createElement('label');
                lbl.className = 'grid-fp-item';
                lbl.setAttribute('draggable', 'true');
                lbl.setAttribute('data-col-index', ci);

                // Drag grip
                var grip = document.createElement('span');
                grip.className = 'grid-col-grip';
                grip.textContent = '\u2807'; // ⠇ braille dots
                lbl.appendChild(grip);

                var cb = document.createElement('input');
                cb.type = 'checkbox';
                cb.checked = !self.hiddenCols.has(ci);
                lbl.appendChild(cb);
                lbl.appendChild(document.createTextNode(' ' + self.columns[ci]));
                listWrap.appendChild(lbl);
                items.push({ cb: cb, colIndex: ci, lbl: lbl });
            })(dialogOrder[k]);
        }

        popup.appendChild(listWrap);

        // ── Auto-sort: checked first, unchecked last ──
        function reorderCheckedFirst() {
            var checked = [], unchecked = [];
            for (var j = 0; j < items.length; j++) {
                if (items[j].cb.checked) checked.push(items[j].lbl);
                else unchecked.push(items[j].lbl);
            }
            // Re-append in order: checkAll stays first, then checked, then unchecked
            for (var c = 0; c < checked.length; c++) listWrap.appendChild(checked[c]);
            for (var u = 0; u < unchecked.length; u++) listWrap.appendChild(unchecked[u]);
        }

        // Attach change listeners to each checkbox
        for (var ci2 = 0; ci2 < items.length; ci2++) {
            items[ci2].cb.addEventListener('change', function() {
                updateCheckAll();
                reorderCheckedFirst();
            });
        }

        // Don't reorder on init — preserve user's columnOrder

        // ── Search filtering ──
        searchInput.addEventListener('input', function() {
            var q = searchInput.value.toLowerCase();
            for (var j = 0; j < items.length; j++) {
                var name = self.columns[items[j].colIndex].toLowerCase();
                items[j].lbl.style.display = name.indexOf(q) !== -1 ? '' : 'none';
            }
        });

        // ── Drag-and-drop reorder ──
        var dragSrc = null;

        function onDragStart(e) {
            dragSrc = closestItem(e.target);
            if (!dragSrc) return;
            dragSrc.classList.add('dragging');
            e.dataTransfer.effectAllowed = 'move';
        }
        function onDragOver(e) {
            e.preventDefault();
            e.dataTransfer.dropEffect = 'move';
            var target = closestItem(e.target);
            if (target && target !== dragSrc && target !== checkAllLabel) {
                clearDragOver();
                target.classList.add('drag-over');
            }
        }
        function onDrop(e) {
            e.preventDefault();
            var target = closestItem(e.target);
            if (target && target !== dragSrc && target !== checkAllLabel) {
                // Insert dragged before or after target
                var rect = target.getBoundingClientRect();
                var midY = rect.top + rect.height / 2;
                if (e.clientY < midY) {
                    listWrap.insertBefore(dragSrc, target);
                } else {
                    listWrap.insertBefore(dragSrc, target.nextSibling);
                }
            }
            cleanupDrag();
        }
        function onDragEnd() { cleanupDrag(); }
        function cleanupDrag() {
            if (dragSrc) dragSrc.classList.remove('dragging');
            dragSrc = null;
            clearDragOver();
        }
        function clearDragOver() {
            var overs = listWrap.querySelectorAll('.drag-over');
            for (var d = 0; d < overs.length; d++) overs[d].classList.remove('drag-over');
        }
        function closestItem(el) {
            while (el && el !== listWrap) {
                if (el.classList && el.classList.contains('grid-fp-item') && !el.classList.contains('grid-fp-item-all')) return el;
                el = el.parentElement;
            }
            return null;
        }

        listWrap.addEventListener('dragstart', onDragStart);
        listWrap.addEventListener('dragover', onDragOver);
        listWrap.addEventListener('drop', onDrop);
        listWrap.addEventListener('dragend', onDragEnd);

        // ── Check all logic ──
        function updateCheckAll() {
            var total = items.length, checked = 0;
            for (var j = 0; j < items.length; j++) {
                if (items[j].cb.checked) checked++;
            }
            checkAll.checked = checked === total;
            checkAll.indeterminate = checked > 0 && checked < total;
        }
        updateCheckAll();

        checkAll.addEventListener('change', function() {
            for (var j = 0; j < items.length; j++) items[j].cb.checked = checkAll.checked;
            reorderCheckedFirst();
        });

        // ── Buttons ──
        var btnRow = document.createElement('div');
        btnRow.className = 'grid-fp-buttons';

        var btnOk = document.createElement('button');
        btnOk.type = 'button';
        btnOk.className = 'grid-fp-btn-ok';
        btnOk.textContent = 'Appliquer';
        btnOk.addEventListener('click', function() {
            // Read new order from DOM
            var labels = listWrap.querySelectorAll('.grid-fp-item:not(.grid-fp-item-all)');
            var newOrder = [];
            var newHidden = new Set();
            var visibleCount = 0;
            for (var n = 0; n < labels.length; n++) {
                var ci = parseInt(labels[n].getAttribute('data-col-index'), 10);
                if (isNaN(ci) || ci < 0 || ci >= self.columns.length) continue;
                newOrder.push(ci);
            }
            // Fallback: if DOM was corrupted, keep current order
            if (newOrder.length !== self.columns.length) {
                newOrder = self.columnOrder.slice();
            }
            for (var j = 0; j < items.length; j++) {
                if (!items[j].cb.checked) {
                    newHidden.add(items[j].colIndex);
                } else {
                    visibleCount++;
                }
            }
            // Prevent hiding ALL columns
            if (visibleCount === 0) {
                newHidden = new Set();
            }
            // No-op detection : si rien n'a changé (ordre identique + hidden
            // identique), pas de snapshot (sinon Ctrl+Z fait croire à une
            // annulation qui n'a rien à défaire).
            var orderChanged = newOrder.length !== self.columnOrder.length;
            if (!orderChanged) {
                for (var oi = 0; oi < newOrder.length; oi++) {
                    if (newOrder[oi] !== self.columnOrder[oi]) { orderChanged = true; break; }
                }
            }
            var hiddenChanged = newHidden.size !== self.hiddenCols.size;
            if (!hiddenChanged) {
                var hiddenIter = newHidden.values();
                var hStep;
                while (!(hStep = hiddenIter.next()).done) {
                    if (!self.hiddenCols.has(hStep.value)) { hiddenChanged = true; break; }
                }
            }
            if (orderChanged || hiddenChanged) self._pushHistory();
            self.columnOrder = newOrder;
            self.hiddenCols = newHidden;
            self._rebuildThead();
            self._rebuildBody();
            self._closeColDialog();
        });
        btnRow.appendChild(btnOk);

        var btnReset = document.createElement('button');
        btnReset.type = 'button';
        btnReset.className = 'grid-fp-btn-reset';
        btnReset.textContent = 'Réinitialiser';
        btnReset.addEventListener('click', function() {
            // No-op : si déjà à l'identité + 0 hidden, pas de snapshot.
            var alreadyDefault = (self.hiddenCols.size === 0);
            if (alreadyDefault) {
                for (var ri = 0; ri < self.columnOrder.length; ri++) {
                    if (self.columnOrder[ri] !== ri) { alreadyDefault = false; break; }
                }
            }
            if (!alreadyDefault) self._pushHistory();
            self.columnOrder = self.columns.map(function(_, i) { return i; });
            self.hiddenCols = new Set();
            self._rebuildThead();
            self._rebuildBody();
            self._closeColDialog();
        });
        btnRow.appendChild(btnReset);



        popup.appendChild(btnRow);

        // ── "Load all columns" button ──
        if (self.sql) {
            var allColsSep = document.createElement('div');
            allColsSep.className = 'grid-fp-separator';
            popup.appendChild(allColsSep);

            var btnAllCols = document.createElement('button');
            btnAllCols.type = 'button';
            btnAllCols.className = 'grid-btn-all-cols';
            btnAllCols.textContent = 'Charger toutes les colonnes';
            btnAllCols.addEventListener('click', function() {
                self._closeColDialog();
                self._loadAllColumns();
            });
            popup.appendChild(btnAllCols);
        }

        // Position near the columns button
        popup.style.position = 'absolute';
        popup.style.top = '40px';
        popup.style.right = '0';

        this.container.style.position = 'relative';
        this.container.appendChild(popup);
        this._activeColDialog = popup;

        // Focus search
        setTimeout(function() { searchInput.focus(); }, 50);

        var closeHandler = function(e) {
            if (!popup.contains(e.target)) {
                self._closeColDialog();
                document.removeEventListener('mousedown', closeHandler);
            }
        };
        setTimeout(function() { document.addEventListener('mousedown', closeHandler); }, 0);
        this._colDialogOutsideHandler = closeHandler;
    };

    SqlResultGrid.prototype._closeColDialog = function() {
        if (this._activeColDialog) {
            this._activeColDialog.remove();
            this._activeColDialog = null;
        }
        if (this._colDialogOutsideHandler) {
            document.removeEventListener('mousedown', this._colDialogOutsideHandler);
            this._colDialogOutsideHandler = null;
        }
    };

    SqlResultGrid.prototype._loadAllColumns = function() {
        var self = this;
        if (!this.sql || this._loadingAllCols) return;
        this._loadingAllCols = true;

        if (this.headerInfoEl) this.headerInfoEl.innerHTML = '<em>Chargement de toutes les colonnes\u2026</em>';

        var xsrf = _getXsrfCookie();
        fetch('/api/expand-columns', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-Xsrftoken': xsrf },
            body: JSON.stringify({ sql: this.sql })
        })
        .then(function(r) { return r.json(); })
        .then(function(data) {
            self._loadingAllCols = false;
            if (data.error) {
                // Toast stylé (cohérent Komptia) plutôt que l'alert() natif moche.
                // Le message vient du backend déjà CLAIR + adapté à l'audience
                // (admin vs user) ; pas de SQL brut ici (bruit pour l'utilisateur,
                // dispo en logs serveur). Fallback alert() si toast.js absent.
                if (typeof window.showToast === 'function') {
                    window.showToast(data.error, 'error');
                } else {
                    alert('Erreur : ' + data.error);
                }
                self._updateHeaderInfo();
                return;
            }
            self.columns = data.columns || [];
            self.allRows = data.rows || [];
            self.sql = data.sql || self.sql;
            self.totalRowCount = data.row_count || self.allRows.length;
            // A12-F1 — flag de troncature AUTORITATIF du backend (cap admin
            // ``DatabaseConnection.max_rows``). Le SELECT élargi est ré-exécuté
            // côté Sage : sa troncature peut différer de la requête d'origine.
            // Sans cette ligne, le badge « tronqué » de la grille restait figé
            // sur l'état pré-expand (données fausses silencieuses).
            self._truncated = !!data.truncated;
            self.isArrayFormat = self.allRows.length > 0 && Array.isArray(self.allRows[0]);
            self.columnMetadata = null;
            self.sortColIndex = -1;
            self.sortDirection = null;
            self.filters = {};
            self.hiddenCols = new Set();
            self.columnOrder = self.columns.map(function(_, i) { return i; });
            self.displayRows = self.allRows.slice();
            self.columnTypes = [];
            self._detectTypes();
            self._build();
        })
        .catch(function(err) {
            self._loadingAllCols = false;
            console.error('[Grid] loadAllColumns error:', err);
            if (self.headerInfoEl) self.headerInfoEl.innerHTML = '<em style="color:var(--status-error,#ef4444);">Erreur de chargement</em>';
            setTimeout(function() { self._updateHeaderInfo(); }, 3000);
        });
    };

    SqlResultGrid.prototype._rebuildThead = function() {
        if (!this.theadEl || !this.theadEl.parentNode) return;
        var table = this.theadEl.parentNode;
        table.removeChild(this.theadEl);
        this._buildThead(table);
        // Re-insert thead before tbody
        if (this.tbodyEl) {
            table.insertBefore(this.theadEl, this.tbodyEl);
        }
        this._updateSortIndicators();
        this._updateFilterIndicators();
    };

    // ── Drill-down ──

    SqlResultGrid.prototype._fetchColumnMetadata = function() {
        var self = this;
        var xsrf = _getXsrfCookie();
        var analyzeToken = this._beginSync('Analyse colonnes…');
        fetch('/api/drilldown/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-Xsrftoken': xsrf },
            body: JSON.stringify({ sql: this.sql })
        })
        .then(function(r) { return r.json(); })
        .then(function(data) {
            self._endSync(analyzeToken, false);
            if (data.columns) {
                self.columnMetadata = data.columns;
                self._rebuildBody(); // Re-render to add drill-down cursors
            }
        })
        .catch(function(err) {
            self._endSync(analyzeToken, true);
            console.warn('[Grid] Failed to fetch column metadata:', err);
        });
    };

    SqlResultGrid.prototype._isDrillable = function(colIndex) {
        if (!this.columnMetadata || colIndex < 0 || colIndex >= this.columnMetadata.length) return false;
        return this.columnMetadata[colIndex].is_drillable === true;
    };

    /**
     * Contrat unique : "cette cellule a-t-elle un drill-down RÉELLEMENT
     * accessible ?" — source de vérité pour l'affichage du point violet
     * (.grid-cell-has-detail), l'item contextmenu "Voir le détail" et la
     * route dblclick vers un détail.
     *
     * Retourne true SI ET SEULEMENT SI ``detail`` est un objet qui contient
     * soit des ``rows`` préchargées non vides, soit un ``sql`` string non
     * vide après trim. Toute autre forme (derived_formula seul, label seul,
     * match sans source SQL, sql="", rows=[] sans sql…) renvoie false → pas
     * d'indicateur UI, pas de clic qui mène nulle part.
     */
    SqlResultGrid.prototype._cellHasRealDetail = function(detail) {
        if (!detail || typeof detail !== 'object') return false;
        if (Array.isArray(detail.rows) && detail.rows.length > 0) return true;
        if (typeof detail.sql === 'string' && detail.sql.trim().length > 0) return true;
        return false;
    };

    SqlResultGrid.prototype._drillDown = function(rowIndex, colIndex) {
        var self = this;
        if (this._drillInProgress) return;
        if (rowIndex < 0 || rowIndex >= this.displayRows.length) return;
        this._drillInProgress = true;
        var row = this.displayRows[rowIndex];

        // Build row_values dict
        var rowValues = {};
        for (var i = 0; i < this.columns.length; i++) {
            var val = this.isArrayFormat ? row[i] : row[this.columns[i]];
            rowValues[this.columns[i]] = val;
        }

        var hasCallback = typeof self._options.onDrillResult === 'function';

        // Save current state to navigation stack (only when no tab manager callback)
        if (!hasCallback) {
            this._navStack.push({
                columns: this.columns.slice(),
                allRows: this.allRows,
                sql: this.sql,
                totalRowCount: this.totalRowCount,
                columnMetadata: this.columnMetadata,
                sortColIndex: this.sortColIndex,
                sortDirection: this.sortDirection,
                filters: JSON.parse(JSON.stringify(this.filters, function(k, v) { return v instanceof Set ? Array.from(v) : v; })),
                hiddenCols: Array.from(this.hiddenCols),
                columnOrder: this.columnOrder.slice(),
                columnTypes: this.columnTypes.slice(),
                isArrayFormat: this.isArrayFormat,
                displayRows: this.displayRows
            });
        }

        // Show loading state
        if (this.headerInfoEl) this.headerInfoEl.innerHTML = '<em>Chargement du détail...</em>';

        var xsrf = _getXsrfCookie();
        var drillMainToken = this._beginSync('Drill-down en cours…');
        fetch('/api/drilldown', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-Xsrftoken': xsrf },
            body: JSON.stringify({
                original_sql: this.sql,
                col_index: colIndex,
                row_values: rowValues
            })
        })
        .then(function(r) { return r.json(); })
        .then(function(data) {
            self._endSync(drillMainToken, !!(data && data.error));
            self._drillInProgress = false;
            if (data.error) {
                // Toast stylé (cohérent Komptia) plutôt que l'alert() natif moche.
                // Message backend déjà CLAIR + adapté à l'audience ; SQL brut
                // retiré du toast (bruit user, dispo en logs). Fallback alert().
                if (typeof window.showToast === 'function') {
                    window.showToast(data.error, 'error');
                } else {
                    alert('Erreur drill-down :\n' + data.error);
                }
                if (!hasCallback) { self._navStack.pop(); }
                self._updateHeaderInfo();
                return;
            }

            // Not drillable — toutes les lignes ont déjà la même valeur sur
            // la colonne ciblée : aucun filtrage n'est possible. On avertit
            // l'utilisateur au lieu d'un silent cancel trompeur.
            if (data.unchanged) {
                if (!hasCallback) { self._navStack.pop(); }
                self._updateHeaderInfo();
                if (typeof self._showSaveToast === 'function') {
                    self._showSaveToast(
                        'Aucun détail à afficher : toutes les lignes ont déjà cette valeur.',
                        false,
                    );
                }
                return;
            }

            // ── Tab manager mode: delegate to callback ──
            if (hasCallback) {
                self._options.onDrillResult(data);
                self._updateHeaderInfo();
                return;
            }

            // ── Legacy mode: nav stack ──
            if (self._breadcrumbs.length === 0) self._breadcrumbs.push('Résultat');
            self._breadcrumbs.push(data.breadcrumb || 'Détail');

            // Multi-CTE: multiple result sets
            if (data.multi && data.results) {
                self._showMultiResults(data.results);
                return;
            }

            // Single result: replace grid
            self.columns = data.columns || [];
            self.allRows = data.rows || [];
            self.sql = data.sql || '';
            self.totalRowCount = data.row_count || self.allRows.length;
            self.isArrayFormat = self.allRows.length > 0 && Array.isArray(self.allRows[0]);
            self.columnMetadata = data.column_metadata || null;
            self.sortColIndex = -1;
            self.sortDirection = null;
            self.filters = {};
            self.hiddenCols = new Set();
            self.columnOrder = self.columns.map(function(_, i) { return i; });
            self.displayRows = self.allRows.slice();
            self.columnTypes = [];
            self._detectTypes();
            self._build();

            if (self.sql && !self.columnMetadata && /GROUP\s+BY/i.test(self.sql)) {
                self._fetchColumnMetadata();
            }
        })
        .catch(function(err) {
            self._endSync(drillMainToken, true);
            self._drillInProgress = false;
            console.error('[Grid] Drill-down error:', err);
            if (!hasCallback) { self._navStack.pop(); }
            self._updateHeaderInfo();
        });
    };

    SqlResultGrid.prototype._goBack = function() {
        if (this._navStack.length === 0) return;
        var prev = this._navStack.pop();
        this._breadcrumbs.pop();

        // Restore state
        this.columns = prev.columns;
        this.allRows = prev.allRows;
        this.sql = prev.sql;
        this.totalRowCount = prev.totalRowCount;
        this.columnMetadata = prev.columnMetadata;
        this.sortColIndex = prev.sortColIndex;
        this.sortDirection = prev.sortDirection;
        this.columnTypes = prev.columnTypes;
        this.isArrayFormat = prev.isArrayFormat;
        this.hiddenCols = new Set(prev.hiddenCols);
        this.columnOrder = prev.columnOrder || this.columns.map(function(_, i) { return i; });
        this.displayRows = prev.displayRows;
        // Restore filters (convert arrays back to Sets)
        this.filters = {};
        for (var k in prev.filters) {
            var f = prev.filters[k];
            this.filters[k] = { excluded: new Set(f.excluded || []), excludeNull: f.excludeNull || false };
        }

        this._build();
    };

    SqlResultGrid.prototype._buildNavBar = function() {
        // Remove old nav bar if exists
        if (this._navBarEl && this._navBarEl.parentNode) {
            this._navBarEl.parentNode.removeChild(this._navBarEl);
        }

        if (this._navStack.length === 0) {
            this._navBarEl = null;
            return;
        }

        var self = this;
        var nav = document.createElement('div');
        nav.className = 'grid-drilldown-nav';

        // Back button
        var btnBack = document.createElement('button');
        btnBack.type = 'button';
        btnBack.className = 'grid-action-btn grid-btn-back';
        btnBack.innerHTML = '← Retour';
        btnBack.addEventListener('click', function() { self._goBack(); });
        nav.appendChild(btnBack);

        // Breadcrumbs
        var crumbs = document.createElement('span');
        crumbs.className = 'grid-breadcrumbs';
        for (var i = 0; i < this._breadcrumbs.length; i++) {
            if (i > 0) {
                var sep = document.createElement('span');
                sep.className = 'grid-breadcrumb-sep';
                sep.textContent = ' › ';
                crumbs.appendChild(sep);
            }
            var crumb = document.createElement('span');
            crumb.className = i === this._breadcrumbs.length - 1 ? 'grid-breadcrumb-active' : 'grid-breadcrumb';
            crumb.textContent = this._breadcrumbs[i];
            // Click on earlier breadcrumb to jump back to that level
            if (i < this._breadcrumbs.length - 1) {
                (function(targetLevel) {
                    crumb.style.cursor = 'pointer';
                    crumb.addEventListener('click', function() {
                        while (self._navStack.length > targetLevel) self._goBack();
                    });
                })(i);
            }
            crumbs.appendChild(crumb);
        }
        nav.appendChild(crumbs);

        this._navBarEl = nav;
        // Insert before header
        this.container.insertBefore(nav, this.container.firstChild);
    };

    // ── Multi-CTE drill-down display ──

    SqlResultGrid.prototype._showMultiResults = function(results) {
        var self = this;
        this.container.innerHTML = '';
        this._buildNavBar();

        // Tab bar
        var tabBar = document.createElement('div');
        tabBar.className = 'grid-multi-tab-bar';
        this.container.appendChild(tabBar);

        // Content area (one grid at a time)
        var contentArea = document.createElement('div');
        contentArea.className = 'grid-multi-content';
        this.container.appendChild(contentArea);

        var activeTab = null;

        function showTab(index) {
            // Update tab active state
            var tabs = tabBar.querySelectorAll('.grid-multi-tab');
            for (var t = 0; t < tabs.length; t++) {
                tabs[t].classList.toggle('grid-multi-tab-active', t === index);
            }

            // Show content
            contentArea.innerHTML = '';
            var r = results[index];

            if (r.error) {
                contentArea.innerHTML = '<div class="iris-no-results" style="padding:1rem;">Erreur : ' + _escHtml(r.error) + '</div>';
                return;
            }

            var subContainer = document.createElement('div');
            subContainer.className = 'grid-multi-sub-container';
            contentArea.appendChild(subContainer);

            try {
                new SqlResultGrid(subContainer, r.columns || [], r.rows || [], r.sql || '', r.row_count || 0);
            } catch (err) {
                console.error('[Grid] Multi sub-grid error:', err);
                subContainer.innerHTML = '<div class="iris-no-results">Erreur d\'affichage</div>';
            }
        }

        // Create tabs
        for (var i = 0; i < results.length; i++) {
            (function(idx) {
                var r = results[idx];
                var tab = document.createElement('button');
                tab.type = 'button';
                tab.className = 'grid-multi-tab' + (idx === 0 ? ' grid-multi-tab-active' : '');
                var count = r.row_count ? ' (' + r.row_count + ')' : '';
                tab.textContent = r.label + count;
                if (r.error) tab.classList.add('grid-multi-tab-error');
                tab.addEventListener('click', function() { showTab(idx); });
                tabBar.appendChild(tab);
            })(i);
        }

        // Show first tab
        showTab(0);
    };

    // ══════════════════════════════════════════════════════════════
    // SyncStatusIndicator — Dot pulsant discret en haut-droite
    // ══════════════════════════════════════════════════════════════
    //
    // Raison d'être : l'utilisateur se plaignait que certaines actions
    // étaient ralenties sans comprendre pourquoi (PUT anonymisation,
    // sauvegarde classeur, drilldown, etc. — chacune prend 50-500ms
    // réseau). L'indicateur rend VISIBLE ces syncs invisibles.
    //
    // API :
    //   var token = indicator.begin("Sauvegarde classeur…")
    //   indicator.end(token, { error: true })  // ou omettre opts
    //
    // Le dot reste visible tant qu'au moins une op est active. Chaque op
    // a un TTL de sécurité de 10s : si le caller oublie ``end()``, le dot
    // s'efface quand même et on n'est pas coincé.

    function SyncStatusIndicator() {
        this._el = document.createElement('div');
        this._el.className = 'grid-sync-indicator';
        this._el.setAttribute('role', 'status');
        this._el.setAttribute('aria-live', 'polite');
        this._ops = Object.create(null); // token -> { label, safetyTimer }
        this._nextToken = 1;
        this._fadeTimer = null;
        this._errorResetTimer = null;
    }

    SyncStatusIndicator.prototype.getElement = function() {
        return this._el;
    };

    SyncStatusIndicator.prototype.begin = function(label) {
        var token = 'sync-' + (this._nextToken++);
        var self = this;
        var safetyTimer = setTimeout(function() {
            // Fallback : si ``end()`` n'est jamais appelé (erreur non-catchée,
            // promesse abandonnée), on libère le slot après SYNC_OP_TTL_MS.
            // Sinon le dot resterait éternellement.
            self.end(token);
        }, SYNC_OP_TTL_MS);
        this._ops[token] = {
            label: (typeof label === 'string' && label) ? label : 'Synchronisation…',
            safetyTimer: safetyTimer,
        };
        this._refresh();
        return token;
    };

    SyncStatusIndicator.prototype.end = function(token, opts) {
        var entry = this._ops[token];
        if (!entry) return;
        clearTimeout(entry.safetyTimer);
        delete this._ops[token];
        if (opts && opts.error) {
            this._el.classList.add('is-error');
            clearTimeout(this._errorResetTimer);
            var self = this;
            this._errorResetTimer = setTimeout(function() {
                self._el.classList.remove('is-error');
            }, SYNC_ERROR_FLASH_MS);
        }
        this._refresh();
    };

    SyncStatusIndicator.prototype._refresh = function() {
        var labels = [];
        for (var k in this._ops) {
            if (Object.prototype.hasOwnProperty.call(this._ops, k)) {
                labels.push(this._ops[k].label);
            }
        }
        if (labels.length > 0) {
            clearTimeout(this._fadeTimer);
            this._el.classList.add('is-active');
            // Tooltip détaillé au hover : l'utilisateur sait ce qui tourne.
            this._el.title = labels.join(' · ');
        } else {
            // Delay hide : si une nouvelle sync démarre dans les
            // SYNC_FADE_DELAY_MS, le dot reste visible en continu (moins
            // de flicker quand plusieurs syncs se succèdent rapidement).
            var self = this;
            clearTimeout(this._fadeTimer);
            this._fadeTimer = setTimeout(function() {
                if (Object.keys(self._ops).length === 0) {
                    self._el.classList.remove('is-active');
                    self._el.title = '';
                }
            }, SYNC_FADE_DELAY_MS);
        }
    };

    // ══════════════════════════════════════════════════════════════
    // Registre global des GridTabManager + flush beforeunload/pagehide
    // ══════════════════════════════════════════════════════════════
    //
    // Le debounce sur persistState + le debounce sur le PUT anonymisation
    // permettent de grouper les writes mais exposent un risque : si
    // l'utilisateur ferme la page pendant la fenêtre de debounce, les
    // données en attente sont perdues. Le flush beforeunload/pagehide les
    // écrit de force en utilisant ``fetch(..., { keepalive: true })`` —
    // la seule API qui garantit l'envoi pendant l'unload sans bloquer.
    //
    // Une page peut héberger plusieurs GridTabManager (iris.js en crée un
    // par message SQL). On installe UN listener global, et tous les
    // managers vivants s'y enregistrent. Évite de multiplier les listeners.

    var _activeManagers = [];
    var _unloadListenerInstalled = false;
    var _focusListenerInstalled = false;
    // Constantes de timing — centralisées pour éviter les magic numbers.
    var ANON_REFETCH_MIN_INTERVAL_MS = 30000; // 30s : ne refetch pas à chaque micro-focus
    // Backoff entre deux tentatives de fetch du state anonymisation après
    // un échec réseau (tâche #13). Assez court pour auto-guérir vite,
    // assez long pour ne pas marteler un serveur down depuis les renders.
    var ANON_FETCH_RETRY_BACKOFF_MS = 15000;
    var ANON_PERSIST_DEBOUNCE_MS = 300;       // conflation des toggles rapides
    var PERSIST_STATE_DEBOUNCE_MS = 500;      // localStorage write coalescing
    // Feature menu [+] « Requête SQL » : cap d'onglets SQL additionnels par
    // widget grille. MIROIR de app/models/dashboard.py:MAX_GRID_EXTRA_TABS —
    // la BDD reste l'autorité (validate() rejette au-delà) ; ce miroir ne sert
    // qu'à désactiver l'item de menu côté UX avant l'aller-retour réseau.
    var GRID_MAX_EXTRA_SQL_TABS = 10;
    // MIROIR de app/models/dashboard.py:MAX_GRID_TAB_LABEL_LEN — cap appliqué
    // au libellé d'un onglet SQL AVANT persistance pour que le backend ne
    // rejette jamais (400) un titre trop long saisi/collé localement.
    var GRID_MAX_EXTRA_TAB_LABEL_LEN = 100;
    var SYNC_OP_TTL_MS = 10000;               // safety : op abandonnée = dot auto-retiré
    var SYNC_FADE_DELAY_MS = 300;             // évite flicker si new sync arrive dans la foulée
    var SYNC_ERROR_FLASH_MS = 2000;           // durée du dot rouge avant reset
    var ANON_ERROR_TOAST_MS = 4000;           // durée du toast d'erreur anonymisation

    var _lastGlobalFocusRefetchTs = 0;        // throttle global du refetch sur focus

    // Manager est "vivant" si son conteneur parent existe toujours dans le
    // DOM. iris.js peut créer plusieurs GridTabManager par page (un par
    // message SQL) et ne pas explicitement les détruire ; ce check évite
    // d'itérer sur des managers zombies dont les DOM nodes ont été retirés.
    function _isManagerAlive(mgr) {
        return !!(mgr && mgr.parentContainer && document.contains(mgr.parentContainer));
    }

    // Purge les managers morts du registre (mutation in-place pour que le
    // caller voie la liste raccourcie). Appelée à chaque itération.
    function _pruneActiveManagers() {
        var i = _activeManagers.length;
        while (i--) {
            if (!_isManagerAlive(_activeManagers[i])) {
                _activeManagers.splice(i, 1);
            }
        }
    }

    function _flushAllManagersForUnload() {
        _pruneActiveManagers();
        for (var i = 0; i < _activeManagers.length; i++) {
            var mgr = _activeManagers[i];
            try { if (typeof mgr.flushPersistState === 'function') mgr.flushPersistState(); }
            catch (e) { /* best-effort */ }
            try {
                for (var j = 0; j < mgr.tabs.length; j++) {
                    var g = mgr.tabs[j].grid;
                    if (g && typeof g._flushAnonymizationPersist === 'function') {
                        g._flushAnonymizationPersist(true); // useBeacon=true (keepalive)
                    }
                }
            } catch (e) { /* best-effort */ }
            // Flush autosave en attente : si l'utilisateur quitte avec
            // un timer idle pending, on tente un dernier save synchrone
            // via fetch keepalive (sendBeacon-equivalent). Best-effort,
            // ne bloque jamais l'unload.
            try {
                if (typeof mgr._flushAutosaveOnUnload === 'function') {
                    mgr._flushAutosaveOnUnload();
                }
            } catch (e) { /* best-effort */ }
        }
    }

    /**
     * Beforeunload guard : declenche la modale native "Voulez-vous
     * vraiment quitter ?" UNIQUEMENT si l'utilisateur a vraiment quelque
     * chose a perdre. Trois cas legitimes (OR) :
     *   1. Iris streame ou est en train de travailler sur un tour
     *      (``window.__irisStreamingActive``) ;
     *   2. Un copilot agent tourne sur AU MOINS une grille
     *      (``window.__copilotRunsActive > 0``) ;
     *   3. Un classeur NOMME (``mgr._currentFilePath`` non null) a des
     *      edits non sauves (``mgr._dirty``) -- protection style Excel
     *      pour de vraies donnees confiees a un fichier.
     *
     * Les classeurs transitoires (resultat Iris affiche dans le chat
     * sans path) NE declenchent PAS le warning meme s'ils sont marques
     * dirty (cas typique : Iris emit un onglet via emit_tab, ce qui
     * passe par _setDirty(true)). L'AutoRecover localStorage couvre la
     * perte accidentelle dans la mesure du possible.
     *
     * Pattern standard ``event.returnValue = ''`` (les navigateurs
     * modernes ignorent le texte custom -- volontaire, empeche les
     * sites malveillants de bloquer la navigation).
     */
    function _beforeUnloadDirtyGuard(event) {
        _pruneActiveManagers();

        // Lecture stricte des deux flags globaux : un type non-numerique
        // ou negatif est traite comme "0/false" sans declencher de
        // warning (au cas ou un dev poserait un getter custom).
        var irisActive = (typeof window !== 'undefined' &&
            !!window.__irisStreamingActive);
        var copilotCount = (typeof window !== 'undefined' &&
            typeof window.__copilotRunsActive === 'number')
            ? window.__copilotRunsActive : 0;
        var copilotActive = copilotCount > 0;

        var hasNamedDirtyWorkbook = false;
        for (var i = 0; i < _activeManagers.length; i++) {
            var mgr = _activeManagers[i];
            if (mgr && mgr._dirty && mgr._currentFilePath) {
                hasNamedDirtyWorkbook = true;
                break;
            }
        }

        if (irisActive || copilotActive || hasNamedDirtyWorkbook) {
            // Standard browser API for "are you sure?" dialog.
            event.preventDefault();
            event.returnValue = '';
            return '';
        }
    }

    function _registerManagerForUnloadFlush(mgr) {
        _activeManagers.push(mgr);
        if (!_unloadListenerInstalled) {
            _unloadListenerInstalled = true;
            // ``pagehide`` est plus fiable que ``beforeunload`` sur mobile
            // (Safari iOS notamment). On écoute les deux : le premier qui tire
            // vide les pending, le second trouve rien à flusher.
            window.addEventListener('pagehide', _flushAllManagersForUnload);
            window.addEventListener('beforeunload', _flushAllManagersForUnload);
            // Listener SÉPARÉ pour le guard dirty : on ne peut pas le
            // mettre dans ``_flushAllManagersForUnload`` car le flush
            // doit toujours s'exécuter (best-effort save), tandis que
            // le guard ne fire que quand dirty=true. Deux concerns
            // distincts, deux listeners.
            window.addEventListener('beforeunload', _beforeUnloadDirtyGuard);
        }
        if (!_focusListenerInstalled) {
            _focusListenerInstalled = true;
            // Quand la page reprend le focus, refetch le state anon si
            // le dernier fetch > 30s. Utile si un autre device du même
            // user a changé la config : sans refetch, la grille bosse
            // avec un cache stale.
            //
            // Throttle GLOBAL (pas per-grid) : le focus fire plusieurs
            // fois par context switch (window, iframe, devtools) — un
            // throttle module-level évite N×M fetches par event.
            // Skip aussi si un PUT est pending : il pushera l'état correct.
            window.addEventListener('focus', function() {
                var now = Date.now();
                if (now - _lastGlobalFocusRefetchTs < ANON_REFETCH_MIN_INTERVAL_MS) return;
                _lastGlobalFocusRefetchTs = now;
                _pruneActiveManagers();
                for (var i = 0; i < _activeManagers.length; i++) {
                    var m = _activeManagers[i];
                    try {
                        for (var j = 0; j < m.tabs.length; j++) {
                            var g = m.tabs[j].grid;
                            if (!g || typeof g._fetchAnonymizationState !== 'function') continue;
                            // Skip si une écriture est en cours : sa réponse
                            // apportera déjà l'état serveur à jour.
                            if (g._anonPersistPending) continue;
                            var lastTs = g._anonymizationLastFetchTs || 0;
                            if (now - lastTs < ANON_REFETCH_MIN_INTERVAL_MS) continue;
                            // Force un nouveau fetch. L'ancien (si encore en vol)
                            // sera ignoré via _anonFetchSeq dans _fetchAnonymizationState.
                            if (typeof g._invalidateAnonymizationCache === 'function') {
                                g._invalidateAnonymizationCache();
                            }
                            g._fetchAnonymizationState();
                        }
                    } catch (e) { /* defensive */ }
                }
            });
        }
    }

    // ══════════════════════════════════════════════════════════════
    // GridTabManager — Persistent tab system wrapping SqlResultGrid
    // ══════════════════════════════════════════════════════════════

    function GridTabManager(parentContainer) {
        this.parentContainer = parentContainer;
        this.tabs = []; // { id, label, containerEl, grid, closable }
        this.activeTabIndex = 0;
        this._nextId = 0;
        this._searchTimer = null;

        // Workbook-level undo/redo history
        this._wbHistory = null; // initialized after first tab is added
        this._wbSnapshotTimer = null;

        // Save state — tracks the current file path for "Enregistrer" (overwrite)
        this._currentFilePath = null; // set when loading or saving a workbook

        // ETag (SHA-256 du contenu sur disque) — utilisé comme version
        // optimiste pour détecter les conflits cross-tab. Set après load
        // ou save success. Envoyé au backend via header ``If-Match`` au
        // prochain save ; backend retourne 412 si le hash a changé entre
        // temps (autre tab qui a écrit). Null = pas de garantie de
        // version (premier save d'un nouveau classeur).
        this._currentFileHash = null;

        // Dirty flag — true dès qu'une modification du classeur a eu
        // lieu sans qu'un save success ne l'ait reset. Reflété dans le
        // titre de la page (``Mon classeur* — Komptia``) à la façon
        // d'Excel. Reset après save manuel ou autosave réussi. Empêche
        // un beforeunload silencieux.
        this._dirty = false;

        // Autosave — timer périodique 60s + idle flush 10s + flush au
        // unload. Skipped tant que ``_currentFilePath`` est null (Excel
        // ne sauve pas un classeur sans destination ; on bascule sur
        // l'AutoRecover localStorage à la place). Single-flight pour
        // empêcher deux saves concurrents (race manuel/auto).
        this._autosavePeriodicTimer = null;
        this._autosaveIdleTimer = null;
        this._autosaveSaving = false;
        this._autosaveQueued = false;
        this._autosaveFailureCount = 0;
        this._autosaveDisabled = false; // par classeur, en runtime
        // Intervalles configurables via constantes (cohérent code base).
        this._AUTOSAVE_PERIODIC_MS = 60_000;
        this._AUTOSAVE_IDLE_MS = 10_000;
        this._AUTOSAVE_MAX_FAILURES = 5;

        // Mémoire copilot inter-runs (par classeur). Cleartext, ≤ 2000 chars.
        // Chargée depuis la racine du .afz.json au load, renvoyée par le
        // backend dans `copilot_memory_new` à chaque run réussi, persistée
        // au prochain save.
        this._copilotMemory = '';

        // Multi-select tabs (Ctrl+click)
        this._selectedTabs = new Set(); // indices of selected tabs

        // Indicateur discret de synchronisation (dot pulsant en haut-droite).
        // Rend visibles les opérations de fond (PUT anonymisation, save
        // classeur, drilldown, etc.) qui, sans indicateur, donnent juste
        // une impression de lag inexpliquée à l'utilisateur.
        this._syncIndicator = new SyncStatusIndicator();

        // Debounce de ``persistState`` : au lieu d'un write localStorage
        // à chaque mutation (qui triggait un JSON.stringify complet du
        // classeur sur 30 onglets = 50-150ms), on attend 500ms de calme.
        this._persistStateTimer = null;
        this._persistStatePending = false;

        // Register pour le flush beforeunload/pagehide global.
        _registerManagerForUnloadFlush(this);

        // DOM
        this.tabBarEl = document.createElement('div');
        this.tabBarEl.className = 'grid-tab-bar';
        this.tabBarEl.style.display = 'none';
        this.searchBarEl = this._buildSearchBar();
        this.contentEl = document.createElement('div');
        this.contentEl.className = 'grid-tab-content';
        this.parentContainer.appendChild(this.tabBarEl);
        this.parentContainer.appendChild(this.searchBarEl);
        this.parentContainer.appendChild(this.contentEl);
    }

    /**
     * T12c — teardown UNIQUE d'un manager (appelé avant remplacement sur le
     * dashboard ou fin de vie). Ferme : (1) les timers persistState/autosave/
     * scan, (2) les listeners ``document`` des grilles enfants (cf.
     * SqlResultGrid.destroy — le mouseup ferme sur toute la grille → fuite
     * cross-instance sous re-render répété), (3) la référence dans le registre
     * ``_activeManagers`` (sinon le manager mort y reste jusqu'au prochain
     * passage de ``_isManagerAlive``). Best-effort + idempotent.
     */
    GridTabManager.prototype.destroy = function() {
        try {
            if (this._persistStateTimer) { clearTimeout(this._persistStateTimer); this._persistStateTimer = null; }
            if (this._autosavePeriodicTimer) { clearInterval(this._autosavePeriodicTimer); this._autosavePeriodicTimer = null; }
            if (this._anonScanTimer) { clearTimeout(this._anonScanTimer); this._anonScanTimer = null; }
        } catch (e) { /* defensive */ }
        if (this._searchOutsideHandler) {
            document.removeEventListener('mousedown', this._searchOutsideHandler);
            this._searchOutsideHandler = null;
        }
        try {
            for (var i = 0; i < this.tabs.length; i++) {
                var g = this.tabs[i] && this.tabs[i].grid;
                if (g && typeof g.destroy === 'function') g.destroy();
            }
        } catch (e2) { /* best-effort cleanup */ }
        var idx = _activeManagers.indexOf(this);
        if (idx !== -1) _activeManagers.splice(idx, 1);
    };

    /**
     * Capture un snapshot du classeur pour l'historique undo/redo.
     * Debounced à 500ms pour éviter les rafales.
     */
    GridTabManager.prototype.snapshotWorkbook = function() {
        var self = this;
        clearTimeout(this._wbSnapshotTimer);
        this._wbSnapshotTimer = setTimeout(function() {
            if (!self.tabs.length) return;
            var state = self.serialize();
            if (!self._wbHistory) {
                self._wbHistory = new ResultHistory(state);
            } else {
                self._wbHistory.push(state);
            }
            self._updateAllUndoRedoButtons();
            // Toute mutation = classeur dirty, asterisk dans le titre.
            // Décliché aussi un autosave différé sur idle (debounce
            // 10s — laisse l'utilisateur finir sa frappe avant de
            // sauver). Le timer periodique 60s reste en parallèle pour
            // les longues sessions d'édition continue.
            // En parallèle, on écrit un snapshot local AutoRecover
            // (filet de sécurité si l'autosave backend échoue ou si
            // le navigateur crashe avant le prochain flush).
            if (!self._restoringState) {
                self._setDirty(true);
                self._scheduleIdleAutosave();
                self._writeAutoRecover();
            }
        }, 500);
    };

    GridTabManager.prototype.workbookUndo = function() {
        if (!this._wbHistory) return;
        var state = this._wbHistory.undo();
        if (state) {
            this._restoreWorkbookState(state);
            this._updateAllUndoRedoButtons();
        }
    };

    GridTabManager.prototype.workbookRedo = function() {
        if (!this._wbHistory) return;
        var state = this._wbHistory.redo();
        if (state) {
            this._restoreWorkbookState(state);
            this._updateAllUndoRedoButtons();
        }
    };

    GridTabManager.prototype._restoreWorkbookState = function(state) {
        // Use loadWorkbook but preserve the history (don't re-snapshot)
        this._restoringState = true;
        this.loadWorkbook(state);
        this._restoringState = false;
        // Feature « feuilles SQL » : un undo/redo peut RESTAURER l'externalSource.query
        // d'une feuille (annuler une édition SQL). Sans re-sync, le serveur garderait
        // le SQL POST-édition → après edit→undo→refresh le backend ré-exécuterait
        // l'ancien SQL (donnée fausse silencieuse, contredit ce que l'user voit).
        // _notifySqlTabsChanged est no-op hors dashboard (_sqlTabContext absent) et
        // dédupé par signature (no-op si la liste {label,query} n'a pas changé).
        this._notifySqlTabsChanged();
    };

    GridTabManager.prototype._updateAllUndoRedoButtons = function() {
        var canUndo = this._wbHistory && this._wbHistory.canUndo();
        var canRedo = this._wbHistory && this._wbHistory.canRedo();
        for (var i = 0; i < this.tabs.length; i++) {
            var grid = this.tabs[i].grid;
            if (grid) {
                if (grid._copilotUndoBtn) grid._copilotUndoBtn.disabled = !canUndo;
                if (grid._copilotRedoBtn) grid._copilotRedoBtn.disabled = !canRedo;
            }
        }
    };

    GridTabManager.prototype._buildSearchBar = function() {
        var self = this;
        var bar = document.createElement('div');
        bar.className = 'grid-global-search';
        bar.style.display = 'none';

        var wrap = document.createElement('div');
        wrap.className = 'grid-global-search-wrap';

        var input = document.createElement('input');
        input.type = 'text';
        input.className = 'grid-global-search-input';
        input.placeholder = 'Rechercher dans tous les onglets\u2026';
        wrap.appendChild(input);

        var clearBtn = document.createElement('button');
        clearBtn.type = 'button';
        clearBtn.className = 'grid-global-search-clear';
        clearBtn.textContent = '\u00d7';
        clearBtn.addEventListener('click', function() {
            input.value = '';
            self._closeSearchResults();
        });
        wrap.appendChild(clearBtn);
        bar.appendChild(wrap);

        var dropdown = document.createElement('div');
        dropdown.className = 'grid-global-search-results';
        dropdown.style.display = 'none';
        bar.appendChild(dropdown);

        this._searchInput = input;
        this._searchDropdown = dropdown;

        input.addEventListener('input', function() {
            clearTimeout(self._searchTimer);
            var q = input.value.trim();
            if (q.length < 2) { self._closeSearchResults(); return; }
            self._searchTimer = setTimeout(function() { self._performSearch(q); }, 250);
        });

        input.addEventListener('keydown', function(e) {
            if (e.key === 'Escape') { input.value = ''; self._closeSearchResults(); }
        });

        // Close dropdown on outside click. Handler STOCKÉ (T12c) sur le manager
        // → retiré dans destroy() (sinon ce listener ``document`` garde le manager
        // + la search bar vivants après remplacement du widget dashboard).
        this._searchOutsideHandler = function(e) {
            if (!bar.contains(e.target)) self._closeSearchResults();
        };
        document.addEventListener('mousedown', this._searchOutsideHandler);

        return bar;
    };

    GridTabManager.prototype._performSearch = function(query) {
        var q = query.toLowerCase();
        var results = [];
        var MAX = 50;

        for (var t = 0; t < this.tabs.length && results.length < MAX; t++) {
            var tab = this.tabs[t];
            var grid = tab.grid;
            if (!grid) continue;

            var tabResults = { tabIndex: t, label: tab.label, matches: [] };

            // Search column names
            for (var c = 0; c < grid.columns.length && results.length + tabResults.matches.length < MAX; c++) {
                if (grid.columns[c].toLowerCase().indexOf(q) !== -1) {
                    tabResults.matches.push({ type: 'column', colIndex: c, colName: grid.columns[c] });
                }
            }

            // Search cell values (displayRows, limit scan)
            var scanLimit = Math.min(grid.displayRows.length, 2000);
            for (var r = 0; r < scanLimit && results.length + tabResults.matches.length < MAX; r++) {
                var row = grid.displayRows[r];
                for (var j = 0; j < grid.columns.length; j++) {
                    var val = grid.isArrayFormat ? row[j] : row[grid.columns[j]];
                    if (val != null && String(val).toLowerCase().indexOf(q) !== -1) {
                        tabResults.matches.push({
                            type: 'cell', rowIndex: r, colIndex: j,
                            colName: grid.columns[j], value: String(val)
                        });
                        break; // one match per row is enough
                    }
                }
            }

            if (tabResults.matches.length > 0) results.push(tabResults);
        }

        this._showSearchResults(results);
    };

    GridTabManager.prototype._showSearchResults = function(results) {
        var self = this;
        var dd = this._searchDropdown;
        dd.innerHTML = '';

        if (results.length === 0) {
            dd.innerHTML = '<div class="grid-search-no-result">Aucun résultat</div>';
            dd.style.display = '';
            return;
        }

        for (var i = 0; i < results.length; i++) {
            (function(group) {
                var header = document.createElement('div');
                header.className = 'grid-search-group-header';
                header.textContent = group.label;
                dd.appendChild(header);

                for (var m = 0; m < group.matches.length; m++) {
                    (function(match) {
                        var item = document.createElement('div');
                        item.className = 'grid-search-result-item';

                        var tabHint = '<span class="grid-search-tab-hint">' + _escHtml(group.label) + '</span> ';
                        if (match.type === 'column') {
                            item.innerHTML = tabHint + '<span class="grid-search-badge">col</span> ' + _escHtml(match.colName);
                        } else {
                            var short = match.value.length > 40 ? match.value.substring(0, 40) + '\u2026' : match.value;
                            item.innerHTML = tabHint + '<span class="grid-search-badge">ligne ' + (match.rowIndex + 1) + '</span> '
                                + _escHtml(short) + ' <span class="grid-search-col-hint">(' + _escHtml(match.colName) + ')</span>';
                        }

                        item.addEventListener('click', function() {
                            self._switchTab(group.tabIndex);
                            self._closeSearchResults();
                            if (match.type === 'cell') {
                                self._highlightCell(group.tabIndex, match.rowIndex, match.colIndex);
                            }
                        });
                        dd.appendChild(item);
                    })(group.matches[m]);
                }
            })(results[i]);
        }

        dd.style.display = '';
    };

    GridTabManager.prototype._closeSearchResults = function() {
        if (this._searchDropdown) this._searchDropdown.style.display = 'none';
    };

    GridTabManager.prototype._highlightCell = function(tabIndex, rowIndex, colIndex) {
        var tab = this.tabs[tabIndex];
        if (!tab || !tab.grid || !tab.grid.tbodyEl) return;

        var rows = tab.grid.tbodyEl.querySelectorAll('tr');
        if (rowIndex >= rows.length) return;

        var tr = rows[rowIndex];
        tr.scrollIntoView({ behavior: 'smooth', block: 'center' });
        tr.classList.add('grid-row-highlight');
        setTimeout(function() { tr.classList.remove('grid-row-highlight'); }, 2000);
    };

    // Prépare les cellDetails d'une feuille IMPORTÉE depuis un autre classeur
    // (« Ajouter feuilles externes… »). Copie superficielle entrée par entrée
    // avec ``source_tab_index`` neutralisé : cet index référence l'ordre des
    // onglets du classeur SOURCE — dans le classeur de destination il pointerait
    // un onglet arbitraire (reconstruction de détail plausible-mais-fausse à
    // l'export). À null, ``_reconstructDetailRowsFromMatch`` retombe sur son
    // auto-détection par couverture de colonnes, valide quel que soit l'hôte.
    // ``rowCount`` = nb de lignes réellement importées : les clés "row,col"
    // au-delà (source tronquée par tab-data max_rows) sont des détails
    // orphelins jamais atteignables → drop pour rester cohérent.
    // Fail-soft : input non-dict → null (l'import continue sans cellDetails).
    // NB cohérence : les shapes « slim » de _captureState (~5100) et
    // serialize() (~16230) allowlistent les champs ; ici on copie tout-venant
    // car la source est le format .afz déjà slim — ``source_tab_index`` est à
    // ce jour le SEUL champ relatif au classeur source à neutraliser. Si un
    // futur champ devient source-relatif, le traiter aux TROIS endroits.
    function _sanitizeImportedCellDetails(cd, rowCount) {
        if (!cd || typeof cd !== 'object' || Array.isArray(cd)) return null;
        var maxRow = (typeof rowCount === 'number' && rowCount >= 0) ? rowCount : null;
        var out = {};
        var has = false;
        for (var k in cd) {
            if (!cd.hasOwnProperty(k)) continue;
            // Clés magiques JS : jamais des coordonnées "row,col" légitimes,
            // et assigner out['__proto__'] remplacerait le prototype de out.
            if (k === '__proto__' || k === 'constructor' || k === 'prototype') continue;
            var d = cd[k];
            if (!d || typeof d !== 'object' || Array.isArray(d)) continue;
            if (maxRow !== null) {
                var rowIdx = parseInt(String(k).split(',')[0], 10);
                if (!isNaN(rowIdx) && rowIdx >= maxRow) continue;
            }
            var copy = {};
            for (var f in d) {
                if (!d.hasOwnProperty(f)) continue;
                if (f === '__proto__' || f === 'constructor' || f === 'prototype') continue;
                copy[f] = d[f];
            }
            copy.source_tab_index = null;
            out[k] = copy;
            has = true;
        }
        return has ? out : null;
    }

    GridTabManager.prototype.addTab = function(label, columns, rows, sql, rowCount, metadata, closable) {
        var self = this;
        var id = this._nextId++;
        var containerEl = document.createElement('div');
        containerEl.className = 'grid-tab-panel';
        containerEl.style.display = 'none';
        this.contentEl.appendChild(containerEl);

        // Extended metadata: callers can pass {columnMetadata, merges, externalSource,
        // cellDetails} or just the raw columnMetadata dict (legacy). NB : la
        // détection du format étendu reste volontairement sur les 3 clés
        // historiques — ``cellDetails`` n'est lu QUE dans la branche détectée
        // (pas de nouveau mot-clé qui pourrait collisionner avec un nom de
        // colonne d'un dict columnMetadata legacy).
        var gridColumnMetadata = metadata;
        var gridMerges = null;
        var externalSource = null;
        var initialCellDetails = null;
        if (metadata && typeof metadata === 'object' && !Array.isArray(metadata)
            && (metadata.hasOwnProperty('merges')
                || metadata.hasOwnProperty('externalSource')
                || metadata.hasOwnProperty('columnMetadata'))) {
            gridColumnMetadata = metadata.columnMetadata || null;
            gridMerges = Array.isArray(metadata.merges) ? metadata.merges : null;
            externalSource = metadata.externalSource || null;
            initialCellDetails = (metadata.cellDetails
                && typeof metadata.cellDetails === 'object'
                && !Array.isArray(metadata.cellDetails))
                ? metadata.cellDetails : null;
        }

        var grid = null;
        try {
            grid = new SqlResultGrid(containerEl, columns, rows, sql, rowCount, gridColumnMetadata, {
                onDrillResult: function(data) { self._handleDrillResult(data); },
                onNewTab: function(lbl, cols, rws, newSql, cnt) {
                    self.addTabSilent(lbl, cols, rws, newSql, cnt, null);
                    // Retourne l'index du nouvel onglet (dernier ajouté) — utile pour
                    // les appels qui ont besoin de référencer la nouvelle grille
                    // (ex: clone_sheet avec new_tab=true).
                    return self.tabs.length - 1;
                },
                onDetailTab: function(lbl, cols, rws, newSql, cnt) {
                    // Ouvrir le détail ET naviguer dessus
                    self.addTab(lbl, cols, rws, newSql, cnt, null, true);
                },
                getTabsContext: function() { return self._getTabsContext(); },
                // ── Mode "workbook by reference" pour le copilot ──
                // Le copilot peut traiter des classeurs gigantesques sans
                // saturer le body POST si on lui passe un `workbook_path`
                // (rel_path dans le datastore user) au lieu du `tabs_context`
                // inline. Le backend lira le `.afz.json` directement. Pour
                // que ce path reflète l'état COURANT (et non la dernière
                // sauvegarde manuelle), la grille déclenchera une sauvegarde
                // synchrone via `saveWorkbookBeforeCopilot` juste avant
                // l'appel.
                getWorkbookPath: function() { return self.getWorkbookPath(); },
                saveWorkbookBeforeCopilot: function() { return self.saveWorkbookAsync(); },
                getTabGrid: function(idx) { return (self.tabs[idx] && self.tabs[idx].grid) || null; },
                // Mutations d'onglets programmatiques (appelées par les
                // handlers copilot_agent : rename_tab/delete_tab). onRenameTab
                // renvoie true en succès, false si idx hors bornes ou label
                // vide ; onDeleteTab renvoie true en succès, false si idx
                // invalide ou dernier onglet (sanity — au moins 1 toujours).
                onRenameTab: function(idx, newLabel) {
                    return self.setTabLabelProgrammatic(idx, newLabel);
                },
                onDeleteTab: function(idx) {
                    return self.deleteTabProgrammatic(idx);
                },
                onReplaceTabContent: function(idx, payload) {
                    return self.replaceTabContentProgrammatic(idx, payload);
                },
                // Feature « feuilles SQL » : quand l'user édite le SQL de CETTE
                // feuille via le bouton "Modifier & réexécuter" de la grille, on
                // remonte la requête D'ORIGINE saisie pour mettre à jour la
                // feuille + persister (dédup). ``id`` identifie la feuille (≠ idx
                // qui bouge au réordonnancement).
                onSqlAuthored: function(newSql) {
                    self._handleTabSqlAuthored(id, newSql);
                },
                tabLabel: label,
                fullscreenTarget: self.parentContainer,
                onStateChange: function() { self.persistState(); },
                // Workbook-level undo/redo (replaces per-grid history)
                onUndo: function() { self.workbookUndo(); },
                onRedo: function() { self.workbookRedo(); },
                onSnapshot: function() { if (!self._restoringState) self.snapshotWorkbook(); },
                onSave: function() { self.saveWorkbook(); },
                // Mémoire copilot : owned par le GridTabManager (racine
                // du classeur), NON per-tab. La grille lit via un GETTER
                // dynamique pour qu'une MAJ depuis un autre onglet du
                // même classeur soit visible immédiatement. `onCopilotMemoryChange`
                // remonte une nouvelle version côté Manager + flag dirty.
                getCopilotMemory: function() { return self._copilotMemory || ''; },
                onCopilotMemoryChange: function(newMem) {
                    self._copilotMemory = newMem || '';
                    if (!self._restoringState) { self.snapshotWorkbook(); }
                },
                // Callbacks de synchronisation : la grille signale toute op
                // réseau (PUT anonymisation, etc.) au manager qui pilote
                // l'indicateur visuel. Shape :
                //   onSyncBegin(label) -> token
                //   onSyncEnd(token, { error: bool })
                onSyncBegin: function(label) {
                    return self._syncIndicator.begin(label);
                },
                onSyncEnd: function(token, opts) {
                    self._syncIndicator.end(token, opts);
                },
                merges: gridMerges,
                // Provenance de la feuille — la grille en a besoin DÈS la
                // construction (gate de l'auto-analyze GROUP BY) pour
                // distinguer feuille SQL vivante / snapshot importé.
                externalSource: externalSource
            });
            if (grid && gridMerges && gridMerges.length > 0) {
                grid.setMerges(gridMerges);
                grid._rebuildBody();
                grid._updateHeaderInfo();
            }
        } catch (err) {
            console.error('[TabManager] Grid creation error:', err);
            containerEl.innerHTML = '<div class="iris-no-results">Erreur d\'affichage</div>';
        }

        // cellDetails initiaux (import « Ajouter feuilles externes… » : SQL par
        // cellule du classeur source). Posés AVANT le snapshotWorkbook plus bas
        // pour que le premier snapshot undo de l'onglet les contienne — une
        // assignation après le retour d'addTab laisserait un snapshot amputé
        // (un undo+redo perdrait les SQL de cellules silencieusement).
        if (grid && initialCellDetails) {
            grid._cellDetails = initialCellDetails;
        }

        var tabInfo = {
            id: id,
            label: label,
            containerEl: containerEl,
            grid: grid,
            closable: closable !== false,
            noSwitch: false,
            externalSource: externalSource
        };
        this.tabs.push(tabInfo);
        this._renderTabBar();
        if (!tabInfo.noSwitch) this._switchTab(this.tabs.length - 1);

        // Snapshot workbook state after adding a tab
        if (!this._restoringState) this.snapshotWorkbook();

        // 2026-05-19 — Anonymisation : le scan tire UNIQUEMENT depuis les
        // cellules VISIBLES dans la grille (= classeurs ouverts par l'user
        // dans /iris, /datastore, preview automation). Les hooks backend
        // qui scannaient TOUTES les exécutions SQL d'Iris en background
        // (agent_tools.execute_sql, preview_service.preview_step) ont été
        // retirés — ils insèraient des termes invisibles à l'user (GUIDs,
        // colonnes techniques) en BDD.
        //
        // Trigger frontend au lieu :
        //  - À l'ouverture d'un classeur datastore (cf. _loadWorkbookFromDatastore)
        //  - ICI à chaque ``addTab`` avec rows non-vides — couvre tous
        //    les chemins où l'user voit des données affichées : résultats
        //    Iris, previews automation, imports xlsx, etc.
        //  - À chaque ``_setDirty(true)`` (édition) — debounce 2.5s
        //
        // Pas de doublon : ``_scheduleAnonymizationScan`` debounce 2.5s
        // donc plusieurs addTab successifs (chargement multi-onglets)
        // produisent un seul scan.
        if (
            !this._restoringState
            && Array.isArray(rows)
            && rows.length > 0
            && typeof this._scheduleAnonymizationScan === 'function'
        ) {
            this._scheduleAnonymizationScan();
        }

        return tabInfo;
    };

    GridTabManager.prototype.addTabSilent = function(label, columns, rows, sql, rowCount, metadata) {
        var previousIdx = this.activeTabIndex;
        var info = this.addTab(label, columns, rows, sql, rowCount, metadata, true);
        this._switchTab(previousIdx);
        return info;
    };

    // ──────────────────────────────────────────────────────────────────────
    // Feature menu [+] « Requête SQL » (widgets grille de dashboard)
    //
    // Un onglet « Requête SQL » est un onglet normal portant son SQL +
    // externalSource:{type:'sql_query', query}. Côté dashboard il est PERSISTÉ
    // dans la config du widget et RÉ-EXÉCUTÉ par le backend à CHAQUE affichage
    // (toujours frais, survit au refresh sans snapshot ni localStorage). Le
    // contexte d'autorisation + la persistance sont injectés par renderIrisGrid
    // (builder_view.html) via ``this._sqlTabContext = {canAuthor, persist}``.
    // Hors dashboard (/iris, /datastore), _sqlTabContext est absent → l'item de
    // menu n'apparaît pas (feature dashboard-only, menu partagé non régressé).
    // ──────────────────────────────────────────────────────────────────────

    // Liste {label, query} des onglets « Requête SQL » courants, dans l'ordre.
    // Source de vérité de ce qui est persisté côté serveur.
    GridTabManager.prototype._collectSqlQueryTabs = function() {
        var out = [];
        for (var i = 0; i < this.tabs.length; i++) {
            var t = this.tabs[i];
            var src = t && t.externalSource;
            if (src && src.type === 'sql_query' && typeof src.query === 'string') {
                // Cap du libellé au point UNIQUE où il devient le payload de
                // persistance → le backend (validate, max 100) ne rejette jamais
                // un titre trop long quelle que soit la voie (rename interactif,
                // copilot, collage). Évite la divergence local↔serveur (400).
                var lbl = String(t.label == null ? '' : t.label);
                if (lbl.length > GRID_MAX_EXTRA_TAB_LABEL_LEN) {
                    lbl = lbl.slice(0, GRID_MAX_EXTRA_TAB_LABEL_LEN);
                }
                out.push({ label: lbl, query: src.query });
            }
        }
        return out;
    };

    // Re-persiste la liste courante d'onglets SQL via le contexte dashboard.
    // No-op hors dashboard. **Idempotente / dédupliquée par signature** : ne
    // déclenche un PUT QUE si la liste {label, query} des onglets SQL a
    // réellement changé. On peut donc l'appeler après N'IMPORTE quelle mutation
    // d'onglet (close, rename, bulk-close, delete programmatique) sans PUT
    // parasite pour les onglets non-SQL (drill-down, feuilles externes).
    // Optimiste : la mutation locale a déjà eu lieu ; en cas d'échec serveur on
    // restaure la signature précédente pour ré-essayer au prochain changement
    // (le builder remonte déjà un toast d'erreur). La baseline initiale est
    // posée par renderIrisGrid après chargement des onglets du backend.
    GridTabManager.prototype._notifySqlTabsChanged = function() {
        var ctx = this._sqlTabContext;
        if (!ctx || !ctx.canAuthor || typeof ctx.persist !== 'function') return;
        var self = this;
        var list = this._collectSqlQueryTabs();
        var sig = JSON.stringify(list);
        if (sig === this._lastPersistedSqlTabsSig) return;
        var prevSig = this._lastPersistedSqlTabsSig;
        this._lastPersistedSqlTabsSig = sig;  // optimiste
        this._enqueueSqlTabsPut(list).then(function(ok) {
            // Échec → restaure la signature pour ré-essayer au prochain changement.
            if (!ok) self._lastPersistedSqlTabsSig = prevSig;
        });
    };

    // Enfile un PUT de ``list`` sur une CHAÎNE de promesses sérialisée. Garantit
    // que deux mutations rapprochées (rename + close, drag, ajout) émettent
    // leurs PUT DANS L'ORDRE — le dernier état gagne côté serveur. Sans ça, deux
    // fetch PUT concurrents non ordonnés pouvaient committer dans le désordre,
    // le PÉRIMÉ en dernier (race « out-of-order PUT », ``set_widget_extra_tabs``
    // fait un remplacement complet sans contrôle de version). La chaîne avance
    // même sur échec (un PUT raté ne bloque pas les suivants). Retourne une
    // Promise<bool> (ok) résolue quand CE maillon a été traité, dans l'ordre.
    GridTabManager.prototype._enqueueSqlTabsPut = function(list) {
        var ctx = this._sqlTabContext;
        if (!ctx || !ctx.canAuthor || typeof ctx.persist !== 'function') {
            return Promise.resolve(false);
        }
        var prev = this._sqlTabsPutChain || Promise.resolve();
        var result = prev.then(function() { return ctx.persist(list); });
        this._sqlTabsPutChain = result.then(function() {}, function() {});
        return result.then(
            function(ok) { return ok !== false; },
            function() { return false; }
        );
    };

    // Feature « feuilles SQL » : l'édition du SQL d'une feuille (bouton
    // "Modifier & réexécuter" de la grille) met à jour la requête PERSISTÉE de
    // cette feuille + déclenche la sauvegarde (dédupée par signature). On
    // identifie la feuille par son ``id`` stable (≠ index, qui bouge au
    // réordonnancement). ``newSql`` = requête D'ORIGINE saisie par l'user
    // (jamais filtre-wrappée). No-op pour une feuille non-SQL (drill-down,
    // feuille externe sans externalSource) ou hors dashboard.
    GridTabManager.prototype._handleTabSqlAuthored = function(id, newSql) {
        if (typeof newSql !== 'string') return;
        for (var i = 0; i < this.tabs.length; i++) {
            var t = this.tabs[i];
            if (t && t.id === id) {
                var src = t.externalSource;
                if (src && src.type === 'sql_query') {
                    src.query = newSql;
                    this._notifySqlTabsChanged();
                }
                return;
            }
        }
    };

    // Ouvre l'éditeur SQL pour créer un nouvel onglet « Requête SQL ».
    // Flux PERSIST-FIRST : on exécute (preview via l'éditeur), on persiste la
    // nouvelle liste côté serveur, et SEULEMENT si la persistance réussit on
    // ajoute l'onglet localement — la BDD reste la source de vérité (pas
    // d'onglet fantôme non sauvegardé qui disparaîtrait au refresh suivant).
    GridTabManager.prototype._openSqlQueryTab = function() {
        var self = this;
        var ctx = self._sqlTabContext;
        if (!ctx || !ctx.canAuthor || typeof ctx.persist !== 'function') return;
        if (typeof window.openSqlEditorModal !== 'function') {
            if (typeof window.showToast === 'function') {
                window.showToast("Éditeur SQL non chargé.", 'error');
            }
            return;
        }
        window.openSqlEditorModal({
            sql: '',
            filename: null,
            allowSave: false,
            title: 'Nouvel onglet : Requête SQL',
            hint: 'Cette requête sera ré-exécutée à chaque affichage du widget '
                + '(données toujours fraîches). Lecture seule — SELECT/WITH.',
            onSuccess: function(result) {
                if (!result || typeof result.sql !== 'string' || !result.sql.trim()) return;
                // Numérote d'après les feuilles ADDITIONNELLES (exclut la
                // principale de confiance, collectée) → la 1ère feuille créée par
                // l'user = « Requête 1 », pas « Requête 2 ».
                var label = 'Requête '
                    + (self._collectSqlQueryTabs().length
                        - (self._primarySheetTrusted ? 1 : 0) + 1);
                var candidate = self._collectSqlQueryTabs().concat([
                    { label: label, query: result.sql }
                ]);
                // PERSIST-FIRST via la CHAÎNE sérialisée (ordonnée vis-à-vis
                // d'un éventuel rename/close en vol) : on n'ajoute l'onglet
                // localement qu'après confirmation serveur.
                self._enqueueSqlTabsPut(candidate).then(function(ok) {
                    if (!ok) {
                        if (typeof window.showToast === 'function') {
                            window.showToast("Onglet non sauvegardé (erreur serveur).", 'error');
                        }
                        return;
                    }
                    self.addTab(
                        label,
                        result.columns || [],
                        result.rows || [],
                        result.sql,
                        (typeof result.row_count === 'number'
                            ? result.row_count
                            : (result.rows ? result.rows.length : 0)),
                        { externalSource: { type: 'sql_query', query: result.sql } },
                        true
                    );
                    // Baseline = état persisté (la liste vient d'être PUT avec
                    // succès) → un rename/close ultérieur sera détecté correctement.
                    self._lastPersistedSqlTabsSig = JSON.stringify(self._collectSqlQueryTabs());
                });
            }
        });
    };

    GridTabManager.prototype._renderTabBar = function() {
        var self = this;
        // Les menus déroulants (add/save) sont attachés au <body> en mode
        // "portal" pour échapper au stacking context du parent en plein écran.
        // Sans ça, ils apparaissent DERRIÈRE le result area en fullscreen.
        // On les retire AVANT de wiper le tab bar pour éviter les orphelins.
        if (this._addMenuEl && this._addMenuEl.parentNode) {
            this._addMenuEl.parentNode.removeChild(this._addMenuEl);
        }
        this._addMenuEl = null;
        if (this._saveMenuEl && this._saveMenuEl.parentNode) {
            this._saveMenuEl.parentNode.removeChild(this._saveMenuEl);
        }
        this._saveMenuEl = null;
        if (this._exportMenuEl && this._exportMenuEl.parentNode) {
            this._exportMenuEl.parentNode.removeChild(this._exportMenuEl);
        }
        this._exportMenuEl = null;
        this.tabBarEl.innerHTML = '';
        this.tabBarEl.style.display = '';

        // Tab container (Chrome-style: tabs compress to fit)
        var scrollWrap = document.createElement('div');
        scrollWrap.className = 'grid-tab-bar-scroll';

        var dragSrcIdx = null;

        for (var i = 0; i < this.tabs.length; i++) {
            (function(idx) {
                var tab = self.tabs[idx];
                var btn = document.createElement('button');
                btn.type = 'button';
                btn.className = 'grid-tab' + (idx === self.activeTabIndex ? ' grid-tab-active' : '');
                btn.setAttribute('draggable', 'true');
                btn.setAttribute('data-tab-idx', idx);

                var labelSpan = document.createElement('span');
                labelSpan.textContent = tab.label;
                btn.appendChild(labelSpan);
                btn.title = tab.label;

                // Double-clic: renommer l'onglet
                labelSpan.addEventListener('dblclick', function(e) {
                    e.stopPropagation();
                    self._startTabRename(idx, labelSpan);
                });

                if (tab.closable) {
                    var closeBtn = document.createElement('span');
                    closeBtn.className = 'grid-tab-close';
                    closeBtn.textContent = '\u00d7'; // ×
                    closeBtn.addEventListener('click', function(e) {
                        e.stopPropagation();
                        self._closeTab(idx);
                    });
                    btn.appendChild(closeBtn);
                }

                btn.addEventListener('click', function(e) {
                    if (e.ctrlKey || e.metaKey) {
                        // Ctrl+click: toggle selection sans changer d'onglet actif
                        if (self._selectedTabs.has(idx)) {
                            self._selectedTabs.delete(idx);
                        } else {
                            self._selectedTabs.add(idx);
                        }
                        self._updateTabSelectionStyles();
                    } else {
                        // Click normal: switch + clear selection
                        self._selectedTabs.clear();
                        self._switchTab(idx);
                    }
                });

                // ── Right-click context menu ──
                btn.addEventListener('contextmenu', function(e) {
                    e.preventDefault();
                    self._showTabContextMenu(e, idx);
                });

                // ── Drag to reorder ──
                btn.addEventListener('dragstart', function(e) {
                    dragSrcIdx = idx;
                    btn.classList.add('dragging');
                    e.dataTransfer.effectAllowed = 'move';
                });
                btn.addEventListener('dragover', function(e) {
                    e.preventDefault();
                    e.dataTransfer.dropEffect = 'move';
                    if (dragSrcIdx !== null && dragSrcIdx !== idx) {
                        // Clear all drag-over, add to this one
                        var allTabs = self.tabBarEl.querySelectorAll('.grid-tab');
                        for (var t = 0; t < allTabs.length; t++) allTabs[t].classList.remove('grid-tab-drag-over');
                        btn.classList.add('grid-tab-drag-over');
                    }
                });
                btn.addEventListener('drop', function(e) {
                    e.preventDefault();
                    // Feuille PRINCIPALE (index 0) figée en 1ère position pour un
                    // widget dashboard : interdit de la déplacer OU d'insérer une
                    // autre feuille avant elle (le backend mappe la feuille 0 →
                    // data_source_config["query"]). Hors dashboard
                    // (_sqlTabContext absent) : réordonnancement libre.
                    if (self._sqlTabContext && (dragSrcIdx === 0 || idx === 0)) {
                        dragSrcIdx = null;
                        var dragOvers = self.tabBarEl.querySelectorAll('.grid-tab-drag-over');
                        for (var d = 0; d < dragOvers.length; d++) {
                            dragOvers[d].classList.remove('grid-tab-drag-over');
                        }
                        return;
                    }
                    if (dragSrcIdx !== null && dragSrcIdx !== idx) {
                        // Move tab in array
                        var moved = self.tabs.splice(dragSrcIdx, 1)[0];
                        self.tabs.splice(idx, 0, moved);
                        // Also reorder DOM containers
                        self.contentEl.insertBefore(moved.containerEl, self.tabs[idx + 1] ? self.tabs[idx + 1].containerEl : null);
                        // Update active index
                        if (self.activeTabIndex === dragSrcIdx) {
                            self.activeTabIndex = idx;
                        } else if (dragSrcIdx < self.activeTabIndex && idx >= self.activeTabIndex) {
                            self.activeTabIndex--;
                        } else if (dragSrcIdx > self.activeTabIndex && idx <= self.activeTabIndex) {
                            self.activeTabIndex++;
                        }
                        self._renderTabBar();
                        self._switchTab(self.activeTabIndex);
                        // Feature « Requête SQL » : persiste le nouvel ORDRE des
                        // onglets (le drag réordonne this.tabs). Sans ça, l'ordre
                        // était perdu au refresh — les onglets revenaient dans
                        // l'ordre stocké. Dédup par signature → no-op si le drag
                        // ne touche que des onglets non-SQL. (Fix revue adv.)
                        self._notifySqlTabsChanged();
                    }
                    dragSrcIdx = null;
                });
                btn.addEventListener('dragend', function() {
                    btn.classList.remove('dragging');
                    var allTabs = self.tabBarEl.querySelectorAll('.grid-tab');
                    for (var t = 0; t < allTabs.length; t++) allTabs[t].classList.remove('grid-tab-drag-over');
                    dragSrcIdx = null;
                });

                scrollWrap.appendChild(btn);
            })(i);
        }

        // [+] Add tab dropdown (blank sheet OR external sheets)
        var addWrap = document.createElement('span');
        addWrap.className = 'grid-tab-add-wrap';
        addWrap.style.position = 'relative';
        addWrap.style.display = 'inline-block';

        var btnAdd = document.createElement('button');
        btnAdd.type = 'button';
        btnAdd.className = 'grid-tab grid-tab-add';
        btnAdd.textContent = '+';
        btnAdd.title = 'Ajouter un onglet';
        btnAdd.setAttribute('draggable', 'false');
        addWrap.appendChild(btnAdd);

        var addMenu = document.createElement('div');
        addMenu.className = 'grid-save-menu grid-add-menu';
        addMenu.style.display = 'none';
        addMenu.style.position = 'fixed';

        var itemBlank = document.createElement('button');
        itemBlank.type = 'button';
        itemBlank.className = 'grid-save-menu-item';
        itemBlank.textContent = 'Onglet vide';
        itemBlank.addEventListener('click', function() {
            addMenu.style.display = 'none';
            var n = self.tabs.length;
            self.addTab('Feuille ' + n, [], [], '', 0, null, true);
        });
        addMenu.appendChild(itemBlank);

        var itemExt = document.createElement('button');
        itemExt.type = 'button';
        itemExt.className = 'grid-save-menu-item';
        itemExt.textContent = 'Ajouter feuilles externes…';
        itemExt.addEventListener('click', function() {
            addMenu.style.display = 'none';
            if (typeof window.ExternalSheetsPicker === 'undefined') {
                if (typeof window.alert === 'function') {
                    window.alert('Le sélecteur de feuilles externes n\'est pas chargé.');
                }
                return;
            }
            window.ExternalSheetsPicker.open({
                mode: 'data',
                onSelect: function(sheets) {
                    if (!sheets || !sheets.length) return;
                    sheets.forEach(function(sheet) {
                        self.addTab(
                            sheet.label || 'Feuille externe',
                            sheet.columns || [],
                            sheet.rows || [],
                            // SQL de la feuille source (classeur .afz) : le
                            // transporter pour qu'il survive au save/reload —
                            // avant, '' hardcodé = perte silencieuse du SQL
                            // de chaque feuille importée. Excel/CSV n'en ont
                            // pas → ''.
                            (typeof sheet.sql === 'string') ? sheet.sql : '',
                            sheet.row_count || 0,
                            {
                                columnMetadata: null,
                                merges: sheet.merges || [],
                                externalSource: sheet.source || { type: sheet.type },
                                cellDetails: _sanitizeImportedCellDetails(
                                    sheet.cellDetails, (sheet.rows || []).length)
                            },
                            true
                        );
                    });
                    // T11 — sur un widget dashboard, une feuille externe importée
                    // ne survit au refresh QUE si le widget est enregistré comme
                    // classeur (l'import seul ne persiste pas). On le rappelle.
                    if (self._dashboardWidget && typeof window.showToast === 'function') {
                        window.showToast(
                            'Feuille importée — cliquez « Enregistrer » pour la conserver.',
                            'info'
                        );
                    }
                }
            });
        });
        addMenu.appendChild(itemExt);

        // Item « Requête SQL » — feature dashboard-only (menu [+]). N'apparaît
        // QUE si renderIrisGrid a injecté un contexte d'autorisation
        // (this._sqlTabContext.canAuthor) → owner d'un widget grille de
        // dashboard. Crée un onglet adossé à une requête SQL ré-exécutée à
        // chaque affichage (persistée dans la config du widget).
        if (self._sqlTabContext && self._sqlTabContext.canAuthor) {
            var itemSql = document.createElement('button');
            itemSql.type = 'button';
            itemSql.className = 'grid-save-menu-item';
            itemSql.textContent = 'Requête SQL';
            // Cap sur les onglets SQL ADDITIONNELS (miroir backend
            // MAX_GRID_EXTRA_TABS qui ne compte QUE extra_tabs). En mode « feuille
            // principale de confiance » (source_sql fourni), la principale porte
            // elle-même externalSource sql → elle est collectée → on la retire du
            // compte des additionnels (sinon cap à 9 au lieu de 10). En legacy
            // (principale non collectée) on ne retire rien.
            var _extraSqlCount = self._collectSqlQueryTabs().length
                - (self._primarySheetTrusted ? 1 : 0);
            var atCap = _extraSqlCount >= GRID_MAX_EXTRA_SQL_TABS;
            if (atCap) {
                itemSql.disabled = true;
                itemSql.title = 'Maximum ' + GRID_MAX_EXTRA_SQL_TABS
                    + ' onglets SQL par widget.';
                itemSql.style.opacity = '0.5';
                itemSql.style.cursor = 'not-allowed';
            }
            itemSql.addEventListener('click', function() {
                addMenu.style.display = 'none';
                if (window.OverlayManager) {
                    try { window.OverlayManager.close(addMenu); } catch (_) {}
                }
                if (atCap) return;
                self._openSqlQueryTab();
            });
            addMenu.appendChild(itemSql);
        }

        // Portal vers <body> : sort le menu du stacking context du parent
        // (sinon il est masqué par .grid-fullscreen, dorénavant à
        // var(--z-iris-grid-fullscreen) = 1900 — cf. overlay-layers.css).
        document.body.appendChild(addMenu);
        this._addMenuEl = addMenu;

        btnAdd.addEventListener('click', function(e) {
            e.stopPropagation();
            var visible = addMenu.style.display !== 'none';
            if (visible) {
                addMenu.style.display = 'none';
                if (window.OverlayManager) { try { window.OverlayManager.close(addMenu); } catch (_) {} }
                return;
            }
            addMenu.style.left = '';
            addMenu.style.right = '';
            addMenu.style.top = '';
            addMenu.style.display = 'block';
            if (window.OverlayManager) { try { window.OverlayManager.open(addMenu, { layer: 'dropdown' }); } catch (_) {} }
            var rect = btnAdd.getBoundingClientRect();
            var vw = window.innerWidth;
            var vh = window.innerHeight;
            var menuW = addMenu.offsetWidth;
            var menuH = addMenu.offsetHeight;
            var margin = 4;
            var left = rect.left;
            if (left + menuW > vw - margin) left = vw - menuW - margin;
            if (left < margin) left = margin;
            var spaceBelow = vh - rect.bottom;
            var spaceAbove = rect.top;
            var top;
            if (spaceBelow >= menuH + margin) {
                top = rect.bottom + margin;
            } else if (spaceAbove >= menuH + margin) {
                top = rect.top - menuH - margin;
            } else {
                top = Math.max(margin, vh - menuH - margin);
            }
            addMenu.style.left = left + 'px';
            addMenu.style.top = top + 'px';
        });

        if (this._addMenuOutsideHandler) {
            document.removeEventListener('click', this._addMenuOutsideHandler);
        }
        // Le menu vit sur <body> (portal), donc le check "outside" doit
        // exclure ET le wrapper du bouton ET le menu lui-même — sinon le
        // clic sur un item ferme le menu avant que le handler item ne tire.
        this._addMenuOutsideHandler = function(e) {
            if (!addWrap.contains(e.target) && !addMenu.contains(e.target)) {
                addMenu.style.display = 'none';
                if (window.OverlayManager) { try { window.OverlayManager.close(addMenu); } catch (_) {} }
                }
        };
        document.addEventListener('click', this._addMenuOutsideHandler);

        scrollWrap.appendChild(addWrap);
        this.tabBarEl.appendChild(scrollWrap);

        // ── Right-side action buttons (fixed, never scroll) ──
        var actionsWrap = document.createElement('div');
        actionsWrap.className = 'grid-tab-bar-actions';

        // Indicateur discret de synchronisation (dot pulsant, invisible si idle).
        // Placé en premier pour être visible mais discret, avant les boutons.
        actionsWrap.appendChild(this._syncIndicator.getElement());

        // Search button
        var btnSearch = document.createElement('button');
        btnSearch.type = 'button';
        btnSearch.className = 'grid-tab grid-tab-search-toggle';
        btnSearch.innerHTML = '<i class="bi bi-search"></i>';
        btnSearch.title = 'Rechercher dans tous les onglets';
        btnSearch.setAttribute('draggable', 'false');
        btnSearch.addEventListener('click', function() {
            var visible = self.searchBarEl.style.display !== 'none';
            self.searchBarEl.style.display = visible ? 'none' : '';
            if (!visible) setTimeout(function() { self._searchInput.focus(); }, 50);
            else { self._searchInput.value = ''; self._closeSearchResults(); }
        });
        actionsWrap.appendChild(btnSearch);

        // Save dropdown (Enregistrer + Enregistrer sous)
        var saveWrap = document.createElement('div');
        saveWrap.style.position = 'relative';

        var btnSave = document.createElement('button');
        btnSave.type = 'button';
        btnSave.className = 'grid-tab grid-tab-action-icon';
        btnSave.innerHTML = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M19 21H5a2 2 0 01-2-2V5a2 2 0 012-2h11l5 5v11a2 2 0 01-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg>';
        btnSave.title = 'Enregistrer';
        btnSave.setAttribute('draggable', 'false');
        btnSave.addEventListener('click', function(e) {
            e.stopPropagation();
            // Le menu vit sur <body> (portal) — on garde la référence directe.
            var menu = self._saveMenuEl;
            if (!menu) return;
            var visible = menu.style.display !== 'none';
            if (visible) {
                menu.style.display = 'none';
                if (window.OverlayManager) { try { window.OverlayManager.close(menu); } catch (_) {} }
                return;
            }
            // Afficher le menu puis calculer sa taille (offsetWidth/Height
            // requièrent display != none). On positionne en coords viewport
            // (menu est position:fixed) en préférant "au-dessus" du bouton
            // mais en basculant "en-dessous" si pas assez d'espace, et en
            // clampant toujours au viewport pour éviter de sortir de l'écran.
            menu.style.left = '';
            menu.style.right = '';
            menu.style.top = '';
            menu.style.display = 'block';
            if (window.OverlayManager) { try { window.OverlayManager.open(menu, { layer: 'dropdown' }); } catch (_) {} }
            var rect = btnSave.getBoundingClientRect();
            var vw = window.innerWidth;
            var vh = window.innerHeight;
            var menuW = menu.offsetWidth;
            var menuH = menu.offsetHeight;
            var margin = 4;

            // Horizontal : alignement à droite du bouton, clamp viewport
            var left = rect.right - menuW;
            if (left + menuW > vw - margin) left = vw - menuW - margin;
            if (left < margin) left = margin;

            // Vertical : above si place, sinon below, sinon top-pinned
            var spaceAbove = rect.top;
            var spaceBelow = vh - rect.bottom;
            var top;
            if (spaceAbove >= menuH + margin) {
                top = rect.top - menuH - margin;
            } else if (spaceBelow >= menuH + margin) {
                top = rect.bottom + margin;
            } else {
                // Ni au-dessus ni en-dessous : on pin à une position safe
                top = Math.max(margin, vh - menuH - margin);
            }
            menu.style.left = left + 'px';
            menu.style.top = top + 'px';
        });
        saveWrap.appendChild(btnSave);

        var saveMenu = document.createElement('div');
        saveMenu.className = 'grid-save-menu';
        saveMenu.style.display = 'none';

        var itemSave = document.createElement('button');
        itemSave.type = 'button';
        itemSave.className = 'grid-save-menu-item';
        itemSave.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><path d="M19 21H5a2 2 0 01-2-2V5a2 2 0 012-2h11l5 5v11a2 2 0 01-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg>'
            + ' Enregistrer <span style="color:var(--text-faint,#9ca3af);margin-left:auto;font-size:0.7rem">Ctrl+S</span>';
        itemSave.title = 'Enregistrer (Ctrl+S)';
        itemSave.addEventListener('click', function() {
            saveMenu.style.display = 'none';
            self.saveWorkbook();
        });
        saveMenu.appendChild(itemSave);

        var itemSaveAs = document.createElement('button');
        itemSaveAs.type = 'button';
        itemSaveAs.className = 'grid-save-menu-item';
        itemSaveAs.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><path d="M19 21H5a2 2 0 01-2-2V5a2 2 0 012-2h11l5 5v11a2 2 0 01-2 2z"/><line x1="12" y1="11" x2="12" y2="17"/><line x1="9" y1="14" x2="15" y2="14"/></svg>'
            + ' Enregistrer sous';
        itemSaveAs.title = 'Enregistrer sous (nouveau fichier)';
        itemSaveAs.addEventListener('click', function() {
            saveMenu.style.display = 'none';
            self.saveWorkbookAs();
        });
        saveMenu.appendChild(itemSaveAs);

        // Portal vers <body> : sort le menu du stacking context du parent
        // (sinon il est masqué par .grid-fullscreen, var(--z-iris-grid-fullscreen)
        // = 1900 — cf. overlay-layers.css).
        document.body.appendChild(saveMenu);
        this._saveMenuEl = saveMenu;
        actionsWrap.appendChild(saveWrap);

        // Close save menu on outside click (clean up previous handler to avoid leaks)
        if (this._saveMenuOutsideHandler) {
            document.removeEventListener('click', this._saveMenuOutsideHandler);
        }
        // Le menu vit sur <body> (portal), donc on doit exclure ET le wrap
        // ET le menu lui-même du test "outside" (sinon clic sur un item =
        // fermeture immédiate avant que le handler item ne tire).
        this._saveMenuOutsideHandler = function(e) {
            if (!saveWrap.contains(e.target) && !saveMenu.contains(e.target)) {
                saveMenu.style.display = 'none';
                if (window.OverlayManager) { try { window.OverlayManager.close(saveMenu); } catch (_) {} }
                }
        };
        document.addEventListener('click', this._saveMenuOutsideHandler);

        // Load workbook from datastore
        var btnLoad = document.createElement('button');
        btnLoad.type = 'button';
        btnLoad.className = 'grid-tab grid-tab-action-icon';
        btnLoad.innerHTML = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 19a2 2 0 01-2 2H4a2 2 0 01-2-2V5a2 2 0 012-2h5l2 3h9a2 2 0 012 2z"/></svg>';
        btnLoad.title = 'Charger un classeur';
        btnLoad.setAttribute('draggable', 'false');
        btnLoad.addEventListener('click', function() { self._openDatastorePicker(); });
        actionsWrap.appendChild(btnLoad);

        // ── Export dropdown (Excel + CSV unifiés) ──
        // Bouton icône gris (``grid-tab-action-icon``, comme Save/Load) qui
        // se fond dans le décor, + menu déroulant portalé sur <body>
        // (évite le stacking context du fullscreen). Deux items : Excel
        // multi-onglets, CSV onglet actif.
        var exportWrap = document.createElement('div');
        exportWrap.style.position = 'relative';

        var btnExport = document.createElement('button');
        btnExport.type = 'button';
        btnExport.className = 'grid-tab grid-tab-action-icon';
        // SVG download (Heroicons style, stroke-width 2) — cohérent avec Save/Load.
        btnExport.innerHTML = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>';
        btnExport.title = 'Exporter';
        btnExport.setAttribute('draggable', 'false');
        btnExport.setAttribute('aria-haspopup', 'menu');
        btnExport.setAttribute('aria-expanded', 'false');
        // data-action pour compat tests E2E qui ciblaient l'ancien bouton.
        btnExport.setAttribute('data-action', 'export');

        var exportMenu = document.createElement('div');
        exportMenu.className = 'grid-export-menu';
        exportMenu.style.display = 'none';
        exportMenu.setAttribute('role', 'menu');

        var itemExcel = document.createElement('button');
        itemExcel.type = 'button';
        itemExcel.className = 'grid-export-menu-item';
        itemExcel.setAttribute('role', 'menuitem');
        itemExcel.setAttribute('data-action', 'export-excel');
        itemExcel.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>'
            + ' Excel (.xlsx)<span class="grid-export-menu-item-sub">tous les onglets</span>';
        itemExcel.title = 'Exporter tous les onglets en XLSX';
        exportMenu.appendChild(itemExcel);

        var itemCSV = document.createElement('button');
        itemCSV.type = 'button';
        itemCSV.className = 'grid-export-menu-item';
        itemCSV.setAttribute('role', 'menuitem');
        itemCSV.setAttribute('data-action', 'export-csv');
        itemCSV.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="4" width="16" height="16" rx="2"/><line x1="4" y1="10" x2="20" y2="10"/><line x1="10" y1="4" x2="10" y2="20"/></svg>'
            + ' CSV (.csv)<span class="grid-export-menu-item-sub">onglet actif</span>';
        itemCSV.title = "Exporter l'onglet actif en CSV";
        exportMenu.appendChild(itemCSV);

        // ── Toggle « Valeurs : Clair · Anonymisé » (discret, en tête de menu) ──
        // Régit l'export Excel ET CSV ci-dessus. Défaut = Clair (comportement
        // historique). Le mode est mémorisé sur l'instance (``_exportAnonymize``)
        // donc persiste aux re-render du tab bar. Anonymisé = applique les
        // pseudonymes définis par l'utilisateur sur /data/privacy (anonymisation
        // côté serveur, fail-closed). Styles inline : CSP-safe ET indépendant du
        // fichier CSS chargé (/iris inline dans iris.html, /datastore via
        // iris-grid.css) — pas de double maintenance CSS.
        var modeRow = document.createElement('div');
        modeRow.setAttribute('role', 'radiogroup');
        modeRow.setAttribute('aria-label', 'Mode des valeurs exportées');
        modeRow.style.cssText = 'display:flex;align-items:center;gap:6px;'
            + 'margin:2px 8px 6px;padding-bottom:6px;font-size:11px;'
            + 'border-bottom:1px solid rgba(127,127,127,.2);';
        var modeLabel = document.createElement('span');
        modeLabel.textContent = 'Valeurs :';
        modeLabel.style.cssText = 'opacity:.7;white-space:nowrap;';
        var seg = document.createElement('div');
        seg.style.cssText = 'display:flex;flex:1;gap:2px;padding:2px;'
            + 'border-radius:6px;background:rgba(127,127,127,.14);';
        var _segBase = 'flex:1;border:none;cursor:pointer;font-size:11px;'
            + 'padding:3px 8px;border-radius:4px;font-weight:500;font-family:inherit;'
            + 'line-height:1.4;transition:background .12s,color .12s;';
        var btnClear = document.createElement('button');
        btnClear.type = 'button';
        btnClear.setAttribute('role', 'radio');
        btnClear.textContent = 'Clair';
        btnClear.title = 'Exporter les vraies valeurs (par défaut).';
        var btnAnon = document.createElement('button');
        btnAnon.type = 'button';
        btnAnon.setAttribute('role', 'radio');
        btnAnon.textContent = 'Anonymisé';
        btnAnon.title = 'Remplacer les valeurs sensibles par vos pseudonymes définis '
            + 'sur /data/privacy. Les valeurs non configurées restent en clair.';
        var renderExportMode = function() {
            var anon = !!self._exportAnonymize;
            btnClear.setAttribute('aria-checked', anon ? 'false' : 'true');
            btnAnon.setAttribute('aria-checked', anon ? 'true' : 'false');
            btnClear.setAttribute('tabindex', anon ? '-1' : '0');
            btnAnon.setAttribute('tabindex', anon ? '0' : '-1');
            // Actif = bleu Komptia (#4472C4, cohérent en clair ET dark) ;
            // inactif = transparent atténué.
            btnClear.style.cssText = _segBase + (anon
                ? 'background:transparent;color:currentColor;opacity:.65;'
                : 'background:#4472C4;color:#fff;opacity:1;');
            btnAnon.style.cssText = _segBase + (anon
                ? 'background:#4472C4;color:#fff;opacity:1;'
                : 'background:transparent;color:currentColor;opacity:.65;');
        };
        btnClear.addEventListener('click', function(e) {
            e.stopPropagation();
            self._exportAnonymize = false;
            renderExportMode();
        });
        btnAnon.addEventListener('click', function(e) {
            e.stopPropagation();
            self._exportAnonymize = true;
            renderExportMode();
        });
        seg.addEventListener('keydown', function(e) {
            if (e.key === 'ArrowLeft' || e.key === 'ArrowRight') {
                e.preventDefault();
                self._exportAnonymize = (e.key === 'ArrowRight');
                renderExportMode();
                (self._exportAnonymize ? btnAnon : btnClear).focus();
            }
        });
        renderExportMode();
        seg.appendChild(btnClear);
        seg.appendChild(btnAnon);
        modeRow.appendChild(modeLabel);
        modeRow.appendChild(seg);
        exportMenu.insertBefore(modeRow, exportMenu.firstChild);

        var closeExportMenu = function() {
            exportMenu.style.display = 'none';
            if (window.OverlayManager) { try { window.OverlayManager.close(exportMenu); } catch (_) {} }
            btnExport.setAttribute('aria-expanded', 'false');
        };

        // Hook : items d'export additionnels (ex: JSON original côté workbook viewer).
        // Le callback reçoit le menu DOM + la fonction de fermeture pour pouvoir
        // dismiss après clic. Re-déclenché à chaque _renderTabBar (innerHTML wipe).
        if (typeof this._renderExtraExportItems === 'function') {
            try { this._renderExtraExportItems(exportMenu, closeExportMenu); } catch (e) { /* defensive */ }
        }

        // Portal to <body> : sort le menu du stacking context du parent
        // (sinon masqué en fullscreen à var(--z-iris-grid-fullscreen) = 1900).
        document.body.appendChild(exportMenu);
        this._exportMenuEl = exportMenu;

        var hasExportableContent = function() {
            // Désactivé si 0 onglet ou si aucun onglet n'a de données.
            if (!self.tabs || self.tabs.length === 0) return false;
            for (var i = 0; i < self.tabs.length; i++) {
                var g = self.tabs[i].grid;
                if (g && g.columns && g.columns.length > 0) return true;
            }
            return false;
        };

        var openExportMenu = function() {
            if (!hasExportableContent()) return; // guard : rien à exporter
            exportMenu.style.left = '';
            exportMenu.style.right = '';
            exportMenu.style.top = '';
            exportMenu.style.display = 'block';
            if (window.OverlayManager) { try { window.OverlayManager.open(exportMenu, { layer: 'dropdown' }); } catch (_) {} }
            btnExport.setAttribute('aria-expanded', 'true');
            // Smart placement identique au save menu : above si place,
            // sinon below, sinon top-pinned. Clamp viewport horizontal.
            var rect = btnExport.getBoundingClientRect();
            var vw = window.innerWidth;
            var vh = window.innerHeight;
            var menuW = exportMenu.offsetWidth;
            var menuH = exportMenu.offsetHeight;
            var margin = 4;
            var left = rect.right - menuW;
            if (left + menuW > vw - margin) left = vw - menuW - margin;
            if (left < margin) left = margin;
            var spaceAbove = rect.top;
            var spaceBelow = vh - rect.bottom;
            var top;
            if (spaceAbove >= menuH + margin) {
                top = rect.top - menuH - margin;
            } else if (spaceBelow >= menuH + margin) {
                top = rect.bottom + margin;
            } else {
                top = Math.max(margin, vh - menuH - margin);
            }
            exportMenu.style.left = left + 'px';
            exportMenu.style.top = top + 'px';
            // Focus le premier item pour navigation clavier
            itemExcel.focus();
        };

        btnExport.addEventListener('click', function(e) {
            e.stopPropagation();
            var visible = exportMenu.style.display !== 'none';
            if (visible) {
                closeExportMenu();
            } else {
                openExportMenu();
            }
        });

        itemExcel.addEventListener('click', function() {
            closeExportMenu();
            // Appelle l'export serveur (réexécute les SQL avec un cap de 100k
            // lignes/onglet — pas de troncature à 500 comme l'export
            // client-side). Le mode (clair/anonymisé) suit le toggle ci-dessus.
            self.exportExcelFullServer(!!self._exportAnonymize);
        });
        itemCSV.addEventListener('click', function() {
            closeExportMenu();
            // Bounds check : entre l'ouverture du menu et le clic, un
            // onglet peut avoir été fermé (deleteTabProgrammatic côté
            // copilot, close manuel) → activeTabIndex hors bornes.
            // Un feedback explicite vaut mieux qu'un silent no-op
            // (l'utilisateur croirait que l'action a échoué sans raison).
            if (self.activeTabIndex < 0 || self.activeTabIndex >= self.tabs.length) {
                if (typeof self._showSaveToast === 'function') {
                    self._showSaveToast('Aucun onglet actif à exporter', true);
                }
                return;
            }
            var activeTab = self.tabs[self.activeTabIndex];
            if (activeTab && activeTab.grid && typeof activeTab.grid._exportCSV === 'function') {
                if (self._exportAnonymize) {
                    // Anonymisé : passe par le serveur (fail-closed, SSoT) puis
                    // formate côté client avec le même générateur que le clair.
                    self._exportActiveTabCsvAnonymized(activeTab.grid);
                } else {
                    activeTab.grid._exportCSV();
                }
            } else if (typeof self._showSaveToast === 'function') {
                self._showSaveToast('Export CSV indisponible pour cet onglet', true);
            }
        });

        // Keyboard nav : ArrowUp/ArrowDown entre items, Escape ferme.
        // Enter/Space déclenchent le click (natif sur <button>).
        exportMenu.addEventListener('keydown', function(e) {
            if (exportMenu.style.display === 'none') return;
            var items = [itemExcel, itemCSV];
            var idx = items.indexOf(document.activeElement);
            if (e.key === 'Escape') {
                e.preventDefault();
                closeExportMenu();
                btnExport.focus();
            } else if (e.key === 'ArrowDown') {
                e.preventDefault();
                var nextIdx = idx < 0 ? 0 : (idx + 1) % items.length;
                items[nextIdx].focus();
            } else if (e.key === 'ArrowUp') {
                e.preventDefault();
                var prevIdx = idx < 0 ? items.length - 1 : (idx - 1 + items.length) % items.length;
                items[prevIdx].focus();
            }
        });

        // Outside click : ferme le menu. Cleanup du handler précédent pour
        // éviter les fuites si le tab bar est re-rendered.
        if (this._exportMenuOutsideHandler) {
            document.removeEventListener('click', this._exportMenuOutsideHandler);
        }
        this._exportMenuOutsideHandler = function(e) {
            if (!exportWrap.contains(e.target) && !exportMenu.contains(e.target)) {
                closeExportMenu();
            }
        };
        document.addEventListener('click', this._exportMenuOutsideHandler);

        exportWrap.appendChild(btnExport);
        actionsWrap.appendChild(exportWrap);

        // ⛶ Fullscreen button
        var btnFs = document.createElement('button');
        btnFs.type = 'button';
        btnFs.className = 'grid-tab grid-tab-fullscreen';
        btnFs.textContent = self._isFullscreen ? '\u2715' : '\u26F6';
        btnFs.title = self._isFullscreen ? 'Quitter le plein écran' : 'Plein écran';
        btnFs.setAttribute('draggable', 'false');
        btnFs.addEventListener('click', function() { self._toggleTabFullscreen(); });
        if (!this._hideFullscreenButton) actionsWrap.appendChild(btnFs);

        this.tabBarEl.appendChild(actionsWrap);
    };

    GridTabManager.prototype._toggleTabFullscreen = function() {
        this._isFullscreen = !this._isFullscreen;
        var target = this._fullscreenTarget || this.parentContainer;
        if (this._isFullscreen) {
            target.classList.add('grid-fullscreen');
            if (!this._escFsHandler) {
                var self = this;
                this._escFsHandler = function(e) {
                    if (e.key === 'Escape' && self._isFullscreen) self._toggleTabFullscreen();
                };
                document.addEventListener('keydown', this._escFsHandler);
            }
        } else {
            target.classList.remove('grid-fullscreen');
            if (this._escFsHandler) {
                document.removeEventListener('keydown', this._escFsHandler);
                this._escFsHandler = null;
            }
        }
        this._renderTabBar();
    };

    GridTabManager.prototype._switchTab = function(index) {
        if (index < 0 || index >= this.tabs.length) return;
        this.activeTabIndex = index;
        for (var i = 0; i < this.tabs.length; i++) {
            this.tabs[i].containerEl.style.display = (i === index) ? '' : 'none';
        }
        this._renderTabBar();
    };

    // Helper appele AVANT tout retrait de tab (close one, close many,
    // delete programmatic, loadWorkbook qui purge tous les tabs). Sa
    // raison d'etre : decrementer ``window.__copilotRunsActive`` si la
    // grille du tab avait un copilot run en vol. Sans ce nettoyage, un
    // tab ferme pendant qu'un copilot tourne laissait le compteur a >0
    // pour toujours -- le guard ``beforeunload`` se serait declenche en
    // permanence jusqu'au refresh complet.
    //
    // Implementation directe (sans passer par ``_setCopilotProcessing
    // (false)``) car cette derniere fait un early-return sur ``!this.
    // _copilotBar`` qui peut etre vrai sur des grilles minimalistes
    // (tabs sans copilot bar) et nous priverait alors du nettoyage.
    // Idempotent grace a la garde ``_copilotProcessingActive``.
    GridTabManager.prototype._disposeTabBeforeRemoval = function(tab) {
        try {
            var grid = tab && tab.grid;
            if (!grid || !grid._copilotProcessingActive) return;
            grid._copilotProcessingActive = false;
            if (typeof window !== 'undefined' &&
                typeof window.__copilotRunsActive === 'number' &&
                window.__copilotRunsActive > 0) {
                window.__copilotRunsActive -= 1;
            }
        } catch (e) { /* defensive */ }
    };

    GridTabManager.prototype._closeTab = function(index) {
        if (index < 0 || index >= this.tabs.length) return;
        if (!this.tabs[index].closable) return;
        // Never close the last remaining tab
        if (this.tabs.length <= 1) return;

        this._disposeTabBeforeRemoval(this.tabs[index]);
        this.tabs[index].containerEl.remove();
        this.tabs.splice(index, 1);

        // Adjust active index
        if (this.activeTabIndex >= this.tabs.length) {
            this.activeTabIndex = this.tabs.length - 1;
        } else if (this.activeTabIndex > index) {
            this.activeTabIndex = this.activeTabIndex - 1;
        } else if (this.activeTabIndex === index) {
            this.activeTabIndex = Math.min(index, this.tabs.length - 1);
        }

        this._renderTabBar();
        this._switchTab(this.activeTabIndex);

        // Snapshot workbook state after closing a tab
        if (!this._restoringState) this.snapshotWorkbook();

        // Re-persiste la config widget si la liste d'onglets SQL a changé
        // (no-op hors dashboard ; dédupliqué par signature → pas de PUT pour
        // la fermeture d'un onglet non-SQL comme un drill-down).
        this._notifySqlTabsChanged();
    };

    // ── Mutations programmatiques (utilisées par copilot_agent) ──
    //
    // setTabLabelProgrammatic : renomme l'onglet à idx. Identique au rename
    // par double-clic sauf qu'il est déclenché par le backend et retourne un
    // booléen à l'appelant (permet au handler copilot de remonter un message
    // de statut cohérent à l'utilisateur).

    GridTabManager.prototype.setTabLabelProgrammatic = function(index, newLabel) {
        if (index < 0 || index >= this.tabs.length) return false;
        if (typeof newLabel !== 'string') return false;
        var trimmed = newLabel.trim();
        if (!trimmed) return false;
        if (trimmed.length > 200) trimmed = trimmed.slice(0, 200);
        // No-op silencieux si le label est déjà celui demandé — évite une
        // entrée d'historique undoable inutile qui force l'utilisateur à
        // Ctrl+Z sur une mutation qu'il ne voit pas.
        if (this.tabs[index].label === trimmed) return true;
        this.tabs[index].label = trimmed;
        this._renderTabBar();
        if (!this._restoringState) this.snapshotWorkbook();
        // Feature « Requête SQL » : persiste si le renommage touche un onglet
        // SQL (dédup par signature → no-op sinon).
        this._notifySqlTabsChanged();
        return true;
    };

    // replaceTabContentProgrammatic : MUTE le contenu d'un onglet existant
    // sans le supprimer/recréer (préserve scroll, position dans la barre,
    // focus DOM). Appelé par le handler ``_handleModifyTabSql`` du
    // copilot — délégué via le callback ``onReplaceTabContent`` exposé
    // aux grilles. ``payload`` : ``{sql, columns, rows, row_count, label?}``.
    //
    // Le ``cellDetails`` éventuel de l'ancienne grille est **DROP** par le
    // backend (incohérence valeur↔SQL après mutation) — côté frontend on
    // applique l'écrasement sans recopie de l'ancien cellDetails.
    GridTabManager.prototype.replaceTabContentProgrammatic = function(index, payload) {
        if (index < 0 || index >= this.tabs.length) return false;
        if (!payload || typeof payload !== 'object') return false;
        var tab = this.tabs[index];
        if (!tab || !tab.grid) return false;

        var grid = tab.grid;
        var newSql = (typeof payload.sql === 'string') ? payload.sql : '';
        var newColumns = Array.isArray(payload.columns) ? payload.columns.slice() : [];
        var newRows = Array.isArray(payload.rows) ? payload.rows : [];
        var newRowCount = (typeof payload.row_count === 'number')
            ? payload.row_count : newRows.length;

        if (newColumns.length === 0) return false;

        // Snapshot AVANT mutation pour que Ctrl+Z annule la modification.
        // (Le _pushHistory de la grille est déclenché par le caller via
        // onSnapshot après succès, mais la grille interne capture aussi.)
        if (typeof grid._pushHistory === 'function') {
            try { grid._pushHistory(); } catch (_e) { /* defensive */ }
        }

        // Écrase le state de la grille : SQL, colonnes, rows, cellDetails
        // sont remis à plat. ``isArrayFormat`` recalculé sur le format
        // réel des rows reçues (parité avec _restoreFromState).
        grid.sql = newSql;
        grid.columns = newColumns;
        grid.allRows = newRows.map(function(r) { return Array.isArray(r) ? r.slice() : []; });
        grid.totalRowCount = newRowCount;
        grid.isArrayFormat = grid.allRows.length > 0 && Array.isArray(grid.allRows[0]);
        grid.displayRows = grid.allRows.slice();
        grid._cellDetails = {};  // DROP cellDetails (incohérence valeur↔SQL)
        grid.columnOrder = grid.columns.map(function(_, i) { return i; });
        grid.hiddenCols = new Set();
        grid.sortColIndex = -1;
        grid.sortDirection = null;
        grid.filters = {};
        grid._isBlankSheet = false;
        grid._isDashboardSheet = false;

        // Re-build complet : detect types + render header + body.
        if (typeof grid._detectTypes === 'function') grid._detectTypes();
        if (typeof grid._build === 'function') grid._build();
        if (typeof grid._updateUndoRedoButtons === 'function') {
            grid._updateUndoRedoButtons();
        }

        // Label éventuellement nouveau (backend peut renommer).
        if (typeof payload.label === 'string' && payload.label.trim()
            && payload.label.trim() !== tab.label) {
            tab.label = payload.label.trim().slice(0, 200);
            this._renderTabBar();
        }

        // Feuille SQL : aligner le contrat de persistance ``externalSource``
        // sur le SQL muté. Sans ça, un ``modify_tab_sql`` du copilot mutait
        // ``grid.sql`` (affichage) mais PAS la requête PERSISTÉE → au refresh
        // le serveur ré-exécutait l'ANCIEN SQL (bug constaté en prod
        // 2026-06-10 : « le copilot a modifié le SQL, le refresh a remis
        // l'ancien résultat »). _notifySqlTabsChanged est dédupé par
        // signature → no-op hors dashboard / si rien n'a changé.
        if (tab.externalSource && tab.externalSource.type === 'sql_query'
            && typeof newSql === 'string' && newSql) {
            tab.externalSource.query = newSql;
            this._notifySqlTabsChanged();
        }

        if (!this._restoringState) this.snapshotWorkbook();
        return true;
    };

    // deleteTabProgrammatic : suppression déclenchée par copilot_agent. Bypass
    // du check `closable` (le backend a déjà validé les contraintes), mais
    // conserve deux sanity checks fail-closed :
    //   - au moins 1 onglet reste (sinon render crash)
    //   - jamais l'onglet actif (double-check du backend — race si l'user
    //     change d'onglet entre le turn LLM et le retour HTTP)

    GridTabManager.prototype.deleteTabProgrammatic = function(index) {
        if (index < 0 || index >= this.tabs.length) return false;
        if (this.tabs.length <= 1) return false;
        if (index === this.activeTabIndex) return false;
        this._disposeTabBeforeRemoval(this.tabs[index]);
        this.tabs[index].containerEl.remove();
        this.tabs.splice(index, 1);
        if (this.activeTabIndex >= this.tabs.length) {
            this.activeTabIndex = this.tabs.length - 1;
        } else if (this.activeTabIndex > index) {
            this.activeTabIndex = this.activeTabIndex - 1;
        }
        this._renderTabBar();
        this._switchTab(this.activeTabIndex);
        if (!this._restoringState) this.snapshotWorkbook();
        this._notifySqlTabsChanged();  // feature « Requête SQL » (dédup par signature)
        return true;
    };

    // ── Tab selection styles ──

    GridTabManager.prototype._updateTabSelectionStyles = function() {
        var btns = this.tabBarEl.querySelectorAll('.grid-tab[data-tab-idx]');
        for (var i = 0; i < btns.length; i++) {
            var idx = parseInt(btns[i].getAttribute('data-tab-idx'), 10);
            if (this._selectedTabs.has(idx)) {
                btns[i].classList.add('grid-tab-selected');
            } else {
                btns[i].classList.remove('grid-tab-selected');
            }
        }
    };

    // ── Tab rename (double-click) ──

    GridTabManager.prototype._startTabRename = function(tabIdx, labelSpan) {
        var self = this;
        var tab = this.tabs[tabIdx];
        // Feuille PRINCIPALE d'un widget dashboard (index 0) : NON renommable —
        // son titre = celui du widget (pas de champ label en base ; le backend
        // ignore le label de la feuille 0). Un renommage serait éphémère (perdu
        // au reload). Hors dashboard (_sqlTabContext absent) : inchangé.
        if (self._sqlTabContext && tabIdx === 0) return;
        var oldName = tab.label;

        var input = document.createElement('input');
        input.type = 'text';
        // Onglet « Requête SQL » : cap la saisie au max backend (le titre est
        // persisté → un titre >100 serait rejeté 400). Les autres onglets
        // (/iris, feuilles externes) gardent leur comportement (pas de cap).
        if (tab.externalSource && tab.externalSource.type === 'sql_query') {
            input.maxLength = GRID_MAX_EXTRA_TAB_LABEL_LEN;
        }
        input.value = oldName;
        input.style.cssText = 'font:inherit;border:1px solid var(--brand-light);border-radius:3px;'
            + 'padding:0 4px;outline:none;width:' + Math.max(80, labelSpan.offsetWidth + 20) + 'px;'
            + 'background:var(--bg-surface, #fff);color:var(--text-primary, #1e293b);';

        labelSpan.textContent = '';
        labelSpan.appendChild(input);
        input.focus();
        input.select();

        // Empêcher le drag et les clics du <button> parent pendant l'édition
        var btn = labelSpan.parentElement;
        btn.setAttribute('draggable', 'false');

        // Bloquer le comportement natif du <button> (Espace = click)
        // sans bloquer la saisie dans l'input
        var blockBtnDefault = function(e) {
            // Laisser l'input recevoir les touches normalement
            // mais empêcher le <button> de transformer Espace en click
            if (e.type === 'click' && e.target !== input) {
                e.stopImmediatePropagation();
            }
            if ((e.type === 'keydown' || e.type === 'keyup') && e.key === ' ') {
                e.stopImmediatePropagation();
            }
        };
        btn.addEventListener('keydown', blockBtnDefault, true);
        btn.addEventListener('keyup', blockBtnDefault, true);
        btn.addEventListener('click', blockBtnDefault, true);

        var committed = false;
        var commit = function() {
            if (committed) return;
            committed = true;
            var newName = input.value.trim();
            if (!newName) newName = oldName;
            tab.label = newName;
            labelSpan.textContent = newName;
            btn.title = newName;
            btn.setAttribute('draggable', 'true');
            // Nettoyer les intercepteurs
            btn.removeEventListener('keydown', blockBtnDefault, true);
            btn.removeEventListener('keyup', blockBtnDefault, true);
            btn.removeEventListener('click', blockBtnDefault, true);
            if (!self._restoringState) self.snapshotWorkbook();
            // Feature « Requête SQL » : persiste le nouveau titre si l'onglet
            // renommé est un onglet SQL (dédup par signature → no-op si rien
            // n'a changé ou si l'onglet n'est pas un onglet SQL).
            self._notifySqlTabsChanged();
        };

        input.addEventListener('blur', commit);
        input.addEventListener('keydown', function(e) {
            e.stopPropagation();
            if (e.key === 'Enter') { e.preventDefault(); input.blur(); }
            if (e.key === 'Escape') { input.value = oldName; input.blur(); }
        });
    };

    // ── Tab context menu (right-click) ──

    GridTabManager.prototype._showTabContextMenu = function(e, tabIdx) {
        var self = this;
        // Remove any existing context menu
        if (this._tabCtxMenu) { this._tabCtxMenu.remove(); this._tabCtxMenu = null; }

        var tab = this.tabs[tabIdx];

        // Determine the "keep set": if multi-selected, use selection; otherwise just this tab
        var hasSelection = this._selectedTabs.size > 0;
        var keepSet = new Set(hasSelection ? this._selectedTabs : [tabIdx]);
        // Always include the right-clicked tab in the keep set
        keepSet.add(tabIdx);

        var closableCount = 0;
        var closableOutside = 0;  // closable tabs NOT in keepSet
        var closableRight = 0;
        var closableLeft = 0;
        var maxKeep = 0;
        var minKeep = this.tabs.length;
        keepSet.forEach(function(k) { maxKeep = Math.max(maxKeep, k); minKeep = Math.min(minKeep, k); });
        for (var i = 0; i < this.tabs.length; i++) {
            if (this.tabs[i].closable) {
                closableCount++;
                if (!keepSet.has(i)) closableOutside++;
                if (i > maxKeep) closableRight++;
                if (i < minKeep) closableLeft++;
            }
        }

        var selLabel = keepSet.size > 1 ? ' (' + keepSet.size + ' gardés)' : '';

        var items = [
            { label: 'Renommer', enabled: !(self._sqlTabContext && tabIdx === 0), action: function() {
                var btn = self.tabBarEl.querySelector('[data-tab-idx="' + tabIdx + '"] > span:first-child');
                if (btn) self._startTabRename(tabIdx, btn);
            }},
            { separator: true },
            { label: 'Fermer', enabled: tab.closable && this.tabs.length > 1, action: function() { self._selectedTabs.clear(); self._closeTab(tabIdx); } },
            { label: 'Fermer les autres' + selLabel, enabled: closableOutside > 0, action: function() { self._closeTabsExcept(keepSet); } },
            { label: 'Fermer à droite', enabled: closableRight > 0, action: function() { self._selectedTabs.clear(); self._closeTabsRight(maxKeep); } },
            { label: 'Fermer à gauche', enabled: closableLeft > 0, action: function() { self._selectedTabs.clear(); self._closeTabsLeft(minKeep); } },
        ];

        if (hasSelection) {
            items.push({ separator: true });
            items.push({ label: 'Fermer la sélection (' + keepSet.size + ')', enabled: true, action: function() { self._closeTabsIn(keepSet); } });
            items.push({ label: 'Désélectionner tout', enabled: true, action: function() { self._selectedTabs.clear(); self._updateTabSelectionStyles(); } });
        }

        var menu = document.createElement('div');
        menu.className = 'grid-tab-ctx-menu';
        /* 1995 — au-dessus modaux iris-grid (1990) mais sous OverlayManager.modal (2000). */
        menu.style.cssText = 'position:fixed;z-index:1995;background:var(--bg-surface, #fff);'
            + 'border:1px solid var(--border, #e2e8f0);'
            + 'border-radius:8px;padding:4px 0;box-shadow:var(--shadow-md, 0 4px 16px rgba(0,0,0,0.15));'
            + 'min-width:180px;font-size:0.8rem;';

        for (var j = 0; j < items.length; j++) {
            (function(item) {
                if (item.separator) {
                    var sep = document.createElement('div');
                    sep.style.cssText = 'height:1px;background:var(--border, #e2e8f0);margin:4px 0;';
                    menu.appendChild(sep);
                    return;
                }
                var row = document.createElement('div');
                row.textContent = item.label;
                row.style.cssText = 'padding:6px 14px;cursor:' + (item.enabled ? 'pointer' : 'default')
                    + ';color:' + (item.enabled ? 'var(--text-primary, #1e293b)' : 'var(--text-faint, #a0aec0)')
                    + ';white-space:nowrap;';
                if (item.enabled) {
                    row.addEventListener('mouseenter', function() { row.style.background = 'var(--bg-surface-3, #f1f5f9)'; });
                    row.addEventListener('mouseleave', function() { row.style.background = ''; });
                    row.addEventListener('click', function() {
                        menu.remove();
                        self._tabCtxMenu = null;
                        item.action();
                    });
                }
                menu.appendChild(row);
            })(items[j]);
        }

        // Position near cursor
        menu.style.left = Math.min(e.clientX, window.innerWidth - 200) + 'px';
        menu.style.top = Math.min(e.clientY, window.innerHeight - 200) + 'px';
        document.body.appendChild(menu);
        this._tabCtxMenu = menu;

        // Close on click outside or escape
        var closeMenu = function(ev) {
            if (ev.type === 'keydown' && ev.key !== 'Escape') return;
            menu.remove();
            self._tabCtxMenu = null;
            document.removeEventListener('click', closeMenu);
            document.removeEventListener('keydown', closeMenu);
        };
        setTimeout(function() {
            document.addEventListener('click', closeMenu);
            document.addEventListener('keydown', closeMenu);
        }, 0);
    };

    GridTabManager.prototype._closeTabsExcept = function(keepSet) {
        this._selectedTabs.clear();
        for (var i = this.tabs.length - 1; i >= 0; i--) {
            if (!keepSet.has(i) && this.tabs[i].closable) {
                this._disposeTabBeforeRemoval(this.tabs[i]);
                this.tabs[i].containerEl.remove();
                this.tabs.splice(i, 1);
                // Shift indices in keepSet that were above removed index
                var updated = new Set();
                keepSet.forEach(function(k) { updated.add(k > i ? k - 1 : k); });
                keepSet = updated;
            }
        }
        this.activeTabIndex = Math.min(this.activeTabIndex, this.tabs.length - 1);
        this._renderTabBar();
        this._switchTab(this.activeTabIndex);
        if (!this._restoringState) this.snapshotWorkbook();
        this._notifySqlTabsChanged();  // feature « Requête SQL » (dédup par signature)
    };

    GridTabManager.prototype._closeTabsIn = function(closeSet) {
        this._selectedTabs.clear();
        for (var i = this.tabs.length - 1; i >= 0; i--) {
            if (closeSet.has(i) && this.tabs[i].closable && this.tabs.length > 1) {
                this._disposeTabBeforeRemoval(this.tabs[i]);
                this.tabs[i].containerEl.remove();
                this.tabs.splice(i, 1);
            }
        }
        this.activeTabIndex = Math.min(this.activeTabIndex, this.tabs.length - 1);
        this._renderTabBar();
        this._switchTab(this.activeTabIndex);
        if (!this._restoringState) this.snapshotWorkbook();
        this._notifySqlTabsChanged();  // feature « Requête SQL » (dédup par signature)
    };

    GridTabManager.prototype._closeTabsRight = function(fromIdx) {
        this._selectedTabs.clear();
        for (var i = this.tabs.length - 1; i > fromIdx; i--) {
            if (this.tabs[i].closable) {
                this._disposeTabBeforeRemoval(this.tabs[i]);
                this.tabs[i].containerEl.remove();
                this.tabs.splice(i, 1);
            }
        }
        if (this.activeTabIndex >= this.tabs.length) {
            this.activeTabIndex = this.tabs.length - 1;
        }
        this._renderTabBar();
        this._switchTab(this.activeTabIndex);
        if (!this._restoringState) this.snapshotWorkbook();
        this._notifySqlTabsChanged();  // feature « Requête SQL » (dédup par signature)
    };

    GridTabManager.prototype._closeTabsLeft = function(fromIdx) {
        this._selectedTabs.clear();
        var removed = 0;
        for (var i = fromIdx - 1; i >= 0; i--) {
            if (this.tabs[i].closable) {
                this._disposeTabBeforeRemoval(this.tabs[i]);
                this.tabs[i].containerEl.remove();
                this.tabs.splice(i, 1);
                removed++;
            }
        }
        this.activeTabIndex = Math.max(0, this.activeTabIndex - removed);
        this._renderTabBar();
        this._switchTab(this.activeTabIndex);
        if (!this._restoringState) this.snapshotWorkbook();
        this._notifySqlTabsChanged();  // feature « Requête SQL » (dédup par signature)
    };

    GridTabManager.prototype._handleDrillResult = function(data) {
        // Extract the clicked value from breadcrumb (e.g. "Détail — Dossier=UDAF CONSOLIDE" → "UDAF CONSOLIDE")
        var context = '';
        if (data.breadcrumb) {
            var eqIdx = data.breadcrumb.indexOf('=');
            context = eqIdx !== -1 ? data.breadcrumb.substring(eqIdx + 1).trim() : data.breadcrumb.replace('Détail — ', '');
        }

        if (data.multi && data.results) {
            for (var i = 0; i < data.results.length; i++) {
                var r = data.results[i];
                if (r.error) continue;
                var count = r.row_count ? ' (' + r.row_count + ')' : '';
                var label = r.label + (context ? ' · ' + context : '') + count;
                this.addTab(label, r.columns || [], r.rows || [], r.sql || '', r.row_count || 0, null, true);
            }
        } else {
            var count2 = data.row_count ? ' (' + data.row_count + ')' : '';
            var singleLabel = (context || 'Détail') + count2;
            this.addTab(singleLabel, data.columns || [], data.rows || [], data.sql || '', data.row_count || 0, data.column_metadata || null, true);
        }
    };

    GridTabManager.prototype._getTabsContext = function() {
        var ctx = [];
        var seenSqlHashes = {};
        for (var i = 0; i < this.tabs.length; i++) {
            var tab = this.tabs[i];
            var grid = tab.grid;
            var tabSql = grid ? grid.sql : '';
            // Deduplicate tabs with identical SQL
            if (tabSql) {
                var sqlHash = tabSql.length + ':' + tabSql.substring(0, 200);
                if (seenSqlHashes[sqlHash]) {
                    seenSqlHashes[sqlHash].count++;
                    continue; // Skip duplicate
                }
                seenSqlHashes[sqlHash] = { count: 1 };
            }
            var gridCols = grid ? grid.columns : [];
            var gridMerges = (grid && typeof grid.getMerges === 'function') ? grid.getMerges() : [];
            var entry = {
                label: tab.label,
                sql: tabSql,
                columns: gridCols,
                row_count: grid ? grid.totalRowCount : 0,
                is_active: i === this.activeTabIndex,
                merges: gridMerges,
                _tabIndex: i  // real index into tabs/grids (not affected by dedup)
            };
            // Distinct values per column — gives the LLM the full vocabulary
            if (grid && grid.allRows && grid.allRows.length > 0 && i !== this.activeTabIndex && tabSql) {
                var MAX_DISTINCT = 30;
                var MAX_SCAN_ROWS = 5000;  // cap scan to avoid UI freeze
                var MAX_TOTAL_CHARS = 4000;  // budget total across all columns
                var scanLimit = Math.min(grid.allRows.length, MAX_SCAN_ROWS);
                var colDistinct = {};
                var totalChars = 0;

                for (var ci = 0; ci < grid.columns.length; ci++) {
                    if (totalChars >= MAX_TOTAL_CHARS) break;
                    var colName = grid.columns[ci];
                    var vals = {};
                    var numCount = 0, nonNumCount = 0, numMin = Infinity, numMax = -Infinity;
                    for (var ri = 0; ri < scanLimit; ri++) {
                        var v = grid.isArrayFormat ? grid.allRows[ri][ci] : grid.allRows[ri][colName];
                        if (v === null || v === undefined || v === '') continue;
                        var s = String(v).trim();
                        if (!s) continue;
                        var n = Number(s);
                        if (!isNaN(n) && isFinite(n)) {
                            numCount++;
                            if (n < numMin) numMin = n;
                            if (n > numMax) numMax = n;
                        } else {
                            nonNumCount++;
                        }
                        vals[s] = true;
                    }
                    var uniqueCount = Object.keys(vals).length;
                    if (uniqueCount === 0) continue;

                    // Numeric if >95% of non-null values are numbers
                    var isNumeric = numCount > 0 && nonNumCount <= numCount * 0.05;

                    if (isNumeric) {
                        var desc = colName + ': numeric (min=' + numMin + ', max=' + numMax + ', ' + uniqueCount + ' distinct)';
                        totalChars += desc.length;
                        colDistinct[colName] = {
                            type: 'numeric',
                            min: numMin,
                            max: numMax,
                            distinct: uniqueCount
                        };
                    } else {
                        var allVals = Object.keys(vals).sort();
                        var sliced = allVals.slice(0, MAX_DISTINCT);
                        var desc2 = colName + ': ' + sliced.join(', ');
                        totalChars += desc2.length;
                        colDistinct[colName] = {
                            type: 'text',
                            values: sliced,
                            distinct: uniqueCount,
                            truncated: uniqueCount > MAX_DISTINCT
                        };
                    }
                }
                entry.col_distinct = colDistinct;
                // #18f (triage caps 2026-06-10) — au-delà de MAX_SCAN_ROWS,
                // min/max/comptes distincts sont calculés sur un PRÉFIXE :
                // sans ce flag, le LLM lit « min=X, max=Y, N distinct »
                // comme des faits de table entière (filtres/analyses faux).
                if (grid.allRows.length > scanLimit) {
                    entry.col_distinct_scan = {
                        scanned: scanLimit,
                        total: grid.allRows.length
                    };
                }
            }
            // sheet_content — pour TOUS les onglets sœurs avec lignes (SQL ou non).
            // - Non-SQL (dashboard / xlsx) : émet chaque cellule non vide + cellDetails existants
            // - SQL : identifie colonnes-dimensions (via GROUP BY du SQL ou heuristique
            //   cardinalité) et émet 1 cellule par (row, mesure) avec match = dims. Permet
            //   au LLM et au backend (recompute emit_tab) de sommer sans réexécuter le SQL.
            // Onglets non-SQL (xlsx, templates, dashboards) : tronquage SÉLECTIF.
            // Labels = structure à cloner → cap haut. Nombres purs = data → cap plus
            // serré. Cellules avec cellDetails (drill-down SQL/match) → jamais
            // tronquées. Cf. commentaire principal au path MAX_LABEL_CELLS pour la
            // logique détaillée.
            var SIBLING_MAX_LABEL_CELLS = 2000;
            var SIBLING_MAX_NUMERIC_CELLS = 500;
            // Onglets SQL : cap large (6000) parce que le backend `_recompute_emit_tab`
            // itère sur le sheet_content COMPLET pour retrouver les matches (mois ×
            // année × expert × code). Avec 500 on perdait ~90% des rows de Mois CA EC
            // (946 × ~5 mesures = 4730 cells) → beaucoup de `no_source` au recompute.
            // Le rendu LLM reste capé à 300 cells par _truncate_sheet_content_for_llm
            // côté backend (ne voir que l'échantillon), ce qui laisse le recompute
            // accéder aux rows complètes sans bloater le prompt.
            var SIBLING_MAX_CELLS_SQL = 6000;
            var isSiblingSheetWithRows =
                grid
                && i !== this.activeTabIndex
                && grid.allRows && grid.allRows.length > 0;
            if (isSiblingSheetWithRows) {
                var isSqlTab = !!tabSql;
                var maxCells = isSqlTab ? SIBLING_MAX_CELLS_SQL : null;
                var siblingCells = [];
                var siblingCount = 0;
                var siblingTruncated = false;
                // Compteurs séparés pour le path non-SQL (tronquage sélectif)
                var siblingLabelCount = 0;
                var siblingNumericCount = 0;
                var siblingLabelTruncated = false;
                var siblingNumericTruncated = false;

                if (isSqlTab) {
                    var classification = this._classifyColumnsForSqlTab(grid);
                    var dimCols = classification.dims;
                    var measureCols = classification.measures;
                    for (var sr = 0; sr < grid.allRows.length && !siblingTruncated; sr++) {
                        var rowMatch = {};
                        for (var dIdx = 0; dIdx < dimCols.length; dIdx++) {
                            var dCol = dimCols[dIdx];
                            var dCi = grid.columns.indexOf(dCol);
                            if (dCi < 0) continue;
                            var dVal = grid.isArrayFormat ? grid.allRows[sr][dCi] : grid.allRows[sr][dCol];
                            if (dVal === null || dVal === undefined || dVal === '') continue;
                            var dStr = String(dVal).trim();
                            if (!dStr) continue;
                            var dNum = Number(dStr);
                            rowMatch[dCol] = (!isNaN(dNum) && isFinite(dNum) && /^-?\d+(\.\d+)?$/.test(dStr))
                                ? dNum : dStr;
                        }
                        for (var mIdx = 0; mIdx < measureCols.length && !siblingTruncated; mIdx++) {
                            var mCol = measureCols[mIdx];
                            var mCi = grid.columns.indexOf(mCol);
                            if (mCi < 0) continue;
                            var mVal = grid.isArrayFormat ? grid.allRows[sr][mCi] : grid.allRows[sr][mCol];
                            if (mVal === null || mVal === undefined || mVal === '') continue;
                            var mStr = String(mVal).trim();
                            if (!mStr) continue;
                            var mNum = Number(mStr);
                            if (isNaN(mNum) || !isFinite(mNum)) continue;
                            if (siblingCount >= maxCells) {
                                siblingTruncated = true;
                                break;
                            }
                            siblingCells.push({
                                row: sr + 1,
                                col: mCol,
                                value: mNum,
                                match: rowMatch
                            });
                            siblingCount++;
                        }
                    }
                } else {
                    // Path non-SQL : tronquage sélectif par rôle sémantique.
                    // cellDetails présent = toujours gardé. Sinon : string=label
                    // (cap LABEL), number=data (cap NUMERIC).
                    for (var sr2 = 0; sr2 < grid.allRows.length; sr2++) {
                        for (var ci2 = 0; ci2 < grid.columns.length; ci2++) {
                            var sv = grid.isArrayFormat ? grid.allRows[sr2][ci2] : grid.allRows[sr2][grid.columns[ci2]];
                            if (!sv && sv !== 0) continue;
                            var svStr = String(sv);
                            var svTrim = svStr.trim();
                            if (!svTrim) continue;
                            var sibDetailKey = sr2 + ',' + ci2;
                            var sibDetail = grid._cellDetails ? grid._cellDetails[sibDetailKey] : null;
                            var sibHasDetail = !!(sibDetail && (sibDetail.sql || sibDetail.match || sibDetail.label || sibDetail.description));
                            var sibNumVal = Number(svTrim);
                            var sibIsNumeric = (typeof sv === 'number') ||
                                (!isNaN(sibNumVal) && isFinite(sibNumVal));
                            if (!sibHasDetail) {
                                if (sibIsNumeric) {
                                    if (siblingNumericCount >= SIBLING_MAX_NUMERIC_CELLS) {
                                        siblingNumericTruncated = true;
                                        continue;
                                    }
                                    siblingNumericCount++;
                                } else {
                                    if (siblingLabelCount >= SIBLING_MAX_LABEL_CELLS) {
                                        siblingLabelTruncated = true;
                                        continue;
                                    }
                                    siblingLabelCount++;
                                }
                            }
                            var sibEntry = { row: sr2 + 1, col: grid.columns[ci2], value: svStr };
                            if (sibDetail) {
                                if (sibDetail.sql) sibEntry.source_sql = sibDetail.sql;
                                if (sibDetail.match) sibEntry.match = sibDetail.match;
                                sibEntry.label = sibDetail.label || sibDetail.description || null;
                            }
                            siblingCells.push(sibEntry);
                            siblingCount++;
                        }
                    }
                    if (siblingLabelTruncated || siblingNumericTruncated) {
                        var sibParts = [];
                        if (siblingLabelTruncated) sibParts.push('labels > ' + SIBLING_MAX_LABEL_CELLS);
                        if (siblingNumericTruncated) sibParts.push('valeurs numériques > ' + SIBLING_MAX_NUMERIC_CELLS);
                        siblingCells.push({
                            row: 0, col: '_meta',
                            value: '(tronqué — ' + sibParts.join(', ') +
                                '). Les cellules avec cellDetails sont préservées.'
                        });
                    }
                }

                if (isSqlTab && siblingTruncated) {
                    siblingCells.push({
                        row: 0, col: '_meta',
                        value: '(contenu tronqué — feuille dépasse ' + maxCells + ' cellules)'
                    });
                }
                if (siblingCells.length > 0) entry.sheet_content = siblingCells;
            }
            ctx.push(entry);
        }
        // Annotate deduplicated tabs
        for (var j = 0; j < ctx.length; j++) {
            if (ctx[j].sql) {
                var hash = ctx[j].sql.length + ':' + ctx[j].sql.substring(0, 200);
                var info = seenSqlHashes[hash];
                if (info && info.count > 1) {
                    ctx[j].label += ' (×' + info.count + ')';
                }
            }
        }
        // Global size guard — purely defensive : on NE TRONQUE PLUS les sheet_content
        // des onglets SQL ici, car le backend en a besoin INTÉGRAUX pour
        // `_recompute_emit_tab` (sommer les rows matchant). Le backend a son propre
        // `_truncate_sheet_content_for_llm` à 300 cells uniquement pour le rendu LLM,
        // ce qui protège la fenêtre de contexte du LLM sans sacrifier la précision
        // du recompute. Pour les non-SQL sheets (xlsx importés avec potentiellement
        // des milliers de cellules), on garde une cascade à 1500 cells si global > 200K.
        var estimatedTokens = JSON.stringify(ctx).length / 4;
        if (estimatedTokens > 200000) {
            for (var k = 0; k < ctx.length; k++) {
                if (ctx[k].sheet_content && !ctx[k].sql && ctx[k].sheet_content.length > 1500) {
                    ctx[k].sheet_content = ctx[k].sheet_content.slice(0, 1500);
                    ctx[k].sheet_content.push({
                        row: 0, col: '_meta',
                        value: '(truncated to 1500 for prompt size budget — non-SQL sheet)'
                    });
                }
            }
        }
        return ctx;
    };

    // Classifie les colonnes d'un onglet SQL en dimensions (GROUP BY ou faible
    // cardinalité) et mesures (valeurs agrégées). Utilise le GROUP BY du SQL
    // top-level quand extrait-able ; fallback heuristique sinon.
    //
    // Pièges gérés :
    // - GROUP BY positional (`GROUP BY 1, 2`) → résolu via columns[n-1].
    // - GROUP BY dans une sous-requête imbriquée → ignoré via décompte de
    //   parenthèses (on ne matche qu'au depth 0).
    // - GROUP BY avec expression (`YEAR(d)`) → expr ignorée (pas de match direct
    //   sur un nom de colonne), tombe en heuristique pour cette colonne.
    GridTabManager.prototype._classifyColumnsForSqlTab = function(grid) {
        var dims = [];
        var measures = [];
        var sql = grid.sql || '';
        var columns = grid.columns || [];
        var declaredDims = null;

        // Trouve la dernière occurrence de "GROUP BY" au depth 0 (hors sous-requêtes).
        var topGroupBy = (function() {
            var depth = 0;
            var gbRe = /GROUP\s+BY\b/gi;
            var m;
            var lastStart = -1;
            while ((m = gbRe.exec(sql)) !== null) {
                // Compte depth jusqu'à la position du match
                var d = 0;
                for (var i = 0; i < m.index; i++) {
                    var ch = sql.charAt(i);
                    if (ch === '(') d++;
                    else if (ch === ')') d--;
                }
                if (d === 0) lastStart = m.index + m[0].length;
            }
            if (lastStart === -1) return '';
            // Trouver la fin de la clause (ORDER BY, HAVING, ; ou fin)
            var tail = sql.substring(lastStart);
            var endMatch = tail.match(/\bORDER\s+BY\b|\bHAVING\b|;|$/i);
            var endIdx = endMatch ? endMatch.index : tail.length;
            return tail.substring(0, endIdx);
        })();

        if (topGroupBy) {
            declaredDims = {};
            var gbCols = topGroupBy.split(',');
            for (var k = 0; k < gbCols.length; k++) {
                var expr = gbCols[k].trim();
                if (!expr) continue;
                // Positional GROUP BY (ex: "GROUP BY 1, 2") → resolve via columns[n-1]
                if (/^\d+$/.test(expr)) {
                    var posIdx = parseInt(expr, 10) - 1;
                    if (posIdx >= 0 && posIdx < columns.length) {
                        declaredDims[columns[posIdx].toLowerCase()] = true;
                    }
                    continue;
                }
                // Skip expressions (ex: YEAR(d), UPPER(col)) — traitées en heuristique
                if (/[()]/.test(expr)) continue;
                // Strip qualifier prefix (T.col → col) and quotes/brackets
                var bare = expr.replace(/^[^.\s()]+\./, '').replace(/[`"\[\]]/g, '').trim();
                if (bare) declaredDims[bare.toLowerCase()] = true;
            }
            // Si aucune dim résolvable malgré un GROUP BY présent (ex: tout expressions),
            // désactive le mode "declared" et bascule en heuristique pure.
            if (Object.keys(declaredDims).length === 0) {
                declaredDims = null;
            }
        }
        var n = grid.allRows.length;
        var sampleLimit = Math.min(n, 1000);
        for (var ci = 0; ci < grid.columns.length; ci++) {
            var colName = grid.columns[ci];
            if (declaredDims && declaredDims[colName.toLowerCase()]) {
                dims.push(colName);
                continue;
            }
            if (declaredDims) {
                // GROUP BY was parsed — anything not in it is a measure
                measures.push(colName);
                continue;
            }
            // No GROUP BY → heuristic: text or low-cardinality numeric = dim
            var uniques = {};
            var numCount = 0, nonNumCount = 0;
            for (var ri = 0; ri < sampleLimit; ri++) {
                var v = grid.isArrayFormat ? grid.allRows[ri][ci] : grid.allRows[ri][colName];
                if (v === null || v === undefined || v === '') continue;
                var s = String(v).trim();
                if (!s) continue;
                var num = Number(s);
                if (!isNaN(num) && isFinite(num)) numCount++;
                else nonNumCount++;
                uniques[s] = true;
            }
            var uq = Object.keys(uniques).length;
            var isMostlyNumeric = numCount > 0 && nonNumCount <= numCount * 0.05;
            if (!isMostlyNumeric) {
                dims.push(colName);
            } else if (uq <= 50 || uq <= sampleLimit * 0.05) {
                dims.push(colName);
            } else {
                measures.push(colName);
            }
        }
        return { dims: dims, measures: measures };
    };

    // ── Workbook save/load (.afz.json) ──

    /**
     * Marque le classeur "dirty" (modifications non sauvées) ou "clean".
     * Met à jour l'asterisk dans ``document.title`` (façon Excel : ``Mon
     * classeur* — Komptia``) et dans le label de l'onglet de la grille.
     * Idempotent : appelable plusieurs fois sans effet de bord.
     */
    GridTabManager.prototype._setDirty = function(dirty) {
        var was = this._dirty;
        this._dirty = !!dirty;
        // **Compteur de mutations monotone** : bumpé à CHAQUE appel dirty=true,
        // même quand le workbook était DÉJÀ dirty (``_setDirty(true)`` est
        // idempotent sur le booléen). Sert à détecter une édition PENDANT un
        // save in-flight dans le cas autosave (où ``_dirty`` est déjà true au
        // départ) — un snapshot booléen ne verrait jamais le changement et
        // resetterait "clean" à tort (perte silencieuse, cf. fix H1).
        if (this._dirty) {
            this._dirtySeq = (this._dirtySeq || 0) + 1;
        }
        // Scan auto anonymization à chaque mutation workbook (debounce 2.5s
        // côté _scheduleAnonymizationScan). Couvre edit cellule, paste, add
        // tab, import xlsx/csv en preview, etc. — alimente
        // anonymization_terms en temps réel (task #8 POINT 1).
        if (this._dirty && !was) {
            this._scheduleAnonymizationScan();
        }
        if (was === this._dirty) return; // pas de changement, skip refresh UI
        this._refreshDirtyTitle();
    };

    /**
     * Schedule un scan d'anonymisation du workbook avec debounce 2.5s.
     * À chaque changement workbook, l'utilisateur peut taper rapidement —
     * on attend qu'il s'arrête ~2.5s puis POST le state au serveur pour
     * alimenter ``anonymization_terms`` (auto-catégorisation PII).
     *
     * Idempotent : si un timer est déjà en cours, on le reset.
     * Fire-and-forget : pas de blocking UX, juste log les erreurs.
     */
    GridTabManager.prototype._scheduleAnonymizationScan = function() {
        var self = this;
        if (this._anonScanTimer) {
            clearTimeout(this._anonScanTimer);
            this._anonScanTimer = null;
        }
        // Fix race condition (review adversariale CRITICAL #3 — 2026-05-19) :
        // on CAPTURE le contexte (notamment ``IRIS_CONFIG.conversationId``)
        // AU MOMENT où le scan est schedulé, PAS au moment du fetch 2.5s
        // plus tard. Sinon : si l'utilisateur enchaîne 2 messages Iris
        // rapidement, le 2ᵉ event WS peut écraser ``conversationId`` AVANT
        // que le debounce ne tire — le scan attribuerait les tokens du
        // 1ᵉʳ message à la 2ᵉ conversation (fausse trace GDPR).
        var capturedCtx = self._detectScanContext();
        this._anonScanTimer = setTimeout(function() {
            self._anonScanTimer = null;
            self._runAnonymizationScan(capturedCtx);
        }, 2500);
    };

    /**
     * Détecte le contexte de la page courante pour annoter le scan
     * d'anonymisation avec la bonne source. Retourne ``{scan_context,
     * context_id}`` ou ``null`` si comportement workbook standard.
     *
     * Trois pages utilisent iris-grid avec GridTabManager :
     *   - ``/datastore`` (et autres) → comportement historique (workbook)
     *   - ``/iris`` → scan_context="iris", context_id = conversationId
     *   - ``/automations/N/edit`` → scan_context="automation_preview",
     *     context_id = N
     *
     * Pourquoi pas dans l'__init__ de GridTabManager : le pathname peut
     * changer (SPA navigation future) et le conversationId d'Iris est
     * réassigné à chaque message (event ``conversation_id`` du WebSocket).
     * Calcul on-demand → toujours frais.
     */
    GridTabManager.prototype._detectScanContext = function() {
        if (typeof window === 'undefined' || !window.location) return null;
        var path = String(window.location.pathname || '');

        // /iris : récupère conversationId depuis IRIS_CONFIG (template).
        // iris.js synchronise ``IRIS_CONFIG.conversationId`` à chaque
        // event WS conversation_id (au 1er message d'une conversation
        // nouvellement créée), donc la valeur est toujours fraîche au
        // moment du scan (qui est debounced 2.5s après l'addTab — bien
        // après l'event WS qui a posé l'ID).
        if (path === '/iris' || path.indexOf('/iris/') === 0) {
            var convId = null;
            if (window.IRIS_CONFIG && window.IRIS_CONFIG.conversationId != null) {
                convId = window.IRIS_CONFIG.conversationId;
            }
            return {
                scan_context: 'iris',
                context_id: convId != null ? String(convId) : null
            };
        }

        // /automations/N/edit : récupère automation_id depuis un attribut
        // ``data-komptia-automation-id`` posé par le template (cf.
        // templates/automations/edit.html L37). Pas de couplage à un
        // composable précis — un seul querySelector au scan.
        if (/^\/automations\/\d+\/edit\/?$/.test(path)) {
            var node = document.querySelector('[data-komptia-automation-id]');
            var autoId = node ? node.getAttribute('data-komptia-automation-id') : null;
            return {
                scan_context: 'automation_preview',
                context_id: autoId || null
            };
        }

        return null;
    };

    /**
     * POST /api/anonymization/scan-workbook avec le state actuel du workbook.
     * Fire-and-forget : on log les erreurs mais on ne notifie pas l'user
     * (le scan auto est un mécanisme silencieux côté UI).
     *
     * ``capturedCtx`` (optionnel) : contexte capturé au moment du
     * ``_scheduleAnonymizationScan`` pour éviter la race condition
     * conversationId (cf. fix CRITICAL #3 review adversariale). Si null,
     * on retombe sur ``_detectScanContext()`` live (cas appel direct
     * sans passer par le scheduler — e.g. tests ou futures invocations).
     */
    GridTabManager.prototype._runAnonymizationScan = function(capturedCtx) {
        var tabsContext;
        try {
            tabsContext = this._getTabsContext();
        } catch (e) {
            return; // pas de scan si on n'arrive pas à extraire le state
        }
        if (!Array.isArray(tabsContext) || tabsContext.length === 0) return;

        // Passe le path du classeur si disponible (workbook chargé depuis
        // /datastore) — utilisé côté serveur comme source_ref pour permettre
        // le groupement par classeur dans /data/privacy (task #15). Si le
        // workbook n'est pas encore nommé (preview xlsx import, scratch),
        // source_ref reste None → grouped sous "Classeurs" générique.
        var classeurPath = (this._currentFilePath || null);
        // Normalise : on garde juste le nom de fichier (l'utilisateur ne
        // voit pas le chemin absolu dans /data/privacy, et le label sera
        // déjà préfixé par "Classeur :").
        var classeurName = classeurPath
            ? classeurPath.split('/').pop()
            : null;

        var body = {
            tabs_context: tabsContext,
            sheet_content: null
        };
        if (classeurName) {
            body.classeur_ref = classeurName;
        }

        // Annotation contextuelle (mai 2026) : sur /iris ou
        // /automations/N/edit, on enrichit le scan avec ``scan_context`` +
        // ``context_id`` pour que le backend insère ``source="sql_result"``
        // et ``source_ref="iris:<conv>" / "automation:<id>"``. Sinon les
        // tokens visibles sur ces pages arrivaient en BDD avec source par
        // défaut, sans distingo possible dans /data/privacy.
        // Sur les autres pages (datastore), comportement inchangé (la
        // détection retourne null → on n'envoie pas scan_context → backend
        // applique source="workbook").
        //
        // ``capturedCtx`` : utilisé si fourni (capture par
        // ``_scheduleAnonymizationScan`` au moment où le scan est schedulé,
        // pour éviter la race condition conversationId). Sinon fallback
        // live (compat appel direct sans scheduler).
        var ctx = capturedCtx || this._detectScanContext();
        if (ctx && ctx.scan_context) {
            body.scan_context = ctx.scan_context;
            if (ctx.context_id) {
                body.context_id = ctx.context_id;
            }
        }

        fetch('/api/anonymization/scan-workbook', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Xsrftoken': (typeof _getXsrfCookie === 'function') ? _getXsrfCookie() : ''
            },
            credentials: 'same-origin',
            body: JSON.stringify(body)
        }).then(function(resp) {
            // 429 (rate-limit) attendu en cas de spam — on n'alerte pas.
            if (!resp.ok && resp.status !== 429) {
                if (window.console && console.debug) {
                    console.debug('anonymization scan-workbook: status', resp.status);
                }
            }
        }).catch(function() {
            // Erreur réseau : silencieux (scan auto best-effort).
        });
    };

    /**
     * Met à jour ``document.title`` avec/sans asterisk selon ``_dirty``.
     * Préserve le titre original (cache au premier appel) pour pouvoir
     * le restaurer au save success. Pas de DOM ailleurs (le label des
     * onglets internes est un détail visuel optionnel — l'asterisk dans
     * la barre d'onglet du navigateur est l'indicateur Excel-like
     * standard).
     */
    GridTabManager.prototype._refreshDirtyTitle = function() {
        try {
            if (!this._originalDocumentTitle) {
                this._originalDocumentTitle = document.title || '';
            }
            var orig = this._originalDocumentTitle;
            var stripped = orig.replace(/^\*\s*/, '');
            document.title = (this._dirty ? '* ' : '') + stripped;
        } catch (e) { /* noop, document indisponible (jsdom partiel) */ }
    };

    /**
     * Démarre l'autosave périodique. Idempotent (no-op si déjà démarré).
     * Appelé après loadWorkbook / saveWorkbookAs success — quand le
     * classeur a un ``_currentFilePath`` et qu'on peut sauver dessus.
     */
    GridTabManager.prototype._startAutosave = function() {
        if (this._autosavePeriodicTimer || this._autosaveDisabled) return;
        var self = this;
        this._autosavePeriodicTimer = setInterval(function() {
            self._maybeAutosave('periodic');
        }, this._AUTOSAVE_PERIODIC_MS);
    };

    /**
     * Arrête tous les timers autosave (periodic + idle pending). Appelé
     * en cas de désactivation manuelle ou quand le classeur est fermé.
     */
    GridTabManager.prototype._stopAutosave = function() {
        if (this._autosavePeriodicTimer) {
            clearInterval(this._autosavePeriodicTimer);
            this._autosavePeriodicTimer = null;
        }
        if (this._autosaveIdleTimer) {
            clearTimeout(this._autosaveIdleTimer);
            this._autosaveIdleTimer = null;
        }
    };

    /**
     * Déclenche un autosave différé après ``_AUTOSAVE_IDLE_MS`` de calme.
     * Chaque appel reset le timer — donc tant que l'utilisateur édite,
     * l'autosave ne se déclenche pas. Standard "debounce on idle"
     * pattern (Google Docs-like). Couplé au timer periodique pour la
     * sécurité (un user qui édite en continu pendant 5 min n'aurait
     * jamais d'autosave sans le periodique).
     */
    GridTabManager.prototype._scheduleIdleAutosave = function() {
        if (this._autosaveDisabled) return;
        if (this._autosaveIdleTimer) clearTimeout(this._autosaveIdleTimer);
        var self = this;
        this._autosaveIdleTimer = setTimeout(function() {
            self._autosaveIdleTimer = null;
            self._maybeAutosave('idle');
        }, this._AUTOSAVE_IDLE_MS);
    };

    /**
     * Flush synchrone de l'autosave au moment du unload (beforeunload /
     * pagehide). Utilise ``fetch`` avec ``keepalive: true`` qui survit
     * à la fermeture de la page (équivalent sendBeacon mais avec
     * support multipart/form-data). Best-effort : pas d'await, pas de
     * gestion d'erreur — au pire le navigateur ferme et la requête
     * est tronquée (le user a choisi de partir, on a fait notre
     * possible).
     *
     * Skip si rien de dirty à sauver ou si pas de path. Skip aussi si
     * un save est en cours (l'unload aura lieu APRÈS sa résolution dans
     * la plupart des cas, et la duplication ne servirait à rien).
     */
    GridTabManager.prototype._flushAutosaveOnUnload = function() {
        if (!this._dirty || !this._currentFilePath || this._autosaveDisabled) return;
        if (this._autosaveSaving) return;
        var self = this;
        try {
            var data = this.serialize();
            var json = JSON.stringify(data);
            // **Cap keepalive 64KB** : la fetch keepalive a une limite
            // body ~64KB (Fetch spec). Au-delà, rejet silencieux →
            // données perdues. Pour les classeurs gros (≥30 onglets,
            // ≥5MB), on skip le keepalive et on s'appuie EXCLUSIVEMENT
            // sur l'AutoRecover localStorage. Le ``_beforeUnloadDirtyGuard``
            // aura déjà demandé à l'utilisateur s'il veut quitter.
            if (json.length > 60_000) {
                this._writeAutoRecover();
                return;
            }
            var blob = new Blob([json], { type: 'application/json;charset=utf-8' });
            var filename = this._currentFilePath.split('/').pop();
            var formData = new FormData();
            formData.append('files', blob, filename);
            formData.append('path', '');
            formData.append('overwrite', 'true');
            var xsrf = _getXsrfCookie();
            var headers = { 'X-Xsrftoken': xsrf };
            if (this._currentFileHash) {
                headers['If-Match'] = this._currentFileHash;
            }
            // Sérialise avec l'autosave normal : on pose ``_autosaveSaving``
            // pour la durée du keepalive afin qu'un ``_maybeAutosave`` concurrent
            // ENQUEUE au lieu de courir avec un ``If-Match`` périmé pendant que le
            // keepalive est en vol (sinon le 412 fantôme se relocalise sur le
            // chemin autosave). L'entrée de ce flush a déjà vérifié
            // ``!_autosaveSaving`` plus haut → on ne piétine aucun save en cours.
            // Fallback localStorage écrit EN PREMIER : indépendant du fetch, il
            // doit s'exécuter même si ``fetch(keepalive)`` lève une exception
            // SYNCHRONE (ex. body multipart > limite keepalive sur certains
            // navigateurs). Posé AVANT le verrou pour ne pas geler l'autosave
            // s'il throwait lui-même.
            this._writeAutoRecover();
            this._autosaveSaving = true;
            var seqAtFlush = this._dirtySeq || 0;
            try {
                // ``keepalive: true`` permet à la requête de survivre à la
                // fermeture de la page (pendant ~30s côté navigateur).
                fetch('/api/datastore/upload', {
                    method: 'POST',
                    headers: headers,
                    body: formData,
                    keepalive: true,
                }).then(function(res) {
                    // Page SURVÉCUE (l'utilisateur a cliqué « Rester » dans le
                    // prompt beforeunload) → la réponse est lisible : on
                    // re-synchronise l'ETag, sinon le prochain save enverrait un
                    // ``If-Match`` périmé = 412 FANTÔME (le flush keepalive a
                    // changé le hash serveur). Page réellement fermée → ce
                    // ``then`` ne tourne jamais (best-effort inchangé, la requête
                    // keepalive part quand même).
                    if (!res.ok) return; // 412/échec RÉEL → ne pas toucher au hash
                    // Lecture SÛRE via le SSoT ``_readJsonSafe`` (ne throw jamais,
                    // même sur une page d'erreur HTML de proxy → pas de skip
                    // silencieux de la re-sync). Retourne ``{status, data}``.
                    return _readJsonSafe(res).then(function(parsed) {
                        var result = (parsed && parsed.data && typeof parsed.data === 'object')
                            ? parsed.data : {};
                        var up = result.uploaded && result.uploaded[0];
                        if (up && typeof up.file_hash === 'string') {
                            self._currentFileHash = up.file_hash;
                            // Reset dirty + purge AutoRecover UNIQUEMENT si aucune
                            // mutation depuis le flush (même garde anti-perte que
                            // ``_saveToPathAsync`` : un edit fait APRÈS « Rester »
                            // ne doit pas être masqué « clean »). ``_setDirty(false)``
                            // (≠ ``_dirty = false`` brut) rafraîchit aussi
                            // l'astérisque du titre/onglet.
                            if ((self._dirtySeq || 0) === seqAtFlush) {
                                self._setDirty(false);
                                self._clearAutoRecover();
                            }
                        }
                    });
                }).catch(function() {
                    /* best-effort : réponse illisible / réseau / page fermée */
                }).then(function() {
                    // Libère le verrou single-flight et relance un autosave mis
                    // en file pendant le vol du keepalive (même logique de queue
                    // que ``_maybeAutosave``). Ce ``then`` final tourne après
                    // succès ET après erreur → le verrou n'est jamais bloqué
                    // (sauf page fermée, où plus aucun autosave ne tournera).
                    self._autosaveSaving = false;
                    if (self._autosaveQueued && self._dirty) {
                        self._autosaveQueued = false;
                        self._scheduleIdleAutosave();
                    } else {
                        self._autosaveQueued = false;
                    }
                });
            } catch (eFetch) {
                // ``fetch`` a throw SYNCHRONEMENT (rare) → relâcher le verrou,
                // sinon l'autosave reste gelé toute la session sur une page
                // survivante. L'AutoRecover ci-dessus a déjà sauvé l'état RAM.
                self._autosaveSaving = false;
                self._autosaveQueued = false;
            }
        } catch (e) { /* best-effort */ }
    };

    /**
     * Décide si un autosave doit se lancer maintenant. Skip si :
     *  - pas de ``_currentFilePath`` (Excel ne sauve pas sans destination)
     *  - pas dirty (rien à sauver)
     *  - autosave désactivé (manuel ou via N échecs successifs)
     *  - un save est déjà en cours (single-flight, on enqueue)
     */
    GridTabManager.prototype._maybeAutosave = function(trigger) {
        if (this._autosaveDisabled) return;
        if (!this._currentFilePath) return; // pas de destination
        if (!this._dirty) return; // rien à sauver
        if (this._autosaveSaving) {
            // single-flight : on note qu'un save futur est demandé pour
            // ne pas perdre le besoin, mais on ne lance pas en parallèle.
            this._autosaveQueued = true;
            return;
        }
        var self = this;
        this._autosaveSaving = true;
        this._saveToPathAsync(this._currentFilePath, true, { silent: true })
            .then(function() {
                self._autosaveSaving = false;
                self._autosaveFailureCount = 0;
                if (self._autosaveQueued && self._dirty) {
                    self._autosaveQueued = false;
                    self._scheduleIdleAutosave();
                } else {
                    self._autosaveQueued = false;
                }
            })
            .catch(function(err) {
                self._autosaveSaving = false;
                self._autosaveQueued = false;
                self._autosaveFailureCount += 1;
                console.warn('[Autosave] failed (' + trigger + '):', err && err.message);
                // **Filet anti-perte de données** : tout échec serveur (412,
                // quota, oversize, panne réseau, 5xx) écrit un AutoRecover
                // localStorage. La version RAM n'est donc jamais silencieusement
                // perdue, même si le serveur refuse durablement (le chemin
                // unload a déjà ce filet ; l'autosave périodique ne l'avait pas).
                try { self._writeAutoRecover(); } catch (e) { /* best-effort */ }
                // 412 conflict — on doit notifier le user qui résoudra
                // (reload ou force overwrite). Bloque les autosaves
                // futurs jusqu'à résolution pour ne pas spammer.
                if (err && err._etagMismatch) {
                    self._autosaveDisabled = true;
                    self._showSaveToast(
                        'Conflit : ce classeur a été modifié ailleurs. '
                        + 'Rechargez ou utilisez Enregistrer sous.',
                        true
                    );
                    return;
                }
                if (err && err._quotaExceeded) {
                    self._autosaveDisabled = true;
                    self._showSaveToast(
                        'Quota atteint — auto-sauvegarde désactivée.',
                        true
                    );
                    return;
                }
                // Oversize passerelle (nginx 413) : un RETRY ne réussira
                // JAMAIS tant que le classeur reste trop gros. On désactive
                // l'autosave avec un message ACTIONNABLE (≠ "réessayez", qui
                // serait un mensonge) et on s'appuie sur l'AutoRecover ci-dessus.
                if (err && err._tooLarge) {
                    self._autosaveDisabled = true;
                    self._showSaveToast(
                        'Classeur trop volumineux pour être sauvegardé sur le '
                        + 'serveur. Réduisez les lignes/colonnes ou supprimez '
                        + 'des onglets, puis réenregistrez.',
                        true
                    );
                    return;
                }
                // Trop d'échecs successifs → désactive l'autosave avec
                // notification explicite (réseau ou serveur en panne).
                if (self._autosaveFailureCount >= self._AUTOSAVE_MAX_FAILURES) {
                    self._autosaveDisabled = true;
                    self._showSaveToast(
                        'Auto-sauvegarde en pause après plusieurs échecs. '
                        + 'Réessayez via le bouton Enregistrer.',
                        true
                    );
                }
            });
    };

    GridTabManager.prototype.serialize = function() {
        var tabs = [];
        for (var i = 0; i < this.tabs.length; i++) {
            var tab = this.tabs[i];
            var grid = tab.grid;
            if (!grid) continue;
            // Snapshot unique des merges (1) pour éviter un double-appel
            // getMerges() coûteux ET un risque d'inconsistance entre les deux
            // valeurs sérialisées (merges et isDashboardSheet doivent venir
            // du MÊME instant). (2) isDashboardSheet est DÉRIVÉ depuis les
            // merges — un onglet est un dashboard SSI il a des cellules
            // fusionnées (layout figé). cellDetails seuls (drill-downs) ne
            // suffisent pas. Recalcul au save pour empêcher tout flag stocké
            // à tort de persister entre sessions.
            var mergesSnapshot = (typeof grid.getMerges === 'function' ? grid.getMerges() : []);
            tabs.push({
                label: tab.label,
                closable: tab.closable,
                sql: grid.sql || '',
                columns: grid.columns,
                rows: grid.allRows,
                totalRowCount: grid.totalRowCount,
                columnMetadata: grid.columnMetadata,
                isArrayFormat: grid.isArrayFormat,
                hiddenCols: Array.from(grid.hiddenCols),
                columnOrder: grid.columnOrder,
                sortColIndex: grid.sortColIndex,
                sortDirection: grid.sortDirection,
                filters: JSON.parse(JSON.stringify(grid.filters, function(k, v) {
                    return v instanceof Set ? Array.from(v) : v;
                })),
                isBlankSheet: grid._isBlankSheet || false,
                isDashboardSheet: mergesSnapshot.length > 0,
                truncated: grid._truncated || false,
                truncatedCols: grid._truncatedCols || false,
                truncatedColsTotal:
                    typeof grid._truncatedColsTotal === 'number' ? grid._truncatedColsTotal : null,
                merges: mergesSnapshot,
                externalSource: tab.externalSource || null,
                cellDetails: (function() {
                    var cd = grid._cellDetails || {};
                    var slim = {};
                    for (var k in cd) {
                        if (cd.hasOwnProperty(k)) {
                            slim[k] = {
                                sql: cd[k].sql || '',
                                columns: cd[k].columns || [],
                                row_count: cd[k].row_count || 0,
                                description: cd[k].description || '',
                                match: cd[k].match || null,
                                label: cd[k].label || null,
                                // Champs nécessaires à la reconstruction des
                                // rows de détail à l'export Excel quand
                                // `rows` n'est pas en cache. Sans eux, après
                                // save+reload, l'export ne pourrait plus
                                // produire le détail des cellules dashboard.
                                match_exclude: cd[k].match_exclude || null,
                                source_tab_index: (typeof cd[k].source_tab_index === 'number')
                                    ? cd[k].source_tab_index : null,
                                value_column: cd[k].value_column || null,
                                derived_formula: cd[k].derived_formula || null
                            };
                        }
                    }
                    return slim;
                })()
            });
        }
        return {
            version: 1,
            app: 'komptia',
            created_at: new Date().toISOString(),
            active_tab: this.activeTabIndex,
            tabs: tabs,
            // Mémoire copilot persistée à la racine du classeur (cleartext,
            // ~2000 chars max). Vide si aucun run copilot n'a encore été
            // effectué sur ce classeur. Lue au prochain load et renvoyée au
            // backend via le body du POST /api/iris/result-modify.
            copilot_memory: (typeof this._copilotMemory === 'string'
                ? this._copilotMemory : '')
        };
    };

    /**
     * Enregistrer — écrase le fichier courant. Si aucun fichier courant, fait "Enregistrer sous".
     */
    GridTabManager.prototype.saveWorkbook = function() {
        // Délégué de sauvegarde custom (widget grille de dashboard : le
        // classeur est persisté SUR LE WIDGET via PUT .../workbook, pas en
        // fichier datastore libre). Posé par le contexte hôte
        // (builder_view.html). Intercepte TOUS les chemins « Enregistrer » :
        // menu de la barre d'onglets, Ctrl+S (onSave), appels programmatiques.
        // « Enregistrer sous » n'est PAS intercepté (export de copie datastore).
        if (typeof this._saveDelegate === 'function') {
            this._saveDelegate();
            return;
        }
        if (this._currentFilePath) {
            this._saveToPath(this._currentFilePath, true);
        } else {
            this.saveWorkbookAs();
        }
    };

    /**
     * Sérialise le classeur complet et le compresse en Blob gzip (même
     * pipeline que la sauvegarde datastore : ``serialize()`` +
     * ``_gzipStringToBlob``). Retourne une Promise<{blob, isGzip}> —
     * ``isGzip=false`` (Blob JSON brut) si CompressionStream indisponible
     * (vieux navigateur) ; le backend accepte les deux (magic bytes).
     * Utilisé par la sauvegarde du widget grille (builder_view.html) —
     * single source of truth de la sérialisation, pas de duplication.
     */
    GridTabManager.prototype.serializeToGzipBlob = function() {
        var json = JSON.stringify(this.serialize());
        return _gzipStringToBlob(json).then(function(gz) {
            if (gz) return { blob: gz, isGzip: true };
            return {
                blob: new Blob([json], { type: 'application/json;charset=utf-8' }),
                isGzip: false
            };
        });
    };

    /**
     * Enregistrer sous — ouvre une modale qui prompte le nom du fichier
     * (façon Excel F12). Default = nom horodaté pour les nouveaux
     * classeurs, ou nom courant pour un Save As d'un classeur existant.
     * Validation client : sanitize les caractères dangereux (`/`, `\`,
     * `..`) avant l'envoi (le backend ``_safe_path`` reste la source de
     * vérité, mais on évite un round-trip inutile pour les cas évidents).
     *
     * Si l'utilisateur tape un nom existant, le backend retourne 409
     * Conflict via ``overwrite=false`` puis renomme automatiquement
     * (legacy behavior). Pour ce flow Save As on fournit explicitement
     * un message d'avertissement avant l'envoi.
     */
    GridTabManager.prototype.saveWorkbookAs = function() {
        var self = this;
        var defaultName;
        if (this._currentFilePath) {
            defaultName = this._currentFilePath.split('/').pop().replace(/\.afz\.json$/i, '');
        } else {
            defaultName = 'classeur_' + new Date().toISOString().slice(0, 16).replace(/[T:]/g, '-');
        }

        this._openSaveAsModal(defaultName, function(chosenName) {
            // Sanitize : retire les séparateurs path et .. (le backend
            // ``_safe_path`` re-vérifiera, mais on cap ici pour UX).
            var clean = chosenName.replace(/[\/\\]/g, '_').replace(/\.\./g, '_').trim();
            if (!clean) {
                self._showSaveToast('Nom invalide', true);
                return;
            }
            // Cap longueur (cohérent FileMetadata.filename String(255))
            if (clean.length > 200) clean = clean.slice(0, 200);
            // Append extension si manquante
            if (!/\.afz\.json$/i.test(clean)) clean = clean + '.afz.json';
            // Save As crée TOUJOURS un nouveau fichier — overwrite=false
            // pour que le backend renomme auto si le nom existe déjà.
            // C'est la sémantique Excel "Save As" : si conflit, on
            // crée une variante (ex: ``rapport_1.afz.json``).
            self._currentFileHash = null; // pas de hash sur un nouveau fichier
            self._saveToPath(clean, false);
        });
    };

    // ── AutoRecover (localStorage) ──
    //
    // Filet de sécurité pour les cas où l'autosave backend a échoué ou
    // n'a pas pu tourner (réseau coupé, navigateur fermé brutalement,
    // crash JS). À chaque modification dirty, on stocke un snapshot
    // léger dans localStorage. Au load suivant, si on détecte un
    // snapshot plus récent que le serveur (le backend nous donne un
    // ``last_modified``), on propose à l'utilisateur de récupérer.
    //
    // Scope : ``autorecover_<filePath>`` — un seul snapshot par
    // classeur. Cap à 4 Mo pour rester sous la limite localStorage
    // (~5 Mo) en laissant marge pour les autres clefs (anonymisation,
    // theme, etc.). Si le classeur fait plus que ce cap, on skip
    // (l'autosave backend reste le filet primaire pour les gros).

    GridTabManager.prototype._autoRecoverKey = function(filePath) {
        // Permet de calculer la clef pour un path SPÉCIFIQUE (utile au
        // Save As pour cleanup de l'ancien path) ou pour le path
        // courant (défaut).
        var path = (typeof filePath === 'string') ? filePath : this._currentFilePath;
        if (!path) return null;
        // **Scope per-user** : sans le user_id dans la clef, sur un
        // device partagé (cabinet comptable, kiosque), User B pourrait
        // restaurer les données confidentielles de User A laissées en
        // localStorage. C'est une violation directe de la stratégie
        // multi-niveaux de confidentialité Komptia. Le user_id est
        // exposé par le bootstrap Tornado dans ``window.komptiaCurrentUserId``
        // (cf. base template). Si absent (anonyme), on utilise ``anon``
        // qui ne match avec aucun user authentifié.
        var userId = (typeof window !== 'undefined'
            && window.komptiaCurrentUserId != null)
            ? String(window.komptiaCurrentUserId)
            : 'anon';
        return 'komptia_autorec_u' + userId + '_' + encodeURIComponent(path);
    };

    GridTabManager.prototype._writeAutoRecover = function() {
        var key = this._autoRecoverKey();
        if (!key) return;
        try {
            var data = this.serialize();
            var ts = Date.now();
            var hash = this._currentFileHash || null;
            // Stockage à étages (cf. design) : le gros blob (workbook entier)
            // va en IndexedDB via GridStore (plus de cap 4 Mo — IDB gère le
            // volume), et un MARQUEUR léger reste en localStorage (sync) pour
            // que ``_checkAutoRecover`` décide "récup plus récente que le
            // serveur ?" SANS charger le blob.
            if (typeof window !== 'undefined' && window.GridStore) {
                try {
                    localStorage.setItem(key, JSON.stringify({
                        version: 1, ts: ts, file_hash_at_load: hash, hasHeavy: true,
                    }));
                } catch (e) { /* marqueur best-effort */ }
                this._autoRecoverPromise = window.GridStore.put('autorec:' + key, {
                    version: 1, ts: ts, _savedAt: ts, file_hash_at_load: hash, data: data,
                }).catch(function () {});
            } else {
                // Très vieux navigateur sans GridStore : repli localStorage
                // direct (avec cap, comme avant) pour ne pas perdre la feature.
                var json = JSON.stringify({
                    version: 1, ts: ts, file_hash_at_load: hash, data: data,
                });
                if (json.length <= 4000000) localStorage.setItem(key, json);
            }
        } catch (e) {
            // Quota exceeded ou storage indisponible — best-effort, on
            // ignore. L'autosave backend reste actif.
            try { console.debug('[AutoRecover] write skipped:', e && e.message); } catch (_) {}
        }
    };

    GridTabManager.prototype._clearAutoRecover = function(filePath) {
        var key = this._autoRecoverKey(filePath);
        if (!key) return;
        try { localStorage.removeItem(key); } catch (e) { /* noop */ }
        // Supprime aussi le blob lourd en IndexedDB (sinon orphelin).
        try {
            if (typeof window !== 'undefined' && window.GridStore) {
                window.GridStore.del('autorec:' + key);
            }
        } catch (e) { /* noop */ }
    };

    /**
     * Cherche un snapshot AutoRecover plus récent que la version
     * chargée et propose à l'utilisateur de restaurer.
     *
     * ``serverLastModifiedTs`` : timestamp UNIX en ms du fichier sur le
     * serveur (header ``Last-Modified`` traduit). C'est l'horloge
     * SERVEUR — fiable malgré les drifts d'horloge OS du client. Si
     * 0/absent (header indisponible), on retombe sur "ne propose pas"
     * (fail-safe : mieux ne pas restaurer que restaurer une version
     * stale par erreur de comparaison).
     *
     * Retourne true si une restauration a été proposée, false sinon.
     */
    GridTabManager.prototype._checkAutoRecover = function(serverLastModifiedTs) {
        var key = this._autoRecoverKey();
        if (!key) return false;
        var raw;
        try {
            raw = localStorage.getItem(key);
        } catch (e) { return false; }
        if (!raw) return false;
        var meta;
        try {
            meta = JSON.parse(raw);
        } catch (e) {
            try { localStorage.removeItem(key); } catch (_) {}
            return false;
        }
        // ``meta`` est soit un MARQUEUR léger (``hasHeavy:true``, données en
        // IndexedDB), soit un full payload legacy (``data`` inline, navigateur
        // sans GridStore). Les deux portent ``version`` + ``ts``.
        var isMarker = meta && meta.hasHeavy === true;
        if (!meta || meta.version !== 1 || (!meta.data && !isMarker)) {
            try { localStorage.removeItem(key); } catch (_) {}
            return false;
        }
        // Compare le timestamp local vs ``Last-Modified`` serveur. Si le local
        // est strictement plus récent (5s de marge), on propose. Fail-safe : si
        // pas de timestamp serveur (0), on ne propose pas (mieux vaut louper une
        // restauration que présenter une version obsolète par erreur de compare).
        var localTs = meta.ts || 0;
        var loadedTs = serverLastModifiedTs || 0;
        if (loadedTs === 0 || localTs <= loadedTs + 5000) {
            try { localStorage.removeItem(key); } catch (_) {}
            // Marqueur pas plus récent → le blob IndexedDB associé est inutile.
            try { if (typeof window !== 'undefined' && window.GridStore) window.GridStore.del('autorec:' + key); } catch (_) {}
            return false;
        }

        var self = this;
        // Propose la restauration via modale (factorisée : appelée depuis le
        // chemin sync legacy OU le chemin async IndexedDB).
        var proposeRestore = function (payload) {
            if (!payload || !payload.data) {
                // Marqueur orphelin (blob évincé/absent) : nettoyer, ne rien proposer.
                self._clearAutoRecover();
                return;
            }
            // Anti-desync marqueur↔blob (multi-onglets sur le même fichier) : le
            // marqueur localStorage peut venir d'un onglet et le blob IndexedDB d'un
            // autre. On RE-vérifie la fraîcheur avec le ts du BLOB (autorité des
            // données), pas seulement celui du marqueur — sinon on restaurerait une
            // version plus ancienne que le serveur sur la foi d'un marqueur trompeur.
            var blobTs = payload.ts || payload._savedAt || 0;
            if (loadedTs === 0 || blobTs <= loadedTs + 5000) {
                self._clearAutoRecover();
                return;
            }
            self._openAutoRecoverModal(payload, function (restore) {
                if (restore) {
                    try {
                        self.loadWorkbook(payload.data);
                        // **Restaure le hash AU MOMENT du write AutoRecover**
                        // (pas le hash serveur courant). Si entre-temps un autre
                        // tab a écrit une version concurrente, le backend
                        // détectera 412 au prochain save et l'user pourra
                        // trancher (au lieu d'un overwrite silencieux).
                        if (typeof payload.file_hash_at_load === 'string') {
                            self._currentFileHash = payload.file_hash_at_load;
                        }
                        self._setDirty(true); // état restauré = à re-sauver
                        self._showSaveToast('Version récupérée — pensez à enregistrer');
                    } catch (e) {
                        self._showSaveToast('Impossible de restaurer la version locale', true);
                    }
                }
                // Dans tous les cas on nettoie la clef pour ne pas re-proposer.
                self._clearAutoRecover();
            });
        };

        if (isMarker) {
            // Données en IndexedDB → fetch async puis propose.
            if (typeof window !== 'undefined' && window.GridStore) {
                window.GridStore.get('autorec:' + key)
                    .then(function (payload) { proposeRestore(payload); })
                    .catch(function () { self._clearAutoRecover(); });
            } else {
                self._clearAutoRecover();
            }
        } else {
            // Full payload legacy (inline) → propose synchrone.
            proposeRestore(meta);
        }
        return true;
    };

    GridTabManager.prototype._openAutoRecoverModal = function(payload, onChoice) {
        var overlay = document.createElement('div');
        // 1990 — cf. overlay-layers.css (sous OverlayManager.modal).
        overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.5);'
            + 'display:flex;align-items:center;justify-content:center;z-index:1990;';
        var dialog = document.createElement('div');
        dialog.style.cssText = 'background:var(--bg-surface, #fff);color:var(--text-primary, #1e293b);'
            + 'border:1px solid var(--border, transparent);border-radius:12px;padding:1.2rem;'
            + 'min-width:380px;max-width:520px;box-shadow:var(--shadow-lg, 0 8px 32px rgba(0,0,0,0.2));'
            + 'display:flex;flex-direction:column;gap:0.8rem;';
        var title = document.createElement('div');
        title.textContent = 'Récupération automatique';
        title.style.cssText = 'font-weight:700;font-size:0.95rem;';
        dialog.appendChild(title);

        // Date dérivée de localStorage — par principe de défense en
        // profondeur, on construit le DOM via createTextNode plutôt que
        // ``innerHTML`` (même si Date.toLocaleString produit toujours
        // une string sûre, la règle "jamais innerHTML avec données
        // externes" empêche un futur changement de format de devenir
        // une faille).
        var date = '';
        try { date = new Date(payload.ts).toLocaleString('fr-FR'); } catch (e) { date = '?'; }
        var msg = document.createElement('div');
        msg.style.cssText = 'font-size:0.85rem;line-height:1.4;';
        msg.appendChild(document.createTextNode(
            'Une version locale plus récente a été détectée pour ce classeur (modifiée le '
        ));
        var dateEl = document.createElement('strong');
        dateEl.textContent = date;
        msg.appendChild(dateEl);
        msg.appendChild(document.createTextNode('). Voulez-vous la restaurer ? '));
        msg.appendChild(document.createElement('br'));
        var hintEl = document.createElement('span');
        hintEl.style.cssText = 'color:var(--text-muted, #6b7280);font-size:0.75rem;';
        hintEl.textContent = 'Si vous ignorez, la version sauvegardée sur le serveur sera utilisée.';
        msg.appendChild(hintEl);
        dialog.appendChild(msg);

        var btnRow = document.createElement('div');
        btnRow.style.cssText = 'display:flex;gap:0.5rem;justify-content:flex-end;margin-top:0.4rem;';
        var btnIgnore = document.createElement('button');
        btnIgnore.textContent = 'Ignorer';
        btnIgnore.style.cssText = 'padding:0.5rem 0.9rem;border-radius:6px;'
            + 'background:var(--bg-surface-3, #f1f5f9);color:var(--text-primary, #1e293b);'
            + 'border:1px solid var(--border, #d1d5db);font-size:0.8rem;cursor:pointer;';
        var btnRestore = document.createElement('button');
        btnRestore.textContent = 'Restaurer';
        btnRestore.style.cssText = 'padding:0.5rem 0.9rem;border-radius:6px;'
            + 'background:var(--brand, #2563eb);color:#fff;border:none;font-size:0.8rem;'
            + 'font-weight:600;cursor:pointer;';
        btnRow.appendChild(btnIgnore);
        btnRow.appendChild(btnRestore);
        dialog.appendChild(btnRow);
        overlay.appendChild(dialog);
        document.body.appendChild(overlay);

        function close(restore) {
            try { overlay.remove(); } catch (e) { /* noop */ }
            try { onChoice(restore); } catch (e) { console.error('[AutoRecover] choice error', e); }
        }
        btnIgnore.addEventListener('click', function() { close(false); });
        btnRestore.addEventListener('click', function() { close(true); });
        overlay.addEventListener('click', function(e) {
            if (e.target === overlay) close(false);
        });
    };

    /**
     * Modale "Enregistrer sous" — input texte + boutons OK / Annuler.
     * Style cohérent avec les autres modales du fichier (overlay
     * fixed + dialog centré). Sur Enter dans l'input → submit ; sur
     * Escape → cancel.
     */
    GridTabManager.prototype._openSaveAsModal = function(defaultName, onConfirm) {
        var self = this;
        var overlay = document.createElement('div');
        // z-index délégué à OverlayManager (layer='modal' = 2000+N×10).
        overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.5);'
            + 'display:flex;align-items:center;justify-content:center;';
        var dialog = document.createElement('div');
        dialog.style.cssText = 'background:var(--bg-surface, #fff);color:var(--text-primary, #1e293b);'
            + 'border:1px solid var(--border, transparent);border-radius:12px;padding:1.2rem;'
            + 'min-width:360px;max-width:480px;box-shadow:var(--shadow-lg, 0 8px 32px rgba(0,0,0,0.2));'
            + 'display:flex;flex-direction:column;gap:0.8rem;';

        var title = document.createElement('div');
        title.textContent = 'Enregistrer sous';
        title.style.cssText = 'font-weight:700;font-size:0.95rem;';
        dialog.appendChild(title);

        var hint = document.createElement('div');
        hint.textContent = 'Nom du fichier (l\'extension .afz.json sera ajoutée si absente)';
        hint.style.cssText = 'font-size:0.75rem;color:var(--text-muted, #6b7280);';
        dialog.appendChild(hint);

        var input = document.createElement('input');
        input.type = 'text';
        input.value = defaultName;
        input.style.cssText = 'padding:0.6rem;border:1px solid var(--border, #d1d5db);'
            + 'border-radius:6px;font-size:0.85rem;width:100%;box-sizing:border-box;'
            + 'background:var(--bg-surface-2, #f9fafb);color:var(--text-primary, #1e293b);';
        input.maxLength = 200;
        dialog.appendChild(input);

        var btnRow = document.createElement('div');
        btnRow.style.cssText = 'display:flex;gap:0.5rem;justify-content:flex-end;margin-top:0.4rem;';

        var btnCancel = document.createElement('button');
        btnCancel.textContent = 'Annuler';
        btnCancel.style.cssText = 'padding:0.5rem 0.9rem;border-radius:6px;'
            + 'background:var(--bg-surface-3, #f1f5f9);color:var(--text-primary, #1e293b);'
            + 'border:1px solid var(--border, #d1d5db);font-size:0.8rem;cursor:pointer;';

        var btnOk = document.createElement('button');
        btnOk.textContent = 'Enregistrer';
        btnOk.style.cssText = 'padding:0.5rem 0.9rem;border-radius:6px;'
            + 'background:var(--brand, #2563eb);color:#fff;border:none;font-size:0.8rem;'
            + 'font-weight:600;cursor:pointer;';

        btnRow.appendChild(btnCancel);
        btnRow.appendChild(btnOk);
        dialog.appendChild(btnRow);
        overlay.appendChild(dialog);
        document.body.appendChild(overlay);
        var _closedSaveAs = false;
        if (window.OverlayManager && typeof window.OverlayManager.open === 'function') {
            window.OverlayManager.open(overlay, {
                layer: 'modal',
                lockScroll: true,
                onClose: function() { close(); },
            });
        }

        function close() {
            if (_closedSaveAs) return;
            _closedSaveAs = true;
            if (window.OverlayManager && typeof window.OverlayManager.close === 'function') {
                try { window.OverlayManager.close(overlay); } catch (e) {}
            }
            try { overlay.remove(); } catch (e) { /* noop */ }
        }
        function confirm() {
            var val = (input.value || '').trim();
            if (!val) return; // refuse vide silencieusement
            close();
            try { onConfirm(val); } catch (e) { console.error('[SaveAs] onConfirm error', e); }
        }

        btnCancel.addEventListener('click', close);
        btnOk.addEventListener('click', confirm);
        input.addEventListener('keydown', function(e) {
            if (e.key === 'Enter') { e.preventDefault(); confirm(); }
            else if (e.key === 'Escape') { e.preventDefault(); close(); }
        });
        overlay.addEventListener('click', function(e) {
            if (e.target === overlay) close();
        });
        // Focus + select pour que l'utilisateur tape directement.
        setTimeout(function() {
            try { input.focus(); input.select(); } catch (e) { /* noop */ }
        }, 50);
    };

    /**
     * Variante async de ``saveWorkbook`` qui retourne une ``Promise<string>``
     * résolue avec le ``filePath`` final (relatif au datastore user) lorsque
     * la sauvegarde a réussi. Pas de toast côté UI (le caller décide).
     *
     * Cette variante est utilisée par le flow copilot pour s'assurer que
     * le ``.afz.json`` reflète l'état courant AVANT que le backend ne le
     * lise par référence (``workbook_path``). Sans cette synchronisation,
     * le copilot verrait un état stale.
     */
    GridTabManager.prototype.saveWorkbookAsync = function() {
        var filePath = this._currentFilePath
            || ('classeur_' + new Date().toISOString().slice(0, 16).replace(/[T:]/g, '-') + '.afz.json');
        var overwrite = !!this._currentFilePath;
        return this._saveToPathAsync(filePath, overwrite);
    };

    /**
     * Retourne le ``rel_path`` du classeur ouvert dans le datastore user,
     * ou ``null`` si le classeur n'a jamais été sauvegardé. Utilisé par le
     * copilot pour passer en mode "référence par path" plutôt que d'envoyer
     * le ``tabs_context`` inline (qui satureraient le body POST sur des
     * classeurs gigantesques).
     */
    GridTabManager.prototype.getWorkbookPath = function() {
        return this._currentFilePath || null;
    };

    /**
     * Sauvegarde interne — envoie le classeur au path donné dans le datastore.
     * Wrapper qui ajoute toast UX par-dessus ``_saveToPathAsync``.
     */
    GridTabManager.prototype._saveToPath = function(filePath, overwrite) {
        var self = this;
        var filename = filePath.split('/').pop();
        var syncToken = this._syncIndicator
            ? this._syncIndicator.begin('Sauvegarde du classeur…')
            : null;
        this._saveToPathAsync(filePath, overwrite)
            .then(function() {
                if (self._syncIndicator && syncToken != null) {
                    self._syncIndicator.end(syncToken);
                }
                var shortName = filename.replace(/\.afz\.json$/i, '');
                self._showSaveToast('Enregistré : ' + shortName);
            })
            .catch(function(err) {
                if (self._syncIndicator && syncToken != null) {
                    self._syncIndicator.end(syncToken, { error: true });
                }
                console.error('[Workbook] Save failed:', err);
                // Oversize passerelle : message dédié actionnable (≠ jeter
                // une "SyntaxError" brute à l'utilisateur, ce que faisait
                // l'ancien chemin quand nginx renvoyait du HTML).
                if (err && err._tooLarge) {
                    self._showSaveToast(
                        'Classeur trop volumineux pour le serveur. Réduisez '
                        + 'les lignes/colonnes ou supprimez des onglets.',
                        true
                    );
                    return;
                }
                self._showSaveToast('Erreur : ' + (err && err.message ? err.message : 'Échec'), true);
            });
    };

    /**
     * Sauvegarde interne async — partagée entre ``_saveToPath`` (UX
     * classique avec toast), ``saveWorkbookAsync`` (utilisé par le
     * copilot) et ``_maybeAutosave`` (auto-save périodique).
     *
     * Retourne une ``Promise<string>`` résolue avec le ``filePath`` sauvé,
     * ou rejetée avec une ``Error`` en cas d'échec. L'erreur peut porter
     * un flag ``_etagMismatch`` (conflit cross-tab, 412), ``_quotaExceeded``
     * (413 + ``error_code: 'QUOTA_EXCEEDED'`` côté serveur) ou ``_tooLarge``
     * (413 oversize passerelle nginx, sans ``error_code``) que le caller exploite.
     *
     * Optional ``options.silent`` : si true, ne marque pas dirty=true
     * en cas d'échec (utile pour autosave qui ne veut pas spammer
     * l'utilisateur de toasts si le réseau flap).
     *
     * Headers envoyés :
     *  - ``X-Xsrftoken`` : XSRF Tornado (toujours)
     *  - ``If-Match: <hash>`` : si ``_currentFileHash`` est connu, pour
     *    déclencher une 412 si le fichier a été modifié ailleurs.
     *
     * Au succès :
     *  - ``_currentFilePath`` mis à jour
     *  - ``_currentFileHash`` mis à jour depuis ``response.uploaded[0].file_hash``
     *  - ``_dirty`` reset à false
     */
    GridTabManager.prototype._saveToPathAsync = function(filePath, overwrite, options) {
        var self = this;
        options = options || {};

        // **Single-flight unifié** entre manuel et autosave : si une
        // sauvegarde est déjà en cours (manuelle OU auto), on attend
        // sa résolution avant de lancer la suivante. Empêche deux
        // POST concurrents qui pourraient se marcher dessus côté
        // backend (write-then-rename séquentiel mais pas atomique
        // entre requêtes parallèles).
        var startNow = function() {
            self._autosaveSaving = true;
            // Snapshot du dirty state AVANT le serialize : si une
            // mutation a lieu pendant l'inflight, on ne reset PAS dirty
            // (la version envoyée est obsolète). Sinon on reset. On capture le
            // COMPTEUR de mutations (pas le booléen ``_dirty`` : dans le cas
            // autosave il est déjà true au départ, un snapshot booléen ne
            // verrait pas une édition concurrente — cf. fix H1).
            var seqAtStart = self._dirtySeq || 0;

            var data = self.serialize();
            var json = JSON.stringify(data);
            var filename = filePath.split('/').pop();
            var xsrf = _getXsrfCookie();
            var headers = { 'X-Xsrftoken': xsrf };
            // If-Match : envoie le hash courant pour détection conflit
            // cross-tab. N'envoyé QUE si on overwrite et qu'on connaît
            // le hash courant (premier save d'un nouveau classeur n'a
            // pas de hash → pas de header → backend skippe la check).
            if (overwrite && self._currentFileHash) {
                headers['If-Match'] = self._currentFileHash;
            }
            // Compression gzip côté client (le serveur décompresse via les
            // magic bytes — cf. ``_gzipStringToBlob``). Fait passer un classeur
            // volumineux (SELECT * large) sous le cap nginx sans rien gonfler.
            // ``null`` → fallback upload BRUT (vieux navigateur), pas de
            // régression : le serveur accepte les deux.
            return _gzipStringToBlob(json).then(function(gzBlob) {
                var blob = gzBlob
                    || new Blob([json], { type: 'application/json;charset=utf-8' });
                var formData = new FormData();
                formData.append('files', blob, filename);
                formData.append('path', '');
                if (overwrite) formData.append('overwrite', 'true');
                return fetch('/api/datastore/upload', {
                    method: 'POST',
                    headers: headers,
                    body: formData,
                });
            })
                .then(function(r) {
                    // Lecture SÛRE : ne throw jamais, même sur la page HTML
                    // d'erreur de nginx (413/429/502/504) qui faisait planter
                    // ``r.json()`` en "SyntaxError: <". ``_readJsonSafe`` garde
                    // la sûreté même si le helper global n'a pas chargé (L1).
                    return _readJsonSafe(r);
                })
                .then(function(res) {
                    var status = res.status;
                    var result = (res.data && typeof res.data === 'object') ? res.data : {};
                    if (status === 412) {
                        var err412 = new Error(
                            'Conflit : ce classeur a été modifié ailleurs.'
                        );
                        err412._etagMismatch = true;
                        err412._currentHash = result.current_hash || null;
                        throw err412;
                    }
                    // 413 : DEUX causes distinctes, désambiguïsées par le body.
                    //  (a) Quota app dépassé → Tornado renvoie un JSON avec
                    //      ``error_code === 'QUOTA_EXCEEDED'`` → ``_quotaExceeded``.
                    //  (b) Oversize passerelle (nginx ``client_max_body_size``)
                    //      → body HTML, aucun ``error_code`` → ``_tooLarge``.
                    // (L'ancien chemin testait ``status === 507`` que le serveur
                    //  n'émet JAMAIS — code mort supprimé. Le serveur émet 413
                    //  pour le quota, cf. datastore.py.)
                    if (status === 413) {
                        if (result.error_code === 'QUOTA_EXCEEDED') {
                            var errQuota = new Error(
                                result.error || 'Quota de stockage dépassé.'
                            );
                            errQuota._quotaExceeded = true;
                            throw errQuota;
                        }
                        var errTooLarge = new Error(
                            res.error || 'Classeur trop volumineux pour le serveur.'
                        );
                        errTooLarge._tooLarge = true;
                        throw errTooLarge;
                    }
                    // **Anti-perte silencieuse (C1)** : quand le SEUL fichier
                    // du batch échoue côté serveur (gunzip illisible, cap de
                    // décompression, validation contenu/extension/taille), le
                    // backend renvoie HTTP 200 ``{success:true, uploaded:[]}``.
                    // Si on ne vérifiait QUE ``res.ok && result.success``, on
                    // marquerait le classeur "sauvé" (reset dirty + clear
                    // AutoRecover) alors que le serveur n'a RIEN écrit → perte
                    // silencieuse. On EXIGE donc une entrée ``uploaded`` réelle.
                    var uploaded = (result.uploaded && result.uploaded[0]) || null;
                    if (res.ok && result.success && uploaded) {
                        // **Path tracking** : on utilise le path
                        // RETOURNÉ par le backend, qui peut différer
                        // du demandé si auto-rename a eu lieu (ex:
                        // ``rapport.afz.json`` existait → backend a
                        // écrit ``rapport_1.afz.json``). Sans cette
                        // ligne, ``_currentFilePath`` pointe vers le
                        // path demandé alors que le serveur a un autre
                        // fichier → tous les saves futurs en 412 ou
                        // écrasent un autre fichier.
                        var actualPath = (uploaded.rel_path || uploaded.path)
                            || filePath;
                        // ``_clearAutoRecover`` AVANT la maj du path
                        // pour bien nettoyer la clef ANCIENNE (ex: cas
                        // Save As où l'ancien path traîne en localStorage).
                        var oldPath = self._currentFilePath;
                        if (oldPath && oldPath !== actualPath) {
                            self._clearAutoRecover(oldPath);
                        }
                        self._currentFilePath = actualPath;
                        // Récupère le file_hash de la response pour le
                        // prochain If-Match.
                        if (uploaded && typeof uploaded.file_hash === 'string') {
                            self._currentFileHash = uploaded.file_hash;
                        }
                        // **Reset dirty conditionnel** : si une mutation a eu
                        // lieu pendant l'inflight (compteur ``_dirtySeq``
                        // avancé depuis le snapshot), on NE reset PAS — la
                        // version sauvegardée ne reflète pas l'état RAM actuel,
                        // marquer "clean" serait mensonger ("données fausses
                        // silencieusement"). Le prochain autosave/idle sauvera
                        // la nouvelle version.
                        if ((self._dirtySeq || 0) === seqAtStart) {
                            self._setDirty(false);
                            // Cleanup AutoRecover seulement si on est
                            // vraiment clean (sinon on en aura besoin
                            // au prochain crash).
                            self._clearAutoRecover();
                        }
                        // Auto-réactive l'autosave si désactivé après
                        // un 412 antérieur — un save manuel réussi
                        // signifie que le conflit est résolu.
                        self._autosaveDisabled = false;
                        self._autosaveFailureCount = 0;
                        self._startAutosave();
                        return actualPath;
                    }
                    // Échec non typé (4xx/5xx, HTML passerelle, JSON
                    // success:false, OU success:true mais uploaded:[] = tous
                    // les fichiers rejetés serveur) : message actionnable issu
                    // du 1er ``errors[]`` serveur, sinon ``error``, sinon
                    // dérivé du status — jamais une "SyntaxError" brute, et le
                    // ``.catch`` préserve l'AutoRecover (pas de perte).
                    throw new Error(
                        (result.errors && result.errors[0])
                        || result.error || res.error || 'Échec sauvegarde'
                    );
                });
        };

        // Chain sur la promise en cours s'il y en a une, sinon démarre.
        // ``_currentSavePromise`` sert de mutex partagé entre tous les
        // chemins de save (manuel + auto). On attend la fin (success
        // OU error) avant de lancer la suivante.
        var prev = this._currentSavePromise || Promise.resolve();
        var thisPromise = prev.then(startNow, startNow).then(function(p) {
            self._autosaveSaving = false;
            return p;
        }, function(err) {
            self._autosaveSaving = false;
            throw err;
        });
        this._currentSavePromise = thisPromise.catch(function() { /* swallow for chaining */ });
        return thisPromise;
    };

    // Backward compat — old code may call exportWorkbook
    GridTabManager.prototype.exportWorkbook = function() { this.saveWorkbook(); };

    GridTabManager.prototype._showSaveToast = function(message, isError) {
        var toast = document.createElement('div');
        toast.textContent = message;
        /* Toast informationnel — utilise le layer toast (10000) défini dans
           overlay-layers.css. Au-dessus des modaux pour rester visible mais
           ne bloque pas l'interaction. */
        toast.style.cssText = 'position:fixed;bottom:2rem;right:2rem;padding:0.6rem 1.2rem;'
            + 'border-radius:8px;font-size:0.8rem;font-weight:600;z-index:10000;'
            + 'color:#fff;background:' + (isError ? 'var(--status-error,#ef4444)' : 'var(--brand, var(--brand))') + ';'
            + 'box-shadow:var(--shadow-md, 0 4px 12px rgba(0,0,0,0.15));transition:opacity 0.3s;';
        document.body.appendChild(toast);
        setTimeout(function() {
            toast.style.opacity = '0';
            setTimeout(function() { toast.remove(); }, 300);
        }, 2500);
    };

    GridTabManager.prototype._openDatastorePicker = function() {
        var self = this;
        // Close existing picker if any
        if (this._datastorePicker) { this._datastorePicker.remove(); this._datastorePicker = null; }

        var overlay = document.createElement('div');
        // z-index délégué à OverlayManager (layer='modal' = 2000+N×10).
        overlay.style.cssText = 'position:fixed;inset:0;background:var(--bg-overlay, rgba(0,0,0,0.3));';
        var dialog = document.createElement('div');
        // Dialog en stacking context interne du overlay (héritera donc du
        // z-index calculé par OverlayManager sur l'overlay parent).
        dialog.style.cssText = 'position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);'
            + 'background:var(--bg-surface, #fff);color:var(--text-primary, #1e293b);'
            + 'border:1px solid var(--border, transparent);'
            + 'border-radius:12px;padding:1.2rem;min-width:320px;max-width:480px;'
            + 'max-height:60vh;box-shadow:var(--shadow-lg, 0 8px 32px rgba(0,0,0,0.2));'
            + 'display:flex;flex-direction:column;';
        var title = document.createElement('div');
        title.textContent = 'Charger un classeur';
        title.style.cssText = 'font-weight:700;font-size:0.95rem;margin-bottom:0.8rem;color:var(--text-primary, #1e293b);';
        dialog.appendChild(title);

        var list = document.createElement('div');
        list.style.cssText = 'overflow-y:auto;flex:1;';
        list.innerHTML = '<div style="color:var(--text-muted, #6b7280);font-size:0.8rem;padding:1rem;text-align:center;">Chargement…</div>';
        dialog.appendChild(list);

        overlay.appendChild(dialog);
        document.body.appendChild(overlay);
        this._datastorePicker = overlay;
        function _closeDatastorePicker() {
            if (window.OverlayManager && typeof window.OverlayManager.close === 'function') {
                try { window.OverlayManager.close(overlay); } catch (e) {}
            }
            if (overlay.parentNode) overlay.remove();
            self._datastorePicker = null;
        }
        if (window.OverlayManager && typeof window.OverlayManager.open === 'function') {
            window.OverlayManager.open(overlay, {
                layer: 'modal',
                lockScroll: true,
                onClose: _closeDatastorePicker,
            });
        }

        overlay.addEventListener('click', function(e) {
            if (e.target === overlay) _closeDatastorePicker();
        });

        // Fetch .afz.json files from user's datastore root
        var xsrf = _getXsrfCookie();
        fetch('/api/datastore', {
            headers: { 'X-Xsrftoken': xsrf }
        })
        .then(function(r) {
            if (!r.ok) return { items: [] };
            return r.json();
        })
        .then(function(result) {
            var files = (result.items || []).filter(function(f) {
                return !f.is_dir && f.name.match(/\.afz(_[\d_]+)?\.json$/i);
            });
            if (files.length === 0) {
                list.innerHTML = '<div style="color:var(--text-muted, #6b7280);font-size:0.8rem;padding:1rem;text-align:center;">'
                    + 'Aucun classeur sauvegardé.</div>';
                return;
            }
            // Sort by modified date, newest first
            files.sort(function(a, b) { return (b.modified || '').localeCompare(a.modified || ''); });
            list.innerHTML = '';
            for (var i = 0; i < files.length; i++) {
                (function(file) {
                    var item = document.createElement('div');
                    item.style.cssText = 'padding:0.5rem 0.6rem;border-radius:6px;cursor:pointer;'
                        + 'display:flex;justify-content:space-between;align-items:center;font-size:0.82rem;';
                    item.onmouseenter = function() { item.style.background = 'var(--brand-soft, rgb(var(--brand-rgb) / 0.08))'; };
                    item.onmouseleave = function() { item.style.background = ''; };
                    var nameSpan = document.createElement('span');
                    nameSpan.textContent = file.name.replace(/\.afz\.json$/i, '');
                    nameSpan.style.cssText = 'font-weight:600;color:var(--text-primary, #1e293b);';
                    var dateSpan = document.createElement('span');
                    dateSpan.textContent = file.size_human || '';
                    dateSpan.style.cssText = 'color:var(--text-faint, #9ca3af);font-size:0.72rem;';
                    item.appendChild(nameSpan);
                    item.appendChild(dateSpan);
                    item.addEventListener('click', function() {
                        self._loadWorkbookFromDatastore(file.path);
                        overlay.remove();
                        self._datastorePicker = null;
                    });
                    list.appendChild(item);
                })(files[i]);
            }
        })
        .catch(function(err) {
            list.innerHTML = '<div style="color:var(--status-error,#ef4444);font-size:0.8rem;padding:1rem;text-align:center;">'
                + 'Erreur de chargement</div>';
            console.error('[Workbook] Datastore list failed:', err);
        });
    };

    GridTabManager.prototype._loadWorkbookFromDatastore = function(filePath) {
        var self = this;
        var xsrf = _getXsrfCookie();
        // On garde la response (pas juste le json) pour pouvoir lire les
        // headers ``ETag`` (hash optimiste pour cross-tab) et
        // ``Last-Modified`` (mtime serveur fiable, utilisé pour la
        // comparaison AutoRecover au lieu d'un timestamp client qui
        // peut dériver — drift d'horloge OS, multi-device).
        var capturedEtag = null;
        var capturedLastModifiedTs = 0;
        fetch('/api/datastore/download?path=' + encodeURIComponent(filePath), {
            headers: { 'X-Xsrftoken': xsrf }
        })
        .then(function(r) {
            if (!r.ok) throw new Error('HTTP ' + r.status);
            var rawEtag = r.headers.get('ETag') || '';
            capturedEtag = rawEtag.replace(/^"(.*)"$/, '$1') || null;
            var rawLastMod = r.headers.get('Last-Modified') || '';
            try {
                capturedLastModifiedTs = rawLastMod
                    ? (new Date(rawLastMod).getTime() || 0)
                    : 0;
            } catch (e) { capturedLastModifiedTs = 0; }
            return r.json();
        })
        .then(function(data) {
            if (data.app === 'komptia' && Array.isArray(data.tabs)) {
                self.loadWorkbook(data);
                self._currentFilePath = filePath; // Remember path for "Enregistrer"
                self._currentFileHash = capturedEtag;
                self._setDirty(false);
                self._autosaveDisabled = false; // reset disable flag (fresh load)
                self._autosaveFailureCount = 0;
                self._startAutosave();
                // Anonymisation : pré-commit en BDD du state du workbook
                // FRAÎCHEMENT chargé, avec ``classeur_ref`` correct (le set
                // de ``_currentFilePath`` vient juste de tirer 3 lignes
                // au-dessus). Sans ce hook, le scan auto ne tirait QUE
                // sur édition (_setDirty(true) → debounce 2.5s) → un user
                // qui ouvre et clique "Save" panneau immédiatement faisait
                // un PUT replace_state avec source default "manual" → tous
                // les termes groupés sous "Origine inconnue" dans /data/privacy
                // au lieu de leur classeur d'origine.
                //
                // ATTENTION : on l'appelle ICI (depuis _loadWorkbookFromDatastore)
                // PAS depuis loadWorkbook(). loadWorkbook est appelé avec
                // _currentFilePath encore à null/ancien → scan tirerait avec
                // classeur_ref=null → bug encore visible.
                if (typeof self._runAnonymizationScan === 'function') {
                    setTimeout(function() { self._runAnonymizationScan(); }, 0);
                }
                var shortName = filePath.split('/').pop().replace(/\.afz\.json$/i, '');
                self._showSaveToast('Classeur chargé : ' + shortName);
                // Vérifie si un snapshot AutoRecover plus récent que
                // le fichier serveur existe localement (signe d'un
                // crash ou d'un autosave qui n'a pas fini). On compare
                // contre le ``Last-Modified`` serveur (fiable) plutôt
                // que ``data.created_at`` (timestamp client posé au
                // moment du save, sujet à drift d'horloge).
                self._checkAutoRecover(capturedLastModifiedTs);
            } else {
                self._showSaveToast('Format de classeur invalide', true);
            }
        })
        .catch(function(err) {
            console.error('[Workbook] Load from datastore failed:', err);
            self._showSaveToast('Erreur de chargement', true);
        });
    };

    GridTabManager.prototype.loadWorkbook = function(data) {
        if (!data || data.app !== 'komptia' || !Array.isArray(data.tabs)) {
            console.error('[Workbook] Format invalide');
            return false;
        }

        // Remove existing tabs
        while (this.tabs.length > 0) {
            this._disposeTabBeforeRemoval(this.tabs[0]);
            this.tabs[0].containerEl.remove();
            this.tabs.shift();
        }
        this.activeTabIndex = 0;

        // Mémoire copilot : restaurée depuis la racine du .afz.json. Ignorée
        // silencieusement si absente (classeur pré-feature ou jamais touché
        // par le copilot). Cap défensif sur taille — même si le handler
        // backend la trim aussi, autant ne pas exploser le state local si
        // un fichier corrompu contient un blob géant.
        if (typeof data.copilot_memory === 'string' &&
            data.copilot_memory.length <= 5000) {
            this._copilotMemory = data.copilot_memory;
        } else {
            this._copilotMemory = '';
        }

        for (var i = 0; i < data.tabs.length; i++) {
            var t = data.tabs[i];
            var tabInfo = this.addTab(
                t.label || 'Onglet ' + (i + 1),
                t.columns || [],
                t.rows || [],
                t.sql || '',
                t.totalRowCount || 0,
                {
                    columnMetadata: t.columnMetadata || null,
                    merges: Array.isArray(t.merges) ? t.merges : [],
                    externalSource: t.externalSource || null
                },
                t.closable !== false
            );

            var grid = tabInfo.grid;
            if (grid) {
                // Restore display state
                grid.hiddenCols = new Set(t.hiddenCols || []);
                grid.columnOrder = t.columnOrder || grid.columns.map(function(_, j) { return j; });
                grid.sortColIndex = typeof t.sortColIndex === 'number' ? t.sortColIndex : -1;
                grid.sortDirection = t.sortDirection || null;
                grid._isBlankSheet = !!t.isBlankSheet;
                // Ignorer le flag stocké isDashboardSheet (peut être faux pour les
                // classeurs créés avant le fix). Le dashboard est dérivé de la
                // présence de merges. Blank sheet = dashboard par défaut (édition
                // spreadsheet vide), comme avant.
                grid._isDashboardSheet = (Array.isArray(t.merges) && t.merges.length > 0) || !!t.isBlankSheet;
                grid._truncated = !!t.truncated;
                grid._truncatedCols = !!t.truncatedCols;
                grid._truncatedColsTotal =
                    typeof t.truncatedColsTotal === 'number' ? t.truncatedColsTotal : null;
                grid.isArrayFormat = t.isArrayFormat !== undefined ? t.isArrayFormat : grid.isArrayFormat;

                // Restore filters
                grid.filters = {};
                var rawF = t.filters || {};
                for (var key in rawF) {
                    if (rawF.hasOwnProperty(key)) {
                        var f = rawF[key] || {};
                        grid.filters[key] = {
                            excluded: new Set(Array.isArray(f.excluded) ? f.excluded : []),
                            excludeNull: !!f.excludeNull
                        };
                    }
                }

                // Restore cell details
                if (t.cellDetails && typeof t.cellDetails === 'object') {
                    grid._cellDetails = t.cellDetails;
                }

                // Rebuild display
                grid.displayRows = grid.allRows.slice();
                grid._build();
                // Ré-appliquer le tri/filtre restaurés depuis le JSON. Sans ce
                // ``_refreshView``, les flags ``grid.filters`` et
                // ``grid.sortColIndex`` sont peuplés en mémoire mais
                // ``displayRows`` reste = ``allRows.slice()`` → la grille
                // affiche toutes les lignes brutes alors que les indicateurs
                // de filtre/tri (badge, flèche) suggèrent qu'un filtre est
                // actif. Bug observé : un onglet avec filtre/tri sauvegardé
                // s'ouvre sans appliquer ces filtres au reload.
                var hasFilters = grid.filters && Object.keys(grid.filters).length > 0;
                var hasSort = typeof grid.sortColIndex === 'number' && grid.sortColIndex >= 0;
                if (hasFilters || hasSort) {
                    grid._refreshView();
                }
            }
        }

        // Switch to saved active tab
        var activeIdx = data.active_tab || 0;
        if (activeIdx >= 0 && activeIdx < this.tabs.length) {
            this._switchTab(activeIdx);
        }

        return true;
    };

    GridTabManager.prototype.importWorkbookFromFile = function(file) {
        var self = this;
        var reader = new FileReader();
        reader.onload = function(e) {
            try {
                var data = JSON.parse(e.target.result);
                if (self.loadWorkbook(data)) {
                    console.log('[Workbook] Classeur chargé : ' + data.tabs.length + ' onglet(s)');
                }
            } catch (err) {
                console.error('[Workbook] Erreur de lecture :', err);
            }
        };
        reader.readAsText(file);
    };

    // ── XLSX builder (pure JS, no library) ──

    function _xlsxEsc(s) {
        if (s == null) return '';
        // 1. Supprimer les caractères de contrôle interdits en XML 1.0
        //    (0x00-0x08, 0x0B, 0x0C, 0x0E-0x1F) — cause #1 du "problème de contenu" Excel
        return String(s)
            .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F]/g, '')
            .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }

    function _xlsxColRef(idx) {
        // 0→A, 1→B, ..., 25→Z, 26→AA
        var s = '';
        idx++;
        while (idx > 0) {
            idx--;
            s = String.fromCharCode(65 + (idx % 26)) + s;
            idx = Math.floor(idx / 26);
        }
        return s;
    }

    // Sanitize sheet name: max 31 chars, no special chars
    function _sanitizeSheetName(name) {
        return name.replace(/[\/\\?*\[\]:]/g, '_').substring(0, 31);
    }

    function _buildDetailSheetXml(detail, sheetLabel) {
        // Build a detail sheet from a _cellDetails entry
        var columns = detail.columns || [];
        var rows = detail.rows || [];
        var sharedStrings = [];

        // <sheetPr><tabColor.../></sheetPr> doit précéder <sheetViews> selon
        // le schéma OOXML. Bleu clair (FF8DB4E2) pour distinguer visuellement
        // les feuilles de détail des feuilles principales dans la barre
        // d'onglets — sans masquer (cacher casse les hyperliens sur
        // certaines versions d'Excel).
        var xml = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            + '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"'
            + ' xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">\n'
            + '<sheetPr><tabColor rgb="FF8DB4E2"/></sheetPr>\n'
            + '<sheetViews><sheetView workbookViewId="0">'
            + '<pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/>'
            + '</sheetView></sheetViews>\n'
            + '<cols>\n';

        // Column widths
        for (var cw = 0; cw < columns.length; cw++) {
            xml += '<col min="' + (cw + 1) + '" max="' + (cw + 1) + '" width="20" bestFit="1"/>\n';
        }
        xml += '</cols>\n<sheetData>\n';

        // Header row (style 1 = bold header)
        xml += '<row r="1">\n';
        for (var h = 0; h < columns.length; h++) {
            var ref = _xlsxColRef(h) + '1';
            var si = sharedStrings.length;
            sharedStrings.push(columns[h]);
            xml += '<c r="' + ref + '" t="s" s="1"><v>' + si + '</v></c>\n';
        }
        xml += '</row>\n';

        // Data rows
        for (var r = 0; r < rows.length; r++) {
            var rowNum = r + 2;
            xml += '<row r="' + rowNum + '">\n';
            var rowData = rows[r];
            for (var c = 0; c < columns.length; c++) {
                var val = rowData[c];
                var cellRef = _xlsxColRef(c) + rowNum;

                if (val == null) {
                    xml += '<c r="' + cellRef + '"/>\n';
                } else {
                    var numVal2 = typeof val === 'number' ? val : NaN;
                    if (typeof val === 'string' && val !== '') {
                        var cleaned2 = val.replace(/[\s\u202f\u00a0]/g, '').replace(',', '.');
                        if (cleaned2 !== '' && !isNaN(Number(cleaned2))) numVal2 = Number(cleaned2);
                    }
                    if (!isNaN(numVal2)) {
                        var st = (numVal2 === Math.floor(numVal2)) ? '2' : '3';
                        xml += '<c r="' + cellRef + '" s="' + st + '"><v>' + numVal2 + '</v></c>\n';
                    } else {
                        var si2 = sharedStrings.length;
                        sharedStrings.push(String(val));
                        xml += '<c r="' + cellRef + '" t="s"><v>' + si2 + '</v></c>\n';
                    }
                }
            }
            xml += '</row>\n';
        }

        xml += '</sheetData>\n</worksheet>';
        return { xml: xml, sharedStrings: sharedStrings };
    }

    // Reconstruit les `rows` d'un cellDetail à partir du tab source en
    // filtrant `srcGrid.allRows` par `match` (+ `match_exclude`). Permet à
    // l'export Excel d'inclure les feuilles de détail des cellules
    // dashboard / emit_tab / copilot — où `rows` n'est pas en cache parce
    // que l'utilisateur n'a pas encore double-cliqué sur la cellule.
    //
    // Sémantique : pour une cellule [Anne, 1500] avec match {expert:"Anne"}
    // sur un tab source SQL agrégé GROUP BY expert,code,mois → le détail
    // contient les N lignes du source dont la somme produit 1500. C'est le
    // "breakdown" qui explique le chiffre, pas le drill-down SQL brut (qui
    // exigerait un appel API + recasse l'agrégation côté serveur).
    //
    // Hors scope : derived_formula (cell composée par +/-/* d'autres cells —
    // rare, demanderait une recursion), drill-down SQL pur sans match.
    //
    // @param {Object} detail   — entry de _cellDetails
    // @param {number} curIdx   — index du tab où vit la cellule (anti self-ref)
    // @param {Array}  allTabs  — this.tabs du GridTabManager
    // @param {number} cap      — max de lignes filtrées (anti-overflow)
    // @returns {{columns:Array, rows:Array, row_count:number} | null}
    function _reconstructDetailRowsFromMatch(detail, curIdx, allTabs, cap) {
        if (!detail || typeof detail !== 'object') return null;
        // Priorité aux rows déjà cachés (l'utilisateur a déjà drill-down,
        // données fraîches venues de l'API).
        if (Array.isArray(detail.rows) && detail.rows.length > 0) return null;

        var match = detail.match;
        if (!match || typeof match !== 'object') return null;
        var matchKeys = Object.keys(match);
        if (matchKeys.length === 0) return null;

        var matchExclude = (detail.match_exclude && typeof detail.match_exclude === 'object')
            ? detail.match_exclude : {};

        if (!Array.isArray(allTabs) || allTabs.length === 0) return null;

        // Étape 1 : choisir le tab source.
        // 1a. Si source_tab_index est fourni, valide et différent du tab
        //     courant, ET que ses colonnes couvrent les clés du match → OK.
        // 1b. Sinon, auto-detect (mimétique du backend _recompute_emit_tab) :
        //     parmi tous les autres tabs, prendre celui dont les colonnes
        //     couvrent toutes les clés du match avec la spécificité maximale.
        var srcIdx = -1;
        var srcGrid = null;

        function _gridCols(g) {
            return (g && Array.isArray(g.columns)) ? g.columns : [];
        }

        function _coversMatch(cols) {
            for (var i = 0; i < matchKeys.length; i++) {
                if (cols.indexOf(matchKeys[i]) < 0) return false;
            }
            return true;
        }

        var hint = detail.source_tab_index;
        if (typeof hint === 'number' && hint >= 0 && hint < allTabs.length && hint !== curIdx) {
            var hintGrid = allTabs[hint] && allTabs[hint].grid;
            var hintCols = _gridCols(hintGrid);
            if (hintCols.length > 0 && _coversMatch(hintCols)
                && Array.isArray(hintGrid.allRows) && hintGrid.allRows.length > 0) {
                srcIdx = hint;
                srcGrid = hintGrid;
            }
        }

        if (!srcGrid) {
            var bestSpec = -1;
            for (var ti = 0; ti < allTabs.length; ti++) {
                if (ti === curIdx) continue;
                var g = allTabs[ti] && allTabs[ti].grid;
                var gc = _gridCols(g);
                if (gc.length === 0) continue;
                if (!Array.isArray(g.allRows) || g.allRows.length === 0) continue;
                if (!_coversMatch(gc)) continue;
                // Spécificité = nombre de colonnes du tab qui apparaissent
                // dans match (toutes par construction de _coversMatch, donc
                // == matchKeys.length). Le backend utilise une heuristique
                // équivalente : on prend le 1er en cas d'égalité (LLM peut
                // signaler des ties, mais ici on fait au mieux silencieux).
                var spec = matchKeys.length;
                if (spec > bestSpec) {
                    bestSpec = spec;
                    srcIdx = ti;
                    srcGrid = g;
                }
            }
        }

        if (!srcGrid) return null;

        // Étape 2 : filtrer srcGrid.allRows. On utilise allRows (pas
        // displayRows) — la sémantique "voici ce qui compose le chiffre" doit
        // être indépendante des filtres/tris UI courants du tab source.
        var srcCols = _gridCols(srcGrid);
        var isArray = !!srcGrid.isArrayFormat;
        var rows = srcGrid.allRows;

        // Index column-name → position (utilisé seulement en isArrayFormat).
        var colIdx = {};
        for (var ci = 0; ci < srcCols.length; ci++) colIdx[srcCols[ci]] = ci;

        // Comparaison loose : matche backend (SQL '=' tolère '2023' vs 2023).
        // null match key se compare strictement à null/undefined.
        function _looseEq(a, b) {
            if (a === b) return true;
            if (a == null || b == null) return false; // null/undefined != 0
            // Try numeric coercion (gère "1 005,76" vs 1005.76).
            var na = typeof a === 'number' ? a : Number(String(a).replace(/[\s  ]/g, '').replace(',', '.'));
            var nb = typeof b === 'number' ? b : Number(String(b).replace(/[\s  ]/g, '').replace(',', '.'));
            if (!isNaN(na) && !isNaN(nb) && na === nb) return true;
            // Fallback: comparaison string.
            return String(a) === String(b);
        }

        function _readCell(row, key) {
            if (isArray) {
                var p = colIdx[key];
                return (p == null) ? undefined : row[p];
            }
            return row[key];
        }

        function _matchOne(rowVal, matchVal) {
            if (Array.isArray(matchVal)) {
                if (matchVal.length === 0) return true; // liste vide = pas de filtre
                for (var i = 0; i < matchVal.length; i++) {
                    if (_looseEq(rowVal, matchVal[i])) return true;
                }
                return false;
            }
            if (matchVal === null) return rowVal === null || rowVal === undefined;
            return _looseEq(rowVal, matchVal);
        }

        var maxRows = (typeof cap === 'number' && cap > 0) ? cap : 1000;
        var filteredArrays = [];
        var totalMatching = 0;
        for (var r = 0; r < rows.length; r++) {
            var row = rows[r];
            var include = true;

            for (var mki = 0; mki < matchKeys.length; mki++) {
                var mk = matchKeys[mki];
                if (!_matchOne(_readCell(row, mk), match[mk])) { include = false; break; }
            }
            if (!include) continue;

            // match_exclude : aucune clé ne doit matcher (NOT IN).
            for (var ek in matchExclude) {
                if (!matchExclude.hasOwnProperty(ek)) continue;
                var ev = matchExclude[ek];
                var rv = _readCell(row, ek);
                if (Array.isArray(ev)) {
                    for (var ei = 0; ei < ev.length; ei++) {
                        if (_looseEq(rv, ev[ei])) { include = false; break; }
                    }
                } else if (ev !== null && ev !== undefined) {
                    if (_looseEq(rv, ev)) include = false;
                }
                if (!include) break;
            }
            if (!include) continue;

            totalMatching++;
            if (filteredArrays.length < maxRows) {
                // Toujours produire un array-of-arrays pour _buildDetailSheetXml.
                if (isArray) {
                    filteredArrays.push(row.slice());
                } else {
                    var arr = new Array(srcCols.length);
                    for (var sci = 0; sci < srcCols.length; sci++) arr[sci] = row[srcCols[sci]];
                    filteredArrays.push(arr);
                }
            }
        }

        if (filteredArrays.length === 0) return null;

        return {
            columns: srcCols.slice(),
            rows: filteredArrays,
            row_count: totalMatching,
            // Indique au caller que c'est une reconstruction (peut servir
            // pour différencier dans les logs / tests).
            _reconstructed: true,
            _source_tab_index: srcIdx
        };
    }

    // Génère un nom de feuille XLSX unique tout en respectant la limite
    // de 31 caractères imposée par le format. Si `base` est déjà pris
    // (collision après troncature), suffixe `~2`, `~3`… en re-tronquant
    // pour garder ≤ 31 caractères. Le `~` est choisi parce qu'il est
    // valide dans un nom de feuille Excel et improbable dans un label
    // utilisateur (vs `-` qui est très commun).
    //
    // @param {string} base   — nom déjà sanitisé (≤31 char)
    // @param {Set}    used   — Set des noms déjà attribués (modifié in-place)
    // @returns {string}      — nom unique inscrit dans `used`
    function _uniqueDetailSheetName(base, used) {
        if (!used.has(base)) { used.add(base); return base; }
        for (var n = 2; n < 1000; n++) {
            var suffix = '~' + n;
            var room = 31 - suffix.length;
            var candidate = base.substring(0, room) + suffix;
            if (!used.has(candidate)) { used.add(candidate); return candidate; }
        }
        // Fallback paranoïaque : si on dépasse 1000 collisions on prend un
        // nom horodaté (impossible en pratique).
        var fallback = ('D~' + Date.now()).substring(0, 31);
        used.add(fallback);
        return fallback;
    }

    function _buildSheetXml(grid, hyperlinks) {
        var cols = grid.columns;
        var types = grid.columnTypes || [];
        var rows = grid.displayRows;
        var visible = grid._getVisibleColIndices();
        var sharedStrings = []; // will be filled

        // Detect "plain integer" columns (no thousands separator needed)
        // A column is plain-int if ALL non-null values are integers AND max(abs) < 10000
        var plainIntCols = new Set();
        for (var pi = 0; pi < visible.length; pi++) {
            var pci = visible[pi];
            if (types[pci] !== 'number') continue;
            var allInt = true, maxAbs = 0, hasAny = false;
            var sampleLen = Math.min(rows.length, 100);
            for (var pr = 0; pr < sampleLen; pr++) {
                var pv = grid.isArrayFormat ? rows[pr][pci] : rows[pr][cols[pci]];
                if (pv == null) continue;
                var pn = typeof pv === 'number' ? pv : Number(String(pv).replace(/[\s\u202f]/g, '').replace(',', '.'));
                if (isNaN(pn)) { allInt = false; break; }
                hasAny = true;
                if (pn !== Math.floor(pn)) { allInt = false; break; }
                if (Math.abs(pn) > maxAbs) maxAbs = Math.abs(pn);
            }
            if (allInt && hasAny && maxAbs < 10000) plainIntCols.add(pci);
        }

        var xml = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            + '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"'
            + ' xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">\n'
            + '<sheetViews><sheetView tabSelected="1" workbookViewId="0">'
            + '<pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/>'
            + '</sheetView></sheetViews>\n'
            + '<cols>\n';

        for (var cw = 0; cw < visible.length; cw++) {
            var w = (types[visible[cw]] === 'number') ? 14 : (types[visible[cw]] === 'date') ? 16 : 20;
            xml += '<col min="' + (cw + 1) + '" max="' + (cw + 1) + '" width="' + w + '" bestFit="1"/>\n';
        }
        xml += '</cols>\n<sheetData>\n';

        // Header row (style 1 = bold header)
        xml += '<row r="1">\n';
        for (var h = 0; h < visible.length; h++) {
            var ref = _xlsxColRef(h) + '1';
            var si = sharedStrings.length;
            sharedStrings.push(cols[visible[h]]);
            xml += '<c r="' + ref + '" t="s" s="1"><v>' + si + '</v></c>\n';
        }
        xml += '</row>\n';

        // Build hyperlink cell set for quick lookup
        var hyperlinkRefs = new Set();
        if (hyperlinks) {
            for (var hlIdx = 0; hlIdx < hyperlinks.length; hlIdx++) {
                hyperlinkRefs.add(hyperlinks[hlIdx].cellRef);
            }
        }

        // Data rows
        for (var r = 0; r < rows.length; r++) {
            var rowNum = r + 2;
            xml += '<row r="' + rowNum + '">\n';
            for (var c = 0; c < visible.length; c++) {
                var ci = visible[c];
                var val = grid.isArrayFormat ? rows[r][ci] : rows[r][cols[ci]];
                var cellRef = _xlsxColRef(c) + rowNum;
                var colType = types[ci] || 'string';
                var isHyperlinked = hyperlinkRefs.has(cellRef);

                if (val == null) {
                    xml += '<c r="' + cellRef + '"/>\n';
                } else {
                    // Tenter parsing nombre sur TOUTE valeur (gère format FR: "1 005,76")
                    var numVal = typeof val === 'number' ? val : NaN;
                    if (typeof val === 'string' && val !== '') {
                        var cleaned = val.replace(/[\s\u202f\u00a0]/g, '').replace(',', '.');
                        if (cleaned !== '' && !isNaN(Number(cleaned))) numVal = Number(cleaned);
                    }

                    if (!isNaN(numVal)) {
                        var st;
                        if (plainIntCols.has(ci) && numVal === Math.floor(numVal)) {
                            st = '7'; // plain integer — no thousands separator
                        } else if (isHyperlinked) {
                            st = (numVal === Math.floor(numVal)) ? '5' : '6';
                        } else {
                            st = (numVal === Math.floor(numVal)) ? '2' : '3';
                        }
                        xml += '<c r="' + cellRef + '" s="' + st + '"><v>' + numVal + '</v></c>\n';
                    } else {
                        var si2 = sharedStrings.length;
                        sharedStrings.push(String(val));
                        var st2 = isHyperlinked ? '4' : '0';
                        xml += '<c r="' + cellRef + '" t="s" s="' + st2 + '"><v>' + si2 + '</v></c>\n';
                    }
                }
            }
            xml += '</row>\n';
        }

        xml += '</sheetData>\n';

        // mergeCells (must appear before hyperlinks per XLSX schema)
        var gridMerges = (grid && typeof grid.getMerges === 'function') ? grid.getMerges() : [];
        if (gridMerges.length > 0) {
            var mergeRefs = [];
            for (var mi = 0; mi < gridMerges.length; mi++) {
                var m = gridMerges[mi];
                var v1 = visible.indexOf(m.c1);
                var v2 = visible.indexOf(m.c2);
                if (v1 < 0 || v2 < 0) continue;
                var ref1 = _xlsxColRef(v1) + (m.r1 + 2);
                var ref2 = _xlsxColRef(v2) + (m.r2 + 2);
                mergeRefs.push(ref1 + ':' + ref2);
            }
            if (mergeRefs.length > 0) {
                xml += '<mergeCells count="' + mergeRefs.length + '">\n';
                for (var mj = 0; mj < mergeRefs.length; mj++) {
                    xml += '<mergeCell ref="' + mergeRefs[mj] + '"/>\n';
                }
                xml += '</mergeCells>\n';
            }
        }

        // Add hyperlinks element if present
        if (hyperlinks && hyperlinks.length > 0) {
            xml += '<hyperlinks>\n';
            for (var hlc = 0; hlc < hyperlinks.length; hlc++) {
                var hl = hyperlinks[hlc];
                xml += '<hyperlink ref="' + _xlsxEsc(hl.cellRef) + '" location="' + _xlsxEsc(hl.location) + '"';
                if (hl.tooltip) {
                    xml += ' tooltip="' + _xlsxEsc(hl.tooltip) + '"';
                }
                xml += '/>\n';
            }
            xml += '</hyperlinks>\n';
        }

        xml += '</worksheet>';
        return { xml: xml, sharedStrings: sharedStrings };
    }

    function _buildZip(files) {
        // Minimal ZIP builder (STORE method, no compression — simple and fast)
        var entries = [];
        var offset = 0;

        for (var i = 0; i < files.length; i++) {
            var name = files[i].name;
            var data = new TextEncoder().encode(files[i].content);
            var nameBytes = new TextEncoder().encode(name);

            // Local file header
            var header = new Uint8Array(30 + nameBytes.length);
            var dv = new DataView(header.buffer);
            dv.setUint32(0, 0x04034b50, true); // signature
            dv.setUint16(4, 20, true); // version
            dv.setUint16(6, 0x0800, true); // flags (UTF-8)
            dv.setUint16(8, 0, true); // STORE
            dv.setUint16(10, 0, true); dv.setUint16(12, 0, true); // time, date
            dv.setUint32(14, _crc32(data), true); // CRC
            dv.setUint32(18, data.length, true); // compressed
            dv.setUint32(22, data.length, true); // uncompressed
            dv.setUint16(26, nameBytes.length, true);
            header.set(nameBytes, 30);

            entries.push({ headerOffset: offset, nameBytes: nameBytes, data: data, header: header });
            offset += header.length + data.length;
        }

        // Central directory
        var cdParts = [];
        var cdSize = 0;
        for (var j = 0; j < entries.length; j++) {
            var e = entries[j];
            var cd = new Uint8Array(46 + e.nameBytes.length);
            var cdv = new DataView(cd.buffer);
            cdv.setUint32(0, 0x02014b50, true); // signature
            cdv.setUint16(4, 20, true); cdv.setUint16(6, 20, true);
            cdv.setUint16(8, 0x0800, true); // flags (UTF-8)
            cdv.setUint16(10, 0, true); // STORE
            cdv.setUint16(12, 0, true); cdv.setUint16(14, 0, true);
            cdv.setUint32(16, new DataView(e.header.buffer).getUint32(14, true), true); // CRC
            cdv.setUint32(20, e.data.length, true);
            cdv.setUint32(24, e.data.length, true);
            cdv.setUint16(28, e.nameBytes.length, true);
            cdv.setUint32(42, e.headerOffset, true);
            cd.set(e.nameBytes, 46);
            cdParts.push(cd);
            cdSize += cd.length;
        }

        // End of central directory
        var eocd = new Uint8Array(22);
        var ev = new DataView(eocd.buffer);
        ev.setUint32(0, 0x06054b50, true);
        ev.setUint16(8, entries.length, true);
        ev.setUint16(10, entries.length, true);
        ev.setUint32(12, cdSize, true);
        ev.setUint32(16, offset, true);

        // Combine all
        var allParts = [];
        for (var k = 0; k < entries.length; k++) {
            allParts.push(entries[k].header);
            allParts.push(entries[k].data);
        }
        for (var l = 0; l < cdParts.length; l++) allParts.push(cdParts[l]);
        allParts.push(eocd);

        var total = 0;
        for (var m = 0; m < allParts.length; m++) total += allParts[m].length;
        var result = new Uint8Array(total);
        var pos = 0;
        for (var n = 0; n < allParts.length; n++) {
            result.set(allParts[n], pos);
            pos += allParts[n].length;
        }
        return result;
    }

    // CRC-32 (standard ZIP)
    var _crc32Table = null;
    function _crc32(data) {
        if (!_crc32Table) {
            _crc32Table = new Uint32Array(256);
            for (var i = 0; i < 256; i++) {
                var c = i;
                for (var j = 0; j < 8; j++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
                _crc32Table[i] = c;
            }
        }
        var crc = 0xFFFFFFFF;
        for (var k = 0; k < data.length; k++) crc = _crc32Table[(crc ^ data[k]) & 0xFF] ^ (crc >>> 8);
        return (crc ^ 0xFFFFFFFF) >>> 0;
    }

    GridTabManager.prototype.exportExcel = function() {
        // Real XLSX — multi-sheet, compatible Numbers + Excel + LibreOffice
        // Main sheets first, then detail sheets (better UX — main data visible first)
        var mainSheets = [];
        var detailSheets = [];
        var allSharedStrings = [];

        // Pass 1: collect detail sheets + hyperlinks (strings accumulated first)
        var allHyperlinks = []; // one entry per tab: array of hyperlink objects
        var usedSheetNames = new Set(); // évite les collisions après truncation 31 char
        // Pré-réserver les noms des onglets principaux : ils seront créés en
        // Pass 2 mais doivent gagner sur les détails en cas de collision.
        for (var pn = 0; pn < this.tabs.length; pn++) {
            var pnt = this.tabs[pn];
            if (pnt && pnt.label) usedSheetNames.add(_sanitizeSheetName(pnt.label));
        }

        for (var t = 0; t < this.tabs.length; t++) {
            var tab = this.tabs[t];
            var grid = tab.grid;
            if (!grid || !grid.columns.length) { allHyperlinks.push([]); continue; }

            var hyperlinks = [];
            var cellDetailsMap = grid._cellDetails || {};

            for (var detailKey in cellDetailsMap) {
                if (!cellDetailsMap.hasOwnProperty(detailKey)) continue;
                var detail = cellDetailsMap[detailKey];

                // Source des rows : (a) cache en mémoire si l'utilisateur a
                // déjà drill-down → priorité (données fraîches API) ; (b) sinon
                // reconstruction locale par filtrage du tab source via match —
                // c'est ce qui débloque les onglets non-SQL (dashboard,
                // emit_tab, copilot) où rows n'est jamais cached avant click.
                var effectiveDetail;
                if (detail && Array.isArray(detail.rows) && detail.rows.length > 0
                    && Array.isArray(detail.columns) && detail.columns.length > 0) {
                    effectiveDetail = detail;
                } else {
                    effectiveDetail = _reconstructDetailRowsFromMatch(detail, t, this.tabs, 1000);
                    if (!effectiveDetail) continue; // pas reconstructible → skip
                }

                var parts = detailKey.split(',');
                if (parts.length !== 2) continue;
                var rawDetailLabel = 'D-' + _sanitizeSheetName(tab.label) + '-' + detailKey.replace(/,/g, '_');
                var baseDetailLabel = _sanitizeSheetName(rawDetailLabel); // re-cap à 31 char
                var detailSheetLabel = _uniqueDetailSheetName(baseDetailLabel, usedSheetNames);

                var detailResult = _buildDetailSheetXml(effectiveDetail, detailSheetLabel);
                var detailSsOffset = allSharedStrings.length;
                if (detailSsOffset > 0) {
                    // Only offset shared string indices (t="s" cells), NOT numeric values
                    detailResult.xml = detailResult.xml.replace(/t="s"[^>]*><v>(\d+)<\/v>/g, function(match, num) {
                        return 't="s"><v>' + (parseInt(num, 10) + detailSsOffset) + '</v>';
                    });
                }
                for (var ds = 0; ds < detailResult.sharedStrings.length; ds++) {
                    allSharedStrings.push(detailResult.sharedStrings[ds]);
                }
                detailSheets.push({ name: detailSheetLabel, xml: detailResult.xml });

                // Map original col index → visible col position
                var origColIdx = parseInt(parts[1], 10);
                var visibleCols = grid._getVisibleColIndices();
                var visColPos = visibleCols.indexOf(origColIdx);
                if (visColPos < 0) continue;
                var cellRef = _xlsxColRef(visColPos) + (parseInt(parts[0], 10) + 2);
                // row_count : préfère le champ explicite (peut être > rows.length
                // pour les détails reconstruits cappés à 1000), sinon longueur.
                var rowCount = (typeof effectiveDetail.row_count === 'number' && effectiveDetail.row_count > 0)
                    ? effectiveDetail.row_count
                    : effectiveDetail.rows.length;
                var displayedCount = effectiveDetail.rows.length;
                var tooltip = 'Voir ' + rowCount + ' ligne' + (rowCount > 1 ? 's' : '') + ' de détail';
                if (displayedCount < rowCount) {
                    tooltip += ' (' + displayedCount + ' affichées)';
                }
                hyperlinks.push({
                    cellRef: cellRef,
                    location: "'" + detailSheetLabel + "'!A1",
                    tooltip: tooltip
                });
            }
            allHyperlinks.push(hyperlinks);
        }

        // Pass 2: build main sheets (with hyperlinks)
        for (var t2 = 0; t2 < this.tabs.length; t2++) {
            var tab2 = this.tabs[t2];
            var grid2 = tab2.grid;
            if (!grid2 || !grid2.columns.length) continue;

            var result = _buildSheetXml(grid2, allHyperlinks[t2]);
            var ssOffset = allSharedStrings.length;
            if (ssOffset > 0) {
                // Only offset shared string indices (t="s" cells), NOT numeric values
                result.xml = result.xml.replace(/t="s"[^>]*><v>(\d+)<\/v>/g, function(match, num) {
                    return 't="s"><v>' + (parseInt(num, 10) + ssOffset) + '</v>';
                });
            }
            for (var s = 0; s < result.sharedStrings.length; s++) {
                allSharedStrings.push(result.sharedStrings[s]);
            }
            mainSheets.push({ name: _sanitizeSheetName(tab2.label), xml: result.xml });
        }

        // Final order: main sheets first, then detail sheets
        var sheets = mainSheets.concat(detailSheets);
        if (!sheets.length) return;

        // Build shared strings XML
        var ssXml = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            + '<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"'
            + ' count="' + allSharedStrings.length + '" uniqueCount="' + allSharedStrings.length + '">\n';
        for (var ss = 0; ss < allSharedStrings.length; ss++) {
            ssXml += '<si><t>' + _xlsxEsc(allSharedStrings[ss]) + '</t></si>\n';
        }
        ssXml += '</sst>';

        // Styles: 0=default, 1=header bold, 2=integer(#,##0), 3=decimal(#,##0.00),
        //         4=hyperlink text, 5=hyperlink integer, 6=hyperlink decimal, 7=plain integer (no thousands sep)
        var stylesXml = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            + '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">\n'
            + '<numFmts count="2">'
            + '<numFmt numFmtId="164" formatCode="#,##0"/>'
            + '<numFmt numFmtId="165" formatCode="#,##0.00"/>'
            + '</numFmts>\n'
            + '<fonts count="4">'
            + '<font><sz val="11"/><name val="Calibri"/></font>'
            + '<font><b/><sz val="11"/><name val="Calibri"/><color rgb="FFFFFFFF"/></font>'
            + '<font><u/><sz val="11"/><name val="Calibri"/><color rgb="FF0563C1"/></font>'
            + '<font><u/><sz val="11"/><name val="Calibri"/></font>'
            + '</fonts>\n'
            + '<fills count="3">'
            + '<fill><patternFill patternType="none"/></fill>'
            + '<fill><patternFill patternType="gray125"/></fill>'
            + '<fill><patternFill patternType="solid"><fgColor rgb="FF4472C4"/></patternFill></fill>'
            + '</fills>\n'
            + '<borders count="1"><border/></borders>\n'
            + '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>\n'
            + '<cellXfs count="8">'
            + '<xf numFmtId="0" fontId="0" fillId="0" borderId="0"/>'
            + '<xf numFmtId="0" fontId="1" fillId="2" borderId="0" applyFont="1" applyFill="1"/>'
            + '<xf numFmtId="164" fontId="0" fillId="0" borderId="0" applyNumberFormat="1"/>'
            + '<xf numFmtId="165" fontId="0" fillId="0" borderId="0" applyNumberFormat="1"/>'
            + '<xf numFmtId="0" fontId="2" fillId="0" borderId="0" applyFont="1"/>'
            + '<xf numFmtId="164" fontId="2" fillId="0" borderId="0" applyFont="1" applyNumberFormat="1"/>'
            + '<xf numFmtId="165" fontId="2" fillId="0" borderId="0" applyFont="1" applyNumberFormat="1"/>'
            + '<xf numFmtId="1" fontId="0" fillId="0" borderId="0" applyNumberFormat="1"/>'
            + '</cellXfs>\n'
            + '</styleSheet>';

        // Workbook
        var wbXml = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            + '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"'
            + ' xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">\n'
            + '<sheets>\n';
        // Feuilles de détail VISIBLES (pas hidden). Excel sur certaines
        // versions refuse de naviguer vers une feuille cachée via hyperlien
        // (le clic ne fait rien) — donc visibles par défaut. La couleur
        // d'onglet (cf. _buildDetailSheetXml ci-dessus) les distingue
        // visuellement des feuilles principales pour limiter la confusion.
        for (var w = 0; w < sheets.length; w++) {
            wbXml += '<sheet name="' + _xlsxEsc(sheets[w].name) + '" sheetId="' + (w + 1)
                + '" r:id="rId' + (w + 1) + '"/>\n';
        }
        wbXml += '</sheets></workbook>';

        // Workbook rels
        var wbRels = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            + '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">\n';
        for (var wr = 0; wr < sheets.length; wr++) {
            wbRels += '<Relationship Id="rId' + (wr + 1) + '" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet"'
                + ' Target="worksheets/sheet' + (wr + 1) + '.xml"/>\n';
        }
        wbRels += '<Relationship Id="rId' + (sheets.length + 1) + '" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>\n';
        wbRels += '<Relationship Id="rId' + (sheets.length + 2) + '" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/sharedStrings" Target="sharedStrings.xml"/>\n';
        wbRels += '</Relationships>';

        // Content types
        var ctXml = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            + '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">\n'
            + '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>\n'
            + '<Default Extension="xml" ContentType="application/xml"/>\n'
            + '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>\n'
            + '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>\n'
            + '<Override PartName="/xl/sharedStrings.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"/>\n';
        for (var ct = 0; ct < sheets.length; ct++) {
            ctXml += '<Override PartName="/xl/worksheets/sheet' + (ct + 1) + '.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>\n';
        }
        ctXml += '</Types>';

        // Root rels
        var rootRels = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            + '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">\n'
            + '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>\n'
            + '</Relationships>';

        // Build ZIP
        var files = [
            { name: '[Content_Types].xml', content: ctXml },
            { name: '_rels/.rels', content: rootRels },
            { name: 'xl/workbook.xml', content: wbXml },
            { name: 'xl/_rels/workbook.xml.rels', content: wbRels },
            { name: 'xl/styles.xml', content: stylesXml },
            { name: 'xl/sharedStrings.xml', content: ssXml },
        ];
        for (var f = 0; f < sheets.length; f++) {
            files.push({ name: 'xl/worksheets/sheet' + (f + 1) + '.xml', content: sheets[f].xml });
        }

        var zipData = _buildZip(files);
        var blob = new Blob([zipData], { type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' });
        var url = URL.createObjectURL(blob);
        var a = document.createElement('a');
        a.href = url;
        a.download = 'resultats_' + new Date().toISOString().slice(0, 10) + '.xlsx';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    };

    /**
     * Export Excel COMPLET via le serveur.
     *
     * À la différence de ``exportExcel`` (100% client, capped à 500 lignes
     * par onglet — la limite du frontend), cette version envoie le payload
     * sérialisé du classeur au backend (``/api/iris/export-xlsx-full``) qui :
     * - Réexécute chaque SQL d'onglet avec un cap de 100 000 lignes
     * - Reconstruit les détails de cellule à partir des données complètes
     * - Génère le .xlsx côté serveur via openpyxl
     * - Streame le fichier en attachment
     *
     * Latence : 1-30s selon la complexité du classeur. Affiche un toast
     * pendant l'opération.
     */
    // Export CSV anonymisé de l'onglet actif. L'anonymisation est faite côté
    // SERVEUR (``/api/iris/anonymize-tabs``, fail-closed, source unique
    // ``/data/privacy``) — un applicateur JS risquerait une fuite silencieuse
    // (divergence casse/espaces/substring avec le backend). Le serveur renvoie
    // les lignes anonymisées ; le FORMATAGE CSV reste client-side (même ``;`` /
    // BOM que l'export en clair, donc fichier de format identique).
    GridTabManager.prototype._exportActiveTabCsvAnonymized = function(grid) {
        var self = this;
        if (!grid || typeof grid._exportCSV !== 'function') {
            if (typeof self._showSaveToast === 'function') {
                self._showSaveToast('Export CSV indisponible pour cet onglet', true);
            }
            return;
        }
        var payload = { tabs: [{ columns: grid.columns, rows: grid.displayRows }] };
        var xsrf = _getXsrfCookie();
        fetch('/api/iris/anonymize-tabs', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-Xsrftoken': xsrf },
            body: JSON.stringify(payload),
            credentials: 'same-origin'
        }).then(function(resp) {
            return resp.text().then(function(text) {
                var data = null;
                try { data = JSON.parse(text); } catch (e) { /* body non-JSON */ }
                if (!resp.ok || !data || !data.success) {
                    var msg = (data && data.error) ? data.error : ('Erreur HTTP ' + resp.status);
                    throw new Error(msg);
                }
                return data;
            });
        }).then(function(data) {
            var tabs = data.tabs || [];
            var anonRows = (tabs[0] && tabs[0].rows) || [];
            // En-têtes anonymisés du serveur (cas pivot) — sinon le header CSV
            // fuiterait les colonnes en clair (re-review it.11).
            var anonCols = (tabs[0] && tabs[0].columns) || grid.columns;
            // Anti fausse-impression : 0 terme configuré → fichier = clair.
            if (data.term_count === 0) {
                var warnMsg = 'Aucun terme configuré sur /data/privacy : le fichier '
                    + 'exporté est identique à un export en clair.';
                if (typeof window.showToast === 'function') {
                    window.showToast(warnMsg, 'warning');
                } else if (typeof self._showSaveToast === 'function') {
                    self._showSaveToast(warnMsg, false);
                }
            }
            grid._exportCSV({ rows: anonRows, columns: anonCols, anonymized: true });
        }).catch(function(err) {
            // Fail-closed visible : on N'EXPORTE PAS en clair en cas d'échec
            // d'anonymisation — l'utilisateur voit l'erreur et peut réessayer
            // ou choisir explicitement l'export clair.
            if (typeof self._showSaveToast === 'function') {
                self._showSaveToast('Échec export anonymisé : ' + (err.message || err), true);
            }
            if (typeof console !== 'undefined' && console.error) {
                console.error('[iris-export-csv-anon] failed:', err);
            }
        });
    };

    GridTabManager.prototype.exportExcelFullServer = function(anonymize) {
        var self = this;
        anonymize = !!anonymize;
        if (!self.tabs || self.tabs.length === 0) {
            if (typeof self._showSaveToast === 'function') {
                self._showSaveToast('Aucun onglet à exporter', true);
            }
            return;
        }

        // Indicateur de chargement persistant — reste visible PENDANT TOUTE
        // la durée de la requête (peut être 1-60s) avec un compteur de
        // temps écoulé en direct, pour que l'utilisateur sache que l'export
        // est en cours et n'imagine pas que rien ne se passe.
        var loading = _createPersistentExportLoader();
        document.body.appendChild(loading.el);
        var startTime = Date.now();
        loading.update(0);
        var timer = setInterval(function() {
            loading.update(Math.floor((Date.now() - startTime) / 1000));
        }, 1000);
        var cleanup = function() {
            clearInterval(timer);
            if (loading.el.parentNode) loading.el.parentNode.removeChild(loading.el);
        };

        var payload;
        try {
            payload = self.serialize();
        } catch (e) {
            cleanup();
            if (typeof self._showSaveToast === 'function') {
                self._showSaveToast('Erreur de sérialisation: ' + e.message, true);
            }
            return;
        }

        // Mode anonymisé : le serveur applique les pseudonymes /data/privacy aux
        // valeurs avant de construire le .xlsx (fail-closed côté backend).
        payload.anonymize = anonymize;

        var xsrf = _getXsrfCookie();
        fetch('/api/iris/export-xlsx-full', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Xsrftoken': xsrf
            },
            body: JSON.stringify(payload),
            credentials: 'same-origin'
        }).then(function(resp) {
            // Récupère les warnings/stats AVANT de consommer le body.
            var warningsHeader = resp.headers.get('X-Iris-Export-Warnings');
            var statsHeader = resp.headers.get('X-Iris-Export-Stats');
            if (!resp.ok) {
                // Erreur métier : le body est probablement du JSON.
                return resp.text().then(function(text) {
                    var msg = 'Erreur HTTP ' + resp.status;
                    try {
                        var parsed = JSON.parse(text);
                        if (parsed && parsed.error) msg = parsed.error;
                    } catch (e) { /* body non-JSON, garder le default */ }
                    throw new Error(msg);
                });
            }
            return resp.blob().then(function(blob) {
                return { blob: blob, warnings: warningsHeader, stats: statsHeader };
            });
        }).then(function(result) {
            cleanup();

            // Trigger download.
            var url = URL.createObjectURL(result.blob);
            var a = document.createElement('a');
            a.href = url;
            // Suffixe ``_anonymise`` pour distinguer d'un coup d'œil un fichier
            // anonymisé d'un fichier en clair (le serveur pose le même suffixe
            // dans Content-Disposition, mais le client impose son propre nom).
            a.download = 'komptia_iris_'
                + new Date().toISOString().slice(0, 19).replace(/[T:]/g, '-')
                + (anonymize ? '_anonymise' : '') + '.xlsx';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);

            // Affiche les warnings non-bloquants si présents.
            var warnings = [];
            try {
                if (result.warnings) warnings = JSON.parse(result.warnings);
            } catch (e) { /* defensive: header possiblement tronqué */ }
            var stats = null;
            try {
                if (result.stats) stats = JSON.parse(result.stats);
            } catch (e) { /* idem */ }

            if (typeof self._showSaveToast === 'function') {
                if (warnings && warnings.length > 0) {
                    // A5-F2 : surfacer le TEXTE du 1er avertissement (pas juste un
                    // compte) — comme saveWorkbook. Un onglet refusé par la RLS ou
                    // en erreur SQL retombe sur un snapshot partiel/périmé dans le
                    // fichier ; l'utilisateur DOIT le savoir avant de diffuser
                    // (données fausses silencieuses), pas le chercher en console.
                    var summary = '⚠ Export partiel : ' + warnings[0];
                    if (warnings.length > 1) {
                        summary += ' (+ ' + (warnings.length - 1) + ' autre'
                            + (warnings.length > 2 ? 's' : '') + ')';
                    }
                    // A5-F2 (adversarial) : alerte d'INTÉGRITÉ DONNÉES → toast
                    // STICKY ('error', persistant) que l'user doit acquitter avant
                    // de diffuser un fichier dont des onglets sont partiels/périmés.
                    if (typeof window.showToast === 'function') {
                        window.showToast(summary, 'error');
                    } else {
                        self._showSaveToast(summary, false);
                    }
                    if (typeof console !== 'undefined' && console.warn) {
                        console.warn('[iris-export-full] warnings:', warnings, 'stats:', stats);
                    }
                } else {
                    var doneMsg = 'Export complet téléchargé';
                    if (stats && typeof stats.total_rows === 'number') {
                        doneMsg += ' (' + stats.total_rows + ' lignes)';
                    }
                    self._showSaveToast(doneMsg, false);
                }
            }
        }).catch(function(err) {
            cleanup();
            if (typeof self._showSaveToast === 'function') {
                self._showSaveToast('Échec export complet: ' + (err.message || err), true);
            }
            if (typeof console !== 'undefined' && console.error) {
                console.error('[iris-export-full] failed:', err);
            }
        });
    };

    // Loader persistant pour l'export complet — overlay fixe en bas à droite
    // de l'écran avec spinner CSS + compteur de temps écoulé. L'enjeu est
    // que l'utilisateur ne pense pas que rien ne se passe pendant un
    // export qui peut prendre 30-60s sur un gros classeur.
    function _createPersistentExportLoader() {
        // Injecte la keyframe d'animation une seule fois par page.
        if (!document.getElementById('iris-export-loader-style')) {
            var styleEl = document.createElement('style');
            styleEl.id = 'iris-export-loader-style';
            styleEl.textContent =
                '@keyframes iris-export-loader-spin{to{transform:rotate(360deg)}}'
                + '.iris-export-loader{position:fixed;bottom:24px;right:24px;'
                + 'background:#1f2937;color:#fff;padding:14px 20px;border-radius:8px;'
                + 'box-shadow:0 4px 16px rgba(0,0,0,.35);'
                + 'font-family:system-ui,-apple-system,sans-serif;font-size:14px;'
                /* Indicateur de loading export — toast-like (z 10000) pour
                   rester visible au-dessus des modaux mais sans bloquer. */
                + 'z-index:10000;display:flex;align-items:center;gap:12px;'
                + 'min-width:240px;max-width:360px;line-height:1.4}'
                + '.iris-export-loader-spinner{width:18px;height:18px;'
                + 'border:2px solid rgba(255,255,255,.25);border-top-color:#fff;'
                + 'border-radius:50%;animation:iris-export-loader-spin 1s linear infinite;'
                + 'flex-shrink:0}'
                + '.iris-export-loader-text{flex:1}'
                + '.iris-export-loader-elapsed{opacity:.7;font-size:12px;margin-left:6px}';
            document.head.appendChild(styleEl);
        }

        var el = document.createElement('div');
        el.className = 'iris-export-loader';
        el.setAttribute('role', 'status');
        el.setAttribute('aria-live', 'polite');
        var spinner = document.createElement('div');
        spinner.className = 'iris-export-loader-spinner';
        var textWrap = document.createElement('div');
        textWrap.className = 'iris-export-loader-text';
        var label = document.createElement('span');
        label.textContent = 'Export Excel en cours';
        var elapsed = document.createElement('span');
        elapsed.className = 'iris-export-loader-elapsed';
        elapsed.textContent = '0 s';
        textWrap.appendChild(label);
        textWrap.appendChild(document.createTextNode(' '));
        textWrap.appendChild(elapsed);
        el.appendChild(spinner);
        el.appendChild(textWrap);

        return {
            el: el,
            update: function(secs) {
                elapsed.textContent = secs + ' s';
                // Au-delà de 30s, message rassurant en plus.
                if (secs >= 30 && secs < 31) {
                    label.textContent = 'Gros classeur, patience…';
                } else if (secs >= 60 && secs < 61) {
                    label.textContent = 'Toujours en cours, ne fermez pas l’onglet';
                }
            }
        };
    }

    // ── GridTabManager — State persistence (localStorage) ──
    // Permet de retrouver l'état exact des grilles après un refresh :
    // tri, filtres, colonnes cachées, ordre des colonnes, onglets, drill-downs.

    /**
     * Assigne un identifiant de persistance à ce GridTabManager.
     * Appelé par iris.js lors de la création de la grille.
     * @param {string} persistId — Identifiant unique (ex: "grid-conv53-3")
     */
    GridTabManager.prototype.setPersistId = function(persistId) {
        this._persistId = persistId;
        // Restaurer l'état sauvé s'il existe
        this._loadPersistedState();
    };

    /**
     * Sauvegarde l'état complet de tous les onglets en localStorage.
     * Debouncée à 500ms : chaque édition cellule / tri / filtre appelait
     * le callback ``onStateChange`` qui fait JSON.stringify du classeur
     * complet. Sur un classeur gros (30 onglets), c'était 50-150ms à
     * chaque keystroke — utilisateur voyait le lag sans raison visible.
     *
     * L'appel publique expose la debounced version ; l'appel effectif
     * est ``_doPersistState``. ``flushPersistState()`` force l'écriture
     * immédiate (utilisé par ``beforeunload``).
     */
    GridTabManager.prototype.persistState = function() {
        var self = this;
        clearTimeout(this._persistStateTimer);
        this._persistStatePending = true;
        this._persistStateTimer = setTimeout(function() {
            self._persistStateTimer = null;
            self._persistStatePending = false;
            self._doPersistState();
        }, PERSIST_STATE_DEBOUNCE_MS);
    };

    GridTabManager.prototype.flushPersistState = function() {
        if (!this._persistStatePending) return;
        clearTimeout(this._persistStateTimer);
        this._persistStateTimer = null;
        this._persistStatePending = false;
        this._doPersistState();
    };

    // ── Stockage à étages (grid-store) ───────────────────────────────────
    // Sépare un état de grille sérialisé en INTENTION (light, sans ``allRows``)
    // et DONNÉES (heavy, juste ``allRows``). L'intention va en localStorage
    // synchrone (minuscule, survit toujours au F5) ; les données vont en
    // IndexedDB via ``window.GridStore`` (capacité Go, async, structured clone).
    // Cf. docs/design/grid_storage_tiered_indexeddb.md.
    function _splitGridState(state) {
        var heavy = { allRows: (state && state.allRows) || [] };
        var light = {};
        if (state) {
            for (var k in state) {
                // On STRIPPE ``allRows`` du light : son absence (undefined) est
                // le signal pour ``_restoreFromState`` de préserver les rows
                // backend (≠ ``[]`` qui voudrait dire "vider").
                if (state.hasOwnProperty(k) && k !== 'allRows') light[k] = state[k];
            }
        }
        return { light: light, heavy: heavy };
    }

    // Recompose un état complet (light + rows) pour ``_restoreFromState``.
    function _withAllRows(lightState, allRows) {
        var out = {};
        for (var k in lightState) {
            if (lightState.hasOwnProperty(k)) out[k] = lightState[k];
        }
        out.allRows = allRows;
        return out;
    }

    // Reconnaît une clé "intention" de grille en localStorage (pour le sweep) :
    // chat ``grid-{user}-conv{id}-{n}`` OU dashboard ``u{id}-dash{id}-w{id}``.
    function _isGridLightKey(key) {
        return key.indexOf('grid-') === 0 || /^u\d+-dash\d+-w/.test(key);
    }

    // Dédup du toast de saturation au niveau SESSION (pas par grille) : c'est une
    // condition globale au navigateur (pool plein) — inutile de la répéter par
    // grille. Conforme au design §5 (« 1×/session »).
    var _quotaToastShownSession = false;

    GridTabManager.prototype._doPersistState = function() {
        if (!this._persistId) return;
        // Guard re-entrance : le timer + flushPersistState peuvent tous
        // deux lancer _doPersistState en concurrence (pagehide + beforeunload
        // qui firent l'un après l'autre). Le 2e appel doit no-op pour éviter
        // le double travail de capture/sérialisation du classeur entier.
        if (this._persistStateRunning) return;
        this._persistStateRunning = true;
        try {
            var lightTabs = [];
            var heavyTabs = [];
            for (var i = 0; i < this.tabs.length; i++) {
                var tab = this.tabs[i];
                var lightState = null;
                var heavyState = { allRows: [] };
                if (tab.grid && typeof tab.grid._captureState === 'function') {
                    var raw = tab.grid._captureState();
                    // Sérialiser les Sets en Arrays pour JSON/structured-clone.
                    var serialized = JSON.parse(JSON.stringify(raw, function(k, v) {
                        return v instanceof Set ? Array.from(v) : v;
                    }));
                    var split = _splitGridState(serialized);
                    lightState = split.light;
                    heavyState = split.heavy;
                }
                lightTabs.push({ label: tab.label, closable: tab.closable, state: lightState });
                heavyTabs.push(heavyState);
            }
            var savedAt = Date.now();
            // ``_schema: 2`` = format à étages (allRows hors localStorage).
            // Son absence sur une vieille clé = legacy monolithique (lu une fois,
            // puis réécrit au nouveau format → pool localStorage libéré).
            var lightData = {
                activeTabIndex: this.activeTabIndex,
                tabs: lightTabs,
                _savedAt: savedAt,
                _schema: 2,
            };
            var heavyData = { tabs: heavyTabs, _savedAt: savedAt };

            // 1) INTENTION → localStorage SYNCHRONE (doit tenir : ~Ko).
            try {
                localStorage.setItem(this._persistId, JSON.stringify(lightData));
            } catch (quotaErr) {
                this._handlePersistQuota(quotaErr, null);
            }

            // 2) DONNÉES → GridStore (IndexedDB ; repli localStorage ``gs1:``).
            //    Async mais SÉRIALISÉ par persistId : on chaîne sur la promesse
            //    précédente pour éviter deux ``put`` concurrents sur la même clé.
            //    Le garde de ré-entrance ``_persistStateRunning`` est SYNCHRONE et
            //    ne couvre pas l'async → sans chaînage, un put N-1 résolu APRÈS un
            //    put N laisserait un heavy périmé face à un light frais (désync
            //    silencieuse). Le dernier état gagne. La ref tient aussi la
            //    promesse (anti-GC). Pas de stringify géant (structured clone IDB).
            if (typeof window !== 'undefined' && window.GridStore) {
                var self = this;
                var prev = this._persistHeavyPromise || Promise.resolve();
                this._persistHeavyPromise = prev.then(function () {
                    return window.GridStore.put(self._persistId, heavyData);
                }).then(function (res) {
                    if (res && res.ok === false) self._handlePersistQuota(null, res.reason);
                }).catch(function () { /* best-effort */ });
            }
        } catch (e) {
            // Erreur dans la capture/sérialisation (rare) — pas critique.
        } finally {
            // ``finally`` (pas après le catch) : si un futur edit ajoute un
            // ``return`` dans le ``try``, le flag de ré-entrance resterait
            // ``true`` et figerait TOUT persist ultérieur. Robustesse.
            this._persistStateRunning = false;
        }
    };

    // Toast dégradation, DÉDUPÉ (1×/session). N'apparaît plus en
    // régime normal (IndexedDB absorbe le volume) — uniquement dans le repli
    // extrême (IDB indispo + localStorage plein). Message corrigé : honnête
    // (l'intention EST conservée) + actionnable (relancer la requête).
    GridTabManager.prototype._handlePersistQuota = function(err, reason) {
        var isQuota = reason === 'quota' || reason === 'too_large'
            || (err && (err.name === 'QuotaExceededError'
                || err.code === 22 || err.code === 1014));
        if (!isQuota) return; // localStorage indisponible (privé Safari) → silencieux
        if (_quotaToastShownSession) return;
        _quotaToastShownSession = true;
        try { console.warn('[Iris] cache plein, données grille non mises en cache:', this._persistId); } catch (e) { /* noop */ }
        if (typeof window !== 'undefined' && typeof window.showToast === 'function') {
            window.showToast(
                "Cache du navigateur saturé : le tri et les filtres restent conservés, "
                + "mais les données complètes ne seront pas remises en cache au "
                + "rafraîchissement. Relancez la requête pour tout réafficher.",
                'warning'
            );
        }
    };

    /**
     * Charge et restaure l'état des onglets depuis localStorage.
     */
    // Mo3 — TTL implicite : les états de grille > 30 jours sont purgés
    // au load. Évite l'accumulation indéfinie de clés orphelines (conv
    // supprimées hors flow "Effacer", admin reset, etc.).
    var GRID_STATE_TTL_MS = 30 * 24 * 60 * 60 * 1000;  // 30 jours

    GridTabManager.prototype._loadPersistedState = function() {
        if (!this._persistId) return;
        var light;
        try {
            var raw = localStorage.getItem(this._persistId);
            if (!raw) return;
            light = JSON.parse(raw);
        } catch (e) { return; }
        if (!light || !Array.isArray(light.tabs) || light.tabs.length === 0) return;

        // TTL : intention absente/trop vieille → drop les DEUX stores et stop.
        // (Avant : seul localStorage était purgé → la donnée lourde restait
        // orpheline. Désormais on nettoie aussi IndexedDB.)
        if (!light._savedAt || (Date.now() - light._savedAt) > GRID_STATE_TTL_MS) {
            try { localStorage.removeItem(this._persistId); } catch (e) { /* noop */ }
            try { if (typeof window !== 'undefined' && window.GridStore) window.GridStore.del(this._persistId); } catch (e) { /* noop */ }
            return;
        }

        // Gate : ne restaurer que si l'onglet 0 a le même SQL (même grille).
        var firstSaved = light.tabs[0];
        if (!firstSaved || !firstSaved.state) return;
        var firstCurrent = this.tabs[0];
        if (!firstCurrent || !firstCurrent.grid) return;
        if (firstSaved.state.sql !== firstCurrent.grid.sql) return;

        // Legacy = schéma monolithique pré-étages : ``allRows`` est DANS le
        // light (localStorage). On restaure synchrone, sans lire IndexedDB ;
        // au prochain persist, la clé est réécrite au format à étages (le gros
        // volume migre vers IndexedDB → pool localStorage libéré).
        var isLegacy = (light._schema !== 2);
        var self = this;

        var applyRestore = function (heavy) {
            try {
                var g = firstCurrent.grid;
                // Anti-mispairing : light (localStorage) et heavy (IndexedDB) sont
                // appariés par INDEX d'onglet. Un heavy périmé d'une session/écriture
                // antérieure (même clé, _savedAt différent) apparié au light frais
                // donnerait des rows au MAUVAIS onglet (données fausses silencieuses).
                // On exige le MÊME _savedAt (les deux sont écrits ensemble dans
                // _doPersistState). Sinon on jette le heavy → fallback sûr.
                if (heavy && light._savedAt && heavy._savedAt !== light._savedAt) {
                    heavy = null;
                }
                // L'utilisateur a-t-il muté la grille depuis le rendu ? (édition
                // cellule, add/remove, fusion, paste…, via _pushHistory). Si oui,
                // NE PAS écraser son travail avec la donnée persistée (course async).
                var dirtied = !!g._userDirtied;

                // ── Onglet 0 (déjà créé par addTab, peuplé par le backend) ──
                var s0 = firstSaved.state;
                var rows0 = (heavy && heavy.tabs && heavy.tabs[0] && heavy.tabs[0].allRows)
                    ? heavy.tabs[0].allRows
                    : (isLegacy ? s0.allRows : null);
                // Pristine = aucune interaction depuis le rendu (ni tri/filtre, ni
                // édition). Sinon on ne CLOBBERE rien : la grille garde l'état user.
                var pristine = !dirtied && !g._restorePersistApplied
                    && (g.sortColIndex == null || g.sortColIndex < 0)
                    && (!g.filters || Object.keys(g.filters).length === 0);
                if (pristine) {
                    var merged0 = (rows0 && rows0.length) ? _withAllRows(s0, rows0) : s0;
                    g._restoreFromState(merged0);
                    g._restorePersistApplied = true;
                    // Applique RÉELLEMENT le tri/filtre restauré à la vue. Avant
                    // ce fix, _restoreFromState posait l'état en mémoire mais
                    // _build() rendait allRows.slice() non filtré/trié → le
                    // tri/filtre persisté était INERTE au reload (bug latent).
                    if (typeof g._refreshView === 'function') g._refreshView();
                    if (typeof g._updateSortIndicators === 'function') g._updateSortIndicators();
                } else if (!dirtied && rows0 && rows0.length) {
                    // L'user a trié/filtré (mais pas édité les données) → on hydrate
                    // juste les rows sous SA vue courante via _refreshView, sans
                    // toucher son intention. Si dirtied : on ne touche RIEN.
                    g.allRows = g._deepCloneSafe(rows0);
                    g.isArrayFormat = rows0.length > 0 && Array.isArray(rows0[0]);
                    if (typeof g._refreshView === 'function') g._refreshView();
                }

                // ── Onglets supplémentaires (drill-downs) ──
                // Reconstruire UNIQUEMENT si seul l'onglet 0 existe (sinon l'user a
                // créé ses propres onglets pendant l'hydratation → ne pas dupliquer)
                // ET s'il n'a pas muté la grille.
                var canRestoreDrillTabs = !dirtied && self.tabs.length === 1;
                var droppedDrill = false;
                if (canRestoreDrillTabs) {
                    for (var i = 1; i < light.tabs.length; i++) {
                        var td = light.tabs[i];
                        if (!td.state || !td.state.columns) continue;
                        var si = td.state;
                        var rowsi = (heavy && heavy.tabs && heavy.tabs[i] && heavy.tabs[i].allRows)
                            ? heavy.tabs[i].allRows
                            : (isLegacy ? si.allRows : null);
                        // Sans rows (IDB indispo/évincé ET pas legacy) : drill-down
                        // non restaurable → on le SIGNALE (pas de perte silencieuse).
                        if (!rowsi) { droppedDrill = true; continue; }
                        var merged = _withAllRows(si, rowsi);
                        var tabInfo = self.addTab(
                            td.label || 'Onglet',
                            merged.columns, merged.allRows, merged.sql,
                            merged.totalRowCount, null,
                            td.closable !== false
                        );
                        if (tabInfo && tabInfo.grid) {
                            tabInfo.grid._restoreFromState(merged);
                            if (typeof tabInfo.grid._refreshView === 'function') tabInfo.grid._refreshView();
                            if (typeof tabInfo.grid._updateSortIndicators === 'function') tabInfo.grid._updateSortIndicators();
                        }
                    }
                    // ── Onglet actif ── (seulement si on a (re)construit l'arbo)
                    var activeIdx = light.activeTabIndex || 0;
                    if (activeIdx >= 0 && activeIdx < self.tabs.length) self._switchTab(activeIdx);
                }

                if (droppedDrill && typeof window !== 'undefined'
                        && typeof window.showToast === 'function') {
                    window.showToast(
                        "Onglets de détail non restaurés (cache navigateur "
                        + "indisponible). Rouvrez-les depuis le tableau si besoin.",
                        'warning'
                    );
                }
            } catch (e) {
                // État corrompu — la grille reste dans son état backend (non vide).
            }
        };

        if (isLegacy) {
            applyRestore(null); // données déjà dans le light → restauration synchrone
        } else if (typeof window !== 'undefined' && window.GridStore) {
            window.GridStore.get(this._persistId)
                .then(function (heavy) { applyRestore(heavy); })
                .catch(function () { applyRestore(null); });
        } else {
            applyRestore(null); // pas de GridStore → intention seule (rows backend conservées)
        }
    };

    /**
     * Supprime l'état persisté (appelé quand la conversation est effacée).
     *
     * Mo3 — Le paramètre ``username`` est optionnel pour rétrocompat : si
     * absent, on purge TOUTES les clés ``grid-*-conv{id}-*`` quel que
     * soit le user (suffit pour le bouton "Effacer" qui agit sur la conv
     * de l'user courant). Si fourni, on cible précisément les clés du
     * user — utile si on veut faire du cleanup ciblé futur.
     *
     * @param {number} conversationId
     * @param {string} [username] — Optionnel, scope par user.
     */
    GridTabManager.clearPersistedState = function(conversationId, username) {
        try {
            // 2 préfixes à matcher pour purger :
            //  - format Mo3 : "grid-{user}-conv{id}-{idx}"
            //  - format legacy (pré-Mo3) : "grid-conv{id}-{idx}"
            // On accepte les deux pour ne pas laisser de clés orphelines
            // pendant la migration (les clés legacy seront purgées par TTL
            // au prochain F5 mais autant les nettoyer maintenant).
            var convToken = 'conv' + conversationId + '-';
            var newScopedPrefix = username
                ? 'grid-' + username + '-' + convToken
                : null;
            var legacyPrefix = 'grid-' + convToken;

            var toRemove = [];
            for (var i = 0; i < localStorage.length; i++) {
                var key = localStorage.key(i);
                if (!key) continue;
                // Matche le format Mo3 (scopé user) si username fourni
                if (newScopedPrefix && key.indexOf(newScopedPrefix) === 0) {
                    toRemove.push(key);
                    continue;
                }
                // Matche le format legacy "grid-conv{id}-..." OU
                // n'importe quel "grid-{X}-conv{id}-..." si username non fourni
                if (key.indexOf(legacyPrefix) === 0) {
                    toRemove.push(key);
                    continue;
                }
                if (!username && key.indexOf('grid-') === 0
                        && key.indexOf('-' + convToken) > 0) {
                    toRemove.push(key);
                }
            }
            for (var j = 0; j < toRemove.length; j++) {
                try { localStorage.removeItem(toRemove[j]); } catch (e) { /* noop */ }
                // Supprime aussi la donnée lourde correspondante (IndexedDB +
                // repli ``gs1:``) — sinon elle resterait orpheline après
                // « Effacer la conversation » (fuite + croissance non bornée).
                try {
                    if (typeof window !== 'undefined' && window.GridStore) {
                        window.GridStore.del(toRemove[j]);
                    }
                } catch (e) { /* noop */ }
            }
        } catch (e) { /* ignore */ }
    };

    /**
     * Mo3 — Sweeper auto : purge les clés ``grid-*`` dont ``_savedAt`` est
     * absent (format legacy pré-Mo3) ou plus vieux que ``maxAgeMs``.
     *
     * Appelé une fois au boot d'Iris pour limiter l'accumulation de clés
     * orphelines sur poste partagé. Pas de coût UX visible : le sweep
     * lit puis drop, en quelques ms même avec 50+ clés.
     *
     * @param {number} [maxAgeMs] — TTL (défaut: GRID_STATE_TTL_MS = 30j)
     * @returns {number} Nombre de clés purgées.
     */
    GridTabManager.purgeStaleKeys = function(maxAgeMs) {
        var ttl = (typeof maxAgeMs === 'number' && maxAgeMs > 0)
            ? maxAgeMs
            : GRID_STATE_TTL_MS;
        var now = Date.now();
        var purged = 0;
        try {
            var toRemove = [];
            for (var i = 0; i < localStorage.length; i++) {
                var key = localStorage.key(i);
                // Clés "intention" : chat ``grid-*`` ET dashboard
                // ``u{id}-dash{id}-w*``. Ces dernières n'étaient JAMAIS purgées
                // (l'ancien filtre ne matchait que ``grid-``) → accumulation
                // indéfinie sur poste partagé jusqu'au quota (bug F5 du design).
                if (!key || !_isGridLightKey(key)) continue;
                try {
                    var raw = localStorage.getItem(key);
                    if (!raw) { toRemove.push(key); continue; }
                    var parsed = JSON.parse(raw);
                    var savedAt = parsed && parsed._savedAt;
                    // Pas de _savedAt = legacy OU format inattendu : on drop par
                    // sécurité (état d'une vieille conv non consultée depuis 30j+).
                    if (!savedAt || (now - savedAt) > ttl) {
                        toRemove.push(key);
                    }
                } catch (parseErr) {
                    // JSON corrompu = drop
                    toRemove.push(key);
                }
            }
            for (var j = 0; j < toRemove.length; j++) {
                try {
                    localStorage.removeItem(toRemove[j]);
                    // Supprime aussi la donnée lourde correspondante (IndexedDB).
                    if (typeof window !== 'undefined' && window.GridStore) {
                        window.GridStore.del(toRemove[j]);
                    }
                    purged++;
                } catch (rmErr) { /* noop */ }
            }
        } catch (e) { /* localStorage indispo : noop */ }
        // Sweep des données lourdes en IndexedDB (+ repli ``gs1:``) par TTL pour
        // TOUS les préfixes grille — couvre aussi un heavy orphelin dont
        // l'intention localStorage aurait déjà disparu.
        try {
            if (typeof window !== 'undefined' && window.GridStore) {
                window.GridStore.sweep({ prefixes: ['grid-', 'u', 'autorec:'], maxAgeMs: ttl });
            }
        } catch (e) { /* noop */ }
        return purged;
    };

    window.GridTabManager = GridTabManager;

    return SqlResultGrid;
})();
