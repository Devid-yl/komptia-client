/**
 * Privacy — term-detail-panel.js
 *
 * Modale de détail d'un terme : aperçu clear/anonymisé, classeurs où le
 * terme apparaît, et historique récent. Charge la couverture via
 * ``GET /api/anonymization/terms/<id>/coverage``.
 *
 * Réutilise ``OverlayManager`` (LIFO + scroll lock) et ``LocalDatetime``
 * (UTC → heure locale sur les ``<time data-fmt-local>``).
 *
 * Doctrine
 * --------
 * 1. **CSP-safe** — toute construction DOM via ``createElement`` +
 *    ``textContent`` ; aucune interpolation HTML user-controlled.
 *    L'``innerHTML`` est utilisé UNIQUEMENT pour vider le body
 *    (``''``), jamais pour injecter du contenu.
 * 2. **Restore focus** — on capture l'élément actif AVANT ouverture et
 *    on le restaure à la fermeture (a11y, navigation clavier).
 * 3. **Anti-XSS** — ``term``, ``pseudo_middle``, ``filename``,
 *    ``triggered_by`` viennent du serveur, mais aussi de saisies user
 *    (term peut être un nom de client avec caractères spéciaux).
 * 4. **Section preview** — section "Aperçu de l'anonymisation"
 *    explique au user ce que voit le LLM cloud. ``term.term`` (clear)
 *    vs ``§<pseudo_middle>§`` (token envoyé). Si pas de pseudo (terme
 *    pas encore confirmé), affiche un placeholder type ``[CATEGORY_N]``.
 */
(function() {
    'use strict';

    /** Résolution de label : on délègue intégralement à ``AnonTokenizer``
     *  (single source of truth Python ↔ JS). ``categoryToLabel`` accepte
     *  toute string catégorie (inconnue → ``TERM`` par fallback), donc plus
     *  besoin de whitelist locale qui dériverait au fil des ajouts BDD.
     *
     *  En environnement Node (tests), ``AnonTokenizer`` est exporté en
     *  CommonJS : on tente ``require`` si ``window`` indisponible. Si rien
     *  ne marche (cas pathologique : page sans tokenizer.js chargé), on
     *  fallback string-only sur le préfixe « TERM ».
     */
    function _tokenizerModule() {
        if (typeof window !== 'undefined' && window.AnonTokenizer) {
            return window.AnonTokenizer;
        }
        if (typeof require === 'function') {
            try {
                return require('../anonymization/tokenizer.js');
            } catch (e) {
                // Fallthrough → fallback minimal.
            }
        }
        return null;
    }

    /** Génère le couple (clear, anonymisé) à afficher dans la section
     *  preview. Pure : testable Node.
     *
     *  Retourne ``{ clear, anonymized, mode }`` où mode ∈
     *  {'pseudo', 'category'}.
     */
    function formatPreview(term) {
        var clear = (term && term.term != null) ? String(term.term) : '';
        if (term && term.pseudo_middle) {
            return {
                clear: clear,
                anonymized: '§' + String(term.pseudo_middle) + '§',
                mode: 'pseudo',
            };
        }
        // Sans pseudo (terme proposé mais non confirmé), on affiche un
        // placeholder réaliste : on calcule directement le middle via
        // ``resolveLabel`` + le hash, identique à ce que le LLM verra.
        // L'ancien format ``[CATEGORY_N]`` était un mensonge UX — l'utilisateur
        // ne verrait jamais ce placeholder car le proxy applique le
        // pseudonymizer avec ``§…§`` (cf. patterns.apply_builtin_pii).
        var tok = _tokenizerModule();
        if (tok && typeof tok.autoPseudoMiddle === 'function') {
            var category = (term && typeof term.category === 'string')
                ? term.category
                : null;
            return {
                clear: clear,
                anonymized: '§' + tok.autoPseudoMiddle(clear, category) + '§',
                mode: 'category',
            };
        }
        // Fallback ultra-conservateur si tokenizer.js absent.
        return {
            clear: clear,
            anonymized: '§TERM_xxxx§',
            mode: 'category',
        };
    }

    function _esc(value) {
        return value == null ? '' : String(value);
    }

    function _attachBrowser() {
        if (typeof document === 'undefined') return;
        // Idempotence : un double-include (hot-reload dev, ou inclusion
        // du script dans plusieurs templates qui se chargent successivement
        // dans la même page SPA) ne doit pas créer un 2ᵉ overlay ni des
        // listeners orphelins. Si l'API est déjà exposée, on no-op.
        if (typeof window !== 'undefined' && window.PrivacyDetailPanel) return;

        var state = { lastFocus: null, onKeyDown: null };

        function $(id) { return document.getElementById(id); }

        // Crée le DOM ``#modal-term-coverage`` à la volée si absent. Permet
        // d'utiliser ``PrivacyDetailPanel`` depuis n'importe quelle page
        // (privacy, iris, datastore, automations) sans dupliquer le markup.
        // Styling inline pour rester self-contained et fonctionner avec ou
        // sans privacy.css. CSP-safe (createElement + textContent).
        function _ensureModal() {
            var existing = $('modal-term-coverage');
            if (existing) return existing;

            var overlay = document.createElement('div');
            overlay.id = 'modal-term-coverage';
            overlay.setAttribute('role', 'dialog');
            overlay.setAttribute('aria-modal', 'true');
            overlay.setAttribute('aria-labelledby', 'modal-term-title');
            overlay.setAttribute('aria-hidden', 'true');
            overlay.hidden = true;
            // z-index intentionnellement omis — c'est OverlayManager.open()
            // qui pilote le layer (cf. openModal() plus bas). Ne PAS remettre
            // une valeur en dur : sans le manager (debug, fork, panel
            // appelé via un autre chemin), elle reprend et casse la
            // hiérarchie globale.
            overlay.style.cssText =
                'position:fixed;inset:0;background:rgba(0,0,0,0.5);' +
                'display:flex;align-items:center;justify-content:center;';

            var dialog = document.createElement('div');
            dialog.style.cssText =
                'background:var(--bg-surface, #fff);color:var(--text-primary, #111827);' +
                'border-radius:0.5rem;box-shadow:0 10px 40px rgba(0,0,0,0.2);' +
                'border:1px solid var(--border, #e5e7eb);' +
                'width:min(640px, 94vw);max-height:86vh;' +
                'display:flex;flex-direction:column;overflow:hidden;';

            var header = document.createElement('div');
            header.style.cssText =
                'display:flex;align-items:center;justify-content:space-between;' +
                'gap:0.75rem;padding:0.85rem 1.1rem;' +
                'border-bottom:1px solid var(--border, #e5e7eb);';

            var titleEl = document.createElement('h3');
            titleEl.id = 'modal-term-title';
            titleEl.textContent = 'Détail du terme';
            titleEl.style.cssText =
                'margin:0;font-size:0.95rem;font-weight:600;' +
                'color:var(--text-primary, #111827);';

            var closeBtn = document.createElement('button');
            closeBtn.id = 'modal-term-close';
            closeBtn.type = 'button';
            closeBtn.setAttribute('aria-label', 'Fermer');
            closeBtn.title = 'Fermer';
            closeBtn.textContent = '×';
            closeBtn.style.cssText =
                'background:transparent;border:0;font-size:1.4rem;line-height:1;' +
                'color:var(--text-muted, #6b7280);cursor:pointer;padding:0 0.4rem;';
            closeBtn.addEventListener('click', closeModal);

            header.appendChild(titleEl);
            header.appendChild(closeBtn);

            var body = document.createElement('div');
            body.id = 'modal-term-body';
            body.style.cssText =
                'flex:1;overflow-y:auto;padding:1rem 1.1rem;' +
                'font-size:0.875rem;color:var(--text-primary, #111827);';

            dialog.appendChild(header);
            dialog.appendChild(body);
            overlay.appendChild(dialog);

            overlay.addEventListener('click', function(ev) {
                if (ev.target === overlay) closeModal();
            });

            document.body.appendChild(overlay);
            return overlay;
        }

        function openModal() {
            var modal = _ensureModal();
            if (!modal) return;
            state.lastFocus = document.activeElement;
            modal.hidden = false;
            modal.setAttribute('aria-hidden', 'false');
            if (window.OverlayManager) {
                window.OverlayManager.open(modal, { layer: 'modal', lockScroll: true });
            }
            state.onKeyDown = function(ev) {
                if (ev.key === 'Escape') closeModal();
            };
            document.addEventListener('keydown', state.onKeyDown);
            var closeBtn = $('modal-term-close');
            if (closeBtn) closeBtn.focus();
        }

        function closeModal() {
            var modal = $('modal-term-coverage');
            if (!modal) return;
            if (state.onKeyDown) {
                document.removeEventListener('keydown', state.onKeyDown);
                state.onKeyDown = null;
            }
            if (window.OverlayManager) window.OverlayManager.close(modal);
            modal.hidden = true;
            modal.setAttribute('aria-hidden', 'true');
            if (state.lastFocus && typeof state.lastFocus.focus === 'function') {
                state.lastFocus.focus();
            }
        }

        function _setLoading() {
            var body = $('modal-term-body');
            if (!body) return;
            body.innerHTML = '';
            var p = document.createElement('p');
            p.className = 'privacy-state-loading';
            p.setAttribute('role', 'status');
            p.textContent = 'Chargement…';
            body.appendChild(p);
        }

        function _setError(message) {
            var body = $('modal-term-body');
            if (!body) return;
            body.innerHTML = '';
            var p = document.createElement('p');
            p.className = 'privacy-state-error';
            p.setAttribute('role', 'alert');
            p.textContent = _esc(message || 'Erreur de chargement.');
            body.appendChild(p);
        }

        function _appendDl(parent, label, value) {
            var dt = document.createElement('dt');
            dt.textContent = label;
            var dd = document.createElement('dd');
            dd.textContent = _esc(value);
            parent.appendChild(dt);
            parent.appendChild(dd);
        }

        function _renderPreviewSection(parent, term) {
            // term peut venir du caller (lookup local) — sinon on affiche
            // la version derived du payload coverage (qui a term + id mais
            // pas pseudo_middle).
            var preview = formatPreview(term);
            var section = document.createElement('section');
            section.className = 'privacy-preview';
            section.setAttribute('aria-label', "Aperçu de l'anonymisation");

            var h4 = document.createElement('h4');
            h4.className = 'privacy-modal-section';
            h4.textContent = "Aperçu de l'anonymisation";
            section.appendChild(h4);

            var help = document.createElement('p');
            help.className = 'privacy-state-help';
            help.textContent = preview.mode === 'pseudo'
                ? "Vous voyez la valeur réelle dans Komptia. Avant chaque envoi à un LLM cloud, "
                  + "elle est remplacée par le pseudonyme ci-dessous."
                : "Ce terme est proposé mais pas encore confirmé. Lorsqu'il sera activé, il sera "
                  + "remplacé par un pseudonyme stable de la forme indiquée.";
            section.appendChild(help);

            var rows = document.createElement('div');
            rows.className = 'privacy-preview-rows';

            var rowClear = document.createElement('div');
            rowClear.className = 'privacy-preview-row';
            var labClear = document.createElement('span');
            labClear.className = 'privacy-preview-label';
            labClear.textContent = 'Vous voyez :';
            var valClear = document.createElement('code');
            valClear.className = 'privacy-preview-clear';
            valClear.textContent = preview.clear || '—';
            rowClear.appendChild(labClear);
            rowClear.appendChild(valClear);
            rows.appendChild(rowClear);

            var rowAnon = document.createElement('div');
            rowAnon.className = 'privacy-preview-row';
            var labAnon = document.createElement('span');
            labAnon.className = 'privacy-preview-label';
            labAnon.textContent = 'Le LLM cloud reçoit :';
            var valAnon = document.createElement('code');
            valAnon.className = 'privacy-preview-anonymized';
            valAnon.textContent = preview.anonymized || '—';
            rowAnon.appendChild(labAnon);
            rowAnon.appendChild(valAnon);
            rows.appendChild(rowAnon);

            section.appendChild(rows);
            parent.appendChild(section);
        }

        async function loadCoverage(termId, opts) {
            opts = opts || {};
            _setLoading();
            openModal();
            try {
                if (!opts.fetchJson) {
                    throw new Error('fetchJson manquant.');
                }
                var data = await opts.fetchJson(
                    '/api/anonymization/terms/' + encodeURIComponent(termId) + '/coverage'
                );
                _renderCoverage(data, opts.localTerm);
            } catch (err) {
                _setError((err && err.message) || 'Erreur de chargement.');
            }
        }

        function _renderCoverage(data, localTerm) {
            var body = $('modal-term-body');
            if (!body) return;
            body.innerHTML = '';

            var classeurs = Array.isArray(data && data.classeurs) ? data.classeurs : [];
            var presentClasseurs = classeurs.filter(function(c) { return c && c.present; });
            var auditRecent = Array.isArray(data && data.audit_recent) ? data.audit_recent : [];

            // Section preview : on préfère le terme local (qui a pseudo_middle)
            // au payload coverage qui a juste term/id.
            var termForPreview = localTerm || {
                term: data && data.term,
                id: data && data.id,
                category: data && data.category,
                pseudo_middle: data && data.pseudo_middle,
            };
            _renderPreviewSection(body, termForPreview);

            // Bloc DL (term, id, classeurs)
            var dl = document.createElement('dl');
            dl.className = 'privacy-modal-dl';
            _appendDl(dl, 'Terme', (data && data.term) || '—');
            _appendDl(dl, 'Identifiant', (data && data.id) || '—');
            _appendDl(dl, 'Classeurs scannés', String(classeurs.length));
            var presentCount = (data && data.classeurs_count != null)
                ? data.classeurs_count : presentClasseurs.length;
            _appendDl(dl, 'Présent dans', String(presentCount));
            body.appendChild(dl);

            if (data && data.scan_truncated) {
                var truncP = document.createElement('p');
                truncP.className = 'privacy-state-help';
                truncP.textContent = "Scan tronqué au cap serveur "
                    + "(certains classeurs n'ont pas été analysés).";
                body.appendChild(truncP);
            }

            // Section : "Apparaît dans"
            var h1 = document.createElement('h4');
            h1.className = 'privacy-modal-section';
            h1.textContent = 'Apparaît dans';
            body.appendChild(h1);

            if (presentClasseurs.length === 0) {
                var emptyC = document.createElement('p');
                emptyC.className = 'privacy-state-empty privacy-state-empty-inline';
                emptyC.textContent = 'Aucun classeur ne contient ce terme.';
                body.appendChild(emptyC);
            } else {
                var ulC = document.createElement('ul');
                ulC.className = 'privacy-modal-list';
                for (var i = 0; i < presentClasseurs.length; i++) {
                    var c = presentClasseurs[i];
                    var li = document.createElement('li');
                    var nameSpan = document.createElement('span');
                    nameSpan.className = 'privacy-modal-list-name';
                    nameSpan.textContent = _esc((c && c.filename) || '—');
                    li.appendChild(nameSpan);
                    ulC.appendChild(li);
                }
                body.appendChild(ulC);
            }

            // Section : "Dernières actions"
            var h2 = document.createElement('h4');
            h2.className = 'privacy-modal-section';
            h2.textContent = 'Dernières actions';
            body.appendChild(h2);

            if (auditRecent.length === 0) {
                var emptyA = document.createElement('p');
                emptyA.className = 'privacy-state-empty privacy-state-empty-inline';
                emptyA.textContent = 'Aucune action consignée.';
                body.appendChild(emptyA);
            } else {
                var ulA = document.createElement('ul');
                ulA.className = 'privacy-modal-list';
                for (var j = 0; j < auditRecent.length; j++) {
                    var a = auditRecent[j];
                    var liA = document.createElement('li');
                    var nameA = document.createElement('span');
                    nameA.className = 'privacy-modal-list-name';
                    nameA.textContent = _esc((a && a.action) || '—');
                    liA.appendChild(nameA);

                    var metaA = document.createElement('span');
                    metaA.className = 'privacy-modal-list-meta';
                    if (a && a.created_at) {
                        var t = document.createElement('time');
                        t.setAttribute('data-fmt-local', '');
                        t.setAttribute('datetime', String(a.created_at));
                        t.textContent = String(a.created_at);
                        metaA.appendChild(t);
                        metaA.appendChild(document.createTextNode(' · '));
                    }
                    metaA.appendChild(document.createTextNode(_esc((a && a.triggered_by) || '—')));
                    liA.appendChild(metaA);
                    ulA.appendChild(liA);
                }
                body.appendChild(ulA);
            }

            if (window.LocalDatetime && typeof window.LocalDatetime.applyAll === 'function') {
                window.LocalDatetime.applyAll(body);
            }
        }

        window.PrivacyDetailPanel = {
            openModal: openModal,
            closeModal: closeModal,
            loadCoverage: loadCoverage,
            formatPreview: formatPreview,
        };
    }

    _attachBrowser();

    if (typeof module !== 'undefined' && module.exports) {
        module.exports = {
            formatPreview: formatPreview,
        };
    }
})();
