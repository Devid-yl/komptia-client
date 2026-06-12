/**
 * Privacy — privacy-page.js
 *
 * Orchestrateur de la page ``/data/privacy``. Coordonne les sous-modules
 * (TermVirtualList, PrivacyDetailPanel, PrivacyScanProgress) et gère :
 *
 *   - chargement initial de stats / termes / audit
 *   - filtres + recherche fuzzy (debounce)
 *   - virtual list (10k+ termes sans freeze)
 *   - sticky bottom-bar bulk (sélection multiple → PUT replace-state)
 *   - bulk actions (enable/disable/confirm/delete)
 *   - filtres + recherche + virtual list
 *   - actions auto-classify / scan (déléguées au module dédié)
 *   - onboarding tour 1ère visite (KomptiaOnboarding)
 *
 * Doctrine
 * --------
 * 1. **CSP-safe** — aucun ``onclick`` inline, ``addEventListener``
 *    partout. Le ``nonce`` est sur le ``<script src=>`` parent.
 * 2. **Taxonomie 4-cas erreurs** — ``fetchJson`` produit des erreurs
 *    typées (``kind``: ``network|client|server|auth``). Les callers
 *    décident entre toast et panel d'erreur.
 * 3. **Anti-XSS** — toute interpolation user-controlled passe par
 *    ``textContent``. ``innerHTML`` réservé aux templates statiques
 *    (vidage + reconstruction par appendChild).
 * 4. **Single source of truth** — la phrase de wipe est lue depuis le
 *    DOM (``#wipe-phrase-target``), pas dupliquée en const JS.
 * 5. **Multi-onglets** — les actions critiques (wipe) refetchent les
 *    stats avant ouverture pour garantir un ``expected_count`` frais.
 * 6. **Vocabulaire user-facing strict** — "Termes confidentiels",
 *    "Activé/Désactivé", "En attente de revue", "Anonymisation".
 */
(function() {
    'use strict';

    // ── Constantes ────────────────────────────────────────────────────
    var DEBOUNCE_MS = 300;
    var ROW_HEIGHT = 36;
    var BUFFER_ROWS = 10;
    var ONBOARDING_KEY = 'privacy_v2';

    // ── État ──────────────────────────────────────────────────────────
    // Nombre de groupes de provenance affichés par page (pagination client).
    var GROUPS_PER_PAGE = 12;

    var state = {
        terms: [],            // Liste complète (référence)
        filteredTerms: [],    // Liste après filtre + recherche
        termsFilter: 'all',
        termsCategoryFilter: 'all',
        // Filtre type de valeur : 'all' | 'numeric' | 'non-numeric'.
        // Miroir du filtre présent dans le modal "Confidentialité" iris-grid
        // pour avoir la même expérience entre vue globale (cross-classeur)
        // et vue classeur courant. Décision binaire pilotée par
        // ``AnonTokenizer.isPureNumeric`` (single source of truth Py↔JS).
        termsTypeFilter: 'all',
        termsSearch: '',
        // Pagination CLIENT par GROUPE de provenance (pas par terme) : la liste
        // est un accordéon groupé/collapsable, paginer les groupes garde chaque
        // groupe intact (compteurs + select-all corrects) et borne le DOM.
        // Reset à 1 quand un filtre/recherche change (applyFilters).
        termsPage: 1,
        statsLoaded: false,
        loadStatsReqId: 0,
        loadTermsReqId: 0,
        selection: new Set(),
        // Modifications locales non encore sauvegardées : Map<id, {enabled?, confirmed?, pseudo_middle?}>.
        // Une entrée existe ssi le terme a été modifié vs sa version BDD.
        // Footer Annuler/Enregistrer s'active dès qu'il y a au moins 1 dirty.
        dirtyTerms: new Map(),
        // Flag d'idempotence du save : ``true`` pendant le PUT (+ loadStats
        // + loadTerms qui suivent). Évite un double-PUT si l'user clique
        // rapide ou spamme Espace (le bouton ``disabled=true`` est posé
        // dans la même synchrone-tick mais un click programmatique pourrait
        // contourner). Adversarial review HIGH 2026-05-20. Remplace aussi
        // le guard fragile ``btnSave.textContent === 'Enregistrement…'``.
        saveInFlight: false,
        // Catégories collapsées (UI seulement, non persisté). État par défaut
        // appliqué par ``_applyDefaultCollapse`` au 1er render de chaque
        // catégorie : tout plié à l'arrivée pour éviter une page submergeante
        // de termes (un user lambda a 100-2000 termes répartis sur 4-10 cat.).
        collapsedCategories: new Set(),
        // Set des catégories déjà rencontrées dans le rendu — sert à
        // distinguer "1ère apparition" (collapse par défaut) vs
        // "re-render après toggle user" (respecter le choix user).
        // Reset uniquement au refresh complet de la page (F5).
        seenCategories: new Set(),
    };

    // ── Helpers DOM ────────────────────────────────────────────────────
    function $(id) { return document.getElementById(id); }
    function show(el) { if (el) el.hidden = false; }
    function hide(el) { if (el) el.hidden = true; }

    function getXsrf() {
        var m = document.cookie.match(/(^|; )_xsrf=([^;]+)/);
        return m ? decodeURIComponent(m[2]) : '';
    }

    function toast(msg, type) {
        if (typeof window.showToast === 'function') {
            window.showToast(msg, type || 'info');
        } else {
            // eslint-disable-next-line no-console
            console.log('[toast]', msg);
        }
    }

    // ── Scan trigger (scope module, pas closure) ──────────────────────
    //
    // Centralise la garde de dispo + try/catch + toast user. Défini au
    // scope module (pas dans ``_attachListeners``) parce que (1) c'est
    // aussi utilisé par la délégation globale ``_delegateScanClicks`` qui
    // doit survivre à un crash de ``_attachListeners``, et (2) la
    // closure locale fragilisait inutilement la séparation des
    // responsabilités.
    // ``deps`` pour ``openAndStartScan`` — factorisés ici pour ne pas
    // dupliquer entre les call-sites (#action-scan et #terms-empty-scan-btn
    // déclenchent le même flow d'auto-lancement).
    function _scanDeps() {
        return {
            getXsrf: getXsrf,
            onComplete: function() {
                Promise.all([loadStats(), loadTerms()]).catch(function() {
                    /* géré au call-site */
                });
            },
        };
    }

    function _triggerScanModal() {
        if (!window.PrivacyScanProgress
            || typeof window.PrivacyScanProgress.openAndStartScan !== 'function') {
            // eslint-disable-next-line no-console
            console.error(
                '[privacy] PrivacyScanProgress.openAndStartScan indisponible. '
                + 'scan-progress.js a-t-il bien été chargé ?'
            );
            toast(
                "Module de scan indisponible. Rechargez la page (Ctrl+F5) ; "
                + 'si le problème persiste, signalez le bug.',
                'error'
            );
            return;
        }
        // Garde anti-double-déclenchement : un user qui clique rapidement
        // 2-3x sur "Scanner mes données" ne doit pas lancer plusieurs scans
        // (consomme le rate-limit 3/5min) ni réinitialiser l'UI d'un scan
        // déjà en cours. Le bouton externe passe en ``disabled`` dans
        // ``setScanButtonLoading(true)`` synchroniquement, mais le browser
        // peut mettre 1-2 frames à propager l'état désactivé — pendant ce
        // temps, un click rapide arrive ici. ``isScanning()`` vérifie le
        // flag d'état du module qui est mis à jour sync dès le 1er click.
        if (typeof window.PrivacyScanProgress.isScanning === 'function'
            && window.PrivacyScanProgress.isScanning()) {
            return;
        }
        try {
            // Auto-lancement : ouvre la modal ET démarre le scan immédiatement.
            // L'étape intermédiaire "Prêt à lancer le scan" + bouton "Lancer"
            // était de la friction (2 clics pour 1 action). Pour relancer un
            // scan après succès ou échec, l'user ferme la modal et re-clique
            // "Scanner mes données" depuis le header (cohérent avec
            // l'auto-lancement, pas de chemin d'accès intra-modal).
            window.PrivacyScanProgress.openAndStartScan(_scanDeps());
        } catch (err) {
            // eslint-disable-next-line no-console
            console.error('[privacy] openAndStartScan a levé une exception', err);
            toast(
                "Erreur à l'ouverture du scan : "
                + ((err && err.message) || 'inconnue'),
                'error'
            );
        }
    }

    // Délégation globale "ceinture et bretelles" : un seul listener sur
    // ``document`` (capture phase) intercepte les clics sur les boutons
    // critiques de la page. Survit à un crash de ``_attachListeners``
    // (qui appelle getElementById puis addEventListener sans null-check
    // sur plusieurs IDs — un seul élément manquant suffit à interrompre
    // toute l'init et laisser l'utilisateur face à un bouton mort sans
    // feedback).
    function _delegateScanClicks() {
        if (typeof document === 'undefined' || !document) return;
        document.addEventListener('click', function(e) {
            if (!e || !e.target || typeof e.target.closest !== 'function') return;
            var btn = e.target.closest('#action-scan, #terms-empty-scan-btn');
            if (!btn) return;
            _triggerScanModal();
        });
    }

    // ── fetchJson — taxonomie 4-cas (axe 5 standards Komptia) ─────────
    async function fetchJson(url, options) {
        options = options || {};
        var headers = options.headers || {};
        headers['X-Requested-With'] = 'XMLHttpRequest';
        if (options.method && options.method !== 'GET' && options.method !== 'HEAD') {
            headers['X-Xsrftoken'] = getXsrf();
            if (!headers['Content-Type']) headers['Content-Type'] = 'application/json';
        }
        options.headers = headers;
        options.credentials = 'same-origin';

        var resp;
        try {
            resp = await fetch(url, options);
        } catch (_netErr) {
            var ne = new Error('Erreur réseau. Vérifiez votre connexion.');
            ne.kind = 'network';
            throw ne;
        }

        var data = null;
        try {
            data = await resp.json();
        } catch (_pe) {
            data = null;
        }
        if (!resp.ok) {
            var msg = (data && data.error) ? data.error
                : (resp.status === 401 ? 'Session expirée. Reconnectez-vous.'
                    : (resp.status === 429 ? 'Trop de requêtes. Patientez.'
                        : (resp.status >= 500 ? 'Erreur serveur (' + resp.status + ').'
                            : 'Erreur (' + resp.status + ').')));
            var err = new Error(msg);
            err.status = resp.status;
            err.data = data;
            err.kind = resp.status >= 500 ? 'server'
                : (resp.status === 401 ? 'auth' : 'client');
            throw err;
        }
        return data || {};
    }

    // ── Search/filter — testable purement (exporté) ───────────────────
    function normalizeForSearch(value) {
        if (value == null) return '';
        var s = String(value).toLowerCase();
        // Strip diacritics (FR : é→e, è→e, à→a, ç→c, etc.) sans dépendance
        // externe. Les chars composés sont décomposés via NFD puis on
        // retire les marks combinantes (U+0300..U+036F). Échappements hex
        // explicites (review F02) — un range littéral ``[̀-ͯ]`` peut être
        // silencieusement corrompu par un éditeur/minifier qui re-sauve
        // en NFC ou en CP-1252.
        if (typeof s.normalize === 'function') {
            s = s.normalize('NFD').replace(/[\u0300-\u036f]/g, '');
        }
        return s;
    }

    // Helper local : pure fonction de détection numérique. Utilise
    // ``AnonTokenizer.isPureNumeric`` côté navigateur (single source of
    // truth, partagé avec iris-grid). En tests Node sans ``AnonTokenizer``,
    // fallback sur la même logique inline pour rester testable hors browser.
    var _NUMERIC_FALLBACK_CHARS = ' \t 0123456789+-_.,/:';
    function _isPureNumericTerm(term) {
        if (typeof window !== 'undefined'
            && window.AnonTokenizer
            && typeof window.AnonTokenizer.isPureNumeric === 'function') {
            return window.AnonTokenizer.isPureNumeric(term);
        }
        if (term == null) return false;
        var s = String(term).trim();
        if (!s) return false;
        var hasDigit = false;
        for (var i = 0; i < s.length; i++) {
            var ch = s.charAt(i);
            if (ch >= '0' && ch <= '9') { hasDigit = true; continue; }
            if (_NUMERIC_FALLBACK_CHARS.indexOf(ch) === -1) return false;
        }
        return hasDigit;
    }

    function termMatchesFilter(term, filterStatus, searchNeedle, sourceFilter, typeFilter) {
        if (!term) return false;
        if (filterStatus === 'enabled' && !term.enabled) return false;
        if (filterStatus === 'disabled' && term.enabled) return false;
        if (filterStatus === 'pending' && term.confirmed) return false;
        if (sourceFilter && sourceFilter !== 'all') {
            // Le filtre stocke une clé "source|ref" (cf. _groupKeyAndLabel).
            if (_groupKeyAndLabel(term).key !== sourceFilter) {
                return false;
            }
        }
        if (typeFilter === 'numeric' && !_isPureNumericTerm(term.term)) return false;
        if (typeFilter === 'non-numeric' && _isPureNumericTerm(term.term)) return false;
        if (searchNeedle) {
            var needle = normalizeForSearch(searchNeedle);
            if (!needle) return true;
            var hayTerm = normalizeForSearch(term.term);
            var hayPseudo = normalizeForSearch(term.pseudo_middle);
            var hayCat = normalizeForSearch(term.category);
            if (hayTerm.indexOf(needle) === -1
                && hayPseudo.indexOf(needle) === -1
                && hayCat.indexOf(needle) === -1) {
                return false;
            }
        }
        return true;
    }

    function applyFilters(keepPage) {
        var arr = [];
        for (var i = 0; i < state.terms.length; i++) {
            if (termMatchesFilter(
                state.terms[i],
                state.termsFilter,
                state.termsSearch,
                state.termsCategoryFilter,
                state.termsTypeFilter
            )) {
                arr.push(state.terms[i]);
            }
        }
        state.filteredTerms = arr;
        // Nouveau filtre/recherche → page 1. Sur une simple MUTATION de la
        // liste (ex: suppression d'un terme), keepPage=true conserve la page
        // courante — le clamp de renderGroupedTerms corrige si elle déborde
        // (évite de ré-éjecter l'admin en page 1 au milieu de son tri).
        if (!keepPage) {
            state.termsPage = 1;
        }
        if (typeof renderGroupedTerms === 'function') {
            renderGroupedTerms();
        }
        // Met à jour le compteur visible.
        var counter = $('terms-count-visible');
        if (counter) {
            counter.textContent = String(arr.length);
        }
    }

    // ── Stats ─────────────────────────────────────────────────────────
    async function loadStats() {
        // ReqId comme loadTerms / loadAudit : sans ce garde, deux PUT bulk
        // rapides peuvent voir l'ancien loadStats() arriver APRÈS le
        // nouveau (race) et écraser le panneau avec un total stale
        // (review F05).
        var reqId = ++state.loadStatsReqId;
        try {
            var data = await fetchJson('/api/anonymization/stats');
            if (reqId !== state.loadStatsReqId) return;
            var s = data.stats || {};
            $('stat-total').textContent = s.total || 0;
            $('stat-enabled').textContent = s.enabled || 0;
            $('stat-pending').textContent = s.pending_review || 0;
            // Le template a remplacé la carte ``#critical-visible-card``
            // (commit redesign Tailwind) par un span inline ``#stat-critical-wrap``
            // — null-check défensif sur les 2 IDs pour ne plus crash si l'un
            // ou l'autre disparaît à nouveau lors d'un redesign futur.
            var critEl = $('stat-critical');
            var critWrap = $('stat-critical-wrap') || $('critical-visible-card');
            if (s.critical_visible && s.critical_visible > 0) {
                if (critEl) critEl.textContent = s.critical_visible;
                if (critWrap) critWrap.hidden = false;
            } else if (critWrap) {
                critWrap.hidden = true;
            }
            state.statsLoaded = true;
        } catch (err) {
            // eslint-disable-next-line no-console
            console.warn('stats load failed', err);
        }
    }

    // ── Termes (rendering groupé par catégorie) ───────────────────────
    function _renderEmptyOrError(state2) {
        // Helper pour basculer entre les divers panneaux.
        hide($('terms-loading'));
        hide($('terms-empty'));
        hide($('terms-error'));
        hide($('terms-groups'));
        if (state2 === 'loading') show($('terms-loading'));
        if (state2 === 'empty') show($('terms-empty'));
        if (state2 === 'error') show($('terms-error'));
        if (state2 === 'groups') show($('terms-groups'));
    }

    function _escapeHTML(s) {
        // #101 (XSS, CWE-79) — échappe AUSSI les guillemets `"` / `'` : ce helper
        // est utilisé DANS des attributs HTML (`value=`, `aria-label=`,
        // `data-group-key=`…) avec des valeurs contrôlées (termes /data-privacy,
        // tapés OU issus d'un scan de classeur / noms de colonnes de la source).
        // Le motif `textContent → innerHTML` n'échappait que `& < >` → un terme
        // contenant `"` cassait l'attribut (breakout → injection d'event handler).
        // Échapper les guillemets rend la sortie sûre en contexte texte ET attribut.
        if (s == null) return '';
        return String(s)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#x27;');
    }

    //: Récupère la valeur "courante" d'un terme : si l'utilisateur a fait des
    //: modifs locales non encore sauvegardées (state.dirtyTerms), elles
    //: surchargent l'état BDD.
    function _termCurrent(t) {
        var d = state.dirtyTerms.get(t.id);
        if (!d) return t;
        return Object.assign({}, t, d);
    }

    function _markDirty(termId, patch) {
        var existing = state.dirtyTerms.get(termId) || {};
        var merged = Object.assign({}, existing, patch);
        // Si toutes les valeurs égalent l'original → retirer du dirty.
        var orig = null;
        for (var i = 0; i < state.terms.length; i++) {
            if (state.terms[i].id === termId) { orig = state.terms[i]; break; }
        }
        if (orig) {
            var isClean = (
                (merged.enabled == null || merged.enabled === !!orig.enabled)
                && (merged.confirmed == null || merged.confirmed === !!orig.confirmed)
                && (merged.pseudo_middle == null || merged.pseudo_middle === (orig.pseudo_middle || ''))
            );
            if (isClean) {
                state.dirtyTerms.delete(termId);
            } else {
                state.dirtyTerms.set(termId, merged);
            }
        } else {
            state.dirtyTerms.set(termId, merged);
        }
        _updateFooter();
    }

    function _updateFooter() {
        var n = state.dirtyTerms.size;
        var btnSave = $('btn-save');
        var btnDiscard = $('btn-discard');
        if (btnSave) btnSave.disabled = n === 0;
        if (btnDiscard) btnDiscard.disabled = n === 0;
    }

    //: Construit une clé de groupe stable + un label lisible à partir
    //: de (source, source_ref). Permet de grouper par provenance dans
    //: l'UI ("Classeur : Bilan2024.afz.json", "Origine inconnue", etc.).
    //: Si source_ref est NULL/vide, on retombe sur le source seul.
    //:
    //: **Distinction ``manual`` vs ``user_added``** (2026-05-19) :
    //: - ``manual`` est le placeholder par défaut posé par l'ORM quand
    //:   un chemin de code n'a pas propagé ``source`` à l'INSERT
    //:   (migration historique, PUT panneau pré-fix). Label
    //:   ``"Origine inconnue"`` — on ne sait pas d'où ça vient.
    //: - ``user_added`` est réservé aux saisies VOLONTAIRES via
    //:   l'endpoint ``POST /api/anonymization/terms/manual`` (modal
    //:   ``Ajouter un terme`` ouverte depuis le bouton du header).
    //:   Label ``"Ajouts manuels"`` — vrai ajout assumé par l'user.
    //: Les deux ne se mélangent jamais : le cleanup nightly purge
    //: ``manual`` orphelin mais préserve ``user_added`` à perpétuité.
    function _groupKeyAndLabel(t) {
        var src = (t && t.source) || 'manual';
        var ref = (t && t.source_ref) || '';
        var key = ref ? (src + '|' + ref) : src;
        var label;
        if (src === 'workbook') {
            label = ref ? ('Classeur : ' + ref) : 'Classeurs';
        } else if (src === 'iris_message') {
            label = ref ? ('Conversation Iris #' + ref) : 'Conversations Iris';
        } else if (src === 'sql_result') {
            // Convention 2026-05-19 : ``source_ref`` peut être préfixé
            // ``iris:<conv_id>`` ou ``automation:<id>`` pour distinguer
            // les origines au sein de ``sql_result``. Cf.
            // ``AnonymizationScanWorkbookAPIHandler`` qui pose ce préfixe
            // selon ``scan_context``. Si pas de préfixe connu, fallback
            // au label brut "Résultat SQL : <ref>".
            if (ref.indexOf('iris:') === 0) {
                var convId = ref.slice('iris:'.length);
                label = convId
                    ? ('Iris — conversation #' + convId)
                    : 'Iris';
            } else if (ref.indexOf('automation:') === 0) {
                var autoId = ref.slice('automation:'.length);
                label = autoId
                    ? ('Automation #' + autoId + ' (preview)')
                    : 'Automation (preview)';
            } else if (ref === 'iris') {
                label = 'Iris';
            } else if (ref === 'automation') {
                label = 'Automation (preview)';
            } else {
                label = ref ? ('Résultat SQL : ' + ref) : 'Résultats SQL';
            }
        } else if (src === 'contact') {
            label = ref ? ('Contact : ' + ref) : 'Contacts';
        } else if (src === 'dashboard') {
            // Champs textuels admin-éditables d'un dashboard (nom,
            // description, titres widgets, labels filtres, sujets/messages
            // envois email). source_ref = nom du dashboard cap 200 chars,
            // fallback "#<id>" si renommé vide. Cf. extract.py
            // ``extract_dashboard_terms_with_origin``.
            label = ref ? ('Tableau de bord : ' + ref) : 'Tableaux de bord';
        } else if (src === 'user_added') {
            label = 'Ajouts manuels';
        } else if (src === 'manual') {
            label = 'Origine inconnue';
        } else {
            label = ref ? (src + ' : ' + ref) : src;
        }
        return { key: key, label: label };
    }

    function _groupTermsBySource(terms) {
        // Conserve l'ordre d'apparition des sources pour stabilité visuelle.
        var groups = {};
        var labels = {};
        var orderedKeys = [];
        for (var i = 0; i < terms.length; i++) {
            var info = _groupKeyAndLabel(terms[i]);
            if (!(info.key in groups)) {
                groups[info.key] = [];
                labels[info.key] = info.label;
                orderedKeys.push(info.key);
            }
            groups[info.key].push(terms[i]);
        }
        // Tri alphabétique sur le label pour stabilité.
        orderedKeys.sort(function(a, b) {
            return labels[a].localeCompare(labels[b]);
        });
        return { groups: groups, labels: labels, orderedKeys: orderedKeys };
    }

    //: task #20 — Pour un classeur donné, sous-groupe les termes par
    //: colonne d'origine. ``t.origins`` est une List[{classeur, col}]
    //: (cf. AnonymizationTerm.to_dict).
    //:
    //: - Un term avec origines dans 2 cols d'un même classeur ⇒ apparaît
    //:   dans 2 sous-groupes (sous "Nom" ET sous "Conjoint"). L'état des
    //:   checkboxes reste synchronisé via le re-render au toggle.
    //: - Un term sans origines (rows historiques pré-task #20, ou ajout
    //:   manuel) ou avec origines orphelines (classeur ne match pas) ⇒
    //:   sous-groupe "Autres / sans colonne".
    //: - Dédoublement intra-col : un même term n'apparaît qu'UNE fois par
    //:   colonne (un origin malformé en doublon ne duplique pas le rendu).
    function _subGroupByColumn(rows, groupClasseur) {
        var byCol = Object.create(null);     // colName → List[term]
        var byColSeen = Object.create(null); // colName → Set(term.id)
        var noCol = [];
        var noColSeen = Object.create(null); // dédup pour noCol
        for (var i = 0; i < rows.length; i++) {
            var t = rows[i];
            var origins = Array.isArray(t.origins) ? t.origins : [];
            var matched = false;
            for (var j = 0; j < origins.length; j++) {
                var o = origins[j];
                if (!o || typeof o !== 'object') continue;
                var classeurMatches =
                    (groupClasseur == null && (o.classeur == null || o.classeur === '')) ||
                    (o.classeur === groupClasseur);
                if (!classeurMatches) continue;
                if (o.col != null && o.col !== '') {
                    if (!byCol[o.col]) {
                        byCol[o.col] = [];
                        byColSeen[o.col] = Object.create(null);
                    }
                    if (!byColSeen[o.col][t.id]) {
                        byColSeen[o.col][t.id] = true;
                        byCol[o.col].push(t);
                    }
                    matched = true;
                } else {
                    if (!noColSeen[t.id]) {
                        noColSeen[t.id] = true;
                        noCol.push(t);
                    }
                    matched = true;
                }
            }
            if (!matched) {
                // Pas d'origine match (origins=[] ou aucune origin pour ce
                // classeur) ⇒ on tombe dans "sans colonne" du classeur courant.
                if (!noColSeen[t.id]) {
                    noColSeen[t.id] = true;
                    noCol.push(t);
                }
            }
        }
        var orderedCols = Object.keys(byCol).sort(function(a, b) {
            return a.localeCompare(b);
        });
        return { byCol: byCol, noCol: noCol, orderedCols: orderedCols };
    }

    //: task #20 — Rend une ligne unique (checkbox + term + badge NOUVEAU
    //: + pseudo). Extrait du rendu inline précédent pour réutilisation
    //: entre rendu flat (groupes non-workbook) et rendu sous-groupé par
    //: colonne (groupes workbook).
    function _renderTermRow(t) {
        var cur = _termCurrent(t);
        var pseudo = (cur.pseudo_middle != null ? cur.pseudo_middle : (cur.auto_pseudo || ''));
        // Miroir du panneau "Confidentialité" iris-grid (renderRow ligne ~6452) :
        // les lignes pending (confirmed=false) sont teintées en rouge subtil
        // pour attirer l'œil — pas juste le badge. ``bg-red-50`` /
        // ``dark:bg-red-900/20`` sont déjà dans le bundle Tailwind built
        // (vérifié 2026-05-19), pas besoin de rebuild CSS.
        var rowBg = !cur.confirmed ? ' bg-red-50 dark:bg-red-900/20' : '';
        var html = '';
        // Wrapper ``privacy-term-row`` pour piloter le hover du bouton ×
        // via CSS dédié (cf. ``static/css/privacy.css`` §"Bouton × delete
        // individuel"). On utilise une classe CSS custom plutôt que la
        // variante ``group`` Tailwind parce que les sub-utilities
        // ``group-hover:opacity-100`` ne sont pas extraites du JS string
        // par le scanner Tailwind — règle dédiée 100% fiable, survit
        // au rebuild.
        html += '<div class="privacy-term-row flex items-center gap-3 px-3 py-2' + rowBg + '" data-term-id="' + t.id + '">';
        html += '<input type="checkbox" data-term-checkbox="' + t.id + '" aria-label="Anonymiser ' + _escapeHTML(t.term) + '" ' + (cur.enabled ? 'checked' : '') + '>';
        html += '<span class="flex-1 text-sm font-mono text-gray-900 dark:text-gray-100">' + _escapeHTML(t.term) + '</span>';
        // Badge "NOUVEAU" pour les termes pending (confirmed=false). Compressé
        // au maximum (``text-[10px]`` + ``px-1 py-0.5``) : la ligne déjà
        // teintée porte le sens visuel ; le badge n'est plus que l'étiquette
        // textuelle, pas le focus principal.
        if (!cur.confirmed) {
            html += '<span class="flex-shrink-0 inline-block text-[10px] font-semibold leading-none px-1 py-0.5 rounded-full bg-red-600 text-white" aria-label="Terme en attente de revue">NOUVEAU</span>';
        }
        html += '<input type="text" data-term-pseudo="' + t.id + '" value="' + _escapeHTML(pseudo) + '" placeholder="auto" maxlength="128" class="w-44 px-2 py-1 text-xs font-mono border border-gray-300 rounded bg-white text-gray-900 placeholder-gray-400 focus:outline-none focus:border-gray-900 dark:bg-gray-800 dark:border-gray-700 dark:text-gray-100 dark:placeholder-gray-500 dark:focus:border-gray-100" aria-label="Pseudonyme pour ' + _escapeHTML(t.term) + '">';
        // Bouton de suppression individuelle (discret) — invisible par
        // défaut, apparaît au hover de la ligne ``.privacy-term-row`` OU
        // au focus clavier (Tab). Styling 100% via la classe CSS dédiée
        // ``.privacy-row-delete-btn`` définie dans ``privacy.css``.
        // Confirmation modale gérée par ``_deleteIndividualTerm`` (cf.
        // backend DELETE /api/anonymization/terms/:id qui audite +
        // check ownership).
        html += '<button type="button" data-delete-term-id="' + t.id + '" '
            + 'aria-label="Supprimer le terme ' + _escapeHTML(t.term) + '" '
            + 'title="Supprimer ce terme" '
            + 'class="privacy-row-delete-btn">'
            + '<svg fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>'
            + '</button>';
        html += '</div>';
        return html;
    }

    //: Extrait la source + ref depuis une clé "source|ref" (cf.
    //: _groupKeyAndLabel — "workbook|Bilan.afz.json" ⇒ {src:"workbook",
    //: ref:"Bilan.afz.json"}, "manual" ⇒ {src:"manual", ref:null}).
    function _splitGroupKey(key) {
        var pipeIdx = key.indexOf('|');
        if (pipeIdx < 0) return { src: key, ref: null };
        return { src: key.substring(0, pipeIdx), ref: key.substring(pipeIdx + 1) };
    }

    function renderGroupedTerms() {
        var container = $('terms-groups');
        if (!container) return;
        var grouped = _groupTermsBySource(state.filteredTerms);
        // Collapse par défaut à la 1ère apparition de chaque catégorie.
        // Couvre 2 cas :
        //   1. Chargement initial de la page (toutes catégories = 1ère fois)
        //      → page concise à l'arrivée, l'user déplie ce qui l'intéresse.
        //   2. Une catégorie nouvelle apparaît après un scan (ex : ``workbook|
        //      foo.afz.json`` jamais vu avant) → également collapse, cohérent.
        // Le set ``seenCategories`` empêche d'écraser un choix user explicite
        // (toggle expand qui supprime la clé de ``collapsedCategories``).
        for (var s = 0; s < grouped.orderedKeys.length; s++) {
            var seenKey = grouped.orderedKeys[s];
            if (!state.seenCategories.has(seenKey)) {
                state.collapsedCategories.add(seenKey);
                state.seenCategories.add(seenKey);
            }
        }
        // ── Pagination par groupe : borne le DOM + nav Première/Dernière ──
        // (le DOM ne contient au plus que GROUPS_PER_PAGE groupes à la fois).
        var allKeys = grouped.orderedKeys;
        var totalGroups = allKeys.length;
        var totalPages = Math.max(1, Math.ceil(totalGroups / GROUPS_PER_PAGE));
        if (state.termsPage > totalPages) { state.termsPage = totalPages; }
        if (state.termsPage < 1) { state.termsPage = 1; }
        var startIdx = (state.termsPage - 1) * GROUPS_PER_PAGE;
        var pageKeys = allKeys.slice(startIdx, startIdx + GROUPS_PER_PAGE);

        var html = '';
        for (var i = 0; i < pageKeys.length; i++) {
            var key = pageKeys[i];
            var label = grouped.labels[key];
            var rows = grouped.groups[key];
            var keyParts = _splitGroupKey(key);
            var collapsed = state.collapsedCategories.has(key);
            var arrow = collapsed ? '▸' : '▾';
            var groupAllChecked = rows.every(function(t) {
                return _termCurrent(t).enabled;
            });
            html += '<div class="mb-2 border border-gray-200 rounded dark:border-gray-800" data-group-key="' + _escapeHTML(key) + '">';
            html += '<div class="flex items-center gap-2 px-3 py-2 bg-gray-50 dark:bg-gray-800 cursor-pointer select-none" data-toggle-group="' + _escapeHTML(key) + '">';
            html += '<span class="text-gray-500 dark:text-gray-400 w-4 text-center" aria-hidden="true">' + arrow + '</span>';
            // PAS de ``onclick="event.stopPropagation()"`` inline ici :
            // violation CSP ``script-src 'self' 'nonce-...'`` qui interdit
            // les event handlers HTML inline. La propagation vers
            // ``[data-toggle-group]`` parent est gérée par la délégation
            // click (~ligne 1306) qui ignore les clics dont la cible est
            // une checkbox (``!e.target.matches('input[type="checkbox"]')``)
            // — donc cocher la case NE toggle PAS le collapse du groupe.
            html += '<input type="checkbox" data-group-checkbox="' + _escapeHTML(key) + '" aria-label="S&eacute;lectionner tout le groupe ' + _escapeHTML(label) + '" ' + (groupAllChecked ? 'checked' : '') + '>';
            html += '<span class="font-medium text-sm text-gray-900 dark:text-gray-100">' + _escapeHTML(label) + '</span>';
            html += '<span class="ml-auto text-xs text-gray-500 dark:text-gray-400">' + rows.length + ' terme' + (rows.length > 1 ? 's' : '') + '</span>';
            html += '</div>';
            if (!collapsed) {
                // task #20 : sous-groupement par colonne pour les groupes
                // workbook (classeurs). Les autres sources (manual,
                // iris_message, sql_result, contact) gardent le rendu flat
                // — origines moins pertinentes côté UX.
                var enableColSubGroup = (keyParts.src === 'workbook');
                if (enableColSubGroup) {
                    var sub = _subGroupByColumn(rows, keyParts.ref);
                    html += '<div class="divide-y divide-gray-100 dark:divide-gray-800">';
                    for (var c = 0; c < sub.orderedCols.length; c++) {
                        var col = sub.orderedCols[c];
                        var colRows = sub.byCol[col];
                        html += '<div>';
                        html += '<div class="flex items-center gap-2 px-3 py-1 text-xs font-medium text-gray-700 dark:text-gray-300 uppercase tracking-wide">';
                        html += '<span aria-hidden="true">└</span>';
                        html += '<span>Colonne&nbsp;: ' + _escapeHTML(col) + '</span>';
                        html += '<span class="ml-auto text-[0.6875rem] font-normal text-gray-500 dark:text-gray-500">' + colRows.length + ' terme' + (colRows.length > 1 ? 's' : '') + '</span>';
                        html += '</div>';
                        for (var jc = 0; jc < colRows.length; jc++) {
                            html += _renderTermRow(colRows[jc]);
                        }
                        html += '</div>';
                    }
                    if (sub.noCol.length > 0) {
                        html += '<div>';
                        html += '<div class="flex items-center gap-2 px-3 py-1 text-xs font-medium text-gray-700 dark:text-gray-300 uppercase tracking-wide">';
                        html += '<span aria-hidden="true">└</span>';
                        html += '<span>Autres / sans colonne</span>';
                        html += '<span class="ml-auto text-[0.6875rem] font-normal text-gray-500 dark:text-gray-500">' + sub.noCol.length + ' terme' + (sub.noCol.length > 1 ? 's' : '') + '</span>';
                        html += '</div>';
                        for (var jn = 0; jn < sub.noCol.length; jn++) {
                            html += _renderTermRow(sub.noCol[jn]);
                        }
                        html += '</div>';
                    }
                    html += '</div>';
                } else {
                    html += '<div class="divide-y divide-gray-100 dark:divide-gray-800">';
                    for (var j = 0; j < rows.length; j++) {
                        html += _renderTermRow(rows[j]);
                    }
                    html += '</div>';
                }
            }
            html += '</div>';
        }
        container.innerHTML = html;
        // Compteur dans footer.
        var cnt = $('terms-count-visible');
        if (cnt) cnt.textContent = String(state.filteredTerms.length);
        // Pagination des groupes de provenance (Première ⏮ ‹ … › Dernière ⏭).
        _renderTermsPager(totalPages, totalGroups);
    }

    function _renderTermsPager(totalPages, totalGroups) {
        var el = $('terms-pagination');
        if (!el || !window.KomptiaPagination) { return; }
        window.KomptiaPagination.render(el, {
            page: state.termsPage,
            totalPages: totalPages,
            onNavigate: function (p) {
                state.termsPage = p;
                renderGroupedTerms();
                // Remonte en haut de la liste scrollable pour voir la page.
                var box = $('terms-groups');
                if (box && typeof box.scrollTo === 'function') {
                    box.scrollTo({ top: 0 });
                }
            },
            countText: totalGroups + ' groupe' + (totalGroups > 1 ? 's' : ''),
        });
    }

    function _populateCategoryFilter(termsArr) {
        // Désormais : peuple par PROVENANCE (source + ref), pas catégorie.
        // Le label du <option> matche le label affiché dans les groupes
        // (cohérence visuelle).
        var sel = $('terms-filter-category');
        if (!sel) return;
        var prev = sel.value;
        var seen = Object.create(null);
        var sources = [];
        for (var i = 0; i < termsArr.length; i++) {
            var info = _groupKeyAndLabel(termsArr[i]);
            if (!seen[info.key]) {
                seen[info.key] = info.label;
                sources.push({ key: info.key, label: info.label });
            }
        }
        sources.sort(function(a, b) { return a.label.localeCompare(b.label); });
        sel.innerHTML = '';
        var optAll = document.createElement('option');
        optAll.value = 'all';
        optAll.textContent = 'Toutes provenances';
        sel.appendChild(optAll);
        for (var j = 0; j < sources.length; j++) {
            var opt = document.createElement('option');
            opt.value = sources[j].key;
            opt.textContent = sources[j].label;
            sel.appendChild(opt);
        }
        if (prev && (prev === 'all' || seen[prev])) {
            sel.value = prev;
        } else {
            sel.value = 'all';
            state.termsCategoryFilter = 'all';
        }
    }

    async function loadTerms() {
        var reqId = ++state.loadTermsReqId;
        _renderEmptyOrError('loading');
        try {
            var data = await fetchJson('/api/anonymization/terms?detailed=1');
            if (reqId !== state.loadTermsReqId) return;
            // Jeton de révision pour le verrou optimiste du PUT (fix lost
            // update 2026-06-10) — renvoyé en expected_revision aux saves.
            state.revision = (data && typeof data.revision === 'string')
                ? data.revision : null;
            var st = (data && data.anonymization_state) || {};
            var termsArr = Array.isArray(st.terms) ? st.terms : [];
            state.terms = termsArr;
            // Reset des modifs locales (la BDD est la nouvelle référence).
            state.dirtyTerms.clear();
            state.selection = new Set();
            _updateFooter();

            if (termsArr.length === 0) {
                _renderEmptyOrError('empty');
                return;
            }
            _populateCategoryFilter(termsArr);
            _renderEmptyOrError('groups');
            applyFilters();
        } catch (err) {
            $('terms-error-msg').textContent = (err && err.message) || 'Erreur inconnue.';
            _renderEmptyOrError('error');
        }
    }

    // ── Bulk bar ──────────────────────────────────────────────────────
    function _renderBulkBar() {
        var bar = $('bulk-bar');
        if (!bar) return;
        var n = state.selection.size;
        var counter = $('bulk-count');
        if (counter) {
            counter.textContent = String(n);
        }
        if (n > 0) {
            bar.hidden = false;
            bar.setAttribute('aria-hidden', 'false');
        } else {
            bar.hidden = true;
            bar.setAttribute('aria-hidden', 'true');
        }
    }

    /** Modale custom de confirmation pour le bulk delete (review F03).
     *
     *  Retourne une Promise<boolean> — ``true`` si l'utilisateur confirme,
     *  ``false`` s'il annule (X / Cancel / Escape via OverlayManager).
     *
     *  Pas de ``window.confirm`` natif (non-stylable dark mode, focus pas
     *  piégé, supprimable par pop-up blockers Safari iOS). Réutilise les
     *  classes ``.privacy-modal`` existantes pour cohérence visuelle avec
     *  les autres modaux de la page.
     */
    function _confirmBulkDelete(count) {
        return new Promise(function(resolve) {
            var modal = $('modal-bulk-delete');
            if (!modal) {
                // Fallback si le DOM est incomplet (template ancien) — on
                // évite l'absence de confirmation en abortant.
                resolve(false);
                return;
            }
            var countEl = $('bulk-delete-count');
            if (countEl) countEl.textContent = String(count);
            var prevFocus = document.activeElement;

            var btnConfirm = $('modal-bulk-delete-confirm');
            var btnCancel = $('modal-bulk-delete-cancel');
            var btnClose = $('modal-bulk-delete-close');

            // Idempotence : ESC via OverlayManager déclenche ``onClose`` qui
            // appelle ``_close(false)``. Sans le flag ``resolved``, l'user
            // qui clique ensuite Cancel/Confirm relance toute la séquence
            // (resolve déjà appelé = no-op, mais side-effects DOM re-tournent).
            // Cf. review adversariale 2026-05-19 finding #1+#2.
            var resolved = false;
            function _close(decision) {
                if (resolved) return;
                resolved = true;
                if (window.OverlayManager) window.OverlayManager.close(modal);
                // Toggle visibilité Tailwind. ``modal.hidden = true`` ne retire
                // que l'attribut HTML — la classe Tailwind ``.hidden`` (template
                // l.143 ``class="... hidden ..."``) applique ``display:none``
                // indépendamment et la modal reste invisible. Cf.
                // ``_setScanModalVisible`` dans scan-progress.js pour la doctrine.
                modal.classList.add('hidden');
                modal.classList.remove('flex');
                modal.setAttribute('aria-hidden', 'true');
                modal.removeEventListener('click', _onBackdrop);
                btnConfirm.removeEventListener('click', _onConfirm);
                btnCancel.removeEventListener('click', _onCancel);
                btnClose.removeEventListener('click', _onCancel);
                if (prevFocus && typeof prevFocus.focus === 'function') {
                    try { prevFocus.focus(); } catch (_e) { /* élément détaché */ }
                }
                resolve(decision);
            }
            function _onConfirm() { _close(true); }
            function _onCancel() { _close(false); }
            // Backdrop click → cancel (pattern Komptia ``feedback_onboarding_
            // overlay_non_bloquant.md``). Filtre ``ev.target === modal`` pour
            // ignorer les clicks sur la dialog interne centrée.
            function _onBackdrop(ev) { if (ev.target === modal) _close(false); }

            btnConfirm.addEventListener('click', _onConfirm);
            btnCancel.addEventListener('click', _onCancel);
            btnClose.addEventListener('click', _onCancel);
            modal.addEventListener('click', _onBackdrop);

            modal.classList.remove('hidden');
            modal.classList.add('flex'); // rétablit ``display:flex`` requis par ``items-center justify-center``
            modal.setAttribute('aria-hidden', 'false');
            if (window.OverlayManager) {
                // ESC → OverlayManager.close → ``onClose`` → ``_close(false)``
                // (équivalent au bouton Annuler). Sans ce callback, ESC dépile
                // mais laisse la modal visible. ``trapFocus`` + ``inertSiblings``
                // pour a11y axe 4 (Tab piégé dans la modal, fond inerte pour
                // les screen readers).
                window.OverlayManager.open(modal, {
                    layer: 'modal',
                    lockScroll: true,
                    trapFocus: true,
                    inertSiblings: true,
                    onClose: function() { _close(false); },
                });
            }
            // Focus sur Annuler (par sécurité — le bouton dangereux ne doit
            // pas être focused par défaut).
            btnCancel.focus();
        });
    }

    /** Modal d'ajout manuel d'un terme à anonymiser.
     *
     *  Pattern identique à ``_confirmBulkDelete`` :
     *  - OverlayManager pour z-index/focus-trap/ESC/inert siblings
     *  - Backdrop click → ferme
     *  - Toggle ``hidden`` ET ``flex`` (Tailwind doctrine doc inline)
     *  - Reset input + status à chaque ouverture pour ne pas afficher
     *    l'ancien message au prochain clic.
     *
     *  POST ``/api/anonymization/terms/manual`` puis recharge la liste.
     */
    function _openAddManualModal() {
        var modal = $('modal-add-manual');
        if (!modal) return;
        var input = $('modal-add-manual-input');
        var status = $('modal-add-manual-status');
        var btnConfirm = $('modal-add-manual-confirm');
        var btnCancel = $('modal-add-manual-cancel');
        var btnClose = $('modal-add-manual-close');
        var prevFocus = document.activeElement;

        // Reset à chaque ouverture (sinon l'ancien message reste affiché).
        if (input) input.value = '';
        if (status) {
            status.textContent = '';
            status.className = 'text-xs hidden';
        }
        if (btnConfirm) btnConfirm.disabled = false;

        var closed = false;
        function _close() {
            if (closed) return;
            closed = true;
            if (window.OverlayManager) window.OverlayManager.close(modal);
            modal.classList.add('hidden');
            modal.classList.remove('flex');
            modal.setAttribute('aria-hidden', 'true');
            modal.removeEventListener('click', _onBackdrop);
            if (btnConfirm) btnConfirm.removeEventListener('click', _onSubmit);
            if (btnCancel) btnCancel.removeEventListener('click', _close);
            if (btnClose) btnClose.removeEventListener('click', _close);
            if (input) input.removeEventListener('keydown', _onKey);
            if (prevFocus && typeof prevFocus.focus === 'function') {
                try { prevFocus.focus(); } catch (_e) { /* élément détaché */ }
            }
        }

        function _setStatus(msg, kind) {
            if (!status) return;
            status.textContent = msg;
            status.classList.remove('hidden', 'text-red-600', 'text-green-600', 'dark:text-red-400', 'dark:text-green-400');
            if (kind === 'error') {
                status.classList.add('text-red-600', 'dark:text-red-400');
            } else if (kind === 'success') {
                status.classList.add('text-green-600', 'dark:text-green-400');
            } else {
                status.classList.add('text-gray-600', 'dark:text-gray-300');
            }
        }

        async function _onSubmit() {
            if (!input) return;
            var raw = (input.value || '').trim();
            if (!raw) {
                _setStatus('Valeur vide — saisissez un terme à anonymiser.', 'error');
                input.focus();
                return;
            }
            if (raw.length > 500) {
                _setStatus('Valeur trop longue (max 500 caractères).', 'error');
                input.focus();
                return;
            }
            btnConfirm.disabled = true;
            _setStatus('Ajout en cours…', 'info');
            try {
                var data = await fetchJson('/api/anonymization/terms/manual', {
                    method: 'POST',
                    body: JSON.stringify({ value: raw }),
                });
                var added = (data && data.added) || 0;
                var msg;
                if (added === 0) {
                    msg = 'Aucun terme exploitable extrait.';
                } else if (added === 1) {
                    msg = '1 terme ajouté : ' + (data.terms && data.terms[0] ? data.terms[0] : raw);
                } else {
                    msg = added + ' termes ajoutés : ' + (data.terms || []).join(', ');
                }
                toast(msg, 'success');
                _close();
                // Reload : badge global + stats + liste.
                await Promise.all([loadStats(), loadTerms()]);
                if (window.KomptiaPrivacyBadge && typeof window.KomptiaPrivacyBadge.invalidate === 'function') {
                    window.KomptiaPrivacyBadge.invalidate();
                }
            } catch (err) {
                btnConfirm.disabled = false;
                var emsg = (err && err.message) || 'erreur inconnue';
                _setStatus('Échec : ' + emsg, 'error');
            }
        }

        function _onBackdrop(ev) { if (ev.target === modal) _close(); }
        function _onKey(ev) {
            if (ev.key === 'Enter' && !ev.shiftKey) {
                ev.preventDefault();
                _onSubmit();
            }
        }

        if (btnConfirm) btnConfirm.addEventListener('click', _onSubmit);
        if (btnCancel) btnCancel.addEventListener('click', _close);
        if (btnClose) btnClose.addEventListener('click', _close);
        modal.addEventListener('click', _onBackdrop);
        if (input) input.addEventListener('keydown', _onKey);

        modal.classList.remove('hidden');
        modal.classList.add('flex');
        modal.setAttribute('aria-hidden', 'false');
        if (window.OverlayManager) {
            window.OverlayManager.open(modal, {
                layer: 'modal',
                lockScroll: true,
                trapFocus: true,
                inertSiblings: true,
                onClose: _close,
            });
        }
        if (input) {
            // Focus input pour saisie immédiate.
            try { input.focus(); } catch (_e) { /* noop */ }
        }
    }

    /** Suppression individuelle d'un terme via DELETE /api/anonymization/
     *  terms/:id. Appelée depuis le bouton × discret de chaque ligne
     *  (cf. _renderTermRow).
     *
     *  **Confirmation obligatoire** (fix review adversariale 2026-05-19
     *  finding #9) — réutilise le modal ``modal-bulk-delete`` existant
     *  avec count=1. Sans ce gate :
     *  - sur touch device le ``opacity-0 group-hover`` se déclenche au
     *    1er tap (le hover s'active) → 2e tap au mauvais endroit =
     *    suppression accidentelle ;
     *  - re-saisie via "Ajouter un terme" ne préserve PAS le pseudo
     *    personnalisé (perte silencieuse pour les termes workbook avec
     *    pseudo édité). Mieux vaut friction modale que perte data.
     *
     *  Comportement post-confirm :
     *  - btnEl.disabled pendant la requête (anti double-clic).
     *  - Succès : mutation locale state.terms + dirtyTerms + selection,
     *    re-render via applyFilters (qui appelle renderGroupedTerms en
     *    interne — pas de double render). Restauration focus sur la
     *    ligne adjacente (fix finding #11, WCAG 2.4.3).
     *  - Erreur 4xx/5xx/réseau : si btnEl encore connecté, re-enable.
     *    Toast clair.
     */
    async function _deleteIndividualTerm(termId, btnEl) {
        if (!Number.isFinite(termId) || termId <= 0) return;
        if (btnEl && btnEl.disabled) return;
        // Récupérer le label avant suppression (pour le toast + le focus
        // restoration qui doit savoir où on était).
        var termLabel = '';
        var indexInTerms = -1;
        for (var i = 0; i < state.terms.length; i++) {
            if (state.terms[i] && state.terms[i].id === termId) {
                termLabel = state.terms[i].term;
                indexInTerms = i;
                break;
            }
        }
        if (indexInTerms < 0) return;  // déjà supprimé (race)

        // Gate de confirmation (fix #9). Pendant que le modal est ouvert,
        // on ré-active le bouton (l'user peut "Annuler" et revenir).
        var confirmed = await _confirmBulkDelete(1);
        if (!confirmed) return;

        if (btnEl) btnEl.disabled = true;
        try {
            await fetchJson('/api/anonymization/terms/' + termId, {
                method: 'DELETE',
            });
            // Mutation locale précise : retire de state.terms + dirtyTerms
            // + selection. Évite le full reload (coût réseau + reset
            // scroll position de la liste).
            state.terms = state.terms.filter(function(t) {
                return !(t && t.id === termId);
            });
            if (state.dirtyTerms && typeof state.dirtyTerms.delete === 'function') {
                state.dirtyTerms.delete(termId);
            }
            if (state.selection && typeof state.selection.delete === 'function') {
                state.selection.delete(termId);
            }
            // applyFilters() chaîne renderGroupedTerms en interne — un
            // seul appel suffit (fix #4 — supprime le double-render
            // qui éjectait le focus sur le body). keepPage=true : une
            // suppression ne doit pas renvoyer l'admin en page 1.
            applyFilters(true);
            // Restauration focus sur la ligne adjacente après re-render
            // (fix #11 — WCAG 2.4.3). On cherche un bouton delete
            // adjacent dans le DOM mis à jour. Préfère la ligne SUIVANTE
            // (= même index, vu qu'on a retiré la courante), fallback
            // précédente, fallback action-add-manual (header), fallback
            // body (jamais en pratique).
            var groupsEl = $('terms-groups');
            if (groupsEl) {
                var btns = groupsEl.querySelectorAll('[data-delete-term-id]');
                var targetBtn = null;
                if (btns.length > 0) {
                    // Index "naturel" = même position que le terme supprimé.
                    // Si la liste filtrée a moins d'éléments à cet index
                    // (parce qu'on était en fin), prendre le dernier.
                    var idx = Math.min(indexInTerms, btns.length - 1);
                    targetBtn = btns[idx >= 0 ? idx : 0];
                }
                if (!targetBtn) {
                    targetBtn = $('action-add-manual');
                }
                if (targetBtn && typeof targetBtn.focus === 'function') {
                    try { targetBtn.focus(); } catch (_e) { /* noop */ }
                }
            }
            // Le compteur en-tête (stat-total) provient de loadStats —
            // léger, on l'appelle. Le badge global aussi.
            loadStats().catch(function() { /* fail-soft */ });
            if (window.KomptiaPrivacyBadge && typeof window.KomptiaPrivacyBadge.invalidate === 'function') {
                window.KomptiaPrivacyBadge.invalidate();
            }
            toast(
                termLabel
                    ? 'Terme supprimé : ' + termLabel
                    : 'Terme supprimé.',
                'success'
            );
        } catch (err) {
            // btnEl peut être détaché du DOM si un re-render a eu lieu
            // entre temps (rare mais possible). Re-enable seulement
            // s'il est encore connecté pour éviter une mutation
            // silencieuse sur un noeud orphelin.
            if (btnEl && btnEl.isConnected) {
                btnEl.disabled = false;
            }
            var msg = (err && err.message) || 'erreur inconnue';
            toast('Échec de la suppression : ' + msg, 'error');
        }
    }

    /** Construit le body PUT à partir d'une projection (nouvelle liste,
     *  pas de mutation de state.terms). Retourne ``{state, collisions}`` —
     *  collisions est la liste des termes en collision (review F01
     *  defense-in-depth : la BDD a UNIQUE(user_id, term) donc impossible
     *  en théorie, mais on guard la sérialisation côté client pour ne
     *  jamais perdre silencieusement un terme).
     */
    function _buildPutPayload(termsList) {
        var out = { version: 1, terms: {} };
        var collisions = [];
        for (var i = 0; i < termsList.length; i++) {
            var t = termsList[i];
            if (!t || !t.term) continue;
            if (Object.prototype.hasOwnProperty.call(out.terms, t.term)) {
                collisions.push(t.term);
                continue;
            }
            var entry = {
                enabled: !!t.enabled,
                confirmed: !!t.confirmed,
            };
            if (t.pseudo_middle) entry.pseudo = t.pseudo_middle;
            out.terms[t.term] = entry;
        }
        return { state: out, collisions: collisions };
    }

    async function performBulkAction(action) {
        // action ∈ {'enable', 'disable', 'confirm', 'delete'}
        var ids = Array.from(state.selection);
        if (ids.length === 0) return;
        // Pour 'delete', confirmation via modale custom (review F03 — pas
        // de window.confirm natif, non-stylable et non-conforme axes 3/4).
        if (action === 'delete') {
            var confirmed = await _confirmBulkDelete(ids.length);
            if (!confirmed) return;
        }
        var idSet = new Set(ids);
        var didChange = false;
        // Construit la projection cible SANS muter state.terms (review
        // F06 — pas d'optimistic update : on attend le serveur, puis full
        // reload pour rester cohérent multi-onglets).
        var targetTerms = [];
        for (var i = 0; i < state.terms.length; i++) {
            var t = state.terms[i];
            if (!t) continue;
            if (idSet.has(t.id)) {
                if (action === 'delete') {
                    didChange = true;
                    continue;
                }
                if (action === 'enable' && !t.enabled) {
                    t = Object.assign({}, t, { enabled: true });
                    didChange = true;
                } else if (action === 'disable' && t.enabled) {
                    t = Object.assign({}, t, { enabled: false });
                    didChange = true;
                } else if (action === 'confirm' && !t.confirmed) {
                    t = Object.assign({}, t, { confirmed: true });
                    didChange = true;
                }
            }
            targetTerms.push(t);
        }
        if (!didChange) {
            toast('Aucun changement à enregistrer.', 'info');
            return;
        }
        var built = _buildPutPayload(targetTerms);
        if (built.collisions.length > 0) {
            // Defense-in-depth : si la BDD est cohérente (UNIQUE constraint),
            // ce path est mort. Mais on bloque la perte silencieuse plutôt
            // que d'envoyer un PUT qui écrase l'un par l'autre (review F01).
            toast(
                'Doublons détectés (' + built.collisions.length + '). '
                    + 'Rechargez la liste.',
                'error'
            );
            return;
        }
        try {
            await fetchJson('/api/anonymization/terms', {
                method: 'PUT',
                // state_scope "full" : /data-privacy charge l'état DÉTAILLÉ
                // complet (?detailed=1) — le replace backend peut donc
                // supprimer y compris les termes désactivés absents du body.
                // Sans cette déclaration, le backend est fail-closed
                // (scope actif) et préserverait les désactivés (fix 2026-06-10).
                // expected_revision : verrou optimiste (409 si un autre
                // onglet/scan a écrit depuis le chargement — rien d'écrasé).
                body: JSON.stringify({
                    anonymization_state: built.state,
                    state_scope: 'full',
                    expected_revision: state.revision || undefined,
                }),
            });
            toast(action === 'delete' ? 'Termes supprimés.'
                : action === 'enable' ? 'Termes activés.'
                    : action === 'disable' ? 'Termes désactivés.'
                        : 'Termes confirmés.', 'info');
            // Full reload (le serveur peut sanitiser silencieusement certains
            // termes, ou un autre onglet peut avoir muté). Pas de mutation
            // locale entre temps : ``state.terms`` est intact si l'erreur
            // se produit après le PUT mais avant le reload (cas réseau lent).
            await Promise.all([loadStats(), loadTerms()]);
            // Notifie le badge global "termes critiques" (anon-impl-loop #14) —
            // un toggle enabled/disable peut changer ``critical_visible``.
            // Le badge rafraichit son cache local + propage cross-tab via
            // ``storage`` event. Pas-op si le module n'est pas charge.
            if (window.KomptiaPrivacyBadge && typeof window.KomptiaPrivacyBadge.invalidate === 'function') {
                window.KomptiaPrivacyBadge.invalidate();
            }
        } catch (err) {
            toast('Échec : ' + ((err && err.message) || 'erreur inconnue'), 'error');
        }
    }

    var _modalLastFocus = {};

    // ── Onboarding ────────────────────────────────────────────────────
    function _maybeStartOnboarding() {
        if (!window.KomptiaOnboarding || typeof window.KomptiaOnboarding.start !== 'function') {
            return;
        }
        window.KomptiaOnboarding.start({
            key: ONBOARDING_KEY,
            title: 'Vos données restent confidentielles',
            steps: [
                {
                    icon: 'sparkle',
                    title: 'Les termes que vous protégez',
                    text: 'Vous décidez quels mots (noms de clients, références, montants sensibles...) doivent être masqués avant tout échange avec l\'intelligence artificielle. Vous gardez la main : « Ajouter un terme », activer/désactiver via la case, ou supprimer à tout moment.'
                },
                {
                    icon: 'chart',
                    title: 'Komptia repère pour vous',
                    text: 'Cliquez sur « Scanner mes données » pour que Komptia parcoure votre datastore et vous propose une liste de termes à protéger. Les nouveaux termes arrivent « en attente » : vous activez ceux qui vous conviennent, vous écartez le reste.'
                },
                {
                    icon: 'shield',
                    title: 'Une protection invisible pour vous',
                    text: 'Avant chaque envoi à l\'IA, vos termes sont remplacés par un pseudonyme neutre. À réception de la réponse, Komptia rétablit automatiquement les vraies valeurs : vous voyez vos données, l\'IA ne les voit jamais.'
                }
            ],
        });
    }

    // ── Listeners ─────────────────────────────────────────────────────
    function _attachListeners() {
        var termsSearchTimer = null;

        $('terms-filter-status').addEventListener('change', function(e) {
            state.termsFilter = e.target.value;
            applyFilters();
        });
        $('terms-search').addEventListener('input', function(e) {
            clearTimeout(termsSearchTimer);
            var v = (e.target.value || '').slice(0, 200);
            if (v !== e.target.value) e.target.value = v;
            termsSearchTimer = setTimeout(function() {
                state.termsSearch = v;
                applyFilters();
            }, DEBOUNCE_MS);
        });
        // Note : le déclencheur scan vit au scope module (``_triggerScanModal``)
        // et est aussi câblé en délégation globale par ``_delegateScanClicks``.
        // Le ``addEventListener`` direct ici reste utile pour la latence
        // perçue (pas de remontée DOM jusqu'au document avant le handler),
        // mais le bouton fonctionne MÊME si cette ligne n'est jamais
        // atteinte (crash en amont dans ``_attachListeners``).
        var btnRetry = $('terms-retry-btn');
        if (btnRetry) btnRetry.addEventListener('click', loadTerms);

        // Délégation sur le container des groupes : checkboxes individuelles,
        // checkbox de groupe, input pseudo, toggle collapse de groupe.
        var groupsEl = $('terms-groups');
        if (groupsEl) {
            groupsEl.addEventListener('click', function(e) {
                // Suppression individuelle d'un terme (bouton × discret
                // au hover de la ligne). Délégation : cherche un ancêtre
                // [data-delete-term-id] pour matcher même si l'event
                // provient du <svg> enfant. Court-circuite la délégation
                // toggle group avant pour ne pas confondre.
                var deleteBtn = e.target.closest('[data-delete-term-id]');
                if (deleteBtn) {
                    e.stopPropagation();
                    var delId = parseInt(deleteBtn.getAttribute('data-delete-term-id'), 10);
                    if (Number.isFinite(delId)) {
                        _deleteIndividualTerm(delId, deleteBtn);
                    }
                    return;
                }
                // Toggle collapse de groupe (clic header sauf sur la checkbox).
                var header = e.target.closest('[data-toggle-group]');
                if (header && !e.target.matches('input[type="checkbox"]')) {
                    var cat = header.getAttribute('data-toggle-group');
                    if (state.collapsedCategories.has(cat)) {
                        state.collapsedCategories.delete(cat);
                    } else {
                        state.collapsedCategories.add(cat);
                    }
                    renderGroupedTerms();
                }
            });
            groupsEl.addEventListener('change', function(e) {
                var tgt = e.target;
                if (!tgt) return;
                if (tgt.matches('input[data-term-checkbox]')) {
                    var tid = parseInt(tgt.getAttribute('data-term-checkbox'), 10);
                    if (Number.isFinite(tid)) {
                        _markDirty(tid, { enabled: !!tgt.checked });
                        // task #20 fix finding #5 : un term affiché dans 2
                        // sous-groupes col (ex: "Nom" et "Conjoint") génère 2
                        // checkboxes avec le même data-term-checkbox. Sync
                        // visuelle immédiate des doublons — l'état réel
                        // (state.dirtyTerms) est déjà mis à jour.
                        var dupes = groupsEl.querySelectorAll(
                            'input[data-term-checkbox="' + tid + '"]'
                        );
                        for (var d = 0; d < dupes.length; d++) {
                            if (dupes[d] !== tgt) dupes[d].checked = tgt.checked;
                        }
                    }
                } else if (tgt.matches('input[data-group-checkbox]')) {
                    var groupKey = tgt.getAttribute('data-group-checkbox');
                    var checked = !!tgt.checked;
                    for (var i = 0; i < state.filteredTerms.length; i++) {
                        var t = state.filteredTerms[i];
                        if (t && _groupKeyAndLabel(t).key === groupKey) {
                            _markDirty(t.id, { enabled: checked });
                        }
                    }
                    renderGroupedTerms();
                }
            });
            groupsEl.addEventListener('input', function(e) {
                var tgt = e.target;
                if (!tgt || !tgt.matches('input[data-term-pseudo]')) return;
                var tid = parseInt(tgt.getAttribute('data-term-pseudo'), 10);
                if (!Number.isFinite(tid)) return;
                _markDirty(tid, { pseudo_middle: tgt.value });
                // task #20 fix finding #5 (idem pour pseudo) : sync immédiate
                // des inputs pseudo dupliqués pour le même term affiché en 2
                // sous-groupes col.
                var dupesP = groupsEl.querySelectorAll(
                    'input[data-term-pseudo="' + tid + '"]'
                );
                for (var dp = 0; dp < dupesP.length; dp++) {
                    if (dupesP[dp] !== tgt) dupesP[dp].value = tgt.value;
                }
            });
        }

        // ``#action-scan`` : aussi câblé par la délégation globale (ceinture
        // et bretelles). Cette ligne donne la latence la plus basse en
        // cas de _attachListeners qui tourne jusqu'au bout.
        var actScan = $('action-scan');
        if (actScan) actScan.addEventListener('click', _triggerScanModal);

        // ``#action-add-manual`` : ouverture du modal d'ajout manuel d'un
        // terme. Distinct du scan datastore (qui détecte automatiquement) :
        // l'user tape une valeur en clair qu'il sait sensible, et elle est
        // enregistrée en BDD avec source="user_added". Cf. POST
        // /api/anonymization/terms/manual côté backend.
        var actAddManual = $('action-add-manual');
        if (actAddManual) actAddManual.addEventListener('click', _openAddManualModal);
        // ``#action-improve-pseudos`` (depuis 2026-05-19) — remplace
        // l'ancien ``#action-classify-llm``. Au lieu de détecter quels
        // termes sont des PII (détection), améliore le pseudo_middle de
        // chaque terme activé pour que le LLM cloud reçoive un pseudonyme
        // sémantique (``§NOM_4b3§`` au lieu de ``§TXT_4b3§``). Préserve
        // les pseudonymes user-customisés.
        var actImprove = $('action-improve-pseudos');
        if (actImprove) actImprove.addEventListener('click', async function() {
            if (!window.PrivacyImprovePseudos
                || typeof window.PrivacyImprovePseudos.openAndStartImprove !== 'function') {
                // eslint-disable-next-line no-console
                console.error(
                    '[privacy] PrivacyImprovePseudos.openAndStartImprove indisponible — '
                    + 'improve-pseudos.js a-t-il bien été chargé ?'
                );
                toast(
                    "Module d'amélioration indisponible. Recharge la page (Ctrl+F5).",
                    'error'
                );
                return;
            }
            // Auto-flush des modifs en attente AVANT amélioration (fix UX
            // 2026-05-20). Avant : on bloquait avec un message « Enregistre
            // d'abord ». Mais (a) ça viole la règle « pas de blocage
            // pédagogique » (cf. ``feedback_no_pedagogical_hard_blocks.md``),
            // (b) c'était une fausse alarme dans la fenêtre 3.5s entre PUT
            // OK et fin du reload (state.dirtyTerms encore plein).
            // Maintenant : on enregistre pour l'user avec feedback clair.
            // Si le PUT échoue, on bloque Améliorer (state incohérent =
            // risque de classifier des labels obsolètes).
            //
            // Note perf : ``_persistDirtyTerms`` envoie le state COMPLET
            // (replace-state) — coût ~3s pour 3K termes, ~30s pour 30K, etc.
            // Une refonte delta-state est tracée dans la dette technique.
            if (state.dirtyTerms && state.dirtyTerms.size > 0) {
                var n = state.dirtyTerms.size;
                toast(
                    "Enregistrement de " + n + " modification"
                    + (n > 1 ? 's' : '') + " avant amélioration…",
                    'info'
                );
                actImprove.disabled = true;
                var _persisted = false;
                try {
                    _persisted = await _persistDirtyTerms();
                } catch (err) {
                    toast(
                        "Échec enregistrement (" + ((err && err.message) || 'inconnue')
                            + "). Amélioration annulée pour éviter un state "
                            + "incohérent. Recharge la page si le problème persiste.",
                        'error'
                    );
                    return;
                } finally {
                    actImprove.disabled = false;
                }
                // Échec SOFT (fix 2026-06-11, finding review #13) :
                // _persistDirtyTerms ne throw pas sur validation KO / save
                // déjà en vol / 409 révision / PUT KO — elle retourne false
                // (et a déjà affiché son toast). Sans ce check, l'amélioration
                // démarrait sur des termes NON persistés — exactement le
                // « state incohérent » que ce flow doit empêcher.
                if (_persisted === false) {
                    return;
                }
            }
            window.PrivacyImprovePseudos.openAndStartImprove(_improveDeps());
        });

        var catFilter = $('terms-filter-category');
        if (catFilter) catFilter.addEventListener('change', function(e) {
            state.termsCategoryFilter = e.target.value;
            applyFilters();
        });

        // Filtre type de valeur (Tous types / Texte / Numériques). Miroir
        // du filtre du modal "Confidentialité" iris-grid : permet d'isoler
        // rapidement les codes/montants/téléphones (numérique) du reste
        // (noms, libellés, références alphanumériques) pour décider en
        // batch quoi anonymiser.
        var typeFilter = $('terms-filter-type');
        if (typeFilter) typeFilter.addEventListener('change', function(e) {
            state.termsTypeFilter = e.target.value;
            applyFilters();
        });

        // Actions visibles (esprit modal iris-grid) : modifient le state
        // local (dirtyTerms) sans appel API immédiat. Le user voit le
        // résultat dans la liste, puis clique "Enregistrer" pour persister.
        function _bulkVisible(action) {
            for (var i = 0; i < state.filteredTerms.length; i++) {
                var t = state.filteredTerms[i];
                if (!t) continue;
                if (action === 'enable') _markDirty(t.id, { enabled: true });
                else if (action === 'disable') _markDirty(t.id, { enabled: false });
                else if (action === 'confirm') _markDirty(t.id, { confirmed: true });
            }
            renderGroupedTerms();
        }
        var actEnableAll = $('action-enable-all');
        var actDisableAll = $('action-disable-all');
        var actConfirmVis = $('action-confirm-visible');
        var actAnonVis = $('action-anonymize-visible');
        if (actEnableAll) actEnableAll.addEventListener('click', function() {
            _bulkVisible('enable');
        });
        if (actDisableAll) actDisableAll.addEventListener('click', function() {
            _bulkVisible('disable');
        });
        if (actConfirmVis) actConfirmVis.addEventListener('click', function() {
            _bulkVisible('confirm');
        });
        if (actAnonVis) actAnonVis.addEventListener('click', function() {
            _bulkVisible('enable');
        });

        // Scan modal listeners — délégués au module. Pas de listener sur
        // ``#modal-scan-start`` : le bouton "Lancer/Relancer le scan" a été
        // retiré (auto-lancement à l'ouverture). Pour relancer, l'user
        // ferme et re-clique "Scanner mes données" depuis le header.
        var scanClose = $('modal-scan-close');
        var scanCancel = $('modal-scan-cancel');
        if (scanClose) scanClose.addEventListener('click', function() {
            if (window.PrivacyScanProgress) window.PrivacyScanProgress.closeScanModal();
        });
        if (scanCancel) scanCancel.addEventListener('click', function() {
            if (window.PrivacyScanProgress) window.PrivacyScanProgress.closeScanModal();
        });

        // Modal "Améliorer l'anonymisation" — close + cancel/arrêter
        // (sortie = arrête le LLM local, contrat V6).
        var improveClose = $('modal-improve-close');
        var improveCancel = $('modal-improve-cancel');
        if (improveClose) improveClose.addEventListener('click', function() {
            if (window.PrivacyImprovePseudos) window.PrivacyImprovePseudos.closeModal();
        });
        if (improveCancel) improveCancel.addEventListener('click', function() {
            if (window.PrivacyImprovePseudos) window.PrivacyImprovePseudos.closeModal();
        });

        // Detail panel close (peut ne pas exister si module non chargé)
        var termClose = $('modal-term-close');
        if (termClose) termClose.addEventListener('click', function() {
            if (window.PrivacyDetailPanel) window.PrivacyDetailPanel.closeModal();
        });

        // Footer : Annuler (drop dirty) / Enregistrer (PUT vers /terms).
        var btnSave = $('btn-save');
        var btnDiscard = $('btn-discard');
        if (btnDiscard) btnDiscard.addEventListener('click', function() {
            state.dirtyTerms.clear();
            _updateFooter();
            renderGroupedTerms();
            toast('Modifications annulées.', 'info');
        });
        if (btnSave) btnSave.addEventListener('click', _persistDirtyTerms);
    }

    /**
     * Highlight visuel des rows correspondant à des ``state_errors``.
     *
     * Adversarial MEDIUM #4 (2026-05-20) : le toast 'warning' est éphémère
     * (~5s) et n'identifie pas QUELLE row a foiré. iris-grid affiche
     * l'erreur sous le bouton + draft éditable inline → l'user voit
     * directement la row en cause. Sur /data/privacy, sans highlight, l'user
     * doit chercher manuellement parmi 3000+ termes après que le toast
     * a disparu.
     *
     * Stratégie :
     *  1. Mapper ``state_errors[].term`` → t.id via ``state.terms``.
     *  2. Ajouter un style inline rouge sur la row DOM matchante.
     *  3. ScrollIntoView sur la première row en erreur (`block: 'center'`).
     *  4. Auto-clear au prochain ``renderGroupedTerms`` (qui reconstruit
     *     le HTML — aucune cleanup explicite nécessaire).
     *
     * Pas d'effet sur ``state.dirtyTerms`` (le PUT a soit réussi avec
     * sanitization partielle, soit échoué — dans les 2 cas l'user décide
     * quoi faire). Fail-safe : si une row n'est pas trouvée (term inconnu
     * côté state.terms — improbable mais possible si race avec loadTerms),
     * on ignore silencieusement, le toast garde le détail textuel.
     *
     * @param {Array<{type: string, term?: string, pseudo?: string}>} stateErrors
     */
    function _highlightErrorRows(stateErrors) {
        if (!Array.isArray(stateErrors) || stateErrors.length === 0) return;
        // Index term → id (Map pour O(1) lookup vs scan O(N) sur state.terms).
        // Re-bâti à chaque appel car state.terms peut changer entre les
        // saves. Coût ~3K lookups = négligeable.
        var termToId = Object.create(null);
        for (var i = 0; i < state.terms.length; i++) {
            var t = state.terms[i];
            if (t && t.term) termToId[t.term] = t.id;
        }
        var firstRow = null;
        var matched = 0;
        for (var j = 0; j < stateErrors.length; j++) {
            var e = stateErrors[j];
            var termStr = e && e.term;
            if (typeof termStr !== 'string' || !termStr) continue;
            var tid = termToId[termStr];
            if (tid === undefined) continue;
            var row = document.querySelector(
                '.privacy-term-row[data-term-id="' + tid + '"]'
            );
            if (!row) continue;
            // Style inline pour éviter de devoir ajouter un bloc CSS. Le
            // ``box-shadow`` rouge + ``outline`` donnent une double emphase
            // visible — outline garantit le contraste WCAG AA même si un
            // thème custom override --status-error vers une couleur low-
            // contrast (R3 MED 2026-05-20). Auto-clean au prochain
            // renderGroupedTerms (qui réécrit innerHTML).
            row.style.boxShadow = '0 0 0 2px var(--status-error, #dc2626)';
            row.style.outline = '2px solid var(--status-error, #dc2626)';
            row.style.outlineOffset = '-2px';
            row.style.transition = 'box-shadow 0.2s ease-in';
            // Marque pour le test/debug — sans dépendre du style inline.
            row.setAttribute('data-term-row-error', '1');
            // A11y (R3 MED 2026-05-20) : signaler aux screen readers
            // que cette row est en état d'erreur. ``aria-invalid`` est
            // la convention ARIA pour les champs/zones qui contiennent
            // une valeur invalide. ``role="alert"`` annonce le changement
            // au screen reader sans qu'il ait à re-focuser.
            row.setAttribute('aria-invalid', 'true');
            // Note : on ne change PAS le role natif du div (qui n'en a pas),
            // un role=alert serait excessif (annonce 1 fois par row).
            // Au lieu de ça, on ajoute un texte sr-only inline (lu par les
            // screen readers, invisible visuellement).
            var srExisting = row.querySelector('[data-sr-error]');
            if (!srExisting) {
                var srNote = document.createElement('span');
                srNote.setAttribute('data-sr-error', '1');
                // sr-only utility Tailwind présente dans Komptia (cf.
                // privacy.html qui charge tailwind.css). Si absent du
                // build CSS, fallback inline avec les attributs équivalents.
                srNote.className = 'sr-only';
                srNote.style.cssText =
                    'position:absolute;width:1px;height:1px;padding:0;'
                    + 'margin:-1px;overflow:hidden;clip:rect(0,0,0,0);'
                    + 'white-space:nowrap;border:0;';
                srNote.textContent =
                    'Erreur de sauvegarde pour ce terme — voir le toast '
                    + 'pour le détail.';
                row.appendChild(srNote);
            }
            matched += 1;
            if (!firstRow) firstRow = row;
        }
        // Scroll vers la 1ère row en erreur pour que l'user voie
        // immédiatement où corriger. block:'center' évite que la row soit
        // collée en haut/bas du viewport. Pas de fallback si pas d'erreur
        // matchée (firstRow=null) — le toast a déjà donné le détail.
        if (firstRow && typeof firstRow.scrollIntoView === 'function') {
            try {
                firstRow.scrollIntoView({ behavior: 'smooth', block: 'center' });
            } catch (_e) {
                // Browsers anciens : fallback positions sans smooth.
                firstRow.scrollIntoView();
            }
        }
        // Log pour observabilité (combien matchés vs envoyés). Si matched
        // << stateErrors.length, c'est un signal qu'un sanitize backend
        // a strippé des termes inconnus côté frontend (race loadTerms).
        if (window.console && matched < stateErrors.length) {
            console.debug(
                '[privacy] highlightErrorRows: ' + matched + '/'
                + stateErrors.length + ' rows DOM trouvées pour les erreurs '
                + 'backend (les autres sont probablement strippées hors '
                + 'state.terms).'
            );
        }
    }

    // Contrat de retour (fix 2026-06-11, tâche #13) : ``true`` si l'état
    // local est COHÉRENT avec le serveur à la sortie (PUT confirmé, ou rien
    // à persister) ; ``false`` sur tout échec soft (validation, save déjà
    // en vol, 409 révision, PUT KO) — la fonction a alors déjà affiché son
    // toast. Elle ne THROW jamais pour ces échecs : les callers qui ont
    // besoin de l'invariant « ne pas continuer sur state incohérent »
    // (ex: flow Améliorer) doivent tester le retour, pas le catch.
    async function _persistDirtyTerms() {
        if (state.dirtyTerms.size === 0) return true;
        // Idempotence guard : si un save est déjà en vol (PUT + reload),
        // refuser un 2e appel. Sans ça, un clic rapide / spam keyboard
        // peut lancer 2 PUTs en parallèle et créer une race sur le clear
        // de ``state.dirtyTerms``. Adversarial HIGH 2026-05-20.
        if (state.saveInFlight) {
            // Feedback explicite au lieu d'un drop SILENCIEUX (fix
            // 2026-06-11, tâche #13) : sur 3000+ termes le PUT+reload dure
            // plusieurs secondes — l'user qui re-clique croyait le bouton
            // cassé (« ça chargeait trop longtemps », bug vécu).
            toast('Enregistrement déjà en cours — patiente quelques secondes…', 'info');
            return false;
        }
        // Construit le payload PUT : copy de l'état complet avec les patches
        // appliqués. Le backend remplace l'état via replace_state (upsert+
        // delete absents) — cohérent avec le contrat existant.
        var payloadTerms = {};
        for (var i = 0; i < state.terms.length; i++) {
            var t = state.terms[i];
            if (!t) continue;
            var cur = _termCurrent(t);
            payloadTerms[t.term] = {
                pseudo: cur.pseudo_middle || null,
                enabled: !!cur.enabled,
                confirmed: !!cur.confirmed || state.dirtyTerms.has(t.id),
            };
        }

        // Validation CLIENT avant envoi — délègue au helper partagé pour
        // parité exacte avec iris-grid.js btnSave. Source de vérité unique.
        // Si le helper manque (template oublié → régression load order),
        // fail-fast avec message actionnable plutôt que silent divergence
        // (adversarial CRITICAL #2 2026-05-20). Pas de fallback inline :
        // le test test_helper_loaded_before_privacy_page garantit le
        // chargement.
        if (!window.AnonymizationSaveHelpers
            || typeof window.AnonymizationSaveHelpers.validatePseudoMap !== 'function') {
            toast(
                'Erreur interne : module de validation indisponible. '
                + 'Rechargez la page (Ctrl+F5).',
                'error'
            );
            if (window.console && console.error) {
                console.error(
                    '[privacy-page] AnonymizationSaveHelpers manquant — '
                    + 'save-helpers.js chargé avant privacy-page.js ?'
                );
            }
            return false;
        }
        var validation = window.AnonymizationSaveHelpers.validatePseudoMap(payloadTerms);
        if (validation.errors.length) {
            var msg = validation.errors[0]
                + (validation.errors.length > 1
                    ? ' (+' + (validation.errors.length - 1) + ' autre(s))'
                    : '');
            toast(msg, 'error');
            return false;
        }

        var btnSave = $('btn-save');
        var btnDiscard = $('btn-discard');
        var _btnSaveOriginalText = btnSave ? btnSave.textContent : 'Enregistrer';
        // Marque le save en vol AVANT d'altérer le DOM. Le flag protège
        // contre les double-clics même si le bouton ``disabled=true`` n'a
        // pas encore pris effet (sync micro-task race).
        state.saveInFlight = true;
        if (btnSave) {
            btnSave.disabled = true;
            // Feedback texte pendant le PUT (parité iris-grid.js btnSave).
            // Sans ça, sur 3000+ termes, le bouton reste "Enregistrer" disabled
            // ~3.5s sans signal de progression.
            btnSave.textContent = 'Enregistrement…';
        }
        if (btnDiscard) btnDiscard.disabled = true;
        // Snapshot des dirty au moment du PUT — pour ne clearer QUE les
        // entries effectivement envoyées (un user peut modifier d'autres
        // termes pendant les 3+s de reload, on ne veut pas perdre ces
        // nouveaux dirty).
        //
        // **Stabilité des IDs garantie côté backend** (validation 2026-05-20) :
        // ``replace_state`` (app/services/anonymization/repository.py:742)
        // utilise UPSERT (UPDATE si terme existe canoniquement, INSERT si
        // nouveau, DELETE des absents). Les UPDATE préservent l'ID PRIMARY
        // KEY — l'utilisateur qui SAVE ses modifs voit ses IDs inchangés
        // au reload. Le snapshot par ID est donc correct sur le cas dominant.
        // Edge case INSERT (un nouveau terme côté payload pas dans la BDD) :
        // il n'aurait pas été dirty AVANT le save (puisqu'il n'existait pas
        // en BDD à snapshotter), donc absent du snapshot — comportement
        // cohérent : le clear ne touche que les modifs explicitement save.
        var _snapshotDirtyIds = Array.from(state.dirtyTerms.keys());
        // ── Phase 1 : PUT ──────────────────────────────────────────────
        // Try ÉTROIT autour du PUT seulement. Avant 2026-05-20 (adversarial
        // HIGH #1), le try englobait aussi le reload (Promise.all([loadStats,
        // loadTerms])) — si le reload throw (réseau down post-PUT, 5xx, 401
        // session expirée), l'utilisateur voyait "Erreur enregistrement"
        // alors que le PUT avait réussi ET le toast success/warning avait
        // déjà fire. Pire : ``dirtyTerms`` était clearé → re-cliquer Save
        // tombait sur ``size === 0 → early return``, données sauvées mais
        // user perdu. Séparation en 2 phases : PUT (critique, erreur dure)
        // vs Reload (cosmétique, erreur soft).
        var resp;
        try {
            resp = await fetchJson('/api/anonymization/terms', {
                method: 'PUT',
                body: JSON.stringify({
                    anonymization_state: { version: 1, terms: payloadTerms },
                    // /data-privacy charge l'état détaillé complet → replace
                    // full légitime (cf. commentaire du PUT bulk ci-dessus).
                    state_scope: 'full',
                    // Verrou optimiste (cf. PUT bulk).
                    expected_revision: state.revision || undefined,
                }),
            });
            // Adopter la révision post-write (filet si le reload phase 2
            // échoue en soft — sinon le prochain save 409-erait à tort).
            if (resp && typeof resp.revision === 'string') {
                state.revision = resp.revision;
            }
        } catch (err) {
            // Le PUT lui-même a échoué : pas de clear, l'user peut retenter.
            // Parse ``err.data.state_errors`` via helper pour message lisible.
            var errData = (err && err.data) || {};
            // Révision périmée (un autre onglet/scan a écrit) : rien n'a été
            // écrasé — recharger la liste (reset dirty + nouvelle révision),
            // l'user réapplique ses modifs sur du frais.
            if (errData.error_code === 'STATE_REVISION_MISMATCH') {
                state.saveInFlight = false;
                if (btnSave) { btnSave.disabled = false; btnSave.textContent = _btnSaveOriginalText; }
                if (btnDiscard) btnDiscard.disabled = false;
                toast(
                    'Tes termes ont été modifiés entre-temps (autre onglet ou '
                    + 'scan). Rien n\'a été écrasé — liste rechargée, '
                    + 'réapplique tes modifications.',
                    'error'
                );
                await Promise.all([loadStats(), loadTerms()]);
                return false;
            }
            var stErrs = Array.isArray(errData.state_errors) ? errData.state_errors : [];
            var detailMsg = window.AnonymizationSaveHelpers.formatStateErrors(
                stErrs,
                errData.state_errors_truncated_count
            );
            var msgFinal = detailMsg
                || ((err && err.message) || 'inconnue');
            // Toast 'error' = sticky (cf. static/js/toast.js:107 isStickyType).
            // Reste jusqu'au dismiss manuel — l'user a le temps de lire et
            // d'agir. Highlight visuel des rows en cause si state_errors
            // dispo (parité comportementale avec iris-grid qui affiche
            // err.textContent sous le bouton + draft inline).
            toast('Erreur enregistrement : ' + msgFinal, 'error');
            _highlightErrorRows(stErrs);
            // Restore UI dans le catch (sans clear dirtyTerms : les modifs
            // sont préservées). ``finally`` global restaure aussi mais on
            // veut être explicite ici et early-return pour ne pas tomber
            // dans la phase reload qui suit (state PUT non confirmé).
            state.saveInFlight = false;
            if (btnSave) {
                btnSave.disabled = false;
                btnSave.textContent = _btnSaveOriginalText;
            }
            if (btnDiscard) btnDiscard.disabled = false;
            return false;
        }
        // ── Phase 2 : clear + toast (PUT confirmé OK) ──────────────────
        // PUT a réussi. Clear immédiat des dirty (avant reload) — fix UX
        // 2026-05-20 : sinon pendant les ~3.5s de loadTerms (3000+ termes
        // côté serveur), un user qui voit le toast "enregistrées" et
        // clique « Améliorer » se fait bloquer par le guard dirtyTerms.size>0.
        for (var _i = 0; _i < _snapshotDirtyIds.length; _i++) {
            state.dirtyTerms.delete(_snapshotDirtyIds[_i]);
        }
        _updateFooter();
        // Backend a sanitizé certains termes : warning au lieu de success
        // silencieux. Fix CRITICAL #1 2026-05-20 — avant ce fix le backend
        // loguait mais ne disait rien au client.
        var sanitizationErrors = Array.isArray(resp && resp.state_errors)
            ? resp.state_errors
            : null;
        if (sanitizationErrors && sanitizationErrors.length) {
            var warnMsg = window.AnonymizationSaveHelpers.formatStateErrors(
                sanitizationErrors,
                resp && resp.state_errors_truncated_count
            );
            // Toast 'warning' est éphémère (~5s par défaut), donc on ajoute
            // un highlight visuel sur les rows en cause. La row a une bordure
            // rouge jusqu'au prochain renderGroupedTerms (= au reload phase 3).
            // Si l'user veut investiguer après que le toast disparaisse, il
            // voit toujours les rows highlightées avant que loadTerms ne
            // rebuilde le DOM.
            toast(
                warnMsg
                    ? warnMsg + ' — modifications partiellement sauvées.'
                    : 'Certaines modifications n\'ont pas été sauvées '
                      + '(' + sanitizationErrors.length + ' erreur(s)).',
                'warning'
            );
            _highlightErrorRows(sanitizationErrors);
        } else {
            toast('Modifications enregistrées.', 'success');
        }
        // ── Phase 3 : reload (cosmétique — un échec ne réverse pas le save)
        // Try ISOLÉ autour du reload : si Promise.all throw (réseau, 5xx,
        // 401), on affiche un toast info "save OK, reload échoué, recharge
        // la page". On NE re-affiche PAS "Erreur enregistrement" qui serait
        // mensonger (les données SONT en BDD). Le badge global est aussi
        // best-effort dans ce try.
        try {
            await Promise.all([loadStats(), loadTerms()]);
            if (window.KomptiaPrivacyBadge && typeof window.KomptiaPrivacyBadge.invalidate === 'function') {
                window.KomptiaPrivacyBadge.invalidate();
            }
        } catch (reloadErr) {
            toast(
                'Sauvegarde réussie, mais le rafraîchissement a échoué. '
                + 'Rechargez la page pour voir l\'état à jour ('
                + ((reloadErr && reloadErr.message) || 'inconnu') + ').',
                'info'
            );
        } finally {
            // Restore bouton + flag d'idempotence DANS TOUS LES CAS (success
            // et erreur). Avant 2026-05-20, le success laissait le bouton à
            // "Enregistrement…" disabled pendant ~3.5s (reload) — résolu
            // ici en restorant après ``await Promise.all([loadStats, loadTerms])``
            // qui a déjà résolu au moment du finally. Le flag
            // ``saveInFlight`` libère le guard d'idempotence.
            state.saveInFlight = false;
            if (btnSave) {
                btnSave.disabled = false;
                btnSave.textContent = _btnSaveOriginalText;
            }
            if (btnDiscard) btnDiscard.disabled = false;
        }
        // PUT confirmé (le reload phase 3 est cosmétique) → état cohérent.
        return true;
    }

    function _classifyDeps() {
        return {
            fetchJson: fetchJson,
            getXsrf: getXsrf,
            toast: toast,
            getPendingTerms: function() {
                return state.terms.filter(function(t) { return t && !t.confirmed; });
            },
            onComplete: function() {
                Promise.all([loadStats(), loadTerms()]).catch(function() {});
            },
        };
    }

    // Deps pour ``#action-improve-pseudos`` (depuis 2026-05-19). Le LLM
    // local enrichit les ``pseudo_middle`` des termes activés sans
    // pseudo personnalisé. Filtre côté client AVANT envoi pour éviter
    // un appel réseau quand la liste est vide (cas géré aussi côté
    // module JS dans ``openAndStartImprove`` — defense in depth).
    function _improveDeps() {
        return {
            getXsrf: getXsrf,
            toast: toast,
            getEligibleTerms: function() {
                // Fix 2026-05-19 (David) :
                // 1. Plus de filtre sur ``pseudo_middle`` côté frontend —
                //    tous les termes ``enabled=true`` sont envoyés. Le
                //    backend distingue NULL / auto-format / custom et
                //    préserve les vrais customs user-saisis.
                // 2. Utilise ``_termCurrent(t)`` qui MERGE les dirty
                //    (toggles non encore sauvegardés). Sans ça, un user
                //    qui active un terme puis clique « Améliorer » sans
                //    Save voyait son toggle ignoré. L'auto-flush dans le
                //    handler #action-improve-pseudos garantit que la BDD
                //    est synchronisée avant l'appel — mais cette lecture
                //    via _termCurrent reste la source de vérité côté UI.
                return state.terms.filter(function(t) {
                    if (!t) return false;
                    var cur = _termCurrent(t);
                    return !!cur.enabled;
                });
            },
            // Update inline du state + re-render DEBOUNCÉ (fix #5 review
            // 2026-05-19). Sans debounce, ``renderGroupedTerms()`` à chaque
            // chunk re-render TOUTE la liste — O(N²) DOM thrashing garanti
            // sur 5000+ termes (contrat V5 « liste infinie »). Avec
            // debounce 500ms on aggrège plusieurs chunks en un seul render.
            refreshTerm: (function() {
                var _pendingRender = null;
                var _RENDER_DEBOUNCE_MS = 500;
                return function(term, newPseudoMiddle) {
                    for (var i = 0; i < state.terms.length; i++) {
                        var t = state.terms[i];
                        if (t && t.term === term) {
                            t.pseudo_middle = newPseudoMiddle;
                            // Si dirty, ne pas écraser la saisie user en cours.
                            if (state.dirtyTerms.has(t.id)) {
                                break;
                            }
                            if (_pendingRender) {
                                clearTimeout(_pendingRender);
                            }
                            _pendingRender = setTimeout(function() {
                                _pendingRender = null;
                                if (typeof renderGroupedTerms === 'function') {
                                    renderGroupedTerms();
                                }
                            }, _RENDER_DEBOUNCE_MS);
                            break;
                        }
                    }
                };
            })(),
            onComplete: function() {
                // Reload complet : stats peuvent avoir changé (audit row +1),
                // et certains termes ont des pseudo_middle frais — re-fetch
                // pour cohérence avec la BDD canonique.
                Promise.all([loadStats(), loadTerms()]).catch(function() {});
            },
        };
    }

    function _init() {
        // ÉTAPE 1 — branche la délégation globale AVANT tout le reste.
        // Si la suite crashe pour une raison X (ID manquant dans
        // ``_attachListeners``, etc.), au moins les boutons Scanner
        // restent fonctionnels grâce à la délégation document.
        try {
            _delegateScanClicks();
        } catch (errDel) {
            // eslint-disable-next-line no-console
            console.error('[privacy] _delegateScanClicks a échoué', errDel);
        }

        // ÉTAPE 2 — listeners spécifiques. Si l'un d'eux throw (typiquement
        // ``$('id-supprimé').addEventListener`` après un refactor template
        // qui n'a pas mis à jour le JS), on logue ET on toast — pas de
        // silence qui mène à un bouton mort sans feedback.
        try {
            _attachListeners();
        } catch (errAttach) {
            // eslint-disable-next-line no-console
            console.error(
                '[privacy] _attachListeners a échoué — '
                + 'des handlers ne sont pas branchés (la délégation globale '
                + 'reste active pour les boutons Scanner)',
                errAttach
            );
            toast(
                "Initialisation partielle de la page. Certaines actions "
                + "peuvent ne pas répondre. Détails dans la console (F12).",
                'error'
            );
        }

        // ÉTAPE 3 — chargement données. Non bloquant pour l'UI.
        try {
            _maybeStartOnboarding();
        } catch (errOnb) {
            // eslint-disable-next-line no-console
            console.error('[privacy] _maybeStartOnboarding a échoué', errOnb);
        }
        Promise.all([loadStats(), loadTerms()]).catch(function() {
            /* géré au call-site */
        });
    }

    if (typeof document !== 'undefined') {
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', _init);
        } else {
            _init();
        }

        // Expose pour debug / tests d'intégration manuels.
        window.PrivacyPage = {
            reload: function() {
                Promise.all([loadStats(), loadTerms()]).catch(function() {});
            },
            getState: function() { return state; },
        };
    }

    // Exports Node — helpers PURS uniquement.
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = {
            normalizeForSearch: normalizeForSearch,
            termMatchesFilter: termMatchesFilter,
        };
    }
})();
