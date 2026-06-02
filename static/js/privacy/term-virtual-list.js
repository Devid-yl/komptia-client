/**
 * Privacy — term-virtual-list.js
 *
 * Liste virtualisée vanilla pour la table des termes confidentiels.
 * Indispensable car un user comptable peut accumuler 5k–10k+ termes
 * sur un datastore conséquent. Le rendu naïf (tous les ``<tr>``) gèle
 * le navigateur dès quelques milliers d'éléments — la virtualisation
 * affiche uniquement les lignes visibles dans le viewport (+ buffer
 * top/bottom pour absorber le scroll).
 *
 * Doctrine
 * --------
 * 1. **Vanilla, sans dépendance** — réutilise uniquement le DOM. Pas
 *    de framework, pas d'infinite-scroll lib (>30KB).
 * 2. **rowHeight fixe** — la virtualisation par hauteur uniforme est
 *    O(1) sur le scroll. Pour des rows variables il faudrait un
 *    measure-and-cache plus lourd, hors scope ici.
 * 3. **CSP-safe** — toute construction DOM passe par
 *    ``createElement`` + ``textContent`` ; aucune interpolation HTML
 *    user-controlled.
 * 4. **Sélection multiple** — checkbox par ligne + état
 *    ``selectedIds`` propagé au caller via ``onSelectionChange`` pour
 *    alimenter la sticky bottom-bar bulk.
 * 5. **Anti-flicker** — sur scroll, on ne re-render que si la fenêtre
 *    visible a changé (memo ``_lastStart`` / ``_lastEnd``).
 */
(function() {
    'use strict';

    /** Calcule la fenêtre visible [start, end) selon scrollTop, viewport
     *  et hauteur de ligne. Pure : testable Node sans DOM.
     *
     *  ``bufferRows`` étend [start, end] avant et après pour préparer
     *  le scroll rapide (rendu silencieux dans la marge).
     */
    function computeVisibleRange(scrollTop, viewportHeight, rowHeight, total, bufferRows) {
        var st = Number(scrollTop);
        var vh = Number(viewportHeight);
        var rh = Number(rowHeight);
        var n = Number(total);
        var buf = Number(bufferRows);
        if (!Number.isFinite(st) || st < 0) st = 0;
        if (!Number.isFinite(vh) || vh < 0) vh = 0;
        if (!Number.isFinite(rh) || rh <= 0) {
            return { start: 0, end: 0 };
        }
        if (!Number.isFinite(n) || n <= 0) {
            return { start: 0, end: 0 };
        }
        if (!Number.isFinite(buf) || buf < 0) buf = 0;
        var startIdx = Math.floor(st / rh) - buf;
        if (startIdx < 0) startIdx = 0;
        var visibleCount = Math.ceil(vh / rh) + 2 * buf;
        var endIdx = startIdx + visibleCount;
        if (endIdx > n) endIdx = n;
        if (startIdx > endIdx) startIdx = endIdx;
        return { start: startIdx, end: endIdx };
    }

    function _esc(value) {
        // Pas utilisé pour HTML (on passe par textContent), juste défensive
        // sur les coercions vers String.
        return value == null ? '' : String(value);
    }

    /** Construit un ``<tr>`` pour un terme. Retourne un Node DOM.
     *
     *  N'interpole JAMAIS de HTML : tout passe par ``textContent``.
     *  Les classes CSS sont des littéraux fixes ; les attributs data-*
     *  sont passés via ``setAttribute`` (string sécurisée par la
     *  sérialisation native du navigateur).
     */
    function buildTermRow(term, options) {
        var tr = document.createElement('tr');
        tr.className = 'privacy-virt-row';
        tr.style.height = options.rowHeight + 'px';
        if (term && term.id != null) {
            tr.setAttribute('data-term-id', String(term.id));
        }

        // Cell 1 : checkbox sélection (bulk)
        var tdSel = document.createElement('td');
        tdSel.className = 'privacy-cell-select';
        var cb = document.createElement('input');
        cb.type = 'checkbox';
        cb.className = 'privacy-select-checkbox';
        cb.setAttribute('aria-label', 'Sélectionner ce terme');
        if (term && term.id != null) {
            cb.setAttribute('data-term-id', String(term.id));
        }
        cb.checked = !!(options.isSelected && options.isSelected(term));
        tdSel.appendChild(cb);
        tr.appendChild(tdSel);

        // Cell 2 : terme (cleartext)
        var tdTerm = document.createElement('td');
        tdTerm.className = 'privacy-cell-term';
        var spanTerm = document.createElement('span');
        spanTerm.className = 'privacy-cell-term-text';
        spanTerm.textContent = _esc(term && term.term);
        tdTerm.appendChild(spanTerm);
        tr.appendChild(tdTerm);

        // Cell 3 : catégorie
        var tdCat = document.createElement('td');
        tdCat.textContent = _esc(term && (term.category || 'unclassified'));
        tr.appendChild(tdCat);

        // Cell 4 : risque (badge)
        var tdRisk = document.createElement('td');
        var risk = (term && term.risk_level) || 'low';
        var spanRisk = document.createElement('span');
        spanRisk.className = 'privacy-badge privacy-badge-risk-' + _esc(risk);
        spanRisk.textContent = _esc(risk);
        tdRisk.appendChild(spanRisk);
        tr.appendChild(tdRisk);

        // Cell 5 : statut
        var tdStatus = document.createElement('td');
        var spanStatus = document.createElement('span');
        if (!term || !term.confirmed) {
            spanStatus.className = 'privacy-badge privacy-badge-warn';
            spanStatus.textContent = 'En attente';
        } else if (term.enabled) {
            spanStatus.className = 'privacy-badge privacy-badge-success';
            spanStatus.textContent = 'Activé';
        } else {
            spanStatus.className = 'privacy-badge privacy-badge-muted';
            spanStatus.textContent = 'Désactivé';
        }
        tdStatus.appendChild(spanStatus);
        tr.appendChild(tdStatus);

        // Cell 6 : action détail
        var tdAction = document.createElement('td');
        if (term && term.id != null) {
            var btn = document.createElement('button');
            btn.type = 'button';
            btn.className = 'privacy-btn-icon';
            btn.setAttribute('data-action', 'coverage');
            btn.setAttribute('data-term-id', String(term.id));
            btn.setAttribute('title', 'Voir où ce terme apparaît');
            btn.setAttribute('aria-label', 'Détail du terme');
            btn.textContent = '…';
            tdAction.appendChild(btn);
        }
        tr.appendChild(tdAction);

        return tr;
    }

    /** Classe TermVirtualList — gère un container scrollable + tbody.
     *
     *  Usage :
     *    var list = new TermVirtualList(scrollEl, tbodyEl, {
     *        rowHeight: 36, bufferRows: 10,
     *        onSelectionChange: function(idsSet) {...},
     *    });
     *    list.setItems([{id, term, ...}, ...]);
     *
     *  Le DOM minimal attendu :
     *    <div class="privacy-virt-scroll" style="overflow-y:auto;height:Npx">
     *        <table class="privacy-table">
     *            <thead>...</thead>
     *            <tbody class="privacy-virt-tbody"></tbody>
     *        </table>
     *    </div>
     */
    function TermVirtualList(scrollEl, tbodyEl, options) {
        if (!scrollEl || !tbodyEl) {
            throw new Error('TermVirtualList: scrollEl et tbodyEl requis');
        }
        this.scrollEl = scrollEl;
        this.tbodyEl = tbodyEl;
        this.options = Object.assign({
            rowHeight: 36,
            bufferRows: 10,
            onSelectionChange: null,
        }, options || {});
        this.items = [];
        this.selectedIds = new Set();
        this._lastStart = -1;
        this._lastEnd = -1;
        this._rafPending = false;

        // Listeners
        var self = this;
        this._onScroll = function() {
            if (self._rafPending) return;
            self._rafPending = true;
            requestAnimationFrame(function() {
                self._rafPending = false;
                self._render();
            });
        };
        this._onClick = function(ev) {
            var cb = ev.target.closest && ev.target.closest('input.privacy-select-checkbox');
            if (cb) {
                var rid = cb.getAttribute('data-term-id');
                var nid = parseInt(rid, 10);
                if (!Number.isFinite(nid) || nid <= 0) return;
                if (cb.checked) {
                    self.selectedIds.add(nid);
                } else {
                    self.selectedIds.delete(nid);
                }
                if (typeof self.options.onSelectionChange === 'function') {
                    self.options.onSelectionChange(new Set(self.selectedIds));
                }
            }
        };

        this.scrollEl.addEventListener('scroll', this._onScroll);
        this.tbodyEl.addEventListener('click', this._onClick);
    }

    TermVirtualList.prototype.setItems = function(items) {
        this.items = Array.isArray(items) ? items : [];
        // Purge les ids sélectionnés qui n'existent plus dans la liste
        // filtrée — sinon la sélection peut "fuire" cross-filter.
        var validIds = new Set();
        for (var i = 0; i < this.items.length; i++) {
            var it = this.items[i];
            if (it && it.id != null) validIds.add(it.id);
        }
        var changed = false;
        var iter = Array.from(this.selectedIds);
        for (var j = 0; j < iter.length; j++) {
            if (!validIds.has(iter[j])) {
                this.selectedIds.delete(iter[j]);
                changed = true;
            }
        }
        if (changed && typeof this.options.onSelectionChange === 'function') {
            this.options.onSelectionChange(new Set(this.selectedIds));
        }
        // Reset scroll au top sur nouvelle liste (UX cohérente avec un
        // re-filter / re-search).
        this.scrollEl.scrollTop = 0;
        this._lastStart = -1;
        this._lastEnd = -1;
        this._render();
    };

    TermVirtualList.prototype.getSelection = function() {
        return new Set(this.selectedIds);
    };

    TermVirtualList.prototype.clearSelection = function() {
        if (this.selectedIds.size === 0) return;
        this.selectedIds.clear();
        if (typeof this.options.onSelectionChange === 'function') {
            this.options.onSelectionChange(new Set());
        }
        // Re-render pour décocher les checkboxes visibles.
        this._lastStart = -1;
        this._lastEnd = -1;
        this._render();
    };

    TermVirtualList.prototype.selectAllVisible = function() {
        var added = false;
        for (var i = 0; i < this.items.length; i++) {
            var it = this.items[i];
            if (it && it.id != null && !this.selectedIds.has(it.id)) {
                this.selectedIds.add(it.id);
                added = true;
            }
        }
        if (added && typeof this.options.onSelectionChange === 'function') {
            this.options.onSelectionChange(new Set(this.selectedIds));
        }
        this._lastStart = -1;
        this._lastEnd = -1;
        this._render();
    };

    TermVirtualList.prototype.destroy = function() {
        this.scrollEl.removeEventListener('scroll', this._onScroll);
        this.tbodyEl.removeEventListener('click', this._onClick);
        this.tbodyEl.innerHTML = '';
    };

    TermVirtualList.prototype._render = function() {
        // Single source of truth pour la sélection : on lit ``selectedIds``
        // à chaque render et on applique ``cb.checked`` en miroir. Si un
        // click utilisateur est perdu (race rare entre scroll inertial +
        // re-render), le state n'est PAS corrompu : la prochaine interaction
        // re-render avec la SoT exacte (review F04). Mitigation principale :
        // memo sur _lastStart/_lastEnd ci-dessous évite la re-render quand
        // la fenêtre visible n'a pas changé.
        var rh = this.options.rowHeight;
        var total = this.items.length;
        var range = computeVisibleRange(
            this.scrollEl.scrollTop,
            this.scrollEl.clientHeight,
            rh,
            total,
            this.options.bufferRows
        );
        if (range.start === this._lastStart && range.end === this._lastEnd) {
            return;
        }
        this._lastStart = range.start;
        this._lastEnd = range.end;

        // Critical #37 review : colSpan dynamique au lieu de hardcoded 6.
        // Si le <thead> évolue (colonne ajoutée/supprimée), les spacers
        // s'alignent automatiquement. Lookup une seule fois par render
        // (cheap : un getElementsByTagName).
        var theadTr = this.tbodyEl.parentNode &&
            this.tbodyEl.parentNode.querySelector &&
            this.tbodyEl.parentNode.querySelector('thead tr');
        var spacerColSpan = theadTr && theadTr.children
            ? theadTr.children.length
            : 6;

        // Capture le node focusé AVANT vidage tbody pour pouvoir restaurer
        // (review F07) — un user qui Tab dans la liste ne perd pas son
        // contexte clavier au scroll. On capture l'id + le rôle (checkbox
        // ou button) ; si le terme reste dans la fenêtre visible après
        // re-render, on focus à nouveau l'élément équivalent.
        var prevFocusInfo = null;
        var active = document.activeElement;
        if (active && this.tbodyEl.contains(active)) {
            var rowEl = active.closest && active.closest('tr[data-term-id]');
            var role = active.tagName === 'INPUT' ? 'checkbox'
                : active.tagName === 'BUTTON' ? 'action'
                    : null;
            if (rowEl && role) {
                prevFocusInfo = {
                    termId: rowEl.getAttribute('data-term-id'),
                    role: role,
                };
            }
        }

        // Le tbody est layouté via deux <tr> spacers (top + bottom) qui
        // occupent (start * rh) et ((total - end) * rh) px en hauteur.
        // Cela conserve la barre de scroll cohérente sans rendre les
        // milliers de <tr> hors-viewport.
        var frag = document.createDocumentFragment();
        var topPx = range.start * rh;
        var bottomPx = (total - range.end) * rh;
        if (topPx > 0) {
            var trTop = document.createElement('tr');
            trTop.setAttribute('aria-hidden', 'true');
            trTop.className = 'privacy-virt-spacer';
            var tdTop = document.createElement('td');
            tdTop.colSpan = spacerColSpan;
            tdTop.style.padding = '0';
            tdTop.style.border = '0';
            tdTop.style.height = topPx + 'px';
            trTop.appendChild(tdTop);
            frag.appendChild(trTop);
        }
        // Critical #37 review : isSelected callback alloué UNE SEULE FOIS
        // hors boucle au lieu d'une nouvelle fonction par row. Sur une
        // fenêtre de 30 rows × scroll inertial 60fps, ça évite ~1800
        // allocations de closures par seconde pour rien.
        var self = this;
        var isSelectedRef = function(t) {
            return t && t.id != null && self.selectedIds.has(t.id);
        };
        var rowOptions = {rowHeight: rh, isSelected: isSelectedRef};
        for (var i = range.start; i < range.end; i++) {
            frag.appendChild(buildTermRow(this.items[i], rowOptions));
        }
        if (bottomPx > 0) {
            var trBot = document.createElement('tr');
            trBot.setAttribute('aria-hidden', 'true');
            trBot.className = 'privacy-virt-spacer';
            var tdBot = document.createElement('td');
            tdBot.colSpan = 6;
            tdBot.style.padding = '0';
            tdBot.style.border = '0';
            tdBot.style.height = bottomPx + 'px';
            trBot.appendChild(tdBot);
            frag.appendChild(trBot);
        }
        this.tbodyEl.innerHTML = '';
        this.tbodyEl.appendChild(frag);

        // Restore focus si le terme focused est encore visible (review F07).
        if (prevFocusInfo) {
            var sel = 'tr[data-term-id="' + prevFocusInfo.termId + '"]';
            var newRow = this.tbodyEl.querySelector(sel);
            if (newRow) {
                var target = prevFocusInfo.role === 'checkbox'
                    ? newRow.querySelector('input.privacy-select-checkbox')
                    : newRow.querySelector('button[data-action="coverage"]');
                if (target && typeof target.focus === 'function') {
                    target.focus();
                }
            }
        }
    };

    if (typeof window !== 'undefined') {
        window.PrivacyVirtualList = {
            TermVirtualList: TermVirtualList,
            computeVisibleRange: computeVisibleRange,
        };
    }

    // Exports Node pour les tests purs (pas de DOM utilisé dans
    // computeVisibleRange).
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = {
            computeVisibleRange: computeVisibleRange,
            TermVirtualList: TermVirtualList,
        };
    }
})();
