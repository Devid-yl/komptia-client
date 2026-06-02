/**
 * OverlayManager — coordinateur d'overlays (modals, menus, popovers, toasts).
 *
 * Philosophie : opt-in strict. Les overlays qui s'enregistrent via open() sont
 * coordonnés (z-index, Escape, scroll-lock, empilement LIFO). Les overlays qui
 * ne passent pas par ce module continuent de fonctionner comme avant — on ne
 * touche jamais à un élément qu'on ne gère pas.
 *
 * Layers (tokens z-index, synchronisés avec overlay-layers.css) :
 *   - dropdown     : 1000  — menus, conflict: dismiss-previous
 *   - popover      : 1500  — popovers, conflict: dismiss-previous
 *   - modal        : 2000  — modals custom, conflict: stack (LIFO)
 *   - system-modal : 9999  — confirm/sync globaux, conflict: stack
 *   - toast        : 10000 — notifications, conflict: coexist (hors stack)
 *
 * Modes "conflict" :
 *   - stack            : empile. Le nouveau passe au-dessus. Escape ferme le top.
 *   - dismiss-previous : ferme les autres du MÊME layer avant d'ouvrir.
 *   - coexist          : indépendant, pas dans le stack LIFO, ignoré par Escape.
 *
 * Usage :
 *   OverlayManager.open(modalEl, { layer: 'modal', lockScroll: true });
 *   OverlayManager.close(modalEl);
 *
 * Le manager ne manipule PAS les classes .hidden / .flex / .show — c'est à
 * l'appelant de les gérer. Le manager s'occupe uniquement de : z-index,
 * Escape (LIFO), scroll-lock (body.overlay-lock), stack ordering, callbacks
 * onClose. Focus trap et inert siblings sont optionnels (off par défaut pour
 * ne pas régresser sur les modals legacy).
 */
(function () {
    'use strict';

    const LAYERS = {
        dropdown: { base: 1000, defaults: { conflict: 'dismiss-previous', lockScroll: false } },
        popover: { base: 1500, defaults: { conflict: 'dismiss-previous', lockScroll: false } },
        modal: { base: 2000, defaults: { conflict: 'stack', lockScroll: true } },
        'system-modal': { base: 9999, defaults: { conflict: 'stack', lockScroll: true } },
        toast: { base: 10000, defaults: { conflict: 'coexist', lockScroll: false } },
    };

    const FOCUSABLE_SELECTOR = [
        'a[href]',
        'button:not([disabled])',
        'input:not([disabled]):not([type="hidden"])',
        'select:not([disabled])',
        'textarea:not([disabled])',
        '[tabindex]:not([tabindex="-1"])',
    ].join(',');

    const _stack = [];
    const _coexist = new Map();
    let _lockCount = 0;
    let _keydownAttached = false;

    function _resolveLayer(layerName) {
        if (LAYERS[layerName]) return layerName;
        if (layerName != null) {
            console.warn('[OverlayManager] Layer inconnu "%s" — fallback sur "modal"', layerName);
        }
        return 'modal';
    }

    function _getMaxZIndexInOpenOverlays() {
        let max = 0;
        _stack.forEach((entry) => {
            const z = parseInt(entry.el.style.zIndex || '0', 10);
            if (Number.isFinite(z) && z > max) max = z;
        });
        _coexist.forEach((entries) => {
            entries.forEach((entry) => {
                const z = parseInt(entry.el.style.zIndex || '0', 10);
                if (Number.isFinite(z) && z > max) max = z;
            });
        });
        // Inclure aussi les containers connus pour porter un z-index
        // élevé sans passer par OverlayManager. ``.grid-fullscreen`` est
        // appliqué directement par iris-grid (``classList.add``), porte
        // un z-index 1900 défini en CSS via ``--z-iris-grid-fullscreen``,
        // et masquerait les dropdowns/popovers ouverts depuis la grille
        // si on ne le compte pas (bug 2026-05-22). On utilise
        // ``getComputedStyle`` pour résoudre la CSS variable.
        try {
            const fullscreenEls = document.querySelectorAll('.grid-fullscreen');
            fullscreenEls.forEach((el) => {
                const computed = window.getComputedStyle(el);
                const z = parseInt(computed.zIndex, 10);
                if (Number.isFinite(z) && z > max) max = z;
            });
        } catch (_) {
            // querySelectorAll/getComputedStyle peuvent throw dans des
            // contextes exotiques (worker, document détaché). Best-effort.
        }
        return max;
    }

    function _computeZIndex(layerName) {
        const layer = LAYERS[layerName];
        const sameLayerCount = _stack.filter((e) => e.layer === layerName).length
            + (_coexist.has(layerName) ? _coexist.get(layerName).length : 0);
        const layerBase = layer.base + sameLayerCount * 10;

        // Garde anti-cachage des sub-overlays : si un overlay d'une couche
        // SUPÉRIEURE est déjà ouvert (ex: modal z=2000), un nouveau
        // dropdown ouvert depuis ce modal serait à z=1000 et donc CACHÉ
        // par le parent. C'était le bug 2026-05-22 du menu « Enregistrer »
        // de la grille sur /datastore (modal-workbook z=2000 masquait
        // saveMenu z=1000). Comportement attendu : un sub-overlay
        // récemment ouvert reste interactif au-dessus de son parent.
        //
        // Fix : prendre max(layerBase, topOfStack + 10). Le LIFO global
        // est préservé car les overlays suivants partiront du nouveau
        // top, pas du layerBase. Les modals ouverts APRÈS un dropdown
        // élevé prendront aussi z=top+10.
        const topOfStack = _getMaxZIndexInOpenOverlays();
        if (topOfStack >= layerBase) {
            return topOfStack + 10;
        }
        return layerBase;
    }

    function _ensureKeydown() {
        if (_keydownAttached) return;
        // Bubble phase : les handlers locaux (overlays legacy comme iris-grid
        // filter popup, autocompletes, datepickers) ont l'opportunité de
        // traiter Escape en premier et d'appeler stopPropagation s'ils
        // consomment l'événement. Le manager ne ferme son top-most que si
        // l'événement remonte jusqu'à document.
        document.addEventListener('keydown', _onKeydown);
        _keydownAttached = true;
    }

    function _onKeydown(event) {
        if (event.key !== 'Escape') return;
        if (_stack.length === 0) return;
        const top = _stack[_stack.length - 1];
        event.stopPropagation();
        if (typeof event.stopImmediatePropagation === 'function') {
            event.stopImmediatePropagation();
        }
        event.preventDefault();
        close(top.el);
    }

    function _applyInertSiblings(el) {
        const parent = el.parentElement || document.body;
        const snapshots = [];
        Array.from(parent.children).forEach((sibling) => {
            if (sibling === el) return;
            snapshots.push({
                node: sibling,
                prevAria: sibling.getAttribute('aria-hidden'),
                prevInert: sibling.hasAttribute('inert'),
            });
            sibling.setAttribute('aria-hidden', 'true');
            sibling.setAttribute('inert', '');
        });
        return snapshots;
    }

    function _restoreInertSiblings(snapshots) {
        if (!snapshots) return;
        snapshots.forEach((snap) => {
            if (snap.prevAria === null) {
                snap.node.removeAttribute('aria-hidden');
            } else {
                snap.node.setAttribute('aria-hidden', snap.prevAria);
            }
            if (!snap.prevInert) {
                snap.node.removeAttribute('inert');
            }
        });
    }

    function _setupFocusTrap(entry) {
        entry._prevFocus = document.activeElement;
        entry._focusHandler = function (e) {
            if (e.key !== 'Tab') return;
            const focusables = entry.el.querySelectorAll(FOCUSABLE_SELECTOR);
            if (!focusables.length) {
                e.preventDefault();
                // Un élément sans tabindex n'est pas focusable. On le rend
                // focusable temporairement pour que le focus reste dans
                // l'overlay au lieu de s'échapper.
                if (!entry.el.hasAttribute('tabindex')) {
                    entry.el.setAttribute('tabindex', '-1');
                    entry._tabindexAdded = true;
                }
                entry.el.focus();
                return;
            }
            const first = focusables[0];
            const last = focusables[focusables.length - 1];
            if (e.shiftKey && document.activeElement === first) {
                e.preventDefault();
                last.focus();
            } else if (!e.shiftKey && document.activeElement === last) {
                e.preventDefault();
                first.focus();
            }
        };
        entry.el.addEventListener('keydown', entry._focusHandler);
        const firstFocusable = entry.el.querySelector(FOCUSABLE_SELECTOR);
        if (firstFocusable) firstFocusable.focus();
    }

    function _teardownFocusTrap(entry) {
        if (entry._focusHandler) {
            entry.el.removeEventListener('keydown', entry._focusHandler);
        }
        if (entry._tabindexAdded) {
            entry.el.removeAttribute('tabindex');
        }
        if (entry._prevFocus && typeof entry._prevFocus.focus === 'function') {
            try { entry._prevFocus.focus(); } catch (_e) { /* noop */ }
        }
    }

    function _dismissPreviousSameLayer(layerName) {
        const toClose = _stack.filter((e) => e.layer === layerName).map((e) => e.el);
        toClose.forEach(close);
    }

    function _snapshotZIndex(el) {
        return el.style.zIndex || '';
    }

    function _restoreZIndex(el, prev) {
        if (prev) {
            el.style.zIndex = prev;
        } else {
            el.style.removeProperty('z-index');
        }
    }

    function _findStackIndex(el) {
        for (let i = 0; i < _stack.length; i++) {
            if (_stack[i].el === el) return i;
        }
        return -1;
    }

    function _findCoexistEntry(el) {
        for (const [layer, entries] of _coexist.entries()) {
            const idx = entries.findIndex((e) => e.el === el);
            if (idx !== -1) return { layer, idx, entry: entries[idx] };
        }
        return null;
    }

    function open(el, opts) {
        if (!el || !(el instanceof Element)) {
            console.warn('[OverlayManager] open() appelé sans élément DOM valide');
            return;
        }
        opts = opts || {};
        const layerName = _resolveLayer(opts.layer);
        const defaults = LAYERS[layerName].defaults;
        const conflict = opts.conflict || defaults.conflict;
        const lockScroll = opts.lockScroll != null ? opts.lockScroll : defaults.lockScroll;
        const trapFocus = opts.trapFocus === true;
        const inertSiblings = opts.inertSiblings === true;

        const existingStackIdx = _findStackIndex(el);
        if (existingStackIdx !== -1) {
            const existing = _stack.splice(existingStackIdx, 1)[0];
            _stack.push(existing);
            existing.el.style.zIndex = _computeZIndex(existing.layer);
            return;
        }
        const existingCoexist = _findCoexistEntry(el);
        if (existingCoexist) {
            existingCoexist.entry.el.style.zIndex = _computeZIndex(existingCoexist.layer);
            return;
        }

        if (conflict === 'dismiss-previous') {
            _dismissPreviousSameLayer(layerName);
        }

        const entry = {
            el: el,
            layer: layerName,
            conflict: conflict,
            lockScroll: !!lockScroll,
            trapFocus: trapFocus,
            inertSiblings: inertSiblings,
            onClose: typeof opts.onClose === 'function' ? opts.onClose : null,
            _prevZ: _snapshotZIndex(el),
            _inertSnapshots: null,
            _prevFocus: null,
            _focusHandler: null,
        };

        if (conflict === 'coexist') {
            if (!_coexist.has(layerName)) _coexist.set(layerName, []);
            _coexist.get(layerName).push(entry);
            el.style.zIndex = _computeZIndex(layerName);
            // Marqueur pour CSS contextuel — voir overlay-layers.css. Permet
            // d'élever le z-index des dropdowns/popovers quand un container
            // ``.grid-fullscreen`` (z=1900) est actif, sans toucher au
            // comportement nominal (LIFO standard).
            el.setAttribute('data-overlay-layer', layerName);
            return;
        }

        _stack.push(entry);
        el.style.zIndex = _computeZIndex(layerName);
        el.setAttribute('data-overlay-layer', layerName);

        if (entry.lockScroll) {
            _lockCount += 1;
            if (_lockCount === 1) document.body.classList.add('overlay-lock');
        }
        if (entry.inertSiblings) {
            entry._inertSnapshots = _applyInertSiblings(el);
        }
        if (entry.trapFocus) {
            _setupFocusTrap(entry);
        }

        _ensureKeydown();
    }

    function close(el) {
        if (!el) return;

        const stackIdx = _findStackIndex(el);
        if (stackIdx !== -1) {
            const entry = _stack.splice(stackIdx, 1)[0];
            _restoreZIndex(entry.el, entry._prevZ);
            entry.el.removeAttribute('data-overlay-layer');

            if (entry.lockScroll) {
                _lockCount -= 1;
                if (_lockCount < 0) {
                    console.warn('[OverlayManager] _lockCount négatif — double close() sans double open() ?');
                    _lockCount = 0;
                }
                if (_lockCount === 0) document.body.classList.remove('overlay-lock');
            }
            if (entry.inertSiblings) {
                _restoreInertSiblings(entry._inertSnapshots);
            }
            if (entry.trapFocus) {
                _teardownFocusTrap(entry);
            }

            _recomputeLayerZIndexes(entry.layer);

            if (entry.onClose) {
                try { entry.onClose(); } catch (err) {
                    console.error('[OverlayManager] onClose a levé :', err);
                }
            }
            return;
        }

        const coexist = _findCoexistEntry(el);
        if (coexist) {
            const entries = _coexist.get(coexist.layer);
            entries.splice(coexist.idx, 1);
            if (entries.length === 0) _coexist.delete(coexist.layer);
            _restoreZIndex(coexist.entry.el, coexist.entry._prevZ);
            coexist.entry.el.removeAttribute('data-overlay-layer');
            _recomputeLayerZIndexes(coexist.layer);
            if (coexist.entry.onClose) {
                try { coexist.entry.onClose(); } catch (err) {
                    console.error('[OverlayManager] onClose a levé :', err);
                }
            }
        }
        // Si l'élément n'est ni dans stack ni dans coexist, on retourne
        // silencieusement : les appelants font parfois un close() défensif
        // sur un élément qui n'a jamais été ouvert via le manager (opt-in).
    }

    function _recomputeLayerZIndexes(layerName) {
        const layer = LAYERS[layerName];
        if (!layer) return;

        // Reset les z-index de TOUS les entries du layer AVANT de
        // recalculer. Sinon on s'auto-compte dans ``topOfStack`` et
        // les z-index dérivent à la hausse à chaque fermeture
        // (bug 2026-05-22 — pendant le développement du fix initial).
        const layerEntries = [];
        _stack.forEach((entry) => {
            if (entry.layer === layerName) {
                entry.el.style.zIndex = '';
                layerEntries.push(entry);
            }
        });
        const coexistEntries = _coexist.has(layerName) ? _coexist.get(layerName) : [];
        coexistEntries.forEach((entry) => {
            entry.el.style.zIndex = '';
        });

        // ``topOfStack`` exclut maintenant TOUS les entries du layer
        // en cours de recompute (puisqu'ils ont leur z-index vide).
        // Si un modal (z=2000) reste ouvert, on remontera les entries
        // au-dessus pour qu'ils restent interactifs au-dessus du parent.
        const topOfStack = _getMaxZIndexInOpenOverlays();

        let idx = 0;
        layerEntries.forEach((entry) => {
            const naiveZ = layer.base + idx * 10;
            // Si on doit élever : ``topOfStack + 10 + idx*10`` préserve
            // l'ordre LIFO interne au layer ET garantit la position
            // au-dessus du parent.
            const elevatedZ = topOfStack + 10 + idx * 10;
            entry.el.style.zIndex = (topOfStack >= naiveZ ? elevatedZ : naiveZ);
            idx += 1;
        });
        coexistEntries.forEach((entry) => {
            const naiveZ = layer.base + idx * 10;
            const elevatedZ = topOfStack + 10 + idx * 10;
            entry.el.style.zIndex = (topOfStack >= naiveZ ? elevatedZ : naiveZ);
            idx += 1;
        });
    }

    function closeTopmost() {
        if (_stack.length === 0) return;
        close(_stack[_stack.length - 1].el);
    }

    function isOpen(el) {
        if (!el) return false;
        return _findStackIndex(el) !== -1 || _findCoexistEntry(el) !== null;
    }

    function getTop() {
        if (_stack.length === 0) return null;
        return _stack[_stack.length - 1].el;
    }

    // ── Auto-tracking des modaux statiques (Phase C, fix 2026-05-20) ──
    // Beaucoup de modaux Komptia sont déclarés statiquement dans les templates
    // avec ``<div class="fixed inset-0 ... hidden" id="myModal">…</div>`` et
    // affichés/masqués via ``modal.classList.add/remove('hidden')`` sans passer
    // par OverlayManager.open(). Sur ``/datastore``, ça causait le bug du
    // panneau Confidentialité qui apparaissait derrière le modal classeur.
    //
    // Au lieu d'auditer + migrer manuellement 13+ modaux dispersés dans
    // 6 templates, on installe ici un MutationObserver qui détecte
    // automatiquement les transitions ``hidden`` ↔ visible sur tout
    // élément ``.fixed.inset-0.hidden`` initial — et appelle open()/close()
    // côté OverlayManager pour piloter le z-index correctement.
    //
    // Opt-out explicite via ``data-overlay-manual="true"`` sur l'élément
    // si un modal a déjà sa propre logique OverlayManager (appConfirmModal,
    // globalSyncOverlay, etc. — pour éviter le double-fire).
    function _setupStaticModalAutoTracking() {
        const _trackedObservers = new WeakMap();

        function _trackElement(el) {
            if (_trackedObservers.has(el)) return;
            if (el.getAttribute('data-overlay-manual') === 'true') return;
            // Ne tracker que les éléments INITIALEMENT cachés (sinon banners,
            // overlays toujours visibles, etc. — qui ne sont pas des modaux).
            if (!el.classList.contains('hidden')) return;

            const observer = new MutationObserver(function(mutations) {
                for (const m of mutations) {
                    if (m.attributeName !== 'class') continue;
                    const isHidden = el.classList.contains('hidden');
                    const alreadyOpen = isOpen(el);
                    if (!isHidden && !alreadyOpen) {
                        // Transition hidden → visible : devient un modal actif
                        open(el, { layer: 'modal', lockScroll: true });
                    } else if (isHidden && alreadyOpen) {
                        // Transition visible → hidden : fermer côté manager
                        close(el);
                    }
                }
            });
            observer.observe(el, { attributes: true, attributeFilter: ['class'] });
            _trackedObservers.set(el, observer);
        }

        function _scanAndTrack() {
            const candidates = document.querySelectorAll('div.fixed.inset-0');
            candidates.forEach(_trackElement);
        }

        // Scan initial au DOM ready + scan secondaire pour les modaux ajoutés
        // dynamiquement plus tard (rare mais possible — ex: templates qui
        // appendChild des modaux après leur init JS).
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', _scanAndTrack);
        } else {
            _scanAndTrack();
        }
        // Observer global pour catcher les nouveaux modaux ajoutés au body
        // ultérieurement (ex: handlers JS qui appendChild un modal-as-template).
        const bodyObserver = new MutationObserver(function(mutations) {
            for (const m of mutations) {
                m.addedNodes.forEach(function(node) {
                    if (!(node instanceof Element)) return;
                    if (node.matches && node.matches('div.fixed.inset-0')) {
                        _trackElement(node);
                    }
                    // Aussi scanner les descendants (un partial ajouté peut
                    // contenir des modaux internes).
                    if (node.querySelectorAll) {
                        node.querySelectorAll('div.fixed.inset-0').forEach(_trackElement);
                    }
                });
            }
        });
        if (document.body) {
            bodyObserver.observe(document.body, { childList: true, subtree: true });
        } else {
            document.addEventListener('DOMContentLoaded', function() {
                bodyObserver.observe(document.body, { childList: true, subtree: true });
            });
        }
    }
    _setupStaticModalAutoTracking();

    window.OverlayManager = {
        open: open,
        close: close,
        closeTopmost: closeTopmost,
        isOpen: isOpen,
        getTop: getTop,
    };
})();
