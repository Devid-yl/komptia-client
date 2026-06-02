/**
 * Info Tooltip — composant réutilisable.
 *
 * Pour TOUT bouton ``.info-icon[data-info]`` dans le DOM, attache un
 * comportement "click → popover". L'info-text est dans ``data-info`` (string
 * pure) — JAMAIS interprété comme HTML (textContent uniquement, défense XSS).
 *
 * Doctrine :
 * 1. Click ≠ hover. Le brief KOMPTIA impose le clic explicite (hover frustre
 *    sur tactile/trackpad et n'est pas accessible au clavier).
 * 2. Un seul tooltip ouvert à la fois (close-on-other-open).
 * 3. Click outside / Escape ferment.
 * 4. ARIA : aria-expanded, aria-controls (lien icône↔popover), role="tooltip".
 * 5. Position auto : flip à gauche si on déborde du viewport à droite.
 * 6. CSP-safe : aucun innerHTML, aucun eval, créé via createElement.
 * 7. Idempotent : guard ``window.__komptiaInfoTooltipInitialized``.
 *
 * Le composant ajoute le SVG "i" à l'icône au boot (les templates n'ont qu'à
 * écrire ``<button class="info-icon" data-info="...">``, sans inner SVG).
 */
(function() {
    'use strict';

    if (window.__komptiaInfoTooltipInitialized) return;
    window.__komptiaInfoTooltipInitialized = true;

    var TOOLTIP_ID_PREFIX = 'komptia-info-';
    var _activeTooltip = null;
    var _tooltipCounter = 0;
    // Bug 2026-05-26 (F4 MOYEN — request user explicite) : on ajoute un mode
    // hover-après-délai en complément du click. L'idée : sur desktop, l'admin
    // n'a plus besoin de cliquer pour voir l'info — un survol prolongé suffit.
    // Le click reste comme fallback (a11y clavier + tactile + intent explicite).
    // Délai 800ms : standard UX desktop (Material Design 350-500ms, Bootstrap
    // 600ms ; Komptia choisit 800ms pour réduire les ouvertures involontaires
    // au mousemove). N'affecte PAS la valeur par défaut click.
    var HOVER_OPEN_DELAY_MS = 800;
    var HOVER_CLOSE_DELAY_MS = 200;  // grace period quand on quitte le button
    var _hoverOpenTimer = null;
    var _hoverCloseTimer = null;

    function _buildSvgIcon() {
        // SVG "i" minimal. Construit via createElementNS pour respecter le
        // namespace SVG (sinon l'élément n'est pas reconnu comme SVG par le
        // navigateur). Pas d'innerHTML.
        var svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
        svg.setAttribute('viewBox', '0 0 16 16');
        svg.setAttribute('width', '8');
        svg.setAttribute('height', '8');
        svg.setAttribute('fill', 'currentColor');
        svg.setAttribute('aria-hidden', 'true');
        var path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
        // "i" = un petit cercle + une barre verticale
        path.setAttribute('d',
            'M8 0a8 8 0 1 0 0 16A8 8 0 0 0 8 0zM7.05 4.5a.95.95 0 1 1 1.9 0 .95.95 0 0 1-1.9 0zM7 7h2v5H7V7z'
        );
        svg.appendChild(path);
        return svg;
    }

    function _ensureIconContent(button) {
        // Si le bouton n'a pas encore son SVG (template écrit juste
        // <button class="info-icon">…</button>), on l'injecte.
        if (button.querySelector('svg')) return;
        // On garde le textContent vide pour ne pas mélanger avec le SVG.
        button.textContent = '';
        button.appendChild(_buildSvgIcon());
    }

    function _closeActive() {
        if (!_activeTooltip) return;
        var t = _activeTooltip;
        _activeTooltip = null;
        t.tooltip.classList.remove('info-tooltip--open');
        if (t.button.classList.contains('info-icon')) {
            t.button.setAttribute('aria-expanded', 'false');
            t.button.removeAttribute('aria-controls');
        } else {
            t.button.removeAttribute('aria-describedby');
        }
        // Délai pour laisser l'animation finir avant de retirer du DOM —
        // idiomatique CSS transition.
        setTimeout(function() {
            if (t.tooltip.parentNode) t.tooltip.parentNode.removeChild(t.tooltip);
        }, 200);
    }

    function _positionTooltip(tooltip, button) {
        // Position en absolu autour de l'icône. On lit getBoundingClientRect
        // (viewport-relative) et on traduit en page-relative via window
        // scrollX/Y.
        var rect = button.getBoundingClientRect();
        tooltip.classList.remove('info-tooltip--left', 'info-tooltip--top');

        // ── Position verticale : sous l'icône par défaut, AU-DESSUS si on
        //    déborde par le bas du viewport (typique d'un i dans un footer
        //    ou en pied d'une modale tout en bas de l'écran). Sans ça le
        //    message sort de l'écran et l'utilisateur ne le voit jamais.
        var spaceBelow = window.innerHeight - rect.bottom;
        var spaceAbove = rect.top;
        var tooltipH = tooltip.offsetHeight || 0;
        var placeAbove = spaceBelow < (tooltipH + 12) && spaceAbove > spaceBelow;
        var top = placeAbove
            ? (rect.top + window.scrollY - tooltipH - 6)
            : (rect.bottom + window.scrollY + 6);
        tooltip.style.top = top + 'px';
        if (placeAbove) tooltip.classList.add('info-tooltip--top');

        // ── Position horizontale : alignée à gauche par défaut, flip à
        //    droite si déborde. Borne mini pour ne pas sortir à gauche.
        var left = rect.left + window.scrollX - 6;
        tooltip.style.left = left + 'px';
        var rightOverflow = (rect.left + tooltip.offsetWidth + 12) - window.innerWidth;
        if (rightOverflow > 0) {
            var flippedLeft = rect.right + window.scrollX - tooltip.offsetWidth + 6;
            tooltip.style.left = Math.max(8, flippedLeft) + 'px';
            tooltip.classList.add('info-tooltip--left');
        }
    }

    function _openTooltip(button) {
        // Lit ``data-info`` (pattern bouton "i" cliquable) OU ``data-tooltip``
        // (pattern inline sur label/div sans bouton visible — 2026-05-27).
        var info = button.getAttribute('data-info') || button.getAttribute('data-tooltip');
        if (!info) return;
        _closeActive();

        var tooltip = document.createElement('div');
        tooltip.className = 'info-tooltip';
        tooltip.setAttribute('role', 'tooltip');
        var id = TOOLTIP_ID_PREFIX + (++_tooltipCounter);
        tooltip.id = id;
        // textContent : zéro risque XSS, même si data-info contient du HTML.
        tooltip.textContent = info;

        // F4 (2026-05-26) : laisse l'utilisateur survoler le tooltip lui-même
        // sans qu'il se ferme (cas typique : lire un long texte). Le close ne
        // se déclenche que quand la souris quitte ET le bouton ET le tooltip.
        tooltip.addEventListener('mouseenter', _cancelHoverClose);
        tooltip.addEventListener('mouseleave', _onMouseLeave);

        document.body.appendChild(tooltip);
        // ARIA : ``aria-expanded``/``aria-controls`` ne sont valides que sur un
        // élément interactif (le bouton « i »). Sur un host inline (label/span/p
        // via ``data-tooltip``) ils sont INVALIDES (axe « aria-* not allowed on
        // role »). On utilise alors ``aria-describedby`` (valide sur tout
        // élément + relation tooltip correcte vers ``role="tooltip"``).
        if (button.classList.contains('info-icon')) {
            button.setAttribute('aria-expanded', 'true');
            button.setAttribute('aria-controls', id);
        } else {
            button.setAttribute('aria-describedby', id);
        }

        _positionTooltip(tooltip, button);
        // Trigger CSS transition au tick suivant.
        requestAnimationFrame(function() { tooltip.classList.add('info-tooltip--open'); });

        _activeTooltip = { tooltip: tooltip, button: button };
    }

    function _onButtonClick(ev) {
        // stopPropagation : empêche le click outside listener de s'auto-
        // fermer immédiatement après l'ouverture.
        // preventDefault : si l'icône est imbriquée dans un ``<a href="...">``
        // (cf. KPI cards user.html qui sont des liens vers /iris, /reports…),
        // le navigateur peut considérer le clic sur le button comme un clic
        // sur l'ancre parente et naviguer. preventDefault bloque ce trigger.
        ev.stopPropagation();
        ev.preventDefault();
        var button = ev.currentTarget;
        var isOpen = button.getAttribute('aria-expanded') === 'true';
        if (isOpen) _closeActive();
        else _openTooltip(button);
    }

    function _cancelHoverOpen() {
        if (_hoverOpenTimer) {
            clearTimeout(_hoverOpenTimer);
            _hoverOpenTimer = null;
        }
    }

    function _cancelHoverClose() {
        if (_hoverCloseTimer) {
            clearTimeout(_hoverCloseTimer);
            _hoverCloseTimer = null;
        }
    }

    function _onMouseEnter(ev) {
        // F4 (2026-05-26) : ouverture après délai de survol. On annule toute
        // fermeture pendante (cas où l'user re-survole pendant la grace period).
        _cancelHoverClose();
        var button = ev.currentTarget;
        // Déjà ouvert → ne rien faire (ev re-trigger sur child elements).
        if (_activeTooltip && _activeTooltip.button === button) return;
        _cancelHoverOpen();
        _hoverOpenTimer = setTimeout(function () {
            _hoverOpenTimer = null;
            _openTooltip(button);
        }, HOVER_OPEN_DELAY_MS);
    }

    function _onMouseLeave(_ev) {
        // Annule l'ouverture en attente. Si déjà ouvert, ferme après grace
        // period (laisse à l'user le temps de bouger sur le tooltip lui-même).
        _cancelHoverOpen();
        _cancelHoverClose();
        if (!_activeTooltip) return;
        _hoverCloseTimer = setTimeout(function () {
            _hoverCloseTimer = null;
            _closeActive();
        }, HOVER_CLOSE_DELAY_MS);
    }

    function _attach(button) {
        if (button.dataset.infoBound === '1') return;
        button.dataset.infoBound = '1';
        button.setAttribute('type', 'button');
        button.setAttribute('aria-expanded', 'false');
        if (!button.hasAttribute('aria-label')) {
            // Fallback : si l'auteur du template a oublié l'aria-label, on
            // prend les 60 premiers caractères de data-info — pas idéal mais
            // mieux qu'un bouton sans nom accessible.
            var info = button.getAttribute('data-info') || '';
            button.setAttribute('aria-label', 'Information : ' + info.slice(0, 60));
        }
        _ensureIconContent(button);
        button.addEventListener('click', _onButtonClick);
        // F4 (2026-05-26) : hover-after-delay branchés en complément du click.
        button.addEventListener('mouseenter', _onMouseEnter);
        button.addEventListener('mouseleave', _onMouseLeave);
        // Focus clavier déclenche aussi l'ouverture (consistent avec hover).
        button.addEventListener('focus', _onMouseEnter);
        button.addEventListener('blur', _onMouseLeave);
    }

    // 2026-05-27 — Pattern "inline tooltip" : même comportement hover-après-
    // délai que le bouton "i", mais SANS bouton visible. L'élément (label,
    // div, span…) porte ``data-tooltip="..."`` et reçoit automatiquement
    // ``cursor: help`` + listeners hover/focus. Utilisé sur les formulaires
    // admin (ex. /admin/ai-config section Paramètres RAG) pour épurer l'UI
    // sans sacrifier la pédagogie ni l'accessibilité.
    function _attachInline(el) {
        if (el.dataset.tooltipBound === '1') return;
        el.dataset.tooltipBound = '1';
        // Curseur help pour signaler visuellement qu'une info est disponible
        // au survol. Posé en JS pour ne pas dupliquer le style dans chaque
        // template.
        if (!el.style.cursor) el.style.cursor = 'help';
        el.addEventListener('mouseenter', _onMouseEnter);
        el.addEventListener('mouseleave', _onMouseLeave);
        // Si l'élément est focusable nativement, on branche aussi focus/blur
        // pour le clavier. Pour les non-focusables (label, div), on ajoute
        // tabindex=0 pour les rendre accessibles ; mais cela perturbe la
        // navigation Tab habituelle — donc on ne le fait QUE si l'auteur
        // l'a explicitement demandé via data-tooltip-focusable="1".
        if (el.getAttribute('data-tooltip-focusable') === '1') {
            if (!el.hasAttribute('tabindex')) el.setAttribute('tabindex', '0');
            el.addEventListener('focus', _onMouseEnter);
            el.addEventListener('blur', _onMouseLeave);
        }
    }

    function _attachAll() {
        var buttons = document.querySelectorAll('button.info-icon[data-info]');
        for (var i = 0; i < buttons.length; i++) _attach(buttons[i]);
        // Pattern inline (sans bouton "i").
        var inlineEls = document.querySelectorAll('[data-tooltip]');
        for (var j = 0; j < inlineEls.length; j++) {
            // Évite de re-binder un .info-icon qui aurait les deux attributs.
            if (inlineEls[j].classList && inlineEls[j].classList.contains('info-icon')) continue;
            _attachInline(inlineEls[j]);
        }
    }

    // Click outside ferme le tooltip actif.
    document.addEventListener('click', function(ev) {
        if (!_activeTooltip) return;
        if (_activeTooltip.button.contains(ev.target)) return;
        if (_activeTooltip.tooltip.contains(ev.target)) return;
        _closeActive();
    });

    // Escape ferme.
    document.addEventListener('keydown', function(ev) {
        if (ev.key === 'Escape' && _activeTooltip) {
            _closeActive();
            // Ne pas perdre le focus utilisateur — rendre au bouton.
            try { _activeTooltip && _activeTooltip.button.focus(); } catch (e) {}
        }
    });

    // Re-position si l'utilisateur scroll/resize pendant qu'un tooltip est
    // ouvert (sinon il reste accroché à une position périmée).
    window.addEventListener('scroll', function() {
        if (_activeTooltip) _positionTooltip(_activeTooltip.tooltip, _activeTooltip.button);
    }, true);
    window.addEventListener('resize', function() {
        if (_activeTooltip) _positionTooltip(_activeTooltip.tooltip, _activeTooltip.button);
    });

    // Init au DOM ready + re-scan en MutationObserver (pour les KPI ajoutés
    // dynamiquement par fetch — ex. /api/ai/usage qui injecte des rows).
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', _attachAll);
    } else {
        _attachAll();
    }

    // ── MutationObserver avec debounce rAF ────────────────────────────
    // Sans debounce : sur lazy-load admin /api/ai/usage qui injecte ~50
    // rows séquentielles, le callback s'exécute 50 fois → 50
    // querySelectorAll → O(N²) de coût. Sur Iris (DOM thrash WebSocket),
    // c'est encore pire. On accumule les nodes ajoutés dans un Set et on
    // traite à la frame suivante via requestAnimationFrame.
    // Cf. review adversariale finding C1.
    var _pendingNodes = new Set();
    var _flushScheduled = false;
    function _processPending() {
        _flushScheduled = false;
        var nodes = Array.from(_pendingNodes);
        _pendingNodes.clear();
        for (var i = 0; i < nodes.length; i++) {
            var n = nodes[i];
            if (!n || n.nodeType !== 1) continue;
            // Élément directement matchant
            if (n.matches && n.matches('button.info-icon[data-info]')) _attach(n);
            // Pattern inline data-tooltip sur l'élément lui-même.
            if (
                n.matches
                && n.matches('[data-tooltip]')
                && !(n.classList && n.classList.contains('info-icon'))
            ) {
                _attachInline(n);
            }
            // Descendants (cas typique : un container ajouté avec N boutons)
            if (n.querySelectorAll) {
                var found = n.querySelectorAll('button.info-icon[data-info]');
                for (var k = 0; k < found.length; k++) _attach(found[k]);
                // Descendants inline (label/div avec data-tooltip).
                var inlineFound = n.querySelectorAll('[data-tooltip]');
                for (var m = 0; m < inlineFound.length; m++) {
                    if (inlineFound[m].classList && inlineFound[m].classList.contains('info-icon')) continue;
                    _attachInline(inlineFound[m]);
                }
            }
        }
    }
    var observer = new MutationObserver(function(mutations) {
        for (var i = 0; i < mutations.length; i++) {
            var added = mutations[i].addedNodes;
            for (var j = 0; j < added.length; j++) _pendingNodes.add(added[j]);
        }
        if (!_flushScheduled && _pendingNodes.size > 0) {
            _flushScheduled = true;
            (window.requestAnimationFrame || function(cb) { setTimeout(cb, 16); })(_processPending);
        }
    });
    observer.observe(document.body || document.documentElement, { childList: true, subtree: true });
})();
