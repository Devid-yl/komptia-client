// toast.js — composant global "queue de toasts" (M6 prod-loop).
//
// Remplace l'empilement inline historique de base.html (cap 5 + drop-oldest,
// TTL 3s, pas de close manuel) par une queue stricte avec mode sticky pour
// les erreurs critiques.
//
// Contrat public (inchange pour les 30+ callers existants):
//
//   window.showToast(msg, type)
//     - msg: string affiche (textContent, anti-XSS)
//     - type: 'success' | 'error' | 'warning' | 'info' (defensive: tout autre
//       type → 'info'). 'error' = sticky (reste jusqu'au dismiss manuel).
//
// Comportement:
//   - Max 3 toasts visibles simultanement (avant: 5).
//   - Au-dela, les nouveaux toasts sont mis en queue FIFO.
//   - Auto-dismiss apres 5s (avant: 3s — trop court pour lire un message
//     long, surtout en mode 'error').
//   - Mode 'error' = sticky : ne disparait pas automatiquement, l'utilisateur
//     doit cliquer le bouton de fermeture (×). Sinon une erreur critique
//     pouvait disparaitre en 3s avant d'etre vue (regression UX axe 5b/c
//     taxonomie 4-cas erreurs Komptia).
//   - Queue cap a 50 toasts (anti croissance non bornee axe Komptia 21 —
//     un fetch storm pourrait sinon remplir la RAM). Les plus anciens en
//     queue sont droppes silencieusement quand le cap est depasse.
//
// Doctrine
// --------
//  1. CSP-safe : addEventListener uniquement, zero ``onclick`` inline.
//     Charge via ``<script src="...">`` avec nonce CSP dans base.html.
//  2. Idempotent boot : ``__komptiaToastInit`` guard — re-eval du bundle ne
//     reinstalle pas le module.
//  3. Defense en profondeur :
//     - textContent (jamais innerHTML) pour le message → anti-XSS.
//     - normalizeType clamp les types non-string vers 'info' → pas de crash.
//     - clearTimeout au dismiss → pas de timer leak si user clique close.
//     - Queue capped → pas de growth non bornee.
//  4. A11y :
//     - role="alert" + aria-live="assertive" pour 'error' (interrompt la
//       lecture screen reader courante).
//     - role="status" + aria-live="polite" pour les autres (annonce non
//       interruptive).
//     - aria-label="Fermer la notification" sur le bouton ×.
//     - prefers-reduced-motion: reduce → pas de fade transition.
//  5. DOM autonome : ``ensureStack()`` cree le container ``#toastStack``
//     a la volee si absent (pas de dependance HTML stricte).
//
// Tests : ``tests/unit/test_toast_js.py`` (Node subprocess sur les helpers
// purs + garde-fous base.html). Pas de DOM dans Node.

(function () {
    'use strict';

    // ── Boot guard ────────────────────────────────────────────────────
    // Si le bundle est re-evalue (HMR dev, inclusion redondante), on
    // preserve les exports Node mais no-op le runtime DOM.
    if (typeof window !== 'undefined' && window.__komptiaToastInit) {
        if (typeof module !== 'undefined' && module.exports &&
            window.__komptiaToastExports) {
            module.exports = window.__komptiaToastExports;
        }
        return;
    }

    // ── Constants ─────────────────────────────────────────────────────
    var STACK_ID = 'toastStack';
    var MAX_VISIBLE = 3;
    var AUTO_DISMISS_MS = 5000;
    var MAX_QUEUED = 50;
    var DISMISS_ANIM_MS = 200;
    var ALLOWED_TYPES = ['success', 'error', 'warning', 'info'];

    // ── Helpers purs (testables Node) ─────────────────────────────────

    /**
     * Normalise le type en une valeur de ALLOWED_TYPES.
     *
     * Defensive : non-string, null, undefined, type inconnu → 'info'
     * (couleur neutre brand, comportement attendu pour les callers qui
     * oublient le type ou passent une valeur invalide).
     *
     * Case-insensitive : 'ERROR', 'Error', 'error' → 'error'.
     *
     * @param {*} type
     * @returns {string} l'un de ALLOWED_TYPES
     */
    function normalizeType(type) {
        if (typeof type !== 'string') return 'info';
        var t = type.toLowerCase();
        return ALLOWED_TYPES.indexOf(t) >= 0 ? t : 'info';
    }

    /**
     * Un type est-il sticky (reste jusqu'au dismiss manuel) ?
     *
     * Actuellement seul 'error' est sticky. Les autres types sont auto-
     * dismisses apres AUTO_DISMISS_MS.
     *
     * Rationale: un message d'erreur peut etre critique (echec validation,
     * action refusee, etc.) et doit rester lisible jusqu'a ce que
     * l'utilisateur l'ait pris en compte. Cf. axe Komptia 5b/c (taxonomie
     * 4-cas erreurs).
     *
     * @param {*} type (sera normalize)
     * @returns {boolean}
     */
    function isStickyType(type) {
        return normalizeType(type) === 'error';
    }

    /**
     * Delay auto-dismiss en ms, ou 0 si sticky.
     *
     * 0 = signal pour le runtime de ne pas planifier de timer (le toast
     * reste affiche jusqu'au clic sur close ×).
     *
     * @param {*} type (sera normalize)
     * @returns {number} 0 (sticky) ou AUTO_DISMISS_MS
     */
    function getAutoDismissMs(type) {
        return isStickyType(type) ? 0 : AUTO_DISMISS_MS;
    }

    /**
     * Classes Tailwind pour la couleur de fond + texte du toast.
     *
     * Aligne sur la palette historique (bg-red-600 / bg-amber-600 /
     * bg-brand-600) pour preserver la coherence visuelle avec les autres
     * surfaces Komptia (banners, modals, boutons).
     *
     * @param {*} type (sera normalize)
     * @returns {string} classes CSS
     */
    function getBgClass(type) {
        var t = normalizeType(type);
        if (t === 'error') return 'bg-red-600 text-white';
        if (t === 'warning') return 'bg-amber-600 text-white';
        if (t === 'success') return 'bg-emerald-600 text-white';
        return 'bg-brand-600 text-white'; // info
    }

    /**
     * Role ARIA pour les screen readers.
     *
     * 'alert' (error) interrompt la lecture courante du screen reader pour
     * annoncer immediatement le toast. A reserver aux messages critiques.
     *
     * 'status' (autres) est non-interruptif : le screen reader annonce a
     * la prochaine pause naturelle. Convient aux confirmations success/info.
     *
     * @param {*} type (sera normalize)
     * @returns {string} 'alert' | 'status'
     */
    function getAriaRole(type) {
        return normalizeType(type) === 'error' ? 'alert' : 'status';
    }

    /**
     * aria-live politeness associee au role.
     *
     * 'assertive' pour 'alert', 'polite' pour 'status'. Redondant avec role
     * mais explicite pour les screen readers qui implementent mal le role.
     *
     * @param {*} type (sera normalize)
     * @returns {string} 'assertive' | 'polite'
     */
    function getAriaLive(type) {
        return normalizeType(type) === 'error' ? 'assertive' : 'polite';
    }

    /**
     * Decide si un nouveau toast peut etre affiche directement ou doit
     * passer par la queue.
     *
     * Defensive : visibleCount < 0 (impossible mais defense) → traite
     * comme 0.
     *
     * @param {number} visibleCount
     * @param {number} maxVisible
     * @returns {string} 'show' | 'queue'
     */
    function computeAdmission(visibleCount, maxVisible) {
        var v = (typeof visibleCount === 'number' && visibleCount > 0)
            ? visibleCount : 0;
        var max = (typeof maxVisible === 'number' && maxVisible > 0)
            ? maxVisible : MAX_VISIBLE;
        return v < max ? 'show' : 'queue';
    }

    /**
     * Apres dismiss d'un visible, peut-on promouvoir un queued vers visible ?
     *
     * True si : il reste de la place ET il y a quelque chose en queue.
     *
     * @param {number} visibleCount (apres dismiss, deja decremente)
     * @param {number} queueLen
     * @param {number} maxVisible
     * @returns {boolean}
     */
    function computePromotion(visibleCount, queueLen, maxVisible) {
        var v = (typeof visibleCount === 'number' && visibleCount > 0)
            ? visibleCount : 0;
        var q = (typeof queueLen === 'number' && queueLen > 0)
            ? queueLen : 0;
        var max = (typeof maxVisible === 'number' && maxVisible > 0)
            ? maxVisible : MAX_VISIBLE;
        return q > 0 && v < max;
    }

    /**
     * Combien de toasts au front de la queue doivent etre droppes pour
     * respecter le cap MAX_QUEUED.
     *
     * Anti-croissance non bornee (axe Komptia 21) : sans ce cap, un fetch
     * storm (ex: 500 erreurs reseau en rafale) pourrait remplir la RAM
     * avec des objets toast en queue jamais affiches.
     *
     * @param {number} queueLen
     * @param {number} maxQueued
     * @returns {number} count a drop du front (>= 0)
     */
    function capQueue(queueLen, maxQueued) {
        var q = (typeof queueLen === 'number' && queueLen > 0)
            ? queueLen : 0;
        var max = (typeof maxQueued === 'number' && maxQueued > 0)
            ? maxQueued : MAX_QUEUED;
        return q > max ? q - max : 0;
    }

    // ── Exports Node (tests purs — pas de DOM dans Node) ──────────────
    var _exports = {
        normalizeType: normalizeType,
        isStickyType: isStickyType,
        getAutoDismissMs: getAutoDismissMs,
        getBgClass: getBgClass,
        getAriaRole: getAriaRole,
        getAriaLive: getAriaLive,
        computeAdmission: computeAdmission,
        computePromotion: computePromotion,
        capQueue: capQueue,
        // Constants exposees pour debug / tests d'integration eventuels.
        MAX_VISIBLE: MAX_VISIBLE,
        AUTO_DISMISS_MS: AUTO_DISMISS_MS,
        MAX_QUEUED: MAX_QUEUED,
    };
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = _exports;
    }

    // ── Suite : DOM/runtime — skip si pas dans browser ────────────────
    if (typeof window === 'undefined' || typeof document === 'undefined') {
        return;
    }
    window.__komptiaToastInit = true;
    window.__komptiaToastExports = _exports;

    // ── State runtime ────────────────────────────────────────────────
    var _state = {
        visible: [], // array of {id, msg, type, element, timerId}
        queue: [],   // array of {id, msg, type} (FIFO)
    };
    var _nextId = 1;

    // ── prefers-reduced-motion (reactif aux changements OS mid-session) ──
    var _reduceMotion = false;
    try {
        if (window.matchMedia) {
            var _mq = window.matchMedia('(prefers-reduced-motion: reduce)');
            _reduceMotion = _mq.matches;
            // Listener reactif : l'user peut basculer le setting OS pendant
            // la session (macOS economie d'energie, Windows Settings, etc.).
            if (typeof _mq.addEventListener === 'function') {
                _mq.addEventListener('change', function (ev) {
                    _reduceMotion = !!ev.matches;
                });
            } else if (typeof _mq.addListener === 'function') {
                // Safari < 14 fallback.
                _mq.addListener(function (ev) {
                    _reduceMotion = !!ev.matches;
                });
            }
        }
    } catch (_e) {
        _reduceMotion = false;
    }

    /**
     * Tronque un message pour l'aria-label du bouton close. Garde le contexte
     * sans devenir un mur de texte pour le screen reader.
     */
    function _shortenForAria(msg) {
        if (msg === null || typeof msg === 'undefined') return '';
        var s;
        try {
            s = String(msg);
        } catch (_e) {
            return '';
        }
        if (s.length > 50) s = s.slice(0, 50) + '…';
        return s;
    }

    // ── DOM helpers ──────────────────────────────────────────────────

    /**
     * Cree ou recupere le container ``#toastStack``. Idempotent.
     *
     * Le container est :
     *  - fixed bottom-right (preserve la position visuelle historique)
     *  - z-index 10001 (sous les system modals z-10010 mais au-dessus du
     *    contenu courant et des overlays — axe Komptia 17)
     *  - flex column-reverse : le toast le plus recent est en bas, les
     *    anciens montent (UX historique)
     *  - pointer-events none sur le container, auto sur les toasts (pour
     *    laisser cliquer "a travers" les zones vides du container)
     */
    function ensureStack() {
        if (!document.body) return null;
        var stack = document.getElementById(STACK_ID);
        if (stack) return stack;
        stack = document.createElement('div');
        stack.id = STACK_ID;
        stack.className = 'fixed bottom-4 right-4 flex flex-col-reverse gap-2 ' +
            'pointer-events-none';
        stack.style.zIndex = '10001';
        stack.style.bottom = '5rem'; // au-dessus de l'eventuel feedback button
        // role region pour permettre aux screen readers d'identifier la zone
        // de notifications globales.
        stack.setAttribute('role', 'region');
        stack.setAttribute('aria-label', 'Notifications');
        document.body.appendChild(stack);
        return stack;
    }

    /**
     * Cree l'element DOM pour un toast.
     *
     * Structure :
     *   <div role=alert|status aria-live=... class="...bg-...">
     *     <span class="...">message</span>
     *     <button aria-label="Fermer" type=button>×</button>
     *   </div>
     */
    function _renderToastElement(toast) {
        var msg = toast.msg;
        var type = toast.type;
        var el = document.createElement('div');
        el.className = 'flex items-start gap-2 pl-4 pr-1 py-2.5 rounded-lg ' +
            'text-sm font-medium shadow-lg pointer-events-auto ' +
            'max-w-md break-words ' + getBgClass(type);
        el.setAttribute('role', getAriaRole(type));
        el.setAttribute('aria-live', getAriaLive(type));
        el.setAttribute('data-toast-id', String(toast.id));
        if (!_reduceMotion) {
            el.style.transition = 'opacity ' + DISMISS_ANIM_MS + 'ms';
        }
        el.style.opacity = '1';

        // Hover-to-pause : standard UX (Bootstrap/MUI/Sonner). Sur mouseenter
        // on annule l'auto-dismiss en cours, sur mouseleave on re-arme avec
        // le delay complet (UX charitable : l'user qui survole veut lire).
        // Sticky errors n'ont pas de timer, donc pas concernes.
        el.addEventListener('mouseenter', function () {
            if (toast.timerId) {
                clearTimeout(toast.timerId);
                toast.timerId = null;
            }
        });
        el.addEventListener('mouseleave', function () {
            // Ne re-arme que si le toast est toujours visible (pas en fade)
            // et n'est pas sticky.
            if (toast.timerId === null && !isStickyType(toast.type)) {
                // Cherche si toast est encore dans visible (n'a pas ete
                // dismissed pendant le hover).
                var stillVisible = false;
                for (var i = 0; i < _state.visible.length; i++) {
                    if (_state.visible[i].id === toast.id) {
                        stillVisible = true; break;
                    }
                }
                if (stillVisible) {
                    toast.timerId = setTimeout(function () {
                        _dismissToast(toast.id);
                    }, AUTO_DISMISS_MS);
                }
            }
        });

        var span = document.createElement('span');
        span.className = 'flex-1';
        // textContent (jamais innerHTML) — anti-XSS defense en profondeur.
        // Coercion safe : null/undefined → "", objet avec toString() qui
        // throw → "" plutot que crash du composant entier.
        var safeText = '';
        if (msg !== null && typeof msg !== 'undefined') {
            try {
                safeText = String(msg);
            } catch (_e) {
                safeText = '';
            }
        }
        span.textContent = safeText;
        el.appendChild(span);

        var btn = document.createElement('button');
        btn.type = 'button';
        // aria-label avec contexte : si 3 toasts visibles, le screen reader
        // entend "Fermer : <msg court>" au lieu de 3x "Fermer la notification".
        var ariaShort = _shortenForAria(msg);
        btn.setAttribute(
            'aria-label',
            ariaShort ? ('Fermer la notification : ' + ariaShort)
                      : 'Fermer la notification'
        );
        // Tap target >= 44x44 (WCAG 2.5.5 mobile) : padding generous + min-w/h
        // explicites pour ne pas dependre du contenu textuel.
        btn.className = 'ml-1 inline-flex items-center justify-center ' +
            'text-white text-lg leading-none opacity-80 hover:opacity-100 ' +
            'focus:outline-none focus:ring-2 focus:ring-white/40 rounded';
        btn.style.minWidth = '44px';
        btn.style.minHeight = '44px';
        btn.textContent = '×';
        btn.addEventListener('click', function (ev) {
            ev.preventDefault();
            ev.stopPropagation();
            _dismissToast(toast.id);
        });
        el.appendChild(btn);

        return el;
    }

    /**
     * Dismiss un toast par son id. Idempotent : un dismiss redondant (ex:
     * timer fire apres click manuel) no-op.
     *
     * Pipeline :
     *  1. Cherche le toast dans _state.visible
     *  2. clearTimeout(timerId) (si pas sticky)
     *  3. Retire de _state.visible (anti double-exec)
     *  4. Fade out (sauf prefers-reduced-motion)
     *  5. Apres DISMISS_ANIM_MS : retire du DOM ET promote depuis queue
     *
     * ⚠️ La promotion est faite APRES le retrait DOM (pas apres splice) pour
     * preserver le cap visuel a MAX_VISIBLE. Sinon, en fetch storm, le fade
     * de l'ancien (200ms) chevauche l'append du nouveau → jusqu'a 2*MAX_VISIBLE
     * toasts visuellement simultanes, contredisant le contrat axe Komptia 17.
     */
    function _dismissToast(id) {
        var idx = -1;
        for (var i = 0; i < _state.visible.length; i++) {
            if (_state.visible[i].id === id) { idx = i; break; }
        }
        if (idx < 0) return; // deja dismissed ou inconnu
        var toast = _state.visible[idx];
        if (toast.timerId) {
            clearTimeout(toast.timerId);
            toast.timerId = null;
        }
        // Retire de _state.visible AVANT le fade pour eviter une double-
        // execution si dismiss est rappele pendant l'animation.
        _state.visible.splice(idx, 1);
        var el = toast.element;
        if (!el || !el.parentNode) {
            // Pas de DOM a animer : promote tout de suite.
            _tryPromoteFromQueue();
            return;
        }
        if (_reduceMotion) {
            el.parentNode.removeChild(el);
            _tryPromoteFromQueue();
        } else {
            el.style.opacity = '0';
            // Stocke le fade timer pour pouvoir le clearer dans
            // dismissAllToasts (sinon timers orphelins post-unmount).
            toast.fadeTimerId = setTimeout(function () {
                if (el.parentNode) el.parentNode.removeChild(el);
                toast.fadeTimerId = null;
                // Promotion APRES retrait DOM = cap visuel garanti.
                _tryPromoteFromQueue();
            }, DISMISS_ANIM_MS);
        }
    }

    /**
     * Si _state.visible a de la place et que _state.queue n'est pas vide,
     * shift le premier de la queue vers visible.
     */
    function _tryPromoteFromQueue() {
        while (computePromotion(_state.visible.length, _state.queue.length, MAX_VISIBLE)) {
            var next = _state.queue.shift();
            _showToastNow(next);
        }
    }

    /**
     * Rend immediatement un toast dans le stack + planifie l'auto-dismiss
     * si applicable.
     */
    function _showToastNow(toast) {
        var stack = ensureStack();
        if (!stack) return; // body absent (impossible apres DOMContentLoaded)
        var el = _renderToastElement(toast);
        toast.element = el;
        stack.appendChild(el);
        _state.visible.push(toast);
        var dismissMs = getAutoDismissMs(toast.type);
        if (dismissMs > 0) {
            toast.timerId = setTimeout(function () {
                _dismissToast(toast.id);
            }, dismissMs);
        } else {
            toast.timerId = null;
        }
    }

    /**
     * Public API: affiche ou enqueue un toast.
     *
     * Contrat preserve depuis l'implementation inline historique :
     *   showToast('Texte', 'error')   // sticky, doit etre cliquee
     *   showToast('Texte', 'success') // disparait apres 5s
     *   showToast('Texte')            // type 'info' par defaut, 5s
     */
    function showToast(msg, type) {
        var toast = {
            id: _nextId++,
            msg: msg,
            type: normalizeType(type),
            element: null,
            timerId: null,
        };
        if (computeAdmission(_state.visible.length, MAX_VISIBLE) === 'show') {
            _showToastNow(toast);
        } else {
            _state.queue.push(toast);
            // Cap defensif : si la queue depasse MAX_QUEUED, drop les plus
            // anciens (front). Anti-RAM-leak en fetch storm.
            var dropCount = capQueue(_state.queue.length, MAX_QUEUED);
            if (dropCount > 0) {
                _state.queue.splice(0, dropCount);
            }
        }
    }

    /**
     * Utility (debug / tests d'integration / E2E) : dismiss tous les toasts
     * visibles, clear les fade timers, ET vide la queue.
     */
    function dismissAllToasts() {
        // Copie pour iteration safe (dismiss mute _state.visible).
        var ids = _state.visible.map(function (t) { return t.id; });
        for (var i = 0; i < ids.length; i++) {
            _dismissToast(ids[i]);
        }
        // Clear immediatement les fade timers en cours (sinon orphelins
        // jusqu'a DISMISS_ANIM_MS apres le dismiss).
        for (var j = 0; j < _state.visible.length; j++) {
            if (_state.visible[j].fadeTimerId) {
                clearTimeout(_state.visible[j].fadeTimerId);
            }
        }
        _state.queue.length = 0;
    }

    /**
     * ESC handler global : dismiss le toast 'error' sticky le plus recent.
     *
     * Rationale a11y : un toast error sticky bloque potentiellement la lecture
     * d'une page (z-index, role=alert qui interrompt le screen reader). Sans
     * raccourci clavier, un user au clavier doit Tab jusqu'au bouton close
     * en traversant TOUT le contenu de page. ESC est la convention universelle
     * pour dismiss un overlay.
     *
     * ⚠️ On ne ferme QUE le top error sticky. Les modals systeme (appConfirm,
     * appShowErrors) ont z-index plus eleve et leur propre handler ESC — ils
     * doivent gagner la priorite. On verifie ``OverlayManager`` qui tient le
     * stack des overlays actifs (voir overlay-manager.js).
     */
    function _onGlobalKeyDown(ev) {
        if (ev.key !== 'Escape' && ev.keyCode !== 27) return;
        // Si un modal systeme est ouvert (OverlayManager a une layer active),
        // on le laisse gerer ESC en priorite.
        if (window.OverlayManager && typeof window.OverlayManager.hasOpen === 'function') {
            try {
                if (window.OverlayManager.hasOpen()) return;
            } catch (_e) { /* noop */ }
        }
        // Trouve le top sticky error (le plus recent = dernier dans visible).
        for (var k = _state.visible.length - 1; k >= 0; k--) {
            if (isStickyType(_state.visible[k].type)) {
                _dismissToast(_state.visible[k].id);
                ev.preventDefault();
                return;
            }
        }
    }
    document.addEventListener('keydown', _onGlobalKeyDown);

    // Expose sur window pour les callers existants (window.showToast(...) +
    // showToast(...) global sans prefix).
    window.showToast = showToast;
    window.dismissAllToasts = dismissAllToasts;
})();
