/**
 * Setup checklist admin (T2.1) — overlay modal pleine page.
 *
 * Pattern : ``fixed inset-0`` + backdrop assombri + card centrée.
 * - Click sur le backdrop (hors card) → ferme l'overlay.
 * - ESC → ferme l'overlay.
 * - Click sur la card → interactions normales (marquer fait, aller, masquer).
 *
 * Cohérent avec le pattern de ``onboarding-tour.js`` (les 5 tours guidés).
 * Cf. feedback ``feedback_onboarding_overlay_non_bloquant.md`` (2026-05-18) :
 * tout l'onboarding Komptia = overlay modal pleine page click-outside-close.
 *
 * Fetch ``/api/admin/tenant-setup`` au load. Tour ``welcome`` auto-posé au
 * premier affichage (signal humain de visite de /admin par opposition à un
 * healthcheck/script). Si user non-admin (401/403 sur le fetch), no-op.
 *
 * CSP-safe : tout via createElement + textContent + classes Tailwind.
 * Aucun innerHTML, aucune dépendance externe.
 */
(function () {
    'use strict';

    if (window.__komptiaTenantSetupChecklistInit) return;
    window.__komptiaTenantSetupChecklistInit = true;

    var CONTAINER_ID = 'tenant-setup-checklist-container';
    var STATE_ENDPOINT = '/api/admin/tenant-setup';
    var MILESTONE_ENDPOINT = '/api/admin/tenant-setup/milestone';
    var DISMISS_ENDPOINT = '/api/admin/tenant-setup/dismiss';

    // Mapping ordonné des jalons → libellé FR + URL cible. Ordre = ordre UI.
    var MILESTONES = [
        {
            key: 'welcome',
            field: 'welcome_seen_at',
            label: 'Bienvenue',
            hint: 'Confirmer que vous avez vu cette checklist.',
            href: null,
        },
        {
            key: 'database',
            field: 'database_configured_at',
            label: 'Connecter votre base de données',
            hint: 'Renseignez et testez votre serveur SQL Server.',
            href: '/admin/database',
        },
        {
            key: 'llm',
            field: 'llm_configured_at',
            label: 'Configurer un modèle d’IA',
            hint: 'Collez la clé API d’un fournisseur LLM (Anthropic, Mistral, etc.).',
            href: '/admin/ai-config',
        },
        {
            key: 'smtp',
            field: 'smtp_configured_at',
            label: 'Configurer l’envoi d’emails',
            hint: 'Renseignez le serveur SMTP pour les rapports automatiques.',
            href: '/admin/smtp-config',
        },
        {
            key: 'first_user',
            field: 'first_user_invited_at',
            label: 'Inviter votre premier collaborateur',
            hint: 'Créez un compte non-admin pour un utilisateur de votre équipe.',
            // /admin = home admin (rend ``templates/admin/users.html``).
            // /admin/users n'existe PAS dans routes.py (bug pré-2026-05-26 :
            // un clic depuis la checklist tombait sur 404 silencieusement).
            // Régression bloquée par ``tests/unit/test_tenant_setup_checklist_routes.py``.
            href: '/admin',
        },
    ];

    function _el(tag, className, text) {
        var node = document.createElement(tag);
        if (className) node.className = className;
        if (text != null) node.textContent = String(text);
        return node;
    }

    function _getXsrfToken() {
        try {
            var m = document.cookie.match(/(?:^|;)\s*_xsrf=([^;\s]+)/);
            return m ? decodeURIComponent(m[1]) : '';
        } catch (e) {
            return '';
        }
    }

    function _fetchJSON(url, options) {
        var opts = options || {};
        var method = opts.method || 'GET';
        var headers = { 'Accept': 'application/json' };
        if (method !== 'GET') {
            var token = _getXsrfToken();
            if (token) headers['X-Xsrftoken'] = token;
            if (opts.body) headers['Content-Type'] = 'application/json';
        }
        return fetch(url, {
            method: method,
            credentials: 'same-origin',
            headers: headers,
            body: opts.body || undefined,
        }).then(function (resp) {
            if (!resp.ok) {
                return Promise.reject(new Error('HTTP ' + resp.status));
            }
            return resp.json();
        });
    }

    // ── State global ──
    // Référence du conteneur d'overlay actuellement monté (singleton).
    // Permet à _renderOverlay de remplacer le précédent sans laisser de DOM
    // orphelin, et à _closeOverlay de nettoyer proprement.
    var _activeOverlay = null;
    var _activeKeyHandler = null;

    function _closeOverlay() {
        if (_activeKeyHandler) {
            document.removeEventListener('keydown', _activeKeyHandler);
            _activeKeyHandler = null;
        }
        if (_activeOverlay && _activeOverlay.parentNode) {
            _activeOverlay.parentNode.removeChild(_activeOverlay);
        }
        _activeOverlay = null;
    }

    function _renderOverlay(state) {
        // Nettoie l'overlay précédent s'il existe (ré-render après action).
        _closeOverlay();

        // Le serveur retourne les jalons à PLAT dans le payload (cf.
        // TenantSetupProgress.to_dict()) — PAS dans un sub-dict ``milestones``.
        // Cette version corrige le bug du code précédent qui lisait
        // ``state.milestones[field]`` (toujours undefined → faux négatifs).
        if (state.should_hide_banner) {
            return;
        }

        var done = 0;
        for (var i = 0; i < MILESTONES.length; i++) {
            if (state[MILESTONES[i].field]) done++;
        }
        var total = MILESTONES.length;

        // ── Overlay backdrop (pleine page, click-outside-close) ──
        // ``fixed inset-0`` couvre toute la viewport. ``bg-black/50`` =
        // backdrop semi-transparent (page reste visible derrière mais
        // assombrie). z-index très élevé pour passer au-dessus de la
        // sidebar et de tout autre contenu.
        var overlay = _el(
            'div',
            'fixed inset-0 z-[9999] flex items-center justify-center bg-black/50 p-4 overflow-y-auto'
        );
        overlay.setAttribute('role', 'dialog');
        overlay.setAttribute('aria-modal', 'true');
        overlay.setAttribute('aria-labelledby', 'tenant-setup-title');

        // Click sur le backdrop (mais pas sur la card) = close.
        overlay.addEventListener('click', function (ev) {
            if (ev.target === overlay) _closeOverlay();
        });

        // ── Card centrée ──
        var card = _el(
            'div',
            'bg-white dark:bg-gray-900 rounded-lg shadow-xl max-w-2xl w-full max-h-[90vh] overflow-y-auto p-6 border border-amber-200 dark:border-amber-800/60'
        );

        // Header
        var header = _el('div', 'flex items-start justify-between gap-3 mb-4 flex-wrap');
        var titleWrap = _el('div');
        var title = _el(
            'h2',
            'text-base font-semibold text-gray-900 dark:text-gray-100',
            'Komptia est presque prête'
        );
        title.id = 'tenant-setup-title';
        var subtitle = _el(
            'p',
            'text-sm text-gray-600 mt-0.5 dark:text-gray-300',
            'Il reste ' + (total - done) + ' étape(s) sur ' + total + ' pour terminer la configuration.'
        );
        titleWrap.appendChild(title);
        titleWrap.appendChild(subtitle);

        // Bouton X (fermeture overlay — fonctionnellement identique à un
        // click backdrop ou ESC ; ne dismisse pas le tour côté serveur).
        var closeBtn = _el(
            'button',
            'text-gray-400 hover:text-gray-600 text-xl leading-none focus:outline-none focus:ring-2 focus:ring-gray-400 rounded dark:text-gray-500 dark:hover:text-gray-300',
            '×'
        );
        closeBtn.type = 'button';
        closeBtn.setAttribute('aria-label', 'Fermer');
        closeBtn.addEventListener('click', _closeOverlay);

        header.appendChild(titleWrap);
        header.appendChild(closeBtn);
        card.appendChild(header);

        // Progress bar
        var progressOuter = _el(
            'div',
            'h-1.5 bg-gray-200 rounded-full overflow-hidden mb-4 dark:bg-gray-800'
        );
        var progressInner = _el('div', 'h-full bg-emerald-500 transition-all dark:bg-emerald-400');
        progressInner.style.width = total ? Math.round((done / total) * 100) + '%' : '0%';
        progressOuter.appendChild(progressInner);
        card.appendChild(progressOuter);

        // Milestones list
        var list = _el('ul', 'space-y-3 mb-4');
        for (var j = 0; j < MILESTONES.length; j++) {
            list.appendChild(_renderMilestone(MILESTONES[j], state, j + 1));
        }
        card.appendChild(list);

        // Footer : bouton dismiss (masque définitivement côté serveur).
        var footer = _el(
            'div',
            'pt-3 border-t border-gray-200 dark:border-gray-800 flex justify-end'
        );
        var dismissBtn = _el(
            'button',
            'text-xs text-gray-500 hover:text-gray-700 underline-offset-2 hover:underline focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-gray-400 rounded px-1 dark:text-gray-400 dark:hover:text-gray-200',
            'Masquer définitivement (je sais ce que je fais)'
        );
        dismissBtn.type = 'button';
        dismissBtn.addEventListener('click', function () {
            if (dismissBtn.disabled) return;
            dismissBtn.disabled = true;
            _dismiss().then(function (result) {
                if (result) {
                    _closeOverlay();
                } else {
                    dismissBtn.disabled = false;
                }
            });
        });
        footer.appendChild(dismissBtn);
        card.appendChild(footer);

        overlay.appendChild(card);
        document.body.appendChild(overlay);
        _activeOverlay = overlay;

        // ESC ferme l'overlay (a11y standard pour les dialog).
        _activeKeyHandler = function (ev) {
            if (ev.key === 'Escape') {
                ev.preventDefault();
                _closeOverlay();
            }
        };
        document.addEventListener('keydown', _activeKeyHandler);
    }

    function _renderMilestone(milestone, state, position) {
        var isDone = !!state[milestone.field];
        var li = _el('li', 'flex items-start gap-3');

        // Status icon (SVG inline CSP-safe).
        var iconWrap = _el('span', 'mt-0.5 flex-shrink-0');
        var iconSvg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
        iconSvg.setAttribute(
            'class',
            'w-5 h-5 ' + (isDone ? 'text-emerald-500' : 'text-gray-400')
        );
        iconSvg.setAttribute('fill', 'none');
        iconSvg.setAttribute('stroke', 'currentColor');
        iconSvg.setAttribute('viewBox', '0 0 24 24');
        iconSvg.setAttribute('aria-hidden', 'true');
        if (isDone) {
            var checkPath = document.createElementNS('http://www.w3.org/2000/svg', 'path');
            checkPath.setAttribute('stroke-linecap', 'round');
            checkPath.setAttribute('stroke-linejoin', 'round');
            checkPath.setAttribute('stroke-width', '2');
            checkPath.setAttribute('d', 'M5 13l4 4L19 7');
            iconSvg.appendChild(checkPath);
        } else {
            var circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
            circle.setAttribute('cx', '12');
            circle.setAttribute('cy', '12');
            circle.setAttribute('r', '9');
            circle.setAttribute('stroke-width', '2');
            iconSvg.appendChild(circle);
        }
        iconWrap.appendChild(iconSvg);

        // Texte
        var textWrap = _el('div', 'flex-1 min-w-0');
        var labelText = _el(
            'div',
            'text-sm font-medium ' +
                (isDone
                    ? 'text-gray-500 line-through dark:text-gray-500'
                    : 'text-gray-900 dark:text-gray-100'),
            position + '. ' + milestone.label
        );
        textWrap.appendChild(labelText);
        var hint = _el('p', 'text-xs text-gray-500 mt-0.5 dark:text-gray-400', milestone.hint);
        textWrap.appendChild(hint);

        // Action buttons
        var actions = _el('div', 'flex items-center gap-2 flex-shrink-0');
        if (!isDone) {
            if (milestone.href) {
                var link = _el(
                    'a',
                    'text-xs text-gray-600 hover:text-gray-900 underline-offset-2 hover:underline dark:text-gray-400 dark:hover:text-gray-100',
                    'Aller →'
                );
                link.href = milestone.href;
                actions.appendChild(link);
            }
            var markBtn = _el(
                'button',
                'text-xs text-emerald-600 hover:text-emerald-700 hover:underline focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-emerald-400 rounded px-1 dark:text-emerald-400 dark:hover:text-emerald-300',
                'Marquer comme fait'
            );
            markBtn.type = 'button';
            markBtn.addEventListener('click', function () {
                if (markBtn.disabled) return;
                markBtn.disabled = true;
                _setMilestone(milestone.key).then(function (newState) {
                    if (newState) {
                        _renderOverlay(newState);
                    } else {
                        markBtn.disabled = false;
                    }
                });
            });
            actions.appendChild(markBtn);
        }

        li.appendChild(iconWrap);
        li.appendChild(textWrap);
        li.appendChild(actions);
        return li;
    }

    function _setMilestone(key) {
        return _fetchJSON(MILESTONE_ENDPOINT, {
            method: 'POST',
            body: JSON.stringify({ milestone: key }),
        }).catch(function () {
            return null;
        });
    }

    function _dismiss() {
        return _fetchJSON(DISMISS_ENDPOINT, { method: 'POST' }).catch(function () {
            return null;
        });
    }

    async function init() {
        // Le conteneur partial reste dans la page (pour rétrocompatibilité
        // mais n'est plus utilisé comme cible de rendu inline — on rend
        // dans body via _renderOverlay).
        if (!document.getElementById(CONTAINER_ID)) {
            // Pas de partial inclus = page non-admin. Skip silencieux.
            return;
        }
        try {
            var state = await _fetchJSON(STATE_ENDPOINT);
            // Auto-pose ``welcome`` au premier load — signal humain de visite
            // de /admin (par opposition à un healthcheck/curl). Best-effort,
            // ne casse pas l'affichage si l'écriture échoue.
            if (state && !state.welcome_seen_at) {
                var updated = await _setMilestone('welcome');
                if (updated) state = updated;
            }
            _renderOverlay(state);
        } catch (e) {
            // 401/403 (non-admin) ou réseau down → overlay invisible.
            // Silencieux : pas d'erreur visible côté user normal.
        }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
