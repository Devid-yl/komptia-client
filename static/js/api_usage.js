/**
 * api_usage.js — section "Consommation API par utilisateur (30 jours)".
 *
 * Lazy-loadé via le `<details>` ``#api-usage-details`` (le partial
 * ``templates/_partials/dashboard_api_usage.html`` fournit la coquille).
 * Inclus sur les pages admin uniquement (dashboard admin + /admin/ai-config).
 *
 * CSP-safe : zéro innerHTML, tout via createElement + textContent.
 */
(function() {
    // AI-7 (2026-05-26) : symbole devise lu depuis <meta name="komptia-pricing-symbol">
    // (injecté par base.html via SSoT app.constants_ai.PRICING_CURRENCY_SYMBOL).
    // Fallback "$" pour le hot-path quand le DOM n'a pas (encore) le meta.
    var _PRICING_SYMBOL = (function () {
        try {
            var meta = document.querySelector('meta[name="komptia-pricing-symbol"]');
            if (meta && meta.content) return String(meta.content);
        } catch (e) { /* defensive */ }
        return '$';
    })();

    function fmtNum(n) {
        if (n >= 1000000) return (n / 1000000).toFixed(1) + 'M';
        if (n >= 1000) return (n / 1000).toFixed(1) + 'k';
        return String(n);
    }

    function _el(tag, className, text) {
        var node = document.createElement(tag);
        if (className) node.className = className;
        if (text != null) node.textContent = String(text);
        return node;
    }

    function _setMessage(container, message) {
        container.replaceChildren();
        var wrap = _el('div', 'px-5 py-6 text-center');
        wrap.appendChild(_el('p', 'text-sm text-gray-400 dark:text-gray-500', message));
        container.appendChild(wrap);
    }

    function _buildSummaryKPI(label, value) {
        var card = _el('div', 'bg-gray-50 rounded-lg p-3 text-center dark:bg-gray-900');
        card.appendChild(_el('p', 'text-xs text-gray-500 dark:text-gray-400', label));
        card.appendChild(_el('p', 'text-lg font-semibold text-gray-900 dark:text-gray-100', value));
        return card;
    }

    function _buildSummaryGrid(totalCost, totalTokens, totalReqs) {
        var grid = _el('div', 'grid grid-cols-3 gap-3 px-5 pt-4 pb-2');
        grid.appendChild(_buildSummaryKPI('Coût total', _PRICING_SYMBOL + totalCost.toFixed(2)));
        grid.appendChild(_buildSummaryKPI('Tokens total', fmtNum(totalTokens)));
        grid.appendChild(_buildSummaryKPI('Requêtes', fmtNum(totalReqs)));
        return grid;
    }

    function _buildTableHead() {
        var thead = document.createElement('thead');
        var tr = _el('tr', 'border-b border-gray-200 text-xs text-gray-500 uppercase dark:border-gray-800 dark:text-gray-400');
        var headers = [
            ['px-5 py-2 text-left font-medium', 'Utilisateur'],
            ['px-3 py-2 text-right font-medium', 'Requêtes'],
            ['px-3 py-2 text-right font-medium', 'Tokens'],
            ['px-3 py-2 text-right font-medium', 'Coût'],
            ['px-3 py-2 text-right font-medium', 'Succès'],
            ['px-5 py-2 text-right font-medium', 'Part'],
        ];
        headers.forEach(function(h) { tr.appendChild(_el('th', h[0], h[1])); });
        thead.appendChild(tr);
        return thead;
    }

    function _buildTokensCell(tokens, maxTokens) {
        var td = _el('td', 'px-3 py-2.5 text-right');
        var wrap = _el('div', 'flex items-center justify-end gap-2');
        var trackOuter = _el('div', 'w-16 bg-gray-100 rounded-full h-1.5 dark:bg-gray-800');
        var trackInner = _el('div', 'bg-gray-700 rounded-full h-1.5');
        var barW = Math.max(0, Math.min(100, Math.round(tokens / maxTokens * 100)));
        trackInner.style.width = barW + '%';
        trackOuter.appendChild(trackInner);
        wrap.appendChild(trackOuter);
        wrap.appendChild(_el('span', 'text-gray-700 w-14 text-right dark:text-gray-300', fmtNum(tokens)));
        td.appendChild(wrap);
        return td;
    }

    function _buildUserRow(u, totalTokens, maxTokens) {
        var pct = totalTokens > 0 ? (u.total_tokens / totalTokens * 100).toFixed(1) : '0.0';
        var costColor = u.estimated_cost_usd > 1 ? 'text-amber-600 font-semibold' : 'text-gray-700';
        var rate = Number(u.success_rate || 0);
        var rateCls = rate >= 80 ? 'text-emerald-600' : rate >= 50 ? 'text-amber-600' : 'text-red-600';
        var tr = _el('tr', 'border-b border-gray-100 hover:bg-gray-50 dark:hover:bg-gray-800 dark:border-gray-800');

        var tdUser = _el('td', 'px-5 py-2.5');
        tdUser.appendChild(_el('span', 'font-medium text-gray-900 dark:text-gray-100', u.username || ''));
        tr.appendChild(tdUser);

        tr.appendChild(_el('td', 'px-3 py-2.5 text-right text-gray-600 dark:text-gray-400', u.requests));
        tr.appendChild(_buildTokensCell(u.total_tokens, maxTokens));
        tr.appendChild(_el('td', 'px-3 py-2.5 text-right ' + costColor, _PRICING_SYMBOL + Number(u.estimated_cost_usd || 0).toFixed(2)));

        var tdSuccess = _el('td', 'px-3 py-2.5 text-right');
        tdSuccess.appendChild(_el('span', rateCls, rate + '%'));
        tr.appendChild(tdSuccess);

        tr.appendChild(_el('td', 'px-5 py-2.5 text-right text-gray-500 dark:text-gray-400', pct + '%'));
        return tr;
    }

    function _buildCallerBreakdown(byCaller) {
        // Section secondaire (drill-down) — pliée par défaut pour ne pas
        // polluer l'écran. Cohérent avec /admin/ai-config qui a le même
        // pattern <details><summary>. Les styles .chev + details[open]
        // viennent de la page parente (admin.html / ai_config.html).
        var wrap = document.createElement('details');
        wrap.className = 'mt-4 px-5';
        var summary = document.createElement('summary');
        summary.className = 'flex items-center gap-1.5 text-xs font-medium text-gray-400 uppercase mb-2 dark:text-gray-500 hover:text-gray-600 dark:hover:text-gray-300 select-none outline-none focus-visible:ring-2 focus-visible:ring-brand-500 rounded';
        // Chevron SVG + libellés via createElementNS/createElement : la
        // doctrine « zéro innerHTML » du fichier (sécurité CSP/XSS) s'applique
        // même au markup statique. Miroir de info-tooltip.js:_buildSvgIcon.
        var SVG_NS = 'http://www.w3.org/2000/svg';
        var chev = document.createElementNS(SVG_NS, 'svg');
        chev.setAttribute('class', 'chev w-3 h-3');
        chev.setAttribute('fill', 'none');
        chev.setAttribute('viewBox', '0 0 24 24');
        chev.setAttribute('stroke', 'currentColor');
        chev.setAttribute('stroke-width', '2.5');
        chev.setAttribute('aria-hidden', 'true');
        var chevPath = document.createElementNS(SVG_NS, 'path');
        chevPath.setAttribute('stroke-linecap', 'round');
        chevPath.setAttribute('stroke-linejoin', 'round');
        chevPath.setAttribute('d', 'M9 5l7 7-7 7');
        chev.appendChild(chevPath);
        summary.appendChild(chev);
        var lblMain = document.createElement('span');
        lblMain.textContent = 'Par feature';
        summary.appendChild(lblMain);
        var lblSub = document.createElement('span');
        lblSub.className = 'font-normal text-[10px] normal-case opacity-70';
        lblSub.textContent = '— origine sémantique';
        summary.appendChild(lblSub);
        wrap.appendChild(summary);
        if (!byCaller || byCaller.length === 0) {
            wrap.appendChild(_el('p', 'text-sm text-gray-400 dark:text-gray-500 pt-1', 'Aucune attribution disponible (caller non posé).'));
            return wrap;
        }
        var maxC = byCaller.reduce(function(acc, c) {
            return c.total_tokens > acc ? c.total_tokens : acc;
        }, 1);
        var body = _el('div', 'pt-1');
        byCaller.forEach(function(c) {
            if ((c.total_tokens || 0) === 0) return;
            var pct = Math.round((c.total_tokens || 0) / maxC * 100);
            var row = _el('div', 'flex items-center gap-3 mb-1');
            row.appendChild(_el('div', 'w-40 text-xs text-gray-700 truncate dark:text-gray-300', String(c.caller || '(non attribué)')));
            var bar = _el('div', 'flex-1 bg-gray-100 rounded-full h-2 dark:bg-gray-800');
            var fill = _el('div', 'bg-blue-600 rounded-full h-2');
            fill.style.width = pct + '%';
            bar.appendChild(fill);
            row.appendChild(bar);
            row.appendChild(_el('div', 'w-12 text-xs text-right text-gray-500 dark:text-gray-400', String(c.requests || 0) + 'x'));
            row.appendChild(_el('div', 'w-20 text-xs text-right text-gray-500 dark:text-gray-400', fmtNum(c.total_tokens || 0)));
            row.appendChild(_el(
                'div', 'w-16 text-xs text-right font-medium',
                (c.estimated_cost_usd || 0) > 0
                    ? _PRICING_SYMBOL + Number(c.estimated_cost_usd).toFixed(4)
                    : '-'
            ));
            body.appendChild(row);
        });
        wrap.appendChild(body);
        return wrap;
    }

    function _renderApiUsage(container, data) {
        var totalCost = data.estimated_total_cost_usd || 0;
        var totalTokens = data.total_tokens || 0;
        var totalReqs = data.total_requests || 0;
        var byUser = Array.isArray(data.by_user) ? data.by_user : [];
        var maxTokens = (byUser[0] && byUser[0].total_tokens) || 1;

        container.replaceChildren();
        container.appendChild(_buildSummaryGrid(totalCost, totalTokens, totalReqs));
        container.appendChild(_buildCallerBreakdown(data.by_caller || []));

        if (byUser.length > 0) {
            var tableWrap = _el('div', 'overflow-x-auto mt-4');
            var table = _el('table', 'w-full text-sm');
            table.appendChild(_buildTableHead());
            var tbody = document.createElement('tbody');
            byUser.forEach(function(u) {
                if (u.total_tokens === 0) return;
                tbody.appendChild(_buildUserRow(u, totalTokens, maxTokens));
            });
            table.appendChild(tbody);
            tableWrap.appendChild(table);
            container.appendChild(tableWrap);
        }
    }

    function loadApiUsage() {
        var container = document.getElementById('api-usage-container');
        if (!container) return;
        _setMessage(container, 'Chargement…');
        fetch('/api/ai/usage?days=30', { credentials: 'same-origin' })
            .then(function(r) {
                // F5 (review loop) — distinguer une vraie erreur HTTP de
                // l'empty state. Avant : ``r.json()`` direct → une 500 (ou un
                // 4xx) renvoyant ``{success:false}`` s'affichait « Aucune
                // donnée » (état FAUX silencieux), et une 401 (session expirée)
                // ne redirigeait pas vers /login. Pattern repris de
                // dashboard-charts.js:408-457 (même SSoT de gestion d'erreur).
                if (r.status === 401) {
                    window.location.href = '/login';
                    throw new Error('session_expired');
                }
                if (!r.ok) {
                    throw new Error('HTTP ' + r.status);
                }
                return r.json();
            })
            .then(function(data) {
                if (!data || !data.success) {
                    // 200 mais le service signale une indisponibilité — NE PAS
                    // afficher « aucune donnée » (qui ferait croire à 0 conso).
                    _setMessage(container, 'Consommation API indisponible pour le moment');
                    return;
                }
                var byUser = Array.isArray(data.by_user) ? data.by_user : [];
                var byCaller = Array.isArray(data.by_caller) ? data.by_caller : [];
                if (byUser.length === 0 && byCaller.length === 0 && (data.total_tokens || 0) === 0) {
                    _setMessage(container, 'Aucune donnée de consommation');
                    return;
                }
                _renderApiUsage(container, data);
            })
            .catch(function(err) {
                // Pas de message si on navigue déjà vers /login (il clignoterait).
                if (err && err.message === 'session_expired') return;
                console.error('Erreur chargement usage API:', err);
                var _detail = (err && err.message) ? String(err.message) : 'détail indisponible';
                _setMessage(container, 'Erreur de chargement : ' + _detail);
            });
    }

    /**
     * Rend SEULEMENT la table "Par utilisateur" dans un container donné.
     * Utilisé par /admin/ai-config qui a sa propre section "Consommation API"
     * et ajoute juste cette table en bas (pas de KPIs duplicates).
     */
    function renderUsersTable(container, data) {
        if (!container) return;
        var byUser = Array.isArray(data && data.by_user) ? data.by_user : [];
        if (byUser.length === 0) {
            _setMessage(container, 'Aucune attribution par utilisateur (appels système / sync).');
            return;
        }
        var totalTokens = (data && data.total_tokens) || 0;
        var maxTokens = (byUser[0] && byUser[0].total_tokens) || 1;
        container.replaceChildren();
        var table = _el('table', 'w-full text-sm');
        table.appendChild(_buildTableHead());
        var tbody = document.createElement('tbody');
        byUser.forEach(function(u) {
            if (u.total_tokens === 0) return;
            tbody.appendChild(_buildUserRow(u, totalTokens, maxTokens));
        });
        table.appendChild(tbody);
        container.appendChild(table);
    }

    // API publique pour les pages qui veulent réutiliser le rendering sans
    // dépendre du partial ``dashboard_api_usage.html`` (ex: /admin/ai-config
    // qui a sa propre section "Consommation API" et veut juste la table user).
    window.ApiUsage = {
        renderUsersTable: renderUsersTable,
    };

    function init() {
        var details = document.getElementById('api-usage-details');
        var container = document.getElementById('api-usage-container');
        if (!container) return;  // partial absent sur cette page
        var summary = details ? details.querySelector('summary') : null;
        var loaded = false;
        function ensureLoaded() {
            if (loaded) return;
            loaded = true;
            container.classList.remove('hidden');
            loadApiUsage();
        }
        function syncAria() {
            if (summary && details) {
                summary.setAttribute('aria-expanded', details.open ? 'true' : 'false');
            }
        }
        syncAria();
        if (details) {
            details.addEventListener('toggle', function() {
                syncAria();
                if (details.open) ensureLoaded();
                else container.classList.add('hidden');
            });
        } else {
            ensureLoaded();
        }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
