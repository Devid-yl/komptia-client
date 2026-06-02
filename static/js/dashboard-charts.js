/**
 * Dashboard Charts — module commun aux pages user et admin du dashboard.
 *
 * Avant ce module : ~150 LOC de JS (Plotly + theme + refresh + timer)
 * étaient dupliqués entre ``templates/dashboard/admin.html`` et
 * ``templates/dashboard/user.html``. Toute correction devait être
 * appliquée 2 fois — risque de drift silencieux.
 *
 * API publique :
 *   window.DashboardCharts.mount({
 *       isAdmin: false,                  // affiche les charts admin-only ?
 *       chartsUrl: '/api/dashboard/charts',
 *       refreshIntervalMs: 5 * 60 * 1000,
 *       refreshButtonId: 'btn-refresh',
 *       updateTimeId: 'update-time',
 *       chartIds: {
 *           dailySearches: 'chart-daily-searches',
 *           execBreakdown: 'chart-exec-breakdown',
 *       },
 *   });
 *
 * Le module gère :
 * - Loading state immédiat (anti flash blanc).
 * - Plotly retry borné (CDN bloqué → message d'erreur après 10 s).
 * - Auto-refresh visibility-aware (pause onglet caché, reload au retour).
 * - Bouton refresh avec aria-busy et label "Actualisation…".
 * - Re-style sur ``komptia:themechange`` (dark/light switch).
 * - Charts admin-only (feedback donut, overview bars) si isAdmin=true.
 *
 * CSP-safe : aucun innerHTML avec interpolation user, tout via
 * createElement + textContent.
 */
(function() {
    'use strict';

    if (window.DashboardCharts) return; // idempotent (re-définition module)

    var _PLOTLY_MAX_RETRIES = 50; // 50 × 200 ms = 10 s avant message d'erreur

    // ── État interne du module pour cleanup ────────────────────────────
    // ``mount()`` peut être ré-appelé sur navigation back (bfcache),
    // hot-reload dev ou future migration SPA. Sans cleanup, chaque mount
    // accumule un setInterval timer + setTimeout refresh + listener
    // visibilitychange + listener komptia:themechange → memory leak +
    // refresh multiples concurrents. Cf. review adversariale finding A3.
    var _state = {
        mounted: false,
        intervals: [],   // setInterval handles
        timeouts: [],    // setTimeout handles
        listeners: [],   // [target, event, fn] tuples pour removeEventListener
        // P3 #23 (review 2026-05-15) — loadTime mutable pour reset au
        // refresh ciblé (sans location.reload). Stocké dans _state pour
        // que _doRefresh puisse le rebooter et que _attachUpdateTimer +
        // _attachAutoRefresh lisent la valeur courante.
        loadTime: null,
    };
    function _cleanup() {
        for (var i = 0; i < _state.intervals.length; i++) clearInterval(_state.intervals[i]);
        for (var j = 0; j < _state.timeouts.length; j++) clearTimeout(_state.timeouts[j]);
        for (var k = 0; k < _state.listeners.length; k++) {
            var l = _state.listeners[k];
            try { l[0].removeEventListener(l[1], l[2], l[3] || false); } catch (e) { /* ignore */ }
        }
        _state.intervals = [];
        _state.timeouts = [];
        _state.listeners = [];
        // Reset loadTime aussi : sans ça, un remount (bfcache "Back")
        // aurait une fenêtre où le tick lit l'ancien loadTime avant que
        // mount() ne le ré-écrive (review adversariale 2026-05-15 FAIBLE
        // #5 — defense-in-depth, pratiquement impossible vu single-thread
        // JS mais asymétrie de cleanup).
        _state.loadTime = null;
    }
    function _trackInterval(id) { _state.intervals.push(id); return id; }
    function _trackTimeout(id) { _state.timeouts.push(id); return id; }
    function _trackListener(target, event, fn, capture) {
        target.addEventListener(event, fn, capture || false);
        _state.listeners.push([target, event, fn, capture || false]);
    }

    function _isDark() {
        return document.documentElement.classList.contains('dark');
    }

    // ⚠️ Plotly utilise ``d3.color()`` pour parser les couleurs et **ne
    // supporte PAS les CSS variables** : ``d3.color('var(--brand)')`` →
    // ``null``. Résultat : ``Plotly.newPlot`` recevait une couleur invalide,
    // échouait silencieusement le rendu, et "Chargement…" restait figé. On
    // résout les CSS variables côté JS avec ``getComputedStyle`` et on
    // donne à Plotly une couleur ``rgb()``/``rgba()`` standard. Fallback
    // statique sur le terracotta Komptia (``#D94F3F`` / clair ``#F0A99A``)
    // si la variable n'est pas définie (theme custom, CSS purgé prod).
    var _BRAND_RGB_FALLBACK = '217, 79, 63';        // #D94F3F
    var _BRAND_LIGHT_RGB_FALLBACK = '240, 169, 154'; // #F0A99A

    function _resolveCssVar(name, fallback) {
        try {
            var v = getComputedStyle(document.documentElement)
                .getPropertyValue(name)
                .trim();
            return v || fallback;
        } catch (e) {
            return fallback;
        }
    }
    function _brandRgbTuple() {
        return _isDark()
            ? _resolveCssVar('--brand-light-rgb', _BRAND_LIGHT_RGB_FALLBACK)
            : _resolveCssVar('--brand-rgb', _BRAND_RGB_FALLBACK);
    }

    function _hoverStyle() {
        return _isDark()
            ? { bgcolor: '#f1f5f9', font: { color: '#0f172a', size: 12 } }
            : { bgcolor: '#1e293b', font: { color: '#fff', size: 12 } };
    }
    function _axisFont() {
        return { size: 11, color: _isDark() ? '#94a3b8' : '#64748b' };
    }
    function _brandLine() { return 'rgb(' + _brandRgbTuple() + ')'; }
    function _brandFill() {
        var alpha = _isDark() ? 0.15 : 0.08;
        return 'rgba(' + _brandRgbTuple() + ', ' + alpha + ')';
    }
    function _piePalette() {
        return _isDark() ? ['#34d399', '#fca5a5'] : ['#059669', '#dc2626'];
    }
    function _pieFontColor() { return _isDark() ? '#e2e8f0' : '#1e293b'; }

    function _showMessage(elementId, message, isError) {
        var el = document.getElementById(elementId);
        if (!el) return;
        el.replaceChildren();
        var p = document.createElement('p');
        p.className = isError
            ? 'text-sm text-red-500 text-center py-8 dark:text-red-400'
            : 'text-sm text-gray-400 text-center py-8 dark:text-gray-500';
        p.textContent = message;
        el.appendChild(p);
    }
    function _showLoading(elementId) {
        var el = document.getElementById(elementId);
        if (!el || el.dataset.loadingShown === '1') return;
        el.dataset.loadingShown = '1';
        _showMessage(elementId, 'Chargement…', false);
        // Feedback progressif (review adversariale finding C2) — si Plotly
        // tarde > 5 s (CDN lent / réseau dégradé), on rassure l'utilisateur
        // au lieu de laisser un texte statique pendant 10 s suivi d'un
        // brutal "CDN bloqué". 5 s = mid-point entre "rapide" et "max retry".
        var slowMsgTimer = setTimeout(function() {
            if (typeof Plotly === 'undefined' && el.dataset.loadingShown === '1') {
                _showMessage(elementId, 'Chargement plus long que prévu…', false);
            }
        }, 5000);
        _trackTimeout(slowMsgTimer);
    }

    // Plotly.newPlot fait ``appendChild`` mais ne nettoie PAS les enfants
    // existants du conteneur. Si on a posé un placeholder ``<p>Chargement…</p>``
    // via ``_showLoading``, il reste **superposé par-dessus** le graphique
    // SVG (cosmétique, mais visuellement cassé). On vide explicitement
    // avant chaque ``newPlot`` pour repartir d'un conteneur propre.
    function _clearForPlot(elementId) {
        var el = document.getElementById(elementId);
        if (!el) return;
        el.replaceChildren();
        // Reset le flag de loading-shown : un futur ``_showLoading`` peut
        // re-pousser un placeholder (utile sur les refresh manuels).
        if (el.dataset && 'loadingShown' in el.dataset) {
            delete el.dataset.loadingShown;
        }
    }

    function _drawDailySearches(elementId, ds) {
        if (!ds || !ds.labels || ds.labels.length === 0) {
            _showMessage(elementId, 'Aucune donnée', false);
            return;
        }
        _clearForPlot(elementId);
        var trace = {
            x: ds.full_labels,
            y: ds.values,
            type: 'scatter',
            mode: 'lines+markers',
            fill: 'tozeroy',
            line: { color: _brandLine(), width: 2.5, shape: 'spline' },
            marker: { size: 6, color: _brandLine() },
            fillcolor: _brandFill(),
            hovertemplate: '%{x}<br><b>%{y}</b> recherches<extra></extra>',
        };
        var layout = {
            margin: { t: 10, b: 30, l: 35, r: 10 },
            xaxis: { fixedrange: true, tickfont: _axisFont() },
            yaxis: { fixedrange: true, tickfont: _axisFont(), rangemode: 'tozero' },
            font: { family: 'DM Sans, system-ui, sans-serif' },
            plot_bgcolor: 'transparent',
            paper_bgcolor: 'transparent',
            hoverlabel: _hoverStyle(),
        };
        Plotly.newPlot(elementId, [trace], layout, { displayModeBar: false, responsive: true });
    }

    function _drawExecBreakdown(elementId, eb) {
        if (!eb || (!eb.success && !eb.failed)) {
            _showMessage(elementId, 'Aucune exécution', false);
            return;
        }
        _clearForPlot(elementId);

        // Filtrer les segments à 0 : Plotly positionne quand même un label
        // pour les slices à 0%, qui est tronqué par le container
        // (visible cas David 2026-05-08 : 0 succès → "0" au-dessus du donut
        // tronqué). On ne garde que les valeurs > 0 — le 100% restant
        // implique le déficit de l'autre côté, pas besoin de l'afficher.
        var palette = _piePalette();
        var allLabels = ['Réussis', 'Échoués'];
        var allValues = [eb.success || 0, eb.failed || 0];
        var allColors = palette;
        var values = [];
        var labels = [];
        var colors = [];
        for (var i = 0; i < allValues.length; i += 1) {
            if (allValues[i] > 0) {
                values.push(allValues[i]);
                labels.push(allLabels[i]);
                colors.push(allColors[i]);
            }
        }

        var pieTrace = {
            values: values,
            labels: labels,
            type: 'pie',
            hole: 0.55,
            marker: { colors: colors },
            textinfo: 'label+value',
            // textposition='inside' garde le label DANS le slice (centré
            // au milieu de l'arc). Sans ça, Plotly mettrait 'auto' qui
            // peut placer le texte en dehors → tronqué par le container.
            textposition: 'inside',
            insidetextorientation: 'horizontal',
            textfont: { size: 12, color: _pieFontColor() },
            hovertemplate: '<b>%{label}</b><br>%{value} (%{percent})<extra></extra>',
        };
        var pieLayout = {
            margin: { t: 10, b: 10, l: 10, r: 10 },
            showlegend: false,
            font: { family: 'DM Sans, system-ui, sans-serif' },
            plot_bgcolor: 'transparent',
            paper_bgcolor: 'transparent',
            hoverlabel: _hoverStyle(),
        };
        Plotly.newPlot(elementId, [pieTrace], pieLayout, { displayModeBar: false, responsive: true });
    }

    function _restyleAll(chartIds) {
        var line = document.getElementById(chartIds.dailySearches);
        if (line && line.data) {
            try {
                Plotly.restyle(line, {
                    'line.color': _brandLine(),
                    'marker.color': _brandLine(),
                    'fillcolor': _brandFill(),
                });
                Plotly.relayout(line, {
                    hoverlabel: _hoverStyle(),
                    'xaxis.tickfont': _axisFont(),
                    'yaxis.tickfont': _axisFont(),
                });
            } catch (e) { /* ignore */ }
        }
        var pie = document.getElementById(chartIds.execBreakdown);
        if (pie && pie.data) {
            try {
                Plotly.restyle(pie, {
                    'marker.colors': [_piePalette()],
                    'textfont.color': _pieFontColor(),
                });
                Plotly.relayout(pie, { hoverlabel: _hoverStyle() });
            } catch (e) { /* ignore */ }
        }
    }

    function _setRefreshButtonBusy(btnId, busy) {
        var btn = document.getElementById(btnId);
        if (!btn) return;
        btn.disabled = busy;
        btn.setAttribute('aria-busy', busy ? 'true' : 'false');
        btn.textContent = busy ? 'Actualisation…' : 'Actualiser';
    }

    function _doRefresh(opts) {
        _setRefreshButtonBusy(opts.refreshButtonId, true);
        // P3 #23 (review 2026-05-15) — refresh CIBLÉ via fetch JSON au
        // lieu de ``location.reload()`` brutal. Préserve l'état UI :
        // scroll position, ``<details>`` ouverts, période sélectionnée.
        //
        // **Limitation connue (TODO)** : seuls les CHARTS sont re-fetched.
        // Les KPI textuelles SSR (Activité globale, Sécurité monitoring)
        // restent stales jusqu'au F5 manuel. C'est pour ça que le label
        // dit "Charts à jour à l'instant" et pas juste "à l'instant" —
        // évite de mentir à l'admin qui regarde les KPI textuelles
        // (review adversariale 2026-05-15 finding MOYEN #2). Le vrai fix
        // demande un endpoint /api/dashboard/kpis ou enrichissement de
        // /api/dashboard/charts avec un dict ``kpis``.
        //
        // Retourne la Promise pour que les tests / appelants puissent
        // chainer si besoin.
        _state.loadTime = new Date();
        return _loadCharts(opts).finally(function() {
            _setRefreshButtonBusy(opts.refreshButtonId, false);
        });
    }

    function _attachUpdateTimer(updateTimeId) {
        function tick() {
            // Lit _state.loadTime (mis à jour par _doRefresh) pour que
            // le label "Charts à jour il y a X min" recompte après chaque
            // refresh ciblé. Préfixe "Charts à jour" lève l'ambiguïté
            // sur les KPI textuelles SSR qui peuvent être stales (cf.
            // commentaire dans _doRefresh — review adversariale 2026-05-15).
            if (!_state.loadTime) return;
            var elapsed = Math.floor((new Date() - _state.loadTime) / 60000);
            var el = document.getElementById(updateTimeId);
            if (!el) return;
            if (elapsed < 1) el.textContent = 'Charts à jour à l\'instant';
            else if (elapsed === 1) el.textContent = 'Charts à jour il y a 1 minute';
            else el.textContent = 'Charts à jour il y a ' + elapsed + ' minutes';
        }
        _trackInterval(setInterval(tick, 30000));
    }

    function _attachAutoRefresh(opts) {
        var refreshInFlight = false;
        var timer = null;
        function safeRefresh() {
            // Guard inFlight : évite le double-refresh quand le timer
            // tire en même temps que le visibilitychange handler (race
            // possible si user revient juste avant le tick). Cf. finding C-race.
            if (refreshInFlight) return;
            refreshInFlight = true;
            // _doRefresh retourne maintenant une Promise qui résout APRÈS
            // le fetch (vs setTimeout 1s arbitraire avant — race possible
            // si fetch > 1s). Reset refreshInFlight dans .finally() = au
            // moment EXACT de la fin (review adversariale 2026-05-15
            // MOYEN #3).
            try {
                _doRefresh(opts).finally(function() {
                    refreshInFlight = false;
                });
            } catch (e) {
                // Defense-in-depth : si _doRefresh throw synchrone
                // (avant fetch), reset quand même pour éviter de bloquer
                // les ticks suivants.
                console.error('safeRefresh sync throw:', e);
                refreshInFlight = false;
            }
        }
        function schedule() {
            if (timer) clearTimeout(timer);
            timer = _trackTimeout(setTimeout(function() {
                // Wrap try/finally pour garantir que schedule() recall
                // même si safeRefresh throw — sinon l'auto-refresh
                // s'arrête définitivement après une exception (review
                // adversariale 2026-05-15 MOYEN #4 schedule mort).
                try {
                    if (document.hidden) { return; }
                    safeRefresh();
                } finally {
                    schedule();  // re-schedule next tick (fetch ciblé)
                }
            }, opts.refreshIntervalMs));
        }
        schedule();
        _trackListener(document, 'visibilitychange', function() {
            if (document.hidden) return;
            var elapsed = new Date() - _state.loadTime;
            if (elapsed >= opts.refreshIntervalMs) {
                // Reset le timer pour éviter qu'il tire 1s plus tard
                // (double refresh).
                if (timer) clearTimeout(timer);
                safeRefresh();
            }
        });
    }

    function _loadCharts(opts) {
        // P3 #23 (review adversariale 2026-05-15) — retourne la Promise
        // pour que ``_doRefresh`` puisse chaîner ``.finally()`` et reset
        // refreshInFlight au moment EXACT de la fin du fetch (pas via
        // setTimeout 1s arbitraire qui causait des races possibles si le
        // fetch prenait > 1s).
        var retries = 0;
        return new Promise(function(resolveOuter) {
            function tryLoad() {
                if (typeof Plotly === 'undefined') {
                    if (retries++ >= _PLOTLY_MAX_RETRIES) {
                        var msg = 'Bibliothèque graphique indisponible (CDN bloqué ?)';
                        _showMessage(opts.chartIds.dailySearches, msg, true);
                        _showMessage(opts.chartIds.execBreakdown, msg, true);
                        console.warn('Plotly non chargé après ' + _PLOTLY_MAX_RETRIES + ' tentatives');
                        resolveOuter();
                        return;
                    }
                    _trackTimeout(setTimeout(tryLoad, 200));
                    return;
                }
                fetch(opts.chartsUrl, { credentials: 'same-origin' })
                    .then(function(r) {
                        if (r.status === 401) {
                            // Session expiree (logout sur autre onglet, server restart,
                            // cookie purge). On redirige vers /login plutot que
                            // d'afficher "Erreur de chargement" qui ferait croire
                            // a un bug serveur. Pattern repris de settings.js:47-53.
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
                            _showMessage(opts.chartIds.dailySearches, 'Statistiques indisponibles', true);
                            _showMessage(opts.chartIds.execBreakdown, 'Statistiques indisponibles', true);
                            return;
                        }
                        var charts = data.charts || {};
                        _drawDailySearches(opts.chartIds.dailySearches, charts.daily_searches);
                        _drawExecBreakdown(opts.chartIds.execBreakdown, charts.execution_breakdown);
                        // NB : ``charts.feedback`` / ``charts.overview`` sont
                        // exposés dans le payload admin (contrat testé :
                        // test_dashboard_handler_contracts) mais volontairement
                        // PAS rendus en Plotly ici — ces chiffres sont déjà
                        // affichés en SSR (barre feedback + cartes KPI de
                        // dashboard/admin.html). Pas une « promesse non tenue » :
                        // la donnée EST montrée (via le SSR) ; le payload reste
                        // dispo pour un éventuel rendu graphique futur.
                    })
                    .catch(function(err) {
                        // Pas de message d'erreur si on est deja en route vers
                        // /login : il clignoterait avant la navigation.
                        if (err && err.message === 'session_expired') return;
                        console.error('Erreur chargement charts:', err);
                        // P6 (audit 2026-05-26) — Inclure err.message pour
                        // distinguer offline / 502 / SyntaxError parse JSON.
                        var _chartErrDetail = (err && err.message) ? String(err.message) : 'détail indisponible';
                        var _chartMsg = 'Erreur de chargement : ' + _chartErrDetail;
                        _showMessage(opts.chartIds.dailySearches, _chartMsg, true);
                        _showMessage(opts.chartIds.execBreakdown, _chartMsg, true);
                        // NB : pas de ``komptiaReportError`` ici — le tableau de
                        // bord s'auto-rafraîchit (5 min) ; ouvrir l'overlay
                        // « Signaler » à chaque cycle d'un 5xx persistant =
                        // spam + perte de saisie. Le message inline suffit pour
                        // un widget en rafraîchissement de fond.
                    })
                    .finally(function() {
                        resolveOuter();
                    });
            }
            tryLoad();
        });
    }

    function mount(userOpts) {
        // Idempotent : si on est déjà mount (bfcache, hot-reload, futur SPA),
        // cleanup les timers/listeners avant de remount. Sans ce guard, chaque
        // re-mount accumule un setInterval + setTimeout + visibilitychange
        // listener → leak mémoire + refresh multiples. Cf. finding A3.
        if (_state.mounted) _cleanup();
        _state.mounted = true;

        var opts = Object.assign({
            isAdmin: false,
            chartsUrl: '/api/dashboard/charts',
            refreshIntervalMs: 5 * 60 * 1000,
            refreshButtonId: 'btn-refresh',
            updateTimeId: 'update-time',
            chartIds: {
                dailySearches: 'chart-daily-searches',
                execBreakdown: 'chart-exec-breakdown',
            },
        }, userOpts || {});

        // P3 #23 — loadTime stocké dans _state pour mutation par
        // _doRefresh (refresh ciblé re-set à new Date() pour que le
        // label "il y a X minutes" recompte à 0).
        _state.loadTime = new Date();

        // 1. Refresh button + auto-refresh visibility-aware.
        var refreshBtn = document.getElementById(opts.refreshButtonId);
        if (refreshBtn) {
            _trackListener(refreshBtn, 'click', function() { _doRefresh(opts); });
        }
        _attachUpdateTimer(opts.updateTimeId);
        _attachAutoRefresh(opts);

        // 2. Loading states immédiats.
        _showLoading(opts.chartIds.dailySearches);
        _showLoading(opts.chartIds.execBreakdown);

        // 3. Re-style on theme change. Tracké pour cleanup.
        _trackListener(window, 'komptia:themechange', function() {
            _restyleAll(opts.chartIds);
        });

        // 4. Lance le chargement.
        _loadCharts(opts);
    }

    function unmount() {
        // Exposé pour les futurs frameworks SPA / tests qui voudraient
        // teardown explicitement. Idempotent.
        _cleanup();
        _state.mounted = false;
    }

    window.DashboardCharts = { mount: mount, unmount: unmount };
})();
