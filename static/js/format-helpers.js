/**
 * format-helpers.js — Single source of truth pour les formatters JS Komptia.
 *
 * Expose ``window.KomptiaFormat`` (objet global, pattern non-module compat
 * avec le reste de la codebase). 9 methodes pures :
 *
 *   dateTimeFr(input, opts)      "DD/MM/YYYY HH:MM" locale fr-FR
 *   numberFr(value, opts)        "1 234,56" (espace fine + virgule)
 *   compactNumber(value)         "1.2k" / "1.5m" / "2g"
 *   percent(used, total)         "12,3%" / "<0,1%" / "100%"
 *   durationSeconds(s)           "~30 secondes" / "~5 min" / "~2h 15min"
 *   durationMs(ms)               "234ms" / "12.40s" / "2m 15s"
 *   timeOfDay(input)             "HH:MM:SS" timezone locale
 *   fileSize(bytes)              "12 B" / "1,5 Ko" / "1,2 Mo" / "3,4 Go"
 *   tokenCount(value)            "1 234" (alias numberFr avec 0 decimale)
 *
 * Charge en <head> dans templates/base.html APRES local-datetime.js et AVANT
 * {% block scripts %} pour etre dispo dans les inline scripts des templates
 * enfantes (cf. mémoire feedback_js_load_order_base_html.md).
 *
 * Module idempotent (boot guard ``__komptiaFormatInit``) — chargement multiple
 * sans risque (defense in depth).
 *
 * Tests : tests/unit/test_format_helpers_js.py
 */
(function () {
    'use strict';

    // Compat Node (tests JS via subprocess) ET browser. ``globalThis`` est
    // dispo Node 12+ et navigateurs modernes — fallback ``window`` pour
    // anciens navigateurs sans globalThis (peu probable, defense in depth).
    var _G = (typeof globalThis !== 'undefined')
        ? globalThis
        : (typeof window !== 'undefined' ? window : this);

    // Idempotent : si module.exports existe et qu'on a déjà initialisé,
    // re-export pour Node + skip le double-init.
    if (_G.__komptiaFormatInit) {
        if (typeof module !== 'undefined' && module.exports && _G.KomptiaFormat) {
            module.exports = _G.KomptiaFormat;
        }
        return;
    }
    _G.__komptiaFormatInit = true;

    var DASH = '—'; // em dash

    // ─── Helpers internes ───────────────────────────────────────────

    function _toFiniteNumber(v) {
        if (v == null) return null;
        var n = typeof v === 'number' ? v : Number(v);
        return isFinite(n) ? n : null;
    }

    function _toDate(input) {
        if (input == null) return null;
        if (input instanceof Date) {
            return isNaN(input.getTime()) ? null : input;
        }
        try {
            var d = new Date(input);
            return isNaN(d.getTime()) ? null : d;
        } catch (_) {
            return null;
        }
    }

    function _pad2(n) {
        n = String(n);
        return n.length < 2 ? '0' + n : n;
    }

    // ─── API publique ───────────────────────────────────────────────

    var api = {};

    /**
     * dateTimeFr(input, opts) — "DD/MM/YYYY HH:MM" timezone locale.
     *
     * NB sur timezone : les ISO sans 'Z' (ex "2026-05-20T14:30") sont parsés
     * par ``new Date()`` en local time. Les ISO avec 'Z' (ex "2026-05-20T14:30Z")
     * sont parsés en UTC PUIS affichés en TZ locale du navigateur. Pour les
     * données SQL Server sans TZ info (cas Sage typique), pas de décalage.
     * Pour les datetimes UTC explicites (audit_logs), l'affichage est local.
     *
     * opts.omitMidnightTime  Si vrai et heure==00:00, retourne "DD/MM/YYYY".
     * opts.onInvalid         'dash' (default) | 'preserve' | 'null'.
     */
    api.dateTimeFr = function (input, opts) {
        opts = opts || {};
        var d = _toDate(input);
        if (!d) {
            if (opts.onInvalid === 'preserve') {
                return String(input == null ? '' : input);
            }
            if (opts.onInvalid === 'null') return null;
            return DASH;
        }
        var dd = _pad2(d.getDate());
        var mm = _pad2(d.getMonth() + 1);
        var yyyy = d.getFullYear();
        var hh = _pad2(d.getHours());
        var mi = _pad2(d.getMinutes());
        if (opts.omitMidnightTime && hh === '00' && mi === '00') {
            return dd + '/' + mm + '/' + yyyy;
        }
        return dd + '/' + mm + '/' + yyyy + ' ' + hh + ':' + mi;
    };

    /**
     * numberFr(value, opts) — "1 234,56" séparateur de milliers fin (U+202F).
     *
     * opts.maxDecimals       Default 2.
     * opts.alwaysDecimals    Default false (si vrai, force toujours .maxDecimals).
     * opts.onInvalid         'dash' (default) | 'preserve' | 'null'.
     */
    api.numberFr = function (value, opts) {
        opts = opts || {};
        var n = _toFiniteNumber(value);
        if (n == null) {
            if (opts.onInvalid === 'preserve') {
                return String(value == null ? '' : value);
            }
            if (opts.onInvalid === 'null') return null;
            return DASH;
        }
        var maxDec = opts.maxDecimals != null ? opts.maxDecimals : 2;
        var alwaysDec = !!opts.alwaysDecimals;
        var isInt = n === Math.floor(n);
        var decimals = (isInt && !alwaysDec) ? 0 : maxDec;
        var parts = n.toFixed(decimals).split('.');
        parts[0] = parts[0].replace(/\B(?=(\d{3})+(?!\d))/g, ' ');
        return parts.join(',');
    };

    /**
     * compactNumber(value) — "0" / "123" / "1.2k" / "1.5m" / "2g".
     * Pour pilules etroites (badge tokens, compteurs nav, etc.).
     * Negatifs clampes a 0 (comportement legacy preserve).
     */
    api.compactNumber = function (value) {
        var n = _toFiniteNumber(value);
        if (n == null) return DASH;
        if (n < 0) n = 0;
        if (n < 1000) return String(Math.round(n));
        if (n < 1000000) {
            var k = n / 1000;
            return (k < 10 ? k.toFixed(1).replace(/\.0$/, '') : Math.round(k)) + 'k';
        }
        if (n < 1000000000) {
            var m = n / 1000000;
            return (m < 10 ? m.toFixed(1).replace(/\.0$/, '') : Math.round(m)) + 'm';
        }
        var g = n / 1000000000;
        return (g < 10 ? g.toFixed(1).replace(/\.0$/, '') : Math.round(g)) + 'g';
    };

    /**
     * percent(used, total) — "0%" / "<0,1%" / "12,3%" / "100%".
     * Decimale virgule fr-FR. 0% pour total<=0 / used null.
     */
    api.percent = function (used, total) {
        var u = _toFiniteNumber(used);
        var t = _toFiniteNumber(total);
        if (u == null || t == null || t <= 0) return '0%';
        var pct = (u / t) * 100;
        if (pct > 0 && pct < 0.1) return '<0,1%';
        if (pct >= 100) return '100%';
        if (pct >= 10) return pct.toFixed(0) + '%';
        return pct.toFixed(1).replace('.', ',') + '%';
    };

    /**
     * durationSeconds(s) — "~30 secondes" / "~5 min 12s" / "~2h 15min".
     * Pour ETA (Iris sync, etc.). Approximation FR.
     */
    api.durationSeconds = function (s) {
        var n = _toFiniteNumber(s);
        if (n == null || n < 0) return DASH;
        var sec = Math.ceil(n);
        if (sec < 2) return 'Presque terminé...';
        if (sec < 60) return '~' + sec + ' secondes';
        if (sec < 3600) {
            var mn = Math.floor(sec / 60);
            var rs = sec % 60;
            return '~' + mn + ' min' + (rs > 0 ? ' ' + rs + 's' : '');
        }
        var h = Math.floor(sec / 3600);
        var mn2 = Math.floor((sec % 3600) / 60);
        return '~' + h + 'h' + (mn2 > 0 ? ' ' + mn2 + 'min' : '');
    };

    /**
     * durationMs(ms) — "234ms" / "12.40s" / "2m 15s".
     * Pour durees de step exec (precision ms).
     */
    api.durationMs = function (ms) {
        var n = _toFiniteNumber(ms);
        if (n == null) return DASH;
        if (n < 0) n = 0;
        if (n < 1000) return Math.round(n) + 'ms';
        if (n < 60000) return (n / 1000).toFixed(2) + 's';
        var mn = Math.floor(n / 60000);
        var sc = Math.round((n % 60000) / 1000);
        return mn + 'm ' + sc + 's';
    };

    /**
     * timeOfDay(input) — "HH:MM:SS" timezone locale.
     */
    api.timeOfDay = function (input) {
        var d = _toDate(input);
        if (!d) return DASH;
        return _pad2(d.getHours()) + ':' + _pad2(d.getMinutes()) + ':' + _pad2(d.getSeconds());
    };

    /**
     * fileSize(bytes) — "12 B" / "1,5 Ko" / "1,2 Mo" / "3,4 Go".
     * Binaire 1024. Decimale virgule fr-FR. '' pour null/NaN.
     */
    api.fileSize = function (bytes) {
        var n = _toFiniteNumber(bytes);
        if (n == null) return '';
        if (n < 0) n = 0;
        if (n < 1024) return Math.round(n) + ' B';
        var ko = n / 1024;
        if (ko < 1024) return ko.toFixed(1).replace('.', ',') + ' Ko';
        var mo = ko / 1024;
        if (mo < 1024) return mo.toFixed(1).replace('.', ',') + ' Mo';
        var go = mo / 1024;
        return go.toFixed(1).replace('.', ',') + ' Go';
    };

    /**
     * tokenCount(value) — "1 234". Alias numberFr 0 decimale, '—' si null/NaN.
     */
    api.tokenCount = function (value) {
        return api.numberFr(value, { maxDecimals: 0 });
    };

    _G.KomptiaFormat = api;

    // Node compat (subprocess tests JS — cf. tests/unit/test_*_js.py).
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = api;
    }
})();
