/**
 * iris-stats-aggregator.js — Calcul de stats agrégées côté navigateur
 *
 * Building block pour la bascule éphémère (Task #42a — cycle APEX #29).
 *
 * Prend un workbook simple ``{columns: ["a", "b"], rows: [[v1, v2], ...]}``
 * et retourne un payload de stats agrégées (par colonne : count, null_count,
 * type_hint, min, max, mean, distinct_count_capped, top_values).
 *
 * Ce module est PUR — pas de network call, pas de DOM, pas de dépendance.
 * Peut être appelé de n'importe où côté frontend, et le payload retourné
 * est sérialisable JSON (apte à être envoyé via WebSocket en lieu et place
 * du file binaire — voir #42b/#42c pour le branchement complet).
 *
 * **Why** : la bascule éphémère élimine le stockage disque côté serveur.
 * Le LLM reçoit les stats agrégées (suffisantes pour 80% des analyses
 * "donne-moi une vue d'ensemble") au lieu du contenu brut. Defense en
 * profondeur — confidentialité par construction (les valeurs individuelles
 * ne quittent jamais le navigateur).
 *
 * **NB** : ce module ne fait PAS d'anonymisation — les top_values
 * retournés sont les valeurs CLEARTEXT vues dans la colonne. Le caller
 * (côté serveur après réception) doit passer le payload par
 * ``anonymize_for_llm`` avant injection LLM (cf. CRIT-3 doctrine 2026-05-26).
 */

(function() {
    'use strict';

    /** Cap d'unique values trackés par colonne (anti-OOM sur high-cardinality). */
    var _UNIQUE_CAP = 20;

    /** Nombre max de top_values retournés par colonne. */
    var _TOP_VALUES_MAX = 5;

    /**
     * Détecte le type hint d'une valeur cellulaire.
     * @returns {'int'|'float'|'str'|'bool'|'null'|'mixed'} — un type primitif
     *   ou 'null' pour les valeurs manquantes.
     */
    function _typeOf(v) {
        if (v === null || v === undefined) return 'null';
        if (typeof v === 'boolean') return 'bool';
        if (typeof v === 'number') {
            if (!Number.isFinite(v)) return 'null';  // NaN/Infinity = null
            return Number.isInteger(v) ? 'int' : 'float';
        }
        if (typeof v === 'string') {
            // Tente de détecter les nombres encodés en string (cas CSV)
            if (v === '') return 'null';
            var asNum = Number(v);
            if (!isNaN(asNum) && isFinite(asNum)) {
                return Number.isInteger(asNum) ? 'int' : 'float';
            }
            return 'str';
        }
        return 'mixed';
    }

    /**
     * Compose un type hint pour une colonne entière depuis la distribution
     * des types par cellule (vu via ``_typeOf``).
     *
     * Règles :
     * - tous null → 'null'
     * - tous int (ou int+null) → 'int'
     * - tous numeric (int+float, +null) → 'numeric'
     * - tous str (+null) → 'str'
     * - sinon → 'mixed:int,str' (liste triée des types non-null)
     */
    function _composeColumnType(typeCounts) {
        var nonNull = {};
        var totalNonNull = 0;
        for (var t in typeCounts) {
            if (Object.prototype.hasOwnProperty.call(typeCounts, t) && t !== 'null') {
                nonNull[t] = typeCounts[t];
                totalNonNull += typeCounts[t];
            }
        }
        if (totalNonNull === 0) return 'null';

        var types = Object.keys(nonNull).sort();
        if (types.length === 1) return types[0];

        // Numeric agrégé : int + float = numeric
        if (types.length === 2 && types.indexOf('int') >= 0 && types.indexOf('float') >= 0) {
            return 'numeric';
        }
        return 'mixed:' + types.join(',');
    }

    /**
     * Calcule les stats d'une colonne unique.
     */
    function _aggregateColumn(colName, values) {
        var nullCount = 0;
        var numericValues = [];
        var typeCounts = {};
        var distinctMap = {};  // value (stringified) → count
        var distinctOverflow = false;

        for (var i = 0; i < values.length; i++) {
            var v = values[i];
            var t = _typeOf(v);

            typeCounts[t] = (typeCounts[t] || 0) + 1;

            if (t === 'null') {
                nullCount++;
                continue;
            }

            // Numeric tracking (int/float — y compris string→numeric)
            if (t === 'int' || t === 'float') {
                var numV = typeof v === 'number' ? v : Number(v);
                if (isFinite(numV)) numericValues.push(numV);
            }

            // Distinct tracking (capped)
            var key = typeof v === 'string' ? v : JSON.stringify(v);
            if (Object.prototype.hasOwnProperty.call(distinctMap, key)) {
                distinctMap[key]++;
            } else if (Object.keys(distinctMap).length < _UNIQUE_CAP) {
                distinctMap[key] = 1;
            } else {
                distinctOverflow = true;
            }
        }

        var stat = {
            name: colName,
            type_hint: _composeColumnType(typeCounts),
            null_count: nullCount,
            distinct_count_capped: Object.keys(distinctMap).length,
            distinct_overflow: distinctOverflow,
        };

        // Numeric stats (min/max/mean/sum) si au moins 1 valeur numérique
        if (numericValues.length > 0) {
            var minV = numericValues[0];
            var maxV = numericValues[0];
            var sumV = 0;
            for (var j = 0; j < numericValues.length; j++) {
                var nv = numericValues[j];
                if (nv < minV) minV = nv;
                if (nv > maxV) maxV = nv;
                sumV += nv;
            }
            stat.numeric_stats = {
                min: minV,
                max: maxV,
                sum: sumV,
                mean: sumV / numericValues.length,
                count: numericValues.length,
            };
        }

        // Top values (capped à _TOP_VALUES_MAX, triés par count desc)
        var distinctList = Object.keys(distinctMap).map(function(k) {
            return { value: k, count: distinctMap[k] };
        });
        distinctList.sort(function(a, b) { return b.count - a.count; });
        stat.top_values = distinctList.slice(0, _TOP_VALUES_MAX);

        return stat;
    }

    /**
     * API publique — agrège un workbook en un payload de stats.
     *
     * @param {Object} workbook - { columns: string[], rows: Array<Array> }
     * @returns {Object} { row_count, column_count, column_stats: [...] }
     *
     * Fail-soft : si workbook est null/undefined/malformé, retourne un
     * payload vide (caller s'attend à un objet valide, pas à un crash).
     */
    function aggregate(workbook) {
        if (!workbook || typeof workbook !== 'object') {
            return { row_count: 0, column_count: 0, column_stats: [] };
        }
        var columns = Array.isArray(workbook.columns) ? workbook.columns : [];
        var rows = Array.isArray(workbook.rows) ? workbook.rows : [];

        var rowCount = rows.length;
        var colCount = columns.length;

        var columnStats = [];
        for (var c = 0; c < colCount; c++) {
            var colName = String(columns[c] != null ? columns[c] : ('col_' + c));
            var colValues = new Array(rowCount);
            for (var r = 0; r < rowCount; r++) {
                var row = rows[r];
                colValues[r] = Array.isArray(row) && c < row.length ? row[c] : null;
            }
            columnStats.push(_aggregateColumn(colName, colValues));
        }

        return {
            row_count: rowCount,
            column_count: colCount,
            column_stats: columnStats,
        };
    }

    // Expose API publique (CSP-safe, pas de eval)
    if (typeof window !== 'undefined') {
        window.IrisStatsAggregator = {
            aggregate: aggregate,
            // Exposé pour tests unitaires JS éventuels
            _typeOf: _typeOf,
            _composeColumnType: _composeColumnType,
            UNIQUE_CAP: _UNIQUE_CAP,
            TOP_VALUES_MAX: _TOP_VALUES_MAX,
        };
    }
})();
