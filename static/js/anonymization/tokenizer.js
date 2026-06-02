/**
 * static/js/anonymization/tokenizer.js
 *
 * Module miroir JavaScript du tokenizer Python d'anonymisation
 * (`app/services/anonymization/extract.py`). Source unique côté front pour
 * éviter le drift entre les surfaces qui doivent reproduire localement la
 * tokenisation backend :
 *   - Modal d'anonymisation rendu par ``static/js/iris-grid.js`` (Iris).
 *   - Page de gestion ``static/js/privacy/privacy-page.js`` (lecture seule
 *     aujourd'hui ; pourra réutiliser ces helpers si elle ouvre une UI
 *     d'édition locale).
 *
 * **Contrat** : les fonctions exposées ici DOIVENT produire les MÊMES sorties
 * que leurs équivalents Python sur les fixtures :
 *   - ``tests/fixtures/anon_tokenizer_contract.json`` (tokenize)
 *   - ``tests/fixtures/anon_auto_pseudo_contract.json`` (autoPseudoMiddle)
 *
 * Le drift = gates 409 ANON_PENDING_REVIEW cassés (le backend refuse des
 * termes que le front n'a jamais montrés à l'utilisateur). En cas de
 * divergence : le backend GAGNE (renvoie le state réconcilié, qui écrase
 * le cache local).
 *
 * **Type** : classic script (PAS un module ES). Charger via
 *     <script src="/static/js/anonymization/tokenizer.js" nonce="…"></script>
 * AVANT tout script qui consomme ``window.AnonTokenizer``.
 *
 * **Compatibilité Node** : exporté en CommonJS pour les tests
 * (`tests/unit/test_anon_tokenizer_js.py`) — pattern identique à
 * ``static/js/privacy-badge.js``.
 */
(function() {
    'use strict';

    // Idempotence : si un autre <script> a déjà chargé ce fichier (double
    // include accidentel), on ne réécrit pas l'API exposée — un caller
    // pourrait avoir capturé une référence avant.
    if (typeof window !== 'undefined' && window.AnonTokenizer) {
        return;
    }

    // ── Constantes (miroir strict du Python) ─────────────────────────────

    //: Source de :data:`anon_terms.TOKEN_SPLIT_RE`. Exposée comme STRING +
    //: flags pour que les callers construisent leur propre RegExp et
    //: évitent de partager ``lastIndex`` (bug récurrent JS sur regex /g).
    //
    //: **Whitespace explicite (BLOCKING #12 review)** : on ne se fie PAS
    //: à ``\\s`` qui ne couvre pas exactement les mêmes points de code
    //: Unicode entre Python et JS-``u``. La liste hex correspond strictement
    //: au Python ``_WHITESPACE_CHARS`` (espace ASCII, tab, NL/CR, FF, VT,
    //: NBSP \\u00A0, NNBSP \\u202F, line-sep \\u2028, paragraph-sep \\u2029).
    //: Le NBSP est très fréquent dans les exports Excel/CSV des cabinets.
    var TOKEN_SPLIT_RE_SOURCE = '[^\\s\\u00A0\\u202F\\u2028\\u2029,;:]+';
    var TOKEN_SPLIT_RE_FLAGS = 'gu';

    //: Miroir de :data:`anon_terms.MAX_VALUE_LEN`. Tokens issus de chaînes
    //: plus longues sont skip pour éviter de polluer le state.
    var MAX_VALUE_LEN = 500;

    //: Miroir de :data:`anon_terms._GUID_FULL_RE`. Une cellule contenant
    //: un GUID/uniqueidentifier SQL Server (``8-4-4-4-12`` hex) est
    //: skippée — c'est un identifiant technique jamais métier.
    //: Sans ce filtre, les GUIDs des résultats SQL Iris (colonnes
    //: ``uniqueidentifier``) entraient en BDD via le PUT panneau
    //: (``replace_state``) car ``TOKEN_SPLIT_RE`` ne split PAS sur les
    //: tirets — un GUID complet ressort comme UN seul token de 36 chars
    //: (bug observé 2026-05-19 : 967 GUIDs polluant /data/privacy de
    //: David, prouvé via ``scripts/diag_parasitic_terms.py``).
    var GUID_FULL_RE = /^\s*[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\s*$/;

    //: Miroir de :func:`anon_terms._looks_like_binary_garbage`. Reject
    //: une string dès qu'elle contient un char control C0/C1 — ces
    //: caractères n'apparaissent JAMAIS dans du texte UTF-8 légitime,
    //: ils signalent un decode latin-1 d'un bytes SQL Server
    //: (``varbinary``/``rowversion``/``timestamp``).
    function looksLikeBinaryGarbage(s) {
        if (!s) return false;
        for (var i = 0; i < s.length; i++) {
            var cp = s.charCodeAt(i);
            // Control C0 (< 0x20) sauf tab/LF/CR — JAMAIS en texte business.
            if (cp < 0x20 && cp !== 0x09 && cp !== 0x0A && cp !== 0x0D) {
                return true;
            }
            // Control C1 (0x7F DEL + 0x80-0x9F supp) — jamais légitime.
            if (cp >= 0x7F && cp <= 0x9F) return true;
        }
        return false;
    }

    //: Miroir de :data:`anon_terms._STRUCTURAL_STOPLIST`. Tokens à ne
    //: jamais retenir (sentinelles, mots-vides FR/EN). Lookup O(1) via
    //: dict-like ``Object.create(null)``.
    var STRUCTURAL_STOPLIST = (function() {
        var s = Object.create(null);
        var entries = [
            'true', 'false', 'none', 'null', 'n/a', 'na', 'nan',
            '-', '—', '…', '...', 'oui', 'non', 'yes', 'no',
            'ok', 'ko'
        ];
        for (var i = 0; i < entries.length; i++) s[entries[i]] = 1;
        return s;
    })();

    function isStoplisted(token) {
        if (typeof token !== 'string') return false;
        return Object.prototype.hasOwnProperty.call(STRUCTURAL_STOPLIST, token);
    }

    // ── tokenizeValue ───────────────────────────────────────────────────
    //
    // Miroir de :func:`anon_terms._tokenize_value`.
    // Retourne ``string[]`` (jamais ``null``).

    function tokenizeValue(value) {
        if (value === null || value === undefined) return [];
        if (typeof value === 'boolean') return [];
        var s;
        if (typeof value === 'number') {
            // Cohérent avec ``str(value)`` Python : ``42`` → ``"42"``.
            s = String(value);
        } else if (typeof value === 'string') {
            s = value;
        } else {
            // Objets/arrays : les callers doivent les flatten avant.
            return [];
        }
        if (s.length > MAX_VALUE_LEN) return [];

        // Miroir du Python ``_tokenize_value`` (fix 2026-05-19) :
        // skip si la valeur entière est un GUID/uniqueidentifier SQL Server
        // OU si elle contient des chars control C0/C1 (bytes binaires
        // mal-décodés). Ces 2 cas n'arrivent que sur des colonnes
        // techniques (id, rowversion, varbinary) — jamais métier.
        if (GUID_FULL_RE.test(s)) return [];
        if (looksLikeBinaryGarbage(s)) return [];

        var out = [];
        // ``new RegExp`` à chaque appel : évite que le ``lastIndex`` d'un
        // regex /g soit partagé entre invocations (bug récurrent JS).
        var re = new RegExp(TOKEN_SPLIT_RE_SOURCE, TOKEN_SPLIT_RE_FLAGS);
        var m;
        while ((m = re.exec(s)) !== null) {
            if (m[0].length >= 2) out.push(m[0]);
        }
        return out;
    }

    // ── isAutoDecidable ─────────────────────────────────────────────────
    //
    // Miroir de :func:`anon_terms.is_auto_decidable`. ``true`` = système
    // peut auto-confirmer (numérique court, date, sentinelle). ``false`` =
    // l'utilisateur tranche (PII potentielle).

    var DATE_LIKE_RE = /^\d{1,4}[-/.]\d{1,4}(?:[-/.]\d{1,4})?$/;
    var NUMERIC_LIKE_RE = /^-?\d+(?:[.,]\d+)?(?:[eE][-+]?\d+)?\s*[€$£%]?$/;

    function isAutoDecidable(token) {
        if (typeof token !== 'string') return true;
        var t = token.trim();
        if (!t || t.length < 2) return true;
        if (isStoplisted(t.toLowerCase())) return true;
        if (DATE_LIKE_RE.test(t)) return true;
        if (NUMERIC_LIKE_RE.test(t)) {
            // Court (≤3 digits) → auto. Ex: "42", "100".
            var pureDigits = t.replace(/[^0-9]/g, '');
            if (pureDigits.length > 0 && pureDigits.length <= 3) return true;
            // Devise/% → auto.
            if (/[€$£%]/.test(t)) return true;
            // Décimal/scientifique → auto.
            if (/[.,]/.test(t) || /e/i.test(t)) return true;
            // Long numérique pur (4+ digits) : peut être tel/SIREN/compte —
            // l'utilisateur tranche.
            return false;
        }
        return false;
    }

    // ── md5Hex (UTF-8) ──────────────────────────────────────────────────
    //
    // MD5 pure-JS, UTF-8 via TextEncoder pour cohérence avec Python
    // ``hashlib.md5(s.encode("utf-8"))``. 32 chars hex en sortie.
    //
    // Implémentation domaine public dérivée de Paul Johnston / Joseph Myers,
    // adaptée pour TextEncoder. ``TextEncoder`` est disponible nativement
    // sur tout navigateur post-IE11 ; en Node ≥ 11 il est global.

    function md5Hex(str) {
        function add32(a, b) { return (a + b) & 0xFFFFFFFF; }
        function rol(x, n) { return (x << n) | (x >>> (32 - n)); }
        function cmn(q, a, b, x, s, t) {
            return add32(rol(add32(add32(a, q), add32(x, t)), s), b);
        }
        function ff(a, b, c, d, x, s, t) {
            return cmn((b & c) | ((~b) & d), a, b, x, s, t);
        }
        function gg(a, b, c, d, x, s, t) {
            return cmn((b & d) | (c & (~d)), a, b, x, s, t);
        }
        function hh(a, b, c, d, x, s, t) {
            return cmn(b ^ c ^ d, a, b, x, s, t);
        }
        function ii(a, b, c, d, x, s, t) {
            return cmn(c ^ (b | (~d)), a, b, x, s, t);
        }

        // UTF-8 encode : TextEncoder est le seul chemin qui produit le même
        // tableau d'octets que Python pour TOUT codepoint (BMP, emoji,
        // surrogates valides). Le fallback historique
        // ``unescape(encodeURIComponent(...))`` corrompt les surrogates
        // isolés — on l'a retiré (Komptia ne supporte pas IE).
        var bytes;
        if (typeof TextEncoder === 'undefined') {
            throw new Error('AnonTokenizer.md5Hex: TextEncoder absent');
        }
        bytes = new TextEncoder().encode(str);

        var n = bytes.length;
        var numBlocks = (((n + 8) >> 6) + 1);
        var x = new Array(numBlocks * 16);
        for (var i2 = 0; i2 < x.length; i2++) x[i2] = 0;
        for (var j = 0; j < n; j++) {
            x[j >> 2] |= bytes[j] << ((j % 4) * 8);
        }
        x[n >> 2] |= 0x80 << ((n % 4) * 8);
        x[numBlocks * 16 - 2] = n * 8;

        var a = 1732584193, b = -271733879, c = -1732584194, d = 271733878;
        for (var k = 0; k < x.length; k += 16) {
            var oa = a, ob = b, oc = c, od = d;
            a = ff(a, b, c, d, x[k + 0], 7, -680876936);
            d = ff(d, a, b, c, x[k + 1], 12, -389564586);
            c = ff(c, d, a, b, x[k + 2], 17, 606105819);
            b = ff(b, c, d, a, x[k + 3], 22, -1044525330);
            a = ff(a, b, c, d, x[k + 4], 7, -176418897);
            d = ff(d, a, b, c, x[k + 5], 12, 1200080426);
            c = ff(c, d, a, b, x[k + 6], 17, -1473231341);
            b = ff(b, c, d, a, x[k + 7], 22, -45705983);
            a = ff(a, b, c, d, x[k + 8], 7, 1770035416);
            d = ff(d, a, b, c, x[k + 9], 12, -1958414417);
            c = ff(c, d, a, b, x[k + 10], 17, -42063);
            b = ff(b, c, d, a, x[k + 11], 22, -1990404162);
            a = ff(a, b, c, d, x[k + 12], 7, 1804603682);
            d = ff(d, a, b, c, x[k + 13], 12, -40341101);
            c = ff(c, d, a, b, x[k + 14], 17, -1502002290);
            b = ff(b, c, d, a, x[k + 15], 22, 1236535329);
            a = gg(a, b, c, d, x[k + 1], 5, -165796510);
            d = gg(d, a, b, c, x[k + 6], 9, -1069501632);
            c = gg(c, d, a, b, x[k + 11], 14, 643717713);
            b = gg(b, c, d, a, x[k + 0], 20, -373897302);
            a = gg(a, b, c, d, x[k + 5], 5, -701558691);
            d = gg(d, a, b, c, x[k + 10], 9, 38016083);
            c = gg(c, d, a, b, x[k + 15], 14, -660478335);
            b = gg(b, c, d, a, x[k + 4], 20, -405537848);
            a = gg(a, b, c, d, x[k + 9], 5, 568446438);
            d = gg(d, a, b, c, x[k + 14], 9, -1019803690);
            c = gg(c, d, a, b, x[k + 3], 14, -187363961);
            b = gg(b, c, d, a, x[k + 8], 20, 1163531501);
            a = gg(a, b, c, d, x[k + 13], 5, -1444681467);
            d = gg(d, a, b, c, x[k + 2], 9, -51403784);
            c = gg(c, d, a, b, x[k + 7], 14, 1735328473);
            b = gg(b, c, d, a, x[k + 12], 20, -1926607734);
            a = hh(a, b, c, d, x[k + 5], 4, -378558);
            d = hh(d, a, b, c, x[k + 8], 11, -2022574463);
            c = hh(c, d, a, b, x[k + 11], 16, 1839030562);
            b = hh(b, c, d, a, x[k + 14], 23, -35309556);
            a = hh(a, b, c, d, x[k + 1], 4, -1530992060);
            d = hh(d, a, b, c, x[k + 4], 11, 1272893353);
            c = hh(c, d, a, b, x[k + 7], 16, -155497632);
            b = hh(b, c, d, a, x[k + 10], 23, -1094730640);
            a = hh(a, b, c, d, x[k + 13], 4, 681279174);
            d = hh(d, a, b, c, x[k + 0], 11, -358537222);
            c = hh(c, d, a, b, x[k + 3], 16, -722521979);
            b = hh(b, c, d, a, x[k + 6], 23, 76029189);
            a = hh(a, b, c, d, x[k + 9], 4, -640364487);
            d = hh(d, a, b, c, x[k + 12], 11, -421815835);
            c = hh(c, d, a, b, x[k + 15], 16, 530742520);
            b = hh(b, c, d, a, x[k + 2], 23, -995338651);
            a = ii(a, b, c, d, x[k + 0], 6, -198630844);
            d = ii(d, a, b, c, x[k + 7], 10, 1126891415);
            c = ii(c, d, a, b, x[k + 14], 15, -1416354905);
            b = ii(b, c, d, a, x[k + 5], 21, -57434055);
            a = ii(a, b, c, d, x[k + 12], 6, 1700485571);
            d = ii(d, a, b, c, x[k + 3], 10, -1894986606);
            c = ii(c, d, a, b, x[k + 10], 15, -1051523);
            b = ii(b, c, d, a, x[k + 1], 21, -2054922799);
            a = ii(a, b, c, d, x[k + 8], 6, 1873313359);
            d = ii(d, a, b, c, x[k + 15], 10, -30611744);
            c = ii(c, d, a, b, x[k + 6], 15, -1560198380);
            b = ii(b, c, d, a, x[k + 13], 21, 1309151649);
            a = ii(a, b, c, d, x[k + 4], 6, -145523070);
            d = ii(d, a, b, c, x[k + 11], 10, -1120210379);
            c = ii(c, d, a, b, x[k + 2], 15, 718787259);
            b = ii(b, c, d, a, x[k + 9], 21, -343485551);
            a = add32(a, oa); b = add32(b, ob);
            c = add32(c, oc); d = add32(d, od);
        }

        function rhex(num) {
            var hex = '0123456789abcdef', out = '';
            for (var p = 0; p < 4; p++) {
                out += hex.charAt((num >> (p * 8 + 4)) & 0x0F)
                     + hex.charAt((num >> (p * 8)) & 0x0F);
            }
            return out;
        }
        return rhex(a) + rhex(b) + rhex(c) + rhex(d);
    }

    // ── autoPseudoMiddle ────────────────────────────────────────────────
    //
    // Miroir de :func:`app.services.anonymization.extract._auto_pseudo_middle`.
    // Deux branches :
    //  - Sans voyelles (consonants === term) : numérique/date/code → ``n_{md5[:8]}``
    //    (opaque). Évite "42 → 42_a1d" qui leak la valeur d'origine.
    //  - Avec voyelles : consonnes (ou ``x`` si purement voyelles) + md5[:3].

    // POST-2026-05-19 : Format `{LABEL}_{md5[:4]}` où LABEL est résolu par
    // `resolveLabel(term, category)` ci-dessous (catégorie stockée >
    // detectPiiLabel runtime > fallback TXT/NUM). Le test cross-impl
    // (fixture v3+) bloque le drift Python <-> JS.

    function _luhnCheck(digits) {
        if (!digits || !/^\d+$/.test(digits)) return false;
        var total = 0;
        var parity = digits.length % 2;
        for (var i = 0; i < digits.length; i++) {
            var d = parseInt(digits.charAt(i), 10);
            if (i % 2 === parity) {
                d *= 2;
                if (d > 9) d -= 9;
            }
            total += d;
        }
        return total % 10 === 0;
    }

    function _luhnValidator(text) {
        var digits = String(text).replace(/\D/g, '');
        return _luhnCheck(digits);
    }

    function _ibanMod97Check(iban) {
        if (typeof iban !== 'string' || !iban) return false;
        var cleaned = iban.replace(/\s/g, '').toUpperCase();
        if (cleaned.length < 4) return false;
        var rearranged = cleaned.slice(4) + cleaned.slice(0, 4);
        var converted = '';
        for (var i = 0; i < rearranged.length; i++) {
            var c = rearranged.charAt(i);
            if (c >= '0' && c <= '9') {
                converted += c;
            } else if (c >= 'A' && c <= 'Z') {
                // A=10, B=11, ..., Z=35
                converted += String(c.charCodeAt(0) - 'A'.charCodeAt(0) + 10);
            } else {
                return false;
            }
        }
        // Long-division MOD-97 sur string : un IBAN converti peut faire
        // 30+ digits, au-delà de Number.MAX_SAFE_INTEGER. Évite BigInt
        // (non dispo IE11 / vieux nav). Pure string, O(n).
        var rem = 0;
        for (var k = 0; k < converted.length; k++) {
            rem = (rem * 10 + parseInt(converted.charAt(k), 10)) % 97;
        }
        return rem === 1;
    }

    function _nirCheck(nir) {
        if (typeof nir !== 'string' || !nir) return false;
        var digits = nir.replace(/\D/g, '');
        if (digits.length !== 15) return false;
        var body = parseInt(digits.slice(0, 13), 10);
        var key = parseInt(digits.slice(13, 15), 10);
        if (isNaN(body) || isNaN(key)) return false;
        return key === 97 - (body % 97);
    }

    function _ipv4Check(ip) {
        if (typeof ip !== 'string' || !ip) return false;
        var parts = ip.trim().split('.');
        if (parts.length !== 4) return false;
        for (var i = 0; i < parts.length; i++) {
            if (!/^\d{1,3}$/.test(parts[i])) return false;
            if (parseInt(parts[i], 10) > 255) return false;
        }
        return true;
    }

    // Miroir strict de patterns._PII_PATTERNS — ancres ^...$ pour fullmatch.
    // ORDRE = priorité en cas de chevauchement longueur identique.
    var _PII_PATTERNS = [
        { label: 'EMAIL', re: /^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$/ },
        { label: 'URL',   re: /^https?:\/\/[^\s"'<>()\[\]{}]+$/ },
        { label: 'IBAN',  re: /^[A-Z]{2}\d{2}\s?(?:[A-Z0-9]{4}\s?){5}[A-Z0-9]{1,4}$/, validate: _ibanMod97Check },
        { label: 'PHONE', re: /^(?:\+33|0)\s?[1-9](?:[\s.\-]?\d{2}){4}$/ },
        { label: 'VAT',   re: /^FR\s?\d{2}\s?\d{9}$/ },
        { label: 'NIR',   re: /^[12]\s?\d{2}\s?\d{2}\s?\d{2}\s?\d{3}\s?\d{3}\s?\d{2}$/, validate: _nirCheck },
        { label: 'SIRET', re: /^\d{3}\s?\d{3}\s?\d{3}\s?\d{5}$/, validate: _luhnValidator },
        { label: 'SIREN', re: /^\d{3}\s?\d{3}\s?\d{3}$/, validate: _luhnValidator },
        { label: 'CARD',  re: /^(?:\d[\s\-]?){12,18}\d$/, validate: _luhnValidator },
        { label: 'IP',    re: /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/, validate: _ipv4Check },
        { label: 'DATE',  re: /^(?:\d{1,2}[-/.]\d{1,2}[-/.]\d{2,4}|\d{4}-\d{1,2}-\d{1,2})$/ },
        { label: 'AMOUNT',re: /^\d{1,3}(?:[\s.]\d{3})*(?:,\d{1,2})?\s*€$/ }
    ];

    function detectPiiLabel(term) {
        if (typeof term !== 'string' || !term) return null;
        for (var i = 0; i < _PII_PATTERNS.length; i++) {
            var entry = _PII_PATTERNS[i];
            if (!entry.re.test(term)) continue;
            if (entry.validate && !entry.validate(term)) continue;
            return entry.label;
        }
        return null;
    }

    // categoryToLabel : miroir strict de patterns.category_to_label.
    // ``_CATEGORY_PREFIXES`` = liste centralisée des préfixes BDD à strip.
    // Pas de `slice(4)/slice(9)` hardcodé sur la longueur — `prefixes[i].length`
    // suit automatiquement si un nouveau préfixe (ex: ``custom_``) est ajouté
    // côté Python. Anti-pattern "code générique apparent, hardcodé en pratique"
    // évité (cf. règle GÉNÉRICITÉ Komptia).
    var _CATEGORY_PREFIXES = ['pii_', 'business_'];
    function categoryToLabel(category) {
        if (typeof category !== 'string') return 'TERM';
        var s = category.trim().toLowerCase();
        if (!s || s === 'unclassified') return 'TERM';
        for (var i = 0; i < _CATEGORY_PREFIXES.length; i++) {
            var pfx = _CATEGORY_PREFIXES[i];
            if (s.indexOf(pfx) === 0) {
                s = s.slice(pfx.length);
                break;
            }
        }
        var label = s.toUpperCase().replace(/[^A-Z0-9]/g, '');
        return label || 'TERM';
    }

    // resolveLabel : miroir de patterns.resolve_label — 3 priorités.
    function resolveLabel(term, category) {
        if (typeof term !== 'string' || !term) return 'TERM';
        var hasCategory = typeof category === 'string'
            && category.trim() !== ''
            && category.trim().toLowerCase() !== 'unclassified';
        if (hasCategory) {
            return categoryToLabel(category);
        }
        var detected = detectPiiLabel(term);
        if (detected) return detected;
        return isPureNumeric(term) ? 'NUM' : 'TXT';
    }

    function autoPseudoMiddle(term, category) {
        if (typeof term !== 'string' || !term) return '';
        var label = resolveLabel(term, category);
        var h = md5Hex(term).slice(0, 4);
        return label + '_' + h;
    }

    // ── isPureNumeric ───────────────────────────────────────────────────
    //
    // Miroir de :func:`app.services.anonymization.auto_classify._is_pure_numeric`.
    // Un token est "purement numérique" si chaque caractère est chiffre ou
    // séparateur autorisé (espace, tab, NBSP, virgule, point, plus, moins,
    // underscore, slash, deux-points) ET qu'il contient au moins un chiffre.
    // Single source of truth : utilisé par /data/privacy ET le modal Confidentialité
    // d'iris-grid pour filtrer "Numérique" / "Texte" de manière cohérente.
    var NUMERIC_ALLOWED_CHARS = ' \t 0123456789+-_.,/:';
    function isPureNumeric(term) {
        if (term === null || term === undefined) return false;
        var s = String(term).trim();
        if (!s) return false;
        var hasDigit = false;
        for (var ix = 0; ix < s.length; ix++) {
            var ch = s.charAt(ix);
            if (ch >= '0' && ch <= '9') { hasDigit = true; continue; }
            if (NUMERIC_ALLOWED_CHARS.indexOf(ch) === -1) return false;
        }
        return hasDigit;
    }

    // ── Export API ──────────────────────────────────────────────────────

    var api = {
        TOKEN_SPLIT_RE_SOURCE: TOKEN_SPLIT_RE_SOURCE,
        TOKEN_SPLIT_RE_FLAGS: TOKEN_SPLIT_RE_FLAGS,
        MAX_VALUE_LEN: MAX_VALUE_LEN,
        STRUCTURAL_STOPLIST: STRUCTURAL_STOPLIST,
        isStoplisted: isStoplisted,
        tokenizeValue: tokenizeValue,
        isAutoDecidable: isAutoDecidable,
        md5Hex: md5Hex,
        autoPseudoMiddle: autoPseudoMiddle,
        isPureNumeric: isPureNumeric,
        // Exposés pour les badges de catégorie côté UI (privacy-page.js,
        // iris-grid.js term-detail-panel.js) — single source of truth.
        categoryToLabel: categoryToLabel,
        detectPiiLabel: detectPiiLabel,
        resolveLabel: resolveLabel
    };
    // Defense-in-depth contre un script tiers (XSS contourné, extension
    // navigateur) qui monkey-patcherait ``window.AnonTokenizer.tokenizeValue``
    // pour leak les tokens. Coût zéro, freeze d'objet superficiel suffit
    // (les fonctions sont remplacées si l'attaquant écrit ``api.x = …``,
    // ``Object.freeze`` rend le slot immutable).
    if (typeof Object.freeze === 'function') {
        Object.freeze(STRUCTURAL_STOPLIST);
        Object.freeze(api);
    }

    // Exposition exclusive : navigateur → ``window``, Node → ``module.exports``.
    // Le ``else`` évite qu'une page navigateur où une extension/userscript
    // a injecté ``globalThis.module = {exports: {}}`` se retrouve avec un
    // alias fantôme dont la mutation n'est pas reflétée sur ``window``.
    if (typeof window !== 'undefined') {
        window.AnonTokenizer = api;
    } else if (typeof module !== 'undefined' && module.exports) {
        module.exports = api;
    }
})();
