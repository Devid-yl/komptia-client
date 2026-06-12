/**
 * grid-store.js — Stockage à étages pour les DONNÉES volumineuses des grilles.
 *
 * Pourquoi : la persistance des grilles SQL (``GridTabManager`` dans
 * ``iris-grid.js``) écrivait le dataset complet (jusqu'à ~10 000 lignes ×
 * N colonnes, format objet répétant les noms de colonnes) dans
 * ``localStorage`` — un pool ~5 Mo PARTAGÉ pour tout le site, synchrone,
 * string-only. Un ``SELECT *`` large saturait le quota → toast « Stockage
 * local plein » + perte du tri/filtres au refresh (cf.
 * ``docs/design/grid_storage_tiered_indexeddb.md``).
 *
 * Ce module déplace le GROS volume vers **IndexedDB** (asynchrone, capacité
 * centaines de Mo–Go, *structured clone* = pas de ``JSON.stringify`` géant),
 * tandis que l'INTENTION légère (tri/filtres/colonnes) reste en
 * ``localStorage`` synchrone côté ``iris-grid.js``. IndexedDB n'était utilisé
 * nulle part — c'est le primitif adapté aux datasets structurés.
 *
 * Contrat :
 *   - Best-effort : aucune méthode ne ``throw`` vers l'appelant (l'intention
 *     en localStorage reste le filet ; le backend reste la source de vérité).
 *   - Fallback : si IndexedDB indisponible (Safari privé ancien, IDB désactivé
 *     par politique), retombe sur ``localStorage`` sous un préfixe DISTINCT
 *     (``gs1:``) pour ne JAMAIS écraser l'état *light* stocké sous le
 *     ``persistId`` nu.
 *   - Scoping : la clé porte déjà l'identifiant user (``grid-{user}-…`` /
 *     ``u{id}-dash…``). Inchangé ici → isolation cross-user préservée.
 *   - Device-only : rien n'est envoyé au serveur (doctrine confidentialité
 *     Komptia : données Sage restent ON-DEVICE).
 *
 * API (tout async sauf ``isAvailable``) :
 *   GridStore.put(key, value)            → Promise<{ok, reason?}>
 *   GridStore.get(key)                   → Promise<any|null>
 *   GridStore.del(key)                   → Promise<void>
 *   GridStore.sweep({prefixes, maxAgeMs})→ Promise<number>  (clés purgées)
 *   GridStore.keys(prefix?)              → Promise<string[]>
 *   GridStore.isAvailable()              → boolean  (best-effort)
 *   GridStore.requestPersistent()        → Promise<boolean>
 *
 * Chargé AVANT iris-grid.js (hard dependency) via le partial
 * ``templates/partials/_grid_deps.html``.
 */
(function () {
    'use strict';

    var DB_NAME = 'komptia_grid';
    var DB_VERSION = 1;
    var STORE = 'heavy';
    // Préfixe du chemin de repli localStorage. DISTINCT du persistId nu pour
    // ne pas clobberer l'état "intention" (light) qu'iris-grid stocke sous la
    // clé persistId elle-même.
    var FALLBACK_PREFIX = 'gs1:';
    // Marge sous le quota localStorage (~5 Mo, UTF-16) pour le repli : on
    // refuse d'écrire un blob > 4 000 000 chars (≈ même borne que l'AutoRecover
    // historique) plutôt que de lever QuotaExceededError.
    var FALLBACK_MAX_CHARS = 4000000;

    // Promesse d'ouverture mémoïsée. Résout vers IDBDatabase ou null (→ repli).
    // Remise à null sur échec TRANSITOIRE pour autoriser une re-tentative.
    var _dbPromise = null;
    // ``null`` = inconnu, ``true``/``false`` = résultat d'ouverture observé.
    var _idbWorks = null;
    // Demande de stockage persistant (anti-éviction) faite une seule fois.
    var _persistRequested = false;

    function _hasIndexedDB() {
        try {
            return (typeof indexedDB !== 'undefined') && indexedDB !== null;
        } catch (e) {
            // Accès à ``indexedDB`` peut throw en iframe sandboxée / privé.
            return false;
        }
    }

    function _openDB() {
        if (_dbPromise) return _dbPromise;
        // Absence d'IndexedDB = condition PERMANENTE : on ne mémoïse pas (re-check
        // à coût nul), on retombe direct sur le repli localStorage.
        if (!_hasIndexedDB()) {
            _idbWorks = false;
            return Promise.resolve(null);
        }
        _dbPromise = new Promise(function (resolve) {
            // Échec TRANSITOIRE (onblocked = autre onglet sur une version différente,
            // onerror ponctuel, open() qui throw) : on remet ``_dbPromise = null``
            // pour autoriser une RE-TENTATIVE au prochain appel. Sinon une erreur
            // passagère figerait tout le module en repli localStorage pour la
            // session entière (régression du pool 5 Mo qu'on veut justement fuir).
            function failTransient() {
                _idbWorks = false;
                _dbPromise = null;
                resolve(null);
            }
            var req;
            try {
                req = indexedDB.open(DB_NAME, DB_VERSION);
            } catch (e) {
                failTransient();
                return;
            }
            req.onupgradeneeded = function () {
                try {
                    var db = req.result;
                    if (!db.objectStoreNames.contains(STORE)) {
                        // Clés out-of-line (on passe la clé à put/get) : la clé
                        // EST le persistId, pas un champ du payload.
                        db.createObjectStore(STORE);
                    }
                } catch (e) { /* defensive */ }
            };
            req.onsuccess = function () {
                _idbWorks = true;
                var db = req.result;
                // Si une autre version est demandée ailleurs, ne pas bloquer.
                try {
                    db.onversionchange = function () { try { db.close(); } catch (e) {} _dbPromise = null; };
                } catch (e) { /* defensive */ }
                // Anti-éviction : demander le stockage persistant UNE fois, à la
                // première ouverture réussie (best-effort, silencieux). Sans ça,
                // le bucket reste « best-effort » → évincible sous pression disque.
                if (!_persistRequested) {
                    _persistRequested = true;
                    try { requestPersistent(); } catch (e) { /* noop */ }
                }
                resolve(db);
            };
            req.onerror = failTransient;
            req.onblocked = failTransient;
        });
        return _dbPromise;
    }

    function _tx(db, mode) {
        return db.transaction(STORE, mode).objectStore(STORE);
    }

    function _reqToPromise(req) {
        return new Promise(function (resolve, reject) {
            req.onsuccess = function () { resolve(req.result); };
            req.onerror = function () { reject(req.error); };
        });
    }

    // ── Repli localStorage (préfixe distinct) ─────────────────────────────
    function _fbKey(key) { return FALLBACK_PREFIX + key; }

    function _fbPut(key, value) {
        try {
            var json = JSON.stringify(value);
            if (json.length > FALLBACK_MAX_CHARS) {
                return { ok: false, reason: 'too_large' };
            }
            localStorage.setItem(_fbKey(key), json);
            return { ok: true };
        } catch (e) {
            var quota = e && (e.name === 'QuotaExceededError'
                || e.code === 22 || e.code === 1014);
            return { ok: false, reason: quota ? 'quota' : 'unavailable' };
        }
    }

    function _fbGet(key) {
        try {
            var raw = localStorage.getItem(_fbKey(key));
            if (!raw) return null;
            return JSON.parse(raw);
        } catch (e) { return null; }
    }

    function _fbDel(key) {
        try { localStorage.removeItem(_fbKey(key)); } catch (e) { /* noop */ }
    }

    // ── API publique ──────────────────────────────────────────────────────

    function put(key, value) {
        if (!key) return Promise.resolve({ ok: false, reason: 'no_key' });
        return _openDB().then(function (db) {
            if (!db) return _fbPut(key, value);
            return new Promise(function (resolve) {
                try {
                    var store = _tx(db, 'readwrite');
                    var req = store.put(value, key);
                    req.onsuccess = function () { resolve({ ok: true }); };
                    req.onerror = function () {
                        // Quota IDB (rare) ou autre → tenter le repli.
                        resolve(_fbPut(key, value));
                    };
                } catch (e) {
                    resolve(_fbPut(key, value));
                }
            });
        }).catch(function () { return _fbPut(key, value); });
    }

    function get(key) {
        if (!key) return Promise.resolve(null);
        return _openDB().then(function (db) {
            if (!db) return _fbGet(key);
            return _reqToPromise(_tx(db, 'readonly').get(key))
                .then(function (v) {
                    // Migration / repli antérieur : si rien en IDB, regarder LS.
                    return (v === undefined || v === null) ? _fbGet(key) : v;
                })
                .catch(function () { return _fbGet(key); });
        }).catch(function () { return _fbGet(key); });
    }

    function del(key) {
        if (!key) return Promise.resolve();
        // Toujours nettoyer le repli aussi (défensif, anti-orphelin).
        _fbDel(key);
        return _openDB().then(function (db) {
            if (!db) return;
            return _reqToPromise(_tx(db, 'readwrite').delete(key)).catch(function () {});
        }).catch(function () {});
    }

    function _matchesAnyPrefix(key, prefixes) {
        if (!prefixes || !prefixes.length) return true;
        for (var i = 0; i < prefixes.length; i++) {
            if (key.indexOf(prefixes[i]) === 0) return true;
        }
        return false;
    }

    /**
     * Purge par TTL : si ``maxAgeMs`` est fourni, supprime les enregistrements
     * dont ``_savedAt`` est absent (legacy) OU plus vieux que ``maxAgeMs``. Si
     * ``maxAgeMs`` est null/absent, NE purge rien (pas de critère d'âge → no-op,
     * voulu : les seuls appelants passent toujours un TTL). ``prefixes``
     * (optionnel) limite aux clés voulues. Balaie IndexedDB ET le repli localStorage.
     */
    function sweep(opts) {
        opts = opts || {};
        var prefixes = opts.prefixes || null;
        var maxAgeMs = (typeof opts.maxAgeMs === 'number' && opts.maxAgeMs > 0)
            ? opts.maxAgeMs : null;
        var now = _now();
        var purged = 0;

        // 1) Repli localStorage (synchrone).
        try {
            var toRemove = [];
            for (var i = 0; i < localStorage.length; i++) {
                var lk = localStorage.key(i);
                if (!lk || lk.indexOf(FALLBACK_PREFIX) !== 0) continue;
                var bareKey = lk.slice(FALLBACK_PREFIX.length);
                if (!_matchesAnyPrefix(bareKey, prefixes)) continue;
                var stale = true;
                if (maxAgeMs !== null) {
                    try {
                        var parsed = JSON.parse(localStorage.getItem(lk));
                        var savedAt = parsed && parsed._savedAt;
                        stale = !savedAt || (now - savedAt) > maxAgeMs;
                    } catch (e) { stale = true; }
                }
                if (stale) toRemove.push(lk);
            }
            for (var j = 0; j < toRemove.length; j++) {
                try { localStorage.removeItem(toRemove[j]); purged++; } catch (e) {}
            }
        } catch (e) { /* localStorage indispo */ }

        // 2) IndexedDB (async, via curseur).
        return _openDB().then(function (db) {
            if (!db) return purged;
            return new Promise(function (resolve) {
                try {
                    var store = _tx(db, 'readwrite');
                    var cur = store.openCursor();
                    cur.onsuccess = function () {
                        var cursor = cur.result;
                        if (!cursor) { resolve(purged); return; }
                        var key = String(cursor.key);
                        var val = cursor.value;
                        var drop = false;
                        if (_matchesAnyPrefix(key, prefixes)) {
                            if (maxAgeMs !== null) {
                                var sa = val && val._savedAt;
                                drop = !sa || (now - sa) > maxAgeMs;
                            }
                        }
                        if (drop) { try { cursor.delete(); purged++; } catch (e) {} }
                        cursor.continue();
                    };
                    cur.onerror = function () { resolve(purged); };
                } catch (e) { resolve(purged); }
            });
        }).catch(function () { return purged; });
    }

    /** Liste les clés (IDB + repli), filtrées par ``prefix`` optionnel. */
    function keys(prefix) {
        var out = [];
        try {
            for (var i = 0; i < localStorage.length; i++) {
                var lk = localStorage.key(i);
                if (!lk || lk.indexOf(FALLBACK_PREFIX) !== 0) continue;
                var bareKey = lk.slice(FALLBACK_PREFIX.length);
                if (!prefix || bareKey.indexOf(prefix) === 0) out.push(bareKey);
            }
        } catch (e) { /* noop */ }
        return _openDB().then(function (db) {
            if (!db) return out;
            return _reqToPromise(_tx(db, 'readonly').getAllKeys()).then(function (ks) {
                (ks || []).forEach(function (k) {
                    var s = String(k);
                    if ((!prefix || s.indexOf(prefix) === 0) && out.indexOf(s) === -1) {
                        out.push(s);
                    }
                });
                return out;
            }).catch(function () { return out; });
        }).catch(function () { return out; });
    }

    function isAvailable() {
        // Best-effort synchrone : ``true`` si IDB n'a pas été observé en échec.
        if (_idbWorks === false) return false;
        return _hasIndexedDB();
    }

    function requestPersistent() {
        try {
            if (navigator && navigator.storage && navigator.storage.persist) {
                return navigator.storage.persist().catch(function () { return false; });
            }
        } catch (e) { /* noop */ }
        return Promise.resolve(false);
    }

    // ``Date.now`` indirection (testabilité + un seul point d'accès horloge).
    function _now() {
        try { return Date.now(); } catch (e) { return 0; }
    }

    var GridStore = {
        put: put,
        get: get,
        del: del,
        sweep: sweep,
        keys: keys,
        isAvailable: isAvailable,
        requestPersistent: requestPersistent,
        // Exposés pour les tests de garde (non destinés à l'usage applicatif).
        _FALLBACK_PREFIX: FALLBACK_PREFIX,
        _resetForTests: function () { _dbPromise = null; _idbWorks = null; }
    };

    if (typeof window !== 'undefined') {
        window.GridStore = GridStore;
    }
    // Export CommonJS-friendly pour les tests Node (ignoré dans le navigateur).
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = GridStore;
    }
})();
