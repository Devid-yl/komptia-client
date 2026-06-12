/**
 * read-json.js — Single source of truth pour la lecture SÛRE d'une réponse
 * ``fetch`` censée renvoyer du JSON.
 *
 * Expose ``window.komptiaReadJson(resp)`` (objet global, pattern non-module
 * compat avec le reste de la codebase — cf. format-helpers.js).
 *
 *   komptiaReadJson(resp) -> Promise<{
 *     ok:         boolean,   // resp.ok
 *     status:     number,    // code HTTP (0 si réponse absente)
 *     data:       object|null,  // JSON parsé, ou null si le body n'était pas du JSON
 *     error:      string|null,  // message FR dérivé du status (null si ok)
 *     errorCode:  string|null,  // ``error_code`` machine du body si présent
 *     isHtmlError:boolean,   // true si le body est du HTML (page d'erreur nginx/proxy)
 *     tooLarge:   boolean,   // status === 413 (payload/quota trop gros)
 *     rawText:    string     // body brut (pour debug / report)
 *   }>
 *
 * POURQUOI : derrière nginx, les erreurs de la *passerelle* (413
 * ``client_max_body_size``, 429 ``limit_req``, 502/504 upstream down/timeout,
 * 403 bot-block) sont renvoyées en **HTML**, PAS en JSON — elles n'atteignent
 * jamais Tornado (dont le ``write_error`` renvoie pourtant du JSON). Un
 * ``resp.json()`` nu sur ce HTML lève ``SyntaxError: Unexpected token <`` qui
 * masque le vrai status (le bug prod du save classeur : un 413 oversize
 * apparaissait comme une "SyntaxError" inexploitable). Ce helper lit le body
 * via ``.text()`` puis tente ``JSON.parse`` — il **ne throw JAMAIS** : tout
 * chemin (HTML, JSON malformé, body déjà consommé, réponse absente) résout en
 * objet structuré. Il tue la classe d'erreurs "Unexpected token <" partout.
 *
 * NE PAS l'enfouir dans un wrap ``window.fetch`` : il consomme le body (lecture
 * unique), ce qui casserait les sites légitimes qui lisent ``.blob()`` /
 * ``.text()`` / streaming (export Excel/CSV, download). C'est un helper
 * **opt-in**, à appeler explicitement à la place de ``resp.json()``.
 *
 * Charge en <head> dans templates/base.html APRÈS format-helpers.js et AVANT
 * session-status.js, pour être dispo dans les inline scripts des templates ET
 * dans tous les modules.
 *
 * Module idempotent (boot guard ``__komptiaReadJsonInit``) — chargement
 * multiple sans risque.
 *
 * Tests : tests/js/test_read_json.mjs
 */
(function () {
    'use strict';

    var _G = (typeof globalThis !== 'undefined')
        ? globalThis
        : (typeof window !== 'undefined' ? window : this);

    // Idempotent : re-export pour Node (tests) si déjà initialisé, puis skip.
    if (_G.__komptiaReadJsonInit) {
        if (typeof module !== 'undefined' && module.exports && _G.komptiaReadJson) {
            module.exports = { komptiaReadJson: _G.komptiaReadJson };
        }
        return;
    }
    _G.__komptiaReadJsonInit = true;

    /**
     * Message utilisateur FR dérivé du status HTTP. Le message *métier* renvoyé
     * par le serveur (``data.error``) est toujours prioritaire — on ne
     * remplace que quand le body n'apporte pas d'explication (typiquement une
     * erreur de passerelle HTML qui n'a pas de ``.error``).
     *
     * Retourne ``null`` pour un status < 400 (pas une erreur).
     */
    function _messageForStatus(status, serverError) {
        if (serverError) return serverError;
        switch (status) {
            case 401:
                return 'Session expirée. Reconnectez-vous.';
            case 403:
                return 'Accès refusé.';
            case 413:
                return 'Données trop volumineuses pour le serveur.';
            case 429:
                return 'Trop de requêtes. Patientez quelques secondes.';
            case 502:
            case 503:
                return 'Serveur momentanément indisponible. Réessayez.';
            case 504:
                return 'Le serveur a mis trop de temps à répondre.';
            default:
                if (status >= 500) return 'Erreur serveur (' + status + ').';
                if (status >= 400) return 'Erreur (' + status + ').';
                return null;
        }
    }

    /** Premier caractère non-blanc (hors BOM) — pour détecter "<…" (HTML). */
    function _firstNonBlankChar(text) {
        for (var i = 0; i < text.length; i++) {
            var c = text.charAt(i);
            if (c === '﻿' || c === ' ' || c === '\t' || c === '\n' || c === '\r') {
                continue;
            }
            return c;
        }
        return '';
    }

    function komptiaReadJson(resp) {
        // Défensif : un wrap fetch peut résoudre sans Response exploitable.
        if (!resp || typeof resp.text !== 'function') {
            return Promise.resolve({
                ok: false,
                status: (resp && typeof resp.status === 'number') ? resp.status : 0,
                data: null,
                error: 'Réponse réseau invalide.',
                errorCode: null,
                isHtmlError: false,
                tooLarge: false,
                rawText: ''
            });
        }

        var status = (typeof resp.status === 'number') ? resp.status : 0;
        var ok = !!resp.ok;
        var ctype = '';
        try {
            ctype = (resp.headers && typeof resp.headers.get === 'function')
                ? (resp.headers.get('content-type') || '')
                : '';
        } catch (e) {
            ctype = '';
        }

        return resp.text().then(function (text) {
            text = text || '';
            var data = null;
            var isHtml = false;

            if (text) {
                try {
                    data = JSON.parse(text);
                } catch (parseErr) {
                    data = null;
                    // Body non-JSON : HTML probable (page d'erreur passerelle)
                    // si content-type le dit OU si le 1er caractère est "<".
                    if (ctype.indexOf('text/html') !== -1
                        || _firstNonBlankChar(text) === '<') {
                        isHtml = true;
                    }
                }
            }

            // ``data`` peut être un non-objet (ex: ``"null"`` ou ``42`` JSON
            // valides) : on garde l'accès aux champs défensif.
            var hasFields = data && typeof data === 'object';
            var errorCode = (hasFields && typeof data.error_code === 'string')
                ? data.error_code
                : null;
            var serverError = (hasFields && typeof data.error === 'string')
                ? data.error
                : null;

            return {
                ok: ok,
                status: status,
                data: data,
                error: ok ? null : _messageForStatus(status, serverError),
                errorCode: errorCode,
                isHtmlError: isHtml,
                tooLarge: status === 413,
                rawText: text
            };
        }, function () {
            // ``.text()`` a rejeté (body déjà lu, flux coupé en plein vol…).
            // On ne perd JAMAIS le status — il porte l'info actionnable.
            return {
                ok: false,
                status: status,
                data: null,
                error: _messageForStatus(status, null) || 'Lecture de la réponse impossible.',
                errorCode: null,
                isHtmlError: false,
                tooLarge: status === 413,
                rawText: ''
            };
        });
    }

    _G.komptiaReadJson = komptiaReadJson;

    if (typeof module !== 'undefined' && module.exports) {
        module.exports = { komptiaReadJson: komptiaReadJson };
    }
})();
