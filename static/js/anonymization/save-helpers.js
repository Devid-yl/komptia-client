/**
 * AnonymizationSaveHelpers — source de vérité unique pour la validation
 * client et le formatage des erreurs backend lors d'un save de termes
 * anonymisés.
 *
 * Consommé par :
 *   - ``static/js/iris-grid.js::_openAnonymizationPanel.btnSave``
 *     (modal "Confidentialité — termes à anonymiser" sur /iris,
 *     /datastore, /automations/N/edit).
 *   - ``static/js/privacy/privacy-page.js::_persistDirtyTerms``
 *     (page /data/privacy).
 *
 * Avant ce module (2026-05-20), les 2 surfaces divergaient : iris-grid
 * validait côté client + parsait les ``state_errors`` backend, privacy-page
 * envoyait sans valider et affichait un toast générique en cas d'erreur.
 * Conséquence UX : message d'erreur inférieur sur /data/privacy, friction
 * inutile pour l'utilisateur. Cf. audit btnSave 2026-05-20.
 *
 * Contrats des helpers :
 *
 * - ``validatePseudoMap(terms) → {errors: string[]}``
 *     Vérifie 3 invariants côté client :
 *       1. Pseudonyme ne doit pas contenir ``§`` (sentinelle du tokenizer
 *          Komptia ; collision écraserait le mécanisme d'anonymisation).
 *       2. Pseudonyme ≠ terme (sinon le LLM voit la valeur réelle, pas
 *          d'anonymisation effective).
 *       3. Pseudonyme unique entre termes activés (sinon le LLM verrait
 *          2 valeurs réelles différentes mappées sur le même token →
 *          collision de désanonymisation).
 *     Seuls les termes ``enabled=true && pseudo`` sont validés (un terme
 *     non activé ou sans pseudo custom n'a pas de mapping à valider).
 *
 * - ``formatStateErrors(arr) → string``
 *     Formate la liste ``data.state_errors`` renvoyée par le backend
 *     (cf. ``app/handlers/anonymization.py:370``) en un message lisible
 *     pour l'utilisateur. Joint plusieurs erreurs avec ``•``.
 *
 * Pas d'export modules (Komptia = vanilla JS, IIFE → namespace global).
 */
(function() {
    'use strict';

    /**
     * @typedef {Object} PseudoEntry
     * @property {boolean} [enabled]
     * @property {string}  [pseudo]
     */

    /**
     * Valide une map ``{term: PseudoEntry}`` avant envoi au PUT.
     * Pure function — ne mute pas ``terms``.
     *
     * Invariants vérifiés :
     *   1. Pseudo ne contient pas ``§`` (sentinelle tokenizer).
     *   2. Pseudo ≠ terme (après ``.trim()`` — un user qui tape
     *      ``"DUPONT "`` avec espace trailing pense écrire ``"DUPONT"``).
     *   3. Pseudos uniques entre termes activés (collision).
     *   4. Pseudo ≠ un AUTRE terme activé (cross-term collision —
     *      sinon le LLM voit le nom d'un terme comme pseudo d'un autre,
     *      anonymisation cassée par confusion sémantique).
     *
     * Adversarial review 2026-05-20 : sans (2.bis trim), un trailing
     * space passe la validation client mais peut violer l'invariant
     * côté backend. Sans (4 cross-term), l'user peut nommer son pseudo
     * comme un autre terme et le LLM verra le nom réel sans le savoir.
     *
     * **Contrat de clé** : ``terms[k]`` où ``k = term string brut`` (le
     * nom du terme tel que persisté côté backend par ``replace_state``,
     * cf. ``app/services/anonymization/repository.py``). Les 2 surfaces
     * consommatrices passent cette forme :
     *   - iris-grid : ``draft[term_string]`` (cf. iris-grid.js btnSave).
     *   - privacy-page : ``payloadTerms[t.term]`` où ``t.term`` est la
     *     valeur BDD canonique (cf. privacy-page.js _persistDirtyTerms).
     * Ne pas passer une map indexée par ID — les comparaisons cross-term
     * et collision pseudo dépendent du terme string lui-même.
     *
     * @param {Object<string, PseudoEntry>} terms
     * @returns {{errors: string[]}}
     */
    function validatePseudoMap(terms) {
        var errors = [];
        if (!terms || typeof terms !== 'object') {
            return { errors: errors };
        }
        var keys = Object.keys(terms);
        // Premier passage : build le set des termes activés (pour la
        // détection cross-term ci-dessous). On utilise ``Object.create(null)``
        // pour éviter les clés réservées (``__proto__`` etc.).
        var enabledTermsSet = Object.create(null);
        for (var ke = 0; ke < keys.length; ke++) {
            var entryE = terms[keys[ke]];
            if (entryE && entryE.enabled) {
                enabledTermsSet[keys[ke]] = true;
            }
        }
        // Map ``pseudo → premier terme rencontré`` pour détecter les
        // collisions intra-pseudo. Index sur la version trim() pour
        // matcher l'invariant perçu par l'user.
        var pseudoToTerm = Object.create(null);
        for (var i = 0; i < keys.length; i++) {
            var k = keys[i];
            var entry = terms[k];
            if (!entry || !entry.enabled) continue;
            if (typeof entry.pseudo !== 'string' || !entry.pseudo) continue;
            // Trim avant comparaisons : "DUPONT " (trailing space) et
            // "DUPONT" doivent être considérés identiques pour les checks.
            // On garde la version trim() pour comparer et la version
            // brute pour les messages (montrer à l'user ce qu'il a tapé).
            var pTrim = entry.pseudo.trim();
            var kTrim = k.trim();
            if (pTrim.indexOf('§') !== -1) {  // § = U+00A7
                errors.push('« ' + k + ' » : pseudonyme ne doit pas contenir §.');
                continue;
            }
            if (pTrim === kTrim) {
                errors.push('« ' + k + ' » : pseudonyme identique au terme.');
                continue;
            }
            // Cross-term : si le pseudo de ce terme matche un AUTRE terme
            // activé, refuser. L'user qui pseudo-nomme "Dupont" en "Martin"
            // alors que "Martin" est aussi un terme activé crée une
            // confusion sémantique (le LLM ne sait plus si "Martin" =
            // pseudo de Dupont ou le vrai terme Martin).
            if (pTrim !== kTrim && enabledTermsSet[pTrim]) {
                errors.push(
                    '« ' + k + ' » : pseudonyme « ' + pTrim
                    + ' » est aussi un terme activé. Choisir un pseudonyme '
                    + 'qui n\'existe pas comme terme.'
                );
                continue;
            }
            if (pseudoToTerm[pTrim]) {
                errors.push(
                    '« ' + entry.pseudo + ' » utilisé pour plusieurs termes : '
                    + pseudoToTerm[pTrim] + ', ' + k + '.'
                );
            } else {
                pseudoToTerm[pTrim] = k;
            }
        }
        return { errors: errors };
    }

    /**
     * Formate ``data.state_errors`` backend en un message lisible.
     * Joint plusieurs erreurs avec ``•`` (separator visuel cohérent
     * avec iris-grid.js historique). Retourne ``''`` si liste vide
     * ou input invalide — le caller décide d'afficher un message
     * de fallback ("Échec de l'enregistrement.").
     *
     * Types reconnus (cf. ``app/handlers/anonymization.py``) :
     *   - duplicate_pseudo : ``{type, pseudo}``
     *   - invalid_pseudo   : ``{type, term}``
     *   - pseudo_equals_term : ``{type, term}``
     *   - too_many_terms   : ``{type, count}``
     *
     * ``truncatedCount`` (optionnel) — backend cap à 10 erreurs visibles ;
     * si plus, il renvoie ``state_errors_truncated_count: N``. Le helper
     * append ``(+N autres tronquées)`` à la fin du message pour que
     * l'user comprenne qu'il y a plus à corriger (R3 MED 2026-05-20).
     *
     * @param {Array<{type: string, term?: string, pseudo?: string, count?: number}>} stateErrors
     * @param {number} [truncatedCount] - nombre d'erreurs cachées au-delà de stateErrors.length
     * @returns {string}
     */
    function formatStateErrors(stateErrors, truncatedCount) {
        if (!Array.isArray(stateErrors) || stateErrors.length === 0) {
            return '';
        }
        var parts = [];
        for (var i = 0; i < stateErrors.length; i++) {
            var e = stateErrors[i];
            if (!e || typeof e !== 'object') continue;
            if (e.type === 'duplicate_pseudo') {
                parts.push('Pseudonyme en double : ' + (e.pseudo || '?'));
            } else if (e.type === 'invalid_pseudo') {
                parts.push('Pseudonyme invalide pour « ' + (e.term || '?') + ' »');
            } else if (e.type === 'pseudo_equals_term') {
                parts.push('Pseudonyme = terme : « ' + (e.term || '?') + ' »');
            } else if (e.type === 'too_many_terms') {
                parts.push('Trop de termes (' + (e.count || '?') + ')');
            } else {
                parts.push('Erreur : ' + (e.type || 'inconnue'));
            }
        }
        var joined = parts.join(' • ');
        // Append signal de tronquature SI fourni et > 0. Le backend ne
        // l'envoie que si le total dépasse le cap visible (10).
        var nTrunc = Number(truncatedCount);
        if (Number.isFinite(nTrunc) && nTrunc > 0) {
            joined += ' (+' + nTrunc + ' autre' + (nTrunc > 1 ? 's' : '')
                + ' tronquée' + (nTrunc > 1 ? 's' : '') + ')';
        }
        return joined;
    }

    window.AnonymizationSaveHelpers = {
        validatePseudoMap: validatePseudoMap,
        formatStateErrors: formatStateErrors,
    };
})();
