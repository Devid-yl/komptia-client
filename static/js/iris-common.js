/**
 * Iris Common Helpers — single source of truth pour les utilitaires JS
 * partagés entre la page complète ``/iris`` (iris.js) et le floating widget
 * (iris-widget.js).
 *
 * Pourquoi (task #14) : avant cette extraction, escapeHtml/escapeAttr/
 * sanitizeHtml/getCookie étaient dupliqués entre les 2 fichiers. Cas
 * vécu : sanitizeHtml a été enrichi pour fermer un mXSS noscript/template
 * en deux endroits différents (fix #5 + adversarial #3) — risque réel
 * qu'un fix sécurité futur soit appliqué à un seul des deux et que
 * l'autre régresse silencieusement.
 *
 * Scope volontairement restreint à cette session : helpers PURS (pas
 * d'état interne, pas de dépendance DOM globale). Ne contient PAS :
 * - ``formatMarkdown`` : versions divergentes (iris.js utilise classes CSS
 *   spécifiques ``iris-code-block`` / ``iris-inline-code`` / ``iris-md-hr``,
 *   widget utilise classes ``jw-*``). Extraction propre demanderait une
 *   normalisation CSS — out of scope.
 * - ``buildResultTable`` : versions divergentes intentionnellement (iris.js
 *   intègre GridTabManager, widget produit une mini-table simplifiée).
 *
 * Exposé sous ``window.IrisCommon``. DOIT être chargé AVANT ``iris.js``
 * (dans templates/iris.html) ET AVANT ``iris-widget.js`` (dans
 * templates/base.html). Si non chargé : les wrappers locaux dans les 2
 * fichiers crasheront — c'est volontaire (fail-loud pour détecter une
 * régression de chargement plutôt que running silencieusement avec une
 * version locale stale).
 */
(function (global) {
    "use strict";

    /**
     * Échappe le contenu pour insertion safe dans du HTML (texte ou attr
     * value qui ne contient ni quote). Utilise textContent du DOM pour
     * garantie navigateur.
     * @param {*} text
     * @returns {string}
     */
    function escapeHtml(text) {
        if (text == null) return "";
        var div = document.createElement("div");
        div.textContent = String(text);
        return div.innerHTML;
    }

    /**
     * Échappe pour contexte attribut HTML (échappe aussi " et ').
     * Plus strict que escapeHtml — à utiliser quand le contenu va dans
     * un attribut entre guillemets (data-*, href, title…).
     * @param {*} text
     * @returns {string}
     */
    function escapeAttr(text) {
        if (text == null) return "";
        return String(text)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#39;");
    }

    /**
     * Sanitise du HTML formaté — supprime les tags/attributs dangereux.
     * Utilisé après formatMarkdown() avant injection dans innerHTML.
     *
     * Defense-in-depth XSS + mXSS :
     * - Strip: script, iframe, object, embed, form, input, textarea, select,
     *   button[type=submit], link, meta, style, base, svg[onload], img[onerror],
     *   noscript, template (les 2 derniers ferment un vecteur mXSS classique
     *   via <noscript><p title="</noscript><img onerror=...>>).
     * - Strip attributs : on*, srcdoc, formaction.
     * - Strip URIs : javascript: sur href/src/action.
     *
     * @param {string} html
     * @returns {string}
     */
    function sanitizeHtml(html) {
        if (!html) return "";
        var temp = document.createElement("div");
        temp.innerHTML = html;
        var dangerous = temp.querySelectorAll(
            "script,iframe,object,embed,form,input,textarea,select," +
            'button[type="submit"],link,meta,style,base,svg[onload],' +
            "img[onerror],noscript,template"
        );
        for (var i = 0; i < dangerous.length; i++) dangerous[i].remove();
        var allEls = temp.querySelectorAll("*");
        for (var j = 0; j < allEls.length; j++) {
            var el = allEls[j];
            var attrs = Array.from(el.attributes);
            for (var k = 0; k < attrs.length; k++) {
                var name = attrs[k].name.toLowerCase();
                if (
                    name.startsWith("on") ||
                    name === "srcdoc" ||
                    name === "formaction"
                ) {
                    el.removeAttribute(attrs[k].name);
                }
                if (
                    (name === "href" || name === "src" || name === "action") &&
                    /^\s*javascript:/i.test(attrs[k].value)
                ) {
                    el.removeAttribute(attrs[k].name);
                }
            }
        }
        return temp.innerHTML;
    }

    /**
     * Lit un cookie par son nom.
     * @param {string} name
     * @returns {string} valeur du cookie, ou "" si absent.
     */
    function getCookie(name) {
        var value = "; " + document.cookie;
        var parts = value.split("; " + name + "=");
        if (parts.length === 2) return parts.pop().split(";").shift();
        return "";
    }

    global.IrisCommon = {
        escapeHtml: escapeHtml,
        escapeAttr: escapeAttr,
        sanitizeHtml: sanitizeHtml,
        getCookie: getCookie,
    };
})(typeof window !== "undefined" ? window : this);
