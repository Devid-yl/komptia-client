// local-datetime.js — convertit les balises <time data-fmt-local> en
// heure locale du navigateur.
//
// Pourquoi : les datetimes UTC (provenant de SQLite, stocké naïf via
// ``DateTime`` non-aware) étaient rendus côté serveur avec ``strftime``
// ou ``isoformat()``, ce qui affichait l'heure UTC brute. Selon le
// fuseau du visiteur, le décalage paraissait incorrect (« DERNIÈRE
// CONNEXION » montrait UTC alors que l'utilisateur attendait son
// heure locale).
//
// Pattern : le serveur émet ``<time datetime="2026-04-30T12:00:00+00:00"
// data-fmt-local="datetime">12:00</time>``. Ce script trouve toutes
// les balises et remplace ``textContent`` par l'heure locale formatée.
//
// ``data-fmt-local`` :
//   * ``"datetime"`` → "30/04/2026 14:00"
//   * ``"short"``    → "30/04/2026 14:00" (équivalent — réservé aux
//                      tableaux denses, garde le nom au cas où on
//                      voudrait différencier plus tard)
//   * ``"date"``     → "30/04/2026"
//   * ``"time"``     → "14:00"
//
// Idempotent : le script peut être appelé plusieurs fois (utile si une
// liste est re-rendue par AJAX). Marque chaque ``<time>`` traitée avec
// ``data-fmt-applied`` pour ne pas reformater inutilement.
(function () {
    'use strict';

    function formatLocal(iso, mode) {
        try {
            var d = new Date(iso);
            if (isNaN(d.getTime())) return null;
            // SSoT : déléguer au formateur JS UNIQUE (KomptiaFormat /
            // format-helpers.js) quand il est chargé — un seul endroit où le
            // format daté est défini. Fallback toLocale* ci-dessous si
            // KomptiaFormat n'est pas encore dispo (edge : applyAll immédiat
            // peut s'exécuter avant format-helpers, chargé juste après ce
            // script dans base.html) → zéro régression.
            var KF = (typeof window !== 'undefined') ? window.KomptiaFormat : null;
            if (KF) {
                if (mode === 'date') return KF.dateFr(d, { onInvalid: 'null' });
                if (mode === 'time') return KF.timeHm(d, { onInvalid: 'null' });
                return KF.dateTimeFr(d, { onInvalid: 'null' }); // datetime / short / fallback
            }
            var fr = 'fr-FR';
            if (mode === 'date') {
                return d.toLocaleDateString(fr);
            }
            if (mode === 'time') {
                return d.toLocaleTimeString(fr, {
                    hour: '2-digit',
                    minute: '2-digit',
                });
            }
            // 'datetime' / 'short' / fallback
            return d.toLocaleString(fr, {
                day: '2-digit',
                month: '2-digit',
                year: 'numeric',
                hour: '2-digit',
                minute: '2-digit',
            });
        } catch (e) {
            return null;
        }
    }

    function applyAll(root) {
        var scope = root || document;
        var nodes = scope.querySelectorAll(
            'time[data-fmt-local]:not([data-fmt-applied])'
        );
        for (var i = 0; i < nodes.length; i++) {
            var el = nodes[i];
            var iso = el.getAttribute('datetime');
            if (!iso) continue;
            var mode = el.getAttribute('data-fmt-local') || 'datetime';
            var formatted = formatLocal(iso, mode);
            if (formatted) {
                el.textContent = formatted;
                // a11y : un screen reader (NVDA/JAWS) lit ``textContent`` —
                // on écrit aussi ``aria-label`` avec la valeur formatée
                // pour que la lecture annoncée corresponde à l'heure
                // locale, pas au texte UTC du SSR fallback.
                el.setAttribute('aria-label', formatted);
                el.setAttribute('data-fmt-applied', '1');
            }
        }
    }

    // API publique : permet à des vues qui re-rendent par AJAX de
    // forcer un nouveau passage (passer le sous-arbre concerné).
    window.LocalDatetime = { applyAll: applyAll };

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', function () {
            applyAll(document);
            wireMutationObserver();
        });
    } else {
        applyAll(document);
        wireMutationObserver();
    }

    // MutationObserver : couvre les vues qui ré-injectent du HTML par
    // AJAX (innerHTML, fetch + replace, partial reload) sans avoir à
    // appeler ``window.LocalDatetime.applyAll(node)`` à la main. Faible
    // coût car on ne réagit qu'aux ajouts qui contiennent une balise
    // ``<time data-fmt-local>`` non encore traitée.
    function wireMutationObserver() {
        if (typeof MutationObserver === 'undefined' || !document.body) return;
        var observer = new MutationObserver(function (mutations) {
            for (var i = 0; i < mutations.length; i++) {
                var added = mutations[i].addedNodes;
                for (var j = 0; j < added.length; j++) {
                    var node = added[j];
                    if (node.nodeType !== 1) continue; // Element only
                    if (node.matches && node.matches('time[data-fmt-local]:not([data-fmt-applied])')) {
                        applyAll(node.parentNode || document);
                    } else if (node.querySelector && node.querySelector('time[data-fmt-local]:not([data-fmt-applied])')) {
                        applyAll(node);
                    }
                }
            }
        });
        observer.observe(document.body, { childList: true, subtree: true });
    }
})();
