/*
 * no-llm-banner.js — JS minimal pour le banner SSR « IA non configurée ».
 *
 * Le banner lui-même est rendu côté serveur par
 * ``templates/_partials/no_llm_banner.html`` quand
 * ``handler._is_llm_configured()`` retourne ``false``. Ce script :
 *
 *  1. Au boot, lit ``localStorage[STORAGE_KEY]`` (timestamp dismiss + TTL) ;
 *     si dismiss valide < TTL, masque le banner immédiatement.
 *  2. Wire le bouton ``×`` : enregistre le dismiss (+ event ``storage``
 *     pour propager aux autres onglets) + masque le banner.
 *  3. Écoute l'event ``storage`` natif : si un AUTRE onglet dismiss, on
 *     masque ici aussi (synchro cross-tab).
 *
 * Pourquoi localStorage + TTL plutôt que sessionStorage :
 * - L'admin Komptia a typiquement plusieurs onglets ouverts. sessionStorage
 *   = per-tab → dismiss sur un onglet, banner reste sur les 9 autres = friction.
 * - Mais on ne veut pas un dismiss éternel : si l'admin fix la clé puis
 *   re-clear, le banner doit re-apparaître. TTL 1h = compromis raisonnable
 *   (re-check au prochain refresh après 1h).
 * - Cohérent avec le pattern ``feedback-reporter.js`` qui a explicitement
 *   abandonné sessionStorage pour cette raison.
 *
 * CSP-friendly : ``addEventListener`` uniquement, zéro ``onclick`` inline.
 * Idempotent : no-op si le banner n'est pas dans le DOM (cas
 * ``llm_configured=true``).
 */
(function () {
    if (typeof window === 'undefined' || typeof document === 'undefined') return;

    var BANNER_ID = 'komptia-no-llm-banner';
    var CLOSE_ID = 'komptia-no-llm-banner-close';
    // Clé localStorage : valeur = timestamp (ms epoch) du dismiss.
    // Si > now - TTL → banner masqué. Sinon → on l'affiche (état expiré).
    var STORAGE_KEY = 'komptia-no-llm-banner-dismissed-at';
    var DISMISS_TTL_MS = 60 * 60 * 1000; // 1h

    function readDismissedAt() {
        try {
            if (!window.localStorage) return 0;
            var raw = localStorage.getItem(STORAGE_KEY);
            if (!raw) return 0;
            var ts = parseInt(raw, 10);
            return isNaN(ts) ? 0 : ts;
        } catch (e) {
            return 0; // localStorage indisponible (Safari privé strict)
        }
    }

    function isDismissedActive() {
        var ts = readDismissedAt();
        if (!ts) return false;
        return (Date.now() - ts) < DISMISS_TTL_MS;
    }

    function hideBanner(banner) {
        if (banner) {
            // ``display:none`` + class ``hidden`` au lieu de ``removeChild`` :
            // permet à un futur event ``komptia:llm-config-changed`` (push WS
            // ou polling) de ré-afficher le banner sans reload — utile quand
            // l'admin re-clear la clé pendant la session.
            banner.style.display = 'none';
            banner.classList.add('hidden');
        }
    }

    function showBanner(banner) {
        if (banner) {
            banner.style.display = '';
            banner.classList.remove('hidden');
        }
    }

    function recordDismiss() {
        try {
            if (window.localStorage) {
                // Date.now() en string ; setItem trigger l'event ``storage``
                // sur les AUTRES tabs/windows ouverts sur le même origin.
                localStorage.setItem(STORAGE_KEY, String(Date.now()));
            }
        } catch (e) {
            // localStorage indisponible — on masque quand même l'instance
            // courante pour respecter l'intent user dans ce contexte.
        }
    }

    function init() {
        var banner = document.getElementById(BANNER_ID);
        if (!banner) return; // SSR a décidé : LLM configuré, pas de banner

        // Si un autre onglet a dismiss < 1h → masquer ici aussi.
        if (isDismissedActive()) {
            hideBanner(banner);
            return;
        }

        var close = document.getElementById(CLOSE_ID);
        if (close) {
            close.addEventListener('click', function (ev) {
                ev.preventDefault();
                recordDismiss();
                hideBanner(banner);
            });
        }

        // Propagation cross-tab : si un autre onglet dismiss, on masque
        // ici aussi. Inversement, si la clé est explicitement removed
        // (admin clear le storage manuellement, ou TTL expiré géré côté
        // autre tab), on ré-affiche.
        window.addEventListener('storage', function (ev) {
            if (ev.key !== STORAGE_KEY) return;
            if (ev.newValue && (Date.now() - parseInt(ev.newValue, 10)) < DISMISS_TTL_MS) {
                hideBanner(banner);
            } else {
                showBanner(banner);
            }
        });

        // Hook pour push update (futur) : émettre
        // ``window.dispatchEvent(new CustomEvent('komptia:llm-config-changed'))``
        // depuis ``/admin/ai-config`` save handler pour ré-afficher / masquer
        // le banner sans reload. Aujourd'hui pas branché — dette tracée.
        window.addEventListener('komptia:llm-config-changed', function (ev) {
            var configured = ev && ev.detail && ev.detail.configured;
            if (configured === true) {
                hideBanner(banner);
            } else if (configured === false && !isDismissedActive()) {
                showBanner(banner);
            }
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
