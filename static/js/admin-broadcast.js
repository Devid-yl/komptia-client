/**
 * admin-broadcast.js — sync multi-onglets pour les pages /admin*.
 *
 * Bug 2026-05-26 (F15 MOYEN) : avant ce helper, quand l'admin Alice modifiait
 * un utilisateur dans Tab 1 (création/édition/suppression), son onglet Tab 2
 * sur /admin ou /admin/users restait avec la version PÉRIMÉE des données.
 * Elle devait F5 manuellement pour voir les changements — confusion garantie
 * sur double-clic ou actions multi-tab.
 *
 * Fix : ``BroadcastChannel('komptia-admin-changes')`` — canal same-origin
 * (sécurisé par construction : ne traverse pas les iframes externes ni les
 * autres origines). Quand un onglet fait une mutation admin (POST/PUT/DELETE
 * réussie sur ``/api/users*``, ``/api/settings/company``, etc.), il poste
 * un message ``{type, kind, originTab}``. Les autres onglets écoutent et
 * déclenchent un refresh ciblé (typiquement ``location.reload()``).
 *
 * Note design :
 * 1. Anti-loop : le ``originTab`` (UUID éphémère) empêche un onglet de
 *    réagir à son propre message (BroadcastChannel re-livre normalement
 *    aux autres onglets, mais defense-in-depth pour les bugs Safari).
 * 2. Throttle 1s : si plusieurs mutations en série, on déclenche UN seul
 *    reload (sinon F5-storm sur 10 toggles bulk).
 * 3. Feature-detect : BroadcastChannel n'existe pas sur Safari < 15.4 et
 *    certains contextes WebView. Silent no-op sinon — l'UX dégradée
 *    reste OK (juste pas de sync auto entre tabs).
 * 4. Idempotent : guard ``window.__komptiaAdminBroadcastInit``.
 *
 * Contrat public :
 * - ``window.komptiaAdminBroadcast.notify(kind)`` — appelée par les pages
 *   APRÈS une mutation réussie. ``kind`` = label libre ("user_created",
 *   "user_deleted", "user_role_changed", "company_changed").
 * - ``window.komptiaAdminBroadcast.onRemoteChange(callback)`` — appelée
 *   par les pages qui veulent réagir à un changement venu d'ailleurs.
 *   ``callback`` reçoit ``{kind, originTab}``.
 */
(function () {
    'use strict';
    if (window.__komptiaAdminBroadcastInit) return;
    window.__komptiaAdminBroadcastInit = true;

    var CHANNEL_NAME = 'komptia-admin-changes';
    var REFRESH_THROTTLE_MS = 1000;
    // UUID léger pour distinguer cet onglet des autres (anti-loop).
    var ORIGIN_TAB = (function () {
        // crypto.randomUUID() : disponible Chrome 92+/Firefox 95+/Safari 15.4+.
        // Fallback : timestamp + random pour les vieux navigateurs.
        if (window.crypto && typeof window.crypto.randomUUID === 'function') {
            return window.crypto.randomUUID();
        }
        return 'tab-' + Date.now() + '-' + Math.random().toString(36).slice(2);
    })();

    var _channel = null;
    var _remoteCallbacks = [];
    var _lastNotifyAt = 0;

    function _initChannel() {
        if (_channel) return _channel;
        if (typeof BroadcastChannel !== 'function') {
            // Feature non supportée — silent no-op. Les notify() seront
            // ignorés ; pas de crash.
            return null;
        }
        try {
            _channel = new BroadcastChannel(CHANNEL_NAME);
            _channel.onmessage = function (event) {
                var data = event && event.data;
                if (!data || typeof data !== 'object') return;
                if (data.originTab === ORIGIN_TAB) return;  // anti-loop
                for (var i = 0; i < _remoteCallbacks.length; i++) {
                    try {
                        _remoteCallbacks[i](data);
                    } catch (e) {
                        console.warn('[komptiaAdminBroadcast] callback failed', e);
                    }
                }
            };
        } catch (e) {
            console.warn('[komptiaAdminBroadcast] init failed', e);
            return null;
        }
        return _channel;
    }

    function notify(kind) {
        var now = Date.now();
        if ((now - _lastNotifyAt) < REFRESH_THROTTLE_MS) {
            // Throttle : si plusieurs notify dans la fenêtre, on garde
            // seulement le 1er. Évite le F5-storm sur 10 toggles bulk.
            return;
        }
        _lastNotifyAt = now;
        var ch = _initChannel();
        if (!ch) return;
        try {
            ch.postMessage({
                type: 'komptia-admin-change',
                kind: String(kind || 'unknown'),
                originTab: ORIGIN_TAB,
                at: now,
            });
        } catch (e) {
            console.warn('[komptiaAdminBroadcast] postMessage failed', e);
        }
    }

    function onRemoteChange(callback) {
        if (typeof callback !== 'function') return;
        _remoteCallbacks.push(callback);
        _initChannel();  // assure que le canal est connecté
    }

    // Helper standard : refresh la page si un changement remote arrive.
    // Throttle pour éviter les F5-storm si plusieurs onglets émettent
    // simultanément.
    //
    // Bug 2026-05-26 (ADV-7 — adversarial review) : avant ce fix, le helper
    // rechargeait l'onglet receveur sans tenir compte du contexte. Si Tab 2
    // était sur /iris (avec chat en cours), un user_created dans Tab 1 forçait
    // le reload → perte de l'état chat. Maintenant : la garde de path
    // ``startsWith('/admin')`` s'applique par défaut. Le caller peut passer
    // ``{always: true}`` pour court-circuiter (anti-régression sur des pages
    // admin sans préfixe URL explicite — hypothétique).
    var _lastRemoteReloadAt = 0;
    function reloadOnRemoteChange(opts) {
        var alwaysReload = !!(opts && opts.always);
        onRemoteChange(function (_msg) {
            // ADV-7 (2026-05-26) : ne reload QUE sur les pages /admin*.
            // Évite la perte d'état sur /iris, /datastore, /automations.
            if (!alwaysReload) {
                try {
                    if (!window.location.pathname.startsWith('/admin')) return;
                } catch (e) { /* defensive — pathname absent en contexte exotique */ }
            }
            var now = Date.now();
            if ((now - _lastRemoteReloadAt) < REFRESH_THROTTLE_MS) return;
            _lastRemoteReloadAt = now;
            // Reload léger après 300ms pour absorber les burst messages
            setTimeout(function () { location.reload(); }, 300);
        });
    }

    window.komptiaAdminBroadcast = {
        notify: notify,
        onRemoteChange: onRemoteChange,
        reloadOnRemoteChange: reloadOnRemoteChange,
    };
})();
