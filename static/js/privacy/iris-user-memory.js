/**
 * Iris user memory panel — page /settings (déplacé depuis /data-privacy
 * le 2026-05-26 : c'est une préférence utilisateur, pas un terme de
 * confidentialité). Le module reste situé sous static/js/privacy/ pour
 * éviter une cascade de renames historiques.
 *
 * UX simplifiée le 2026-05-26 : textarea toujours éditable, un seul bouton
 * « Enregistrer » qui s'active uniquement quand le contenu diffère du
 * dernier état sauvegardé (dirty state). Pour effacer toute la mémoire,
 * l'utilisateur vide le textarea puis enregistre — c'est équivalent à
 * `DELETE /api/iris/user-memory` côté serveur (les deux mènent à une
 * mémoire vide). Plus de bouton « Éditer » ni « Réinitialiser » ni
 * « Annuler » ni modal de confirmation.
 *
 * Endpoints utilisés :
 *   - GET  /api/iris/user-memory  → charge le contenu actuel
 *   - PUT  /api/iris/user-memory  → sauvegarde (même chaîne vide = effacement)
 *
 * Sécurité : CSP nonces actifs → tout via addEventListener (pas d'onclick
 * inline). XSRF token via header `X-Xsrftoken` sur PUT.
 */
(function () {
    'use strict';

    // ── Helpers ──────────────────────────────────────────────────────
    function $(id) { return document.getElementById(id); }

    function getXsrf() {
        var m = document.cookie.match(/(^|; )_xsrf=([^;]+)/);
        return m ? decodeURIComponent(m[2]) : '';
    }

    function toast(msg, type) {
        if (typeof window.showToast === 'function') {
            window.showToast(msg, type || 'info');
        } else {
            // eslint-disable-next-line no-console
            console.log('[iris-user-memory]', type || 'info', msg);
        }
    }

    function setStatus(text, kind) {
        var el = $('iris-memory-status');
        if (!el) return;
        if (!text) {
            el.textContent = '';
            el.className = 'text-xs text-gray-500 dark:text-gray-400';
            return;
        }
        el.textContent = text;
        el.className = 'text-xs ' + (
            kind === 'error'
                ? 'text-red-600 dark:text-red-400'
                : kind === 'success'
                    ? 'text-green-600 dark:text-green-400'
                    : 'text-gray-500 dark:text-gray-400'
        );
    }

    // ── State ────────────────────────────────────────────────────────
    var state = {
        original: '',
        maxChars: 2000,
    };

    function updateCharCount() {
        var ta = $('iris-memory-textarea');
        var counter = $('iris-memory-char-count');
        if (!ta || !counter) return;
        counter.textContent = String(ta.value.length);
        if (ta.value.length >= state.maxChars) {
            counter.className = 'text-red-600 dark:text-red-400 font-medium';
        } else if (ta.value.length >= state.maxChars * 0.9) {
            counter.className = 'text-amber-600 dark:text-amber-400';
        } else {
            counter.className = '';
        }
    }

    function syncSaveButton() {
        var ta = $('iris-memory-textarea');
        var saveBtn = $('iris-memory-save-btn');
        if (!ta || !saveBtn) return;
        // Le bouton n'est cliquable que si le contenu actuel diffère de
        // l'état sauvegardé. Évite les PUT à vide qui n'apportent rien.
        saveBtn.disabled = (ta.value === state.original);
    }

    // ── Fetch helpers ────────────────────────────────────────────────
    async function loadMemory() {
        try {
            var res = await fetch('/api/iris/user-memory', {
                method: 'GET',
                credentials: 'same-origin',
                headers: { 'Accept': 'application/json' },
            });
            if (!res.ok) throw new Error('HTTP ' + res.status);
            var data = await res.json();
            if (!data || data.success !== true) {
                throw new Error(data && data.error ? data.error : 'Réponse serveur invalide');
            }
            var maxC = $('iris-memory-char-max');
            if (typeof data.max_chars === 'number') {
                state.maxChars = data.max_chars;
                if (maxC) maxC.textContent = String(state.maxChars);
            }
            state.original = data.memory || '';
            var ta = $('iris-memory-textarea');
            if (ta) {
                ta.value = state.original;
                ta.maxLength = state.maxChars;
            }
            updateCharCount();
            syncSaveButton();
            setStatus('', null);
        } catch (err) {
            setStatus('Erreur de chargement : ' + (err && err.message ? err.message : err), 'error');
        }
    }

    async function saveMemory() {
        var ta = $('iris-memory-textarea');
        var saveBtn = $('iris-memory-save-btn');
        if (!ta) return;
        var value = ta.value || '';
        if (saveBtn) saveBtn.disabled = true;
        setStatus('Enregistrement…', null);
        try {
            var res = await fetch('/api/iris/user-memory', {
                method: 'PUT',
                credentials: 'same-origin',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'X-Xsrftoken': getXsrf(),
                },
                body: JSON.stringify({ memory: value }),
            });
            if (!res.ok) throw new Error('HTTP ' + res.status);
            var data = await res.json();
            if (!data || data.success !== true) {
                throw new Error(data && data.error ? data.error : 'Réponse serveur invalide');
            }
            // Refléter le contenu sanitizé renvoyé par le serveur
            state.original = data.memory || '';
            ta.value = state.original;
            updateCharCount();
            syncSaveButton();
            if (state.original === '') {
                setStatus('Mémoire vidée. Iris repartira d\'une page blanche.', 'success');
                toast('Mémoire Iris vidée.', 'success');
            } else {
                setStatus('Mémoire enregistrée.', 'success');
                toast('Mémoire Iris mise à jour.', 'success');
            }
        } catch (err) {
            setStatus('Échec enregistrement : ' + (err && err.message ? err.message : err), 'error');
            toast('Enregistrement impossible.', 'error');
            syncSaveButton();
        }
    }

    // ── Wiring ───────────────────────────────────────────────────────
    function init() {
        var ta = $('iris-memory-textarea');
        var saveBtn = $('iris-memory-save-btn');
        if (!ta) return; // page non concernée

        ta.addEventListener('input', function () {
            updateCharCount();
            syncSaveButton();
        });
        if (saveBtn) {
            saveBtn.addEventListener('click', function () { saveMemory(); });
        }

        loadMemory();
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
