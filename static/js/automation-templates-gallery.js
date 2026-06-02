/* ============================================================
 * Komptia — Galerie de templates d'automatisation (Phase 3d).
 *
 * Liste les templates depuis /api/automation-templates, les rend en
 * grid de cards. Click "Utiliser" → POST /:id/instantiate → redirect
 * vers /automations/:new_id/edit.
 *
 * CSP : aucun inline handler, tout via addEventListener.
 * XSRF : header X-Xsrftoken sur le POST instantiate.
 * Anti-XSS : tout le rendu utilise textContent / createElement, pas
 *   d'innerHTML sur du contenu venant du JSON.
 * ============================================================ */

(function () {
    'use strict';

    function getCookie(name) {
        const value = '; ' + document.cookie;
        const parts = value.split('; ' + name + '=');
        if (parts.length === 2) return parts.pop().split(';').shift();
        return null;
    }

    function xsrfHeader() {
        const token = getCookie('_xsrf');
        return token ? { 'X-Xsrftoken': token } : {};
    }

    async function apiFetch(url, options) {
        options = options || {};
        options.credentials = 'same-origin';
        options.headers = Object.assign(
            { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
            options.headers || {},
            xsrfHeader()
        );
        const response = await fetch(url, options);
        const text = await response.text().catch(() => '');
        let json = null;
        if (text) {
            try { json = JSON.parse(text); } catch (_) { /* non-JSON */ }
        }
        if (!response.ok) {
            const err = new Error((json && json.error) || 'HTTP ' + response.status);
            err.status = response.status;
            err.body = json;
            throw err;
        }
        return json;
    }

    function showToastSafe(message, type) {
        if (typeof window.showToast === 'function') {
            window.showToast(message, type || 'info');
        } else if (type === 'error') {
            console.error('Komptia:', message);
        }
    }

    // ---- Couleurs categories (alignees sur palette canvas) ----
    const CATEGORY_BADGES = {
        'starter': { label: 'Démarrage', cls: 'bg-emerald-50 text-emerald-700' },
        'monitoring': { label: 'Surveillance', cls: 'bg-amber-50 text-amber-700' },
        'advanced': { label: 'Avancé', cls: 'bg-purple-50 text-purple-700' },
        'general': { label: 'Général', cls: 'bg-gray-50 text-gray-700' },
    };

    const DIFFICULTY_BADGES = {
        'facile': { label: 'Facile', cls: 'text-emerald-600' },
        'moyen': { label: 'Moyen', cls: 'text-amber-600' },
        'avancé': { label: 'Avancé', cls: 'text-red-600' },
    };

    // ---- Build une card pour un template ----
    function buildCard(template) {
        const card = document.createElement('div');
        card.className = 'card flex flex-col p-4 hover:shadow-md transition-shadow';

        // Header : icone + categorie badge
        const header = document.createElement('div');
        header.className = 'flex items-start justify-between mb-3';

        const icon = document.createElement('div');
        icon.className = 'w-10 h-10 rounded-lg bg-brand-50 dark:bg-brand-900/20 flex items-center justify-center';
        const iconEl = document.createElement('i');
        iconEl.className = 'bi bi-' + (template.icon || 'diagram-3') + ' text-brand-600 dark:text-brand-400 text-lg';
        icon.appendChild(iconEl);
        header.appendChild(icon);

        const catBadge = CATEGORY_BADGES[template.category] || CATEGORY_BADGES.general;
        const cat = document.createElement('span');
        cat.className = 'text-xs font-medium px-2 py-1 rounded-full ' + catBadge.cls;
        cat.textContent = catBadge.label;
        header.appendChild(cat);

        card.appendChild(header);

        // Title (textContent — XSS-safe)
        const title = document.createElement('h3');
        title.className = 'text-sm font-semibold text-gray-900 dark:text-gray-100 mb-2 leading-snug';
        title.textContent = template.label || template.id;
        card.appendChild(title);

        // Description
        const desc = document.createElement('p');
        desc.className = 'text-xs text-gray-500 dark:text-gray-400 leading-relaxed flex-1 mb-3';
        desc.textContent = template.description || '';
        card.appendChild(desc);

        // Meta row : steps + edges + difficulty
        const meta = document.createElement('div');
        meta.className = 'flex items-center gap-3 text-xs text-gray-400 dark:text-gray-500 mb-3';

        const steps = document.createElement('span');
        steps.className = 'flex items-center gap-1';
        const stepsIcon = document.createElement('i');
        stepsIcon.className = 'bi bi-list-ol';
        steps.appendChild(stepsIcon);
        const stepsText = document.createElement('span');
        stepsText.textContent = (template.step_count || 0) + ' étapes';
        steps.appendChild(stepsText);
        meta.appendChild(steps);

        if (template.edge_count != null) {
            const edges = document.createElement('span');
            edges.className = 'flex items-center gap-1';
            const edgesIcon = document.createElement('i');
            edgesIcon.className = 'bi bi-arrow-right-circle';
            edges.appendChild(edgesIcon);
            const edgesText = document.createElement('span');
            edgesText.textContent = template.edge_count + ' liens';
            edges.appendChild(edgesText);
            meta.appendChild(edges);
        }

        if (template.difficulty) {
            const diff = DIFFICULTY_BADGES[template.difficulty] || { label: template.difficulty, cls: 'text-gray-500' };
            const diffEl = document.createElement('span');
            diffEl.className = 'flex items-center gap-1 ' + diff.cls;
            const diffIcon = document.createElement('i');
            diffIcon.className = 'bi bi-bar-chart';
            diffEl.appendChild(diffIcon);
            const diffText = document.createElement('span');
            diffText.textContent = diff.label;
            diffEl.appendChild(diffText);
            meta.appendChild(diffEl);
        }

        card.appendChild(meta);

        // CTA button
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'btn btn-primary text-sm w-full';
        btn.dataset.templateId = template.id;
        btn.setAttribute('aria-label', 'Utiliser ce template');
        const btnIcon = document.createElement('i');
        btnIcon.className = 'bi bi-plus-circle mr-1';
        btn.appendChild(btnIcon);
        const btnText = document.createElement('span');
        btnText.textContent = 'Utiliser ce template';
        btn.appendChild(btnText);

        btn.addEventListener('click', function () {
            instantiateTemplate(template.id, btn);
        });

        card.appendChild(btn);
        return card;
    }

    function setButtonContent(btn, iconClass, text) {
        // Rebuild en createElement (CSP-safe, pas d'innerHTML).
        while (btn.firstChild) btn.removeChild(btn.firstChild);
        const icon = document.createElement('i');
        icon.className = 'bi bi-' + iconClass + ' mr-1';
        btn.appendChild(icon);
        const span = document.createElement('span');
        span.textContent = text;
        btn.appendChild(span);
    }

    async function instantiateTemplate(templateId, btn) {
        btn.disabled = true;
        setButtonContent(btn, 'hourglass-split', 'Création...');

        try {
            const resp = await apiFetch(
                '/api/automation-templates/' + encodeURIComponent(templateId) + '/instantiate',
                { method: 'POST', body: '{}' }
            );
            if (resp && resp.redirect_url) {
                window.location.href = resp.redirect_url;
                return;
            }
            if (resp && resp.id) {
                window.location.href = '/automations/' + resp.id + '/edit';
                return;
            }
            showToastSafe('Création OK mais aucune redirection — recharger la liste', 'warning');
            btn.disabled = false;
            setButtonContent(btn, 'plus-circle', 'Utiliser ce template');
        } catch (e) {
            const msg = (e.body && e.body.error) || e.message;
            showToastSafe('Erreur création : ' + msg, 'error');
            btn.disabled = false;
            setButtonContent(btn, 'plus-circle', 'Utiliser ce template');
        }
    }

    async function loadGallery() {
        const loadingEl = document.getElementById('komptia-templates-loading');
        const errorEl = document.getElementById('komptia-templates-error');
        const errorMsg = document.getElementById('komptia-templates-error-msg');
        const gridEl = document.getElementById('komptia-templates-grid');
        const emptyEl = document.getElementById('komptia-templates-empty');

        try {
            const resp = await apiFetch('/api/automation-templates');
            const templates = (resp && resp.templates) || [];

            if (loadingEl) loadingEl.classList.add('hidden');
            if (errorEl) errorEl.classList.add('hidden');

            if (templates.length === 0) {
                if (emptyEl) emptyEl.classList.remove('hidden');
                return;
            }

            if (gridEl) {
                while (gridEl.firstChild) gridEl.removeChild(gridEl.firstChild);
                for (const tpl of templates) {
                    gridEl.appendChild(buildCard(tpl));
                }
                gridEl.classList.remove('hidden');
            }
        } catch (e) {
            if (loadingEl) loadingEl.classList.add('hidden');
            if (errorEl) errorEl.classList.remove('hidden');
            if (errorMsg) errorMsg.textContent = 'Erreur : ' + e.message;
            console.error('Komptia gallery: load failed', e);
        }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', loadGallery);
    } else {
        loadGallery();
    }
})();
