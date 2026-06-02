/**
 * Contacts & Distribution Lists — Client-side logic.
 *
 * Conventions seniors appliquées :
 *  - safeFetch : redirige sur /login si 401 (session expirée),
 *    retry réseau (timeout/offline) avec backoff, capture le X-Request-ID
 *    de la dernière réponse pour le bug-report, ne throw jamais.
 *  - openOverlay/closeOverlay : helpers centralisés qui combinent
 *    classList.add/remove('hidden','flex') + OverlayManager (trapFocus +
 *    inertSiblings) — évite la double-vérité dans 4 modales.
 *  - debounce : helper unique au lieu de 5 setTimeout dispersés.
 *  - Filter-summary : compteur dynamique "X résultat(s) sur Y" + bouton
 *    "Effacer les filtres" pour ne pas piéger l'utilisateur sur empty state.
 *  - Tri : aria-sort accessible, paramètre ``sort`` propagé à l'API.
 *  - Multi-colonnes search : backend cherche dans email/first_name/
 *    last_name/company ; le frontend affiche cette info dans les hints.
 */
document.addEventListener('DOMContentLoaded', function () {

/* ── State ─────────────────────────────────────────────── */
var DEFAULT_PER_PAGE = 25;
let currentPage = 1;
let currentSortKey = '';      // '' = tri défaut serveur (created_at desc)
let currentSortDir = 'asc';   // 'asc' | 'desc'
let editingId = null;
let editingListId = null;
let currentMembersListId = null;
let selectedInitialContacts = [];
let isSubmitting = false;

/* ── Helpers ───────────────────────────────────────────── */
function esc(s) {
    if (s === null || s === undefined) return '';
    var d = document.createElement('div');
    d.textContent = String(s);
    return d.innerHTML;
}

function escAttr(s) {
    if (s === null || s === undefined) return '';
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

// Helper debounce centralisé (au lieu de 5 setTimeout/clearTimeout dispersés).
function debounce(fn, ms) {
    var timer = null;
    return function () {
        var args = arguments, ctx = this;
        clearTimeout(timer);
        timer = setTimeout(function () { fn.apply(ctx, args); }, ms);
    };
}

// Helper de mise à jour d'une stat (hoisted — était dupliqué localement
// dans updateStats() + loadLists()). Cohérence + un seul endroit à corriger.
function setStat(id, val) {
    var el = document.getElementById(id);
    if (el) el.textContent = String(val == null ? 0 : val);
}

// ── Icônes SVG inline pour le menu kebab d'actions ────────────────
// Convention : préfixe ``_ICON_*``, stroke-width=1.75, viewBox 24×24.
// Définies une fois (pas de re-création par row) et concaténées dans le
// rendu — économise ~80 % de bytes de DOM vs SVG inline répété.
var _ICON_KEBAB = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="5" r="1"/><circle cx="12" cy="12" r="1"/><circle cx="12" cy="19" r="1"/></svg>';
var _ICON_EMAIL = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21.75 6.75v10.5a2.25 2.25 0 01-2.25 2.25h-15a2.25 2.25 0 01-2.25-2.25V6.75m19.5 0A2.25 2.25 0 0019.5 4.5h-15a2.25 2.25 0 00-2.25 2.25m19.5 0v.243a2.25 2.25 0 01-1.07 1.916l-7.5 4.615a2.25 2.25 0 01-2.36 0L3.32 8.91a2.25 2.25 0 01-1.07-1.916V6.75"/></svg>';
var _ICON_EDIT = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M16.862 4.487l1.687-1.688a1.875 1.875 0 112.652 2.652L10.582 16.07a4.5 4.5 0 01-1.897 1.13L6 18l.8-2.685a4.5 4.5 0 011.13-1.897l8.932-8.931zm0 0L19.5 7.125M18 14v4.75A2.25 2.25 0 0115.75 21H5.25A2.25 2.25 0 013 18.75V8.25A2.25 2.25 0 015.25 6H10"/></svg>';
var _ICON_PAUSE = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M14.25 9v6m-4.5 0V9M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>';
var _ICON_PLAY = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/><path d="M15.91 11.672a.375.375 0 010 .656l-5.603 3.113a.375.375 0 01-.557-.328V8.887c0-.286.307-.466.557-.327l5.603 3.112z"/></svg>';
var _ICON_TRASH = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M14.74 9l-.346 9m-4.788 0L9.26 9m9.968-3.21c.342.052.682.107 1.022.166m-1.022-.165L18.16 19.673a2.25 2.25 0 01-2.244 2.077H8.084a2.25 2.25 0 01-2.244-2.077L4.772 5.79m14.456 0a48.108 48.108 0 00-3.478-.397m-12 .562c.34-.059.68-.114 1.022-.165m0 0a48.11 48.11 0 013.478-.397m7.5 0v-.916c0-1.18-.91-2.164-2.09-2.201a51.964 51.964 0 00-3.32 0c-1.18.037-2.09 1.022-2.09 2.201v.916m7.5 0a48.667 48.667 0 00-7.5 0"/></svg>';
var _ICON_USERS = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0z"/></svg>';

/**
 * Toggle un menu d'actions kebab (dropdown). Ferme tous les autres
 * menus ouverts pour éviter le chaos visuel à plusieurs menus simultanés.
 *
 * Sécurité : ``trigger`` est l'élément cliqué (avec la classe
 * ``actions-menu-trigger``), son sibling ``.actions-menu-dropdown`` est
 * le menu à toggler. ``aria-expanded`` mis à jour pour les screen readers.
 */
function toggleActionsMenu(trigger) {
    var dropdown = trigger.parentElement.querySelector('.actions-menu-dropdown');
    if (!dropdown) return;
    var willOpen = dropdown.classList.contains('hidden');
    // Ferme tous les autres menus ouverts (single-open invariant).
    document.querySelectorAll('.actions-menu-dropdown:not(.hidden)').forEach(function (d) {
        d.classList.add('hidden');
        var btn = d.parentElement.querySelector('.actions-menu-trigger');
        if (btn) btn.setAttribute('aria-expanded', 'false');
    });
    if (willOpen) {
        dropdown.classList.remove('hidden');
        trigger.setAttribute('aria-expanded', 'true');
    }
}

function _closeAllActionsMenus() {
    document.querySelectorAll('.actions-menu-dropdown:not(.hidden)').forEach(function (d) {
        d.classList.add('hidden');
        var btn = d.parentElement.querySelector('.actions-menu-trigger');
        if (btn) btn.setAttribute('aria-expanded', 'false');
    });
}

// Constantes nommées plutôt que magic numbers.
var FETCH_TIMEOUT_MS = 30000;     // 30s par tentative — au-delà c'est un serveur hung
var FETCH_RETRY_BACKOFF_MS = 1500; // base exponential, multiplié par attempt
// F1 (review loop) : clé scopée par utilisateur — anti-fuite PII cross-user sur
// poste partagé. Un brouillon (email/objet/corps + destinataire réel d'un
// contact) de user A ne doit JAMAIS être proposé à user B après un changement de
// compte sur le même navigateur. Même pattern établi que iris.js (_getDraftKey
// 'iris.draft.text.'+who) et privacy-badge.js (cacheKeyForUser). L'id vient du
// <meta name="komptia-user-id"> injecté par base.html sur toutes les pages.
function _contactsDraftUserId() {
    try {
        var meta = document.querySelector('meta[name="komptia-user-id"]');
        if (meta && meta.content) return String(meta.content);
    } catch (_e) { /* defensive */ }
    return 'anon';
}
var DRAFT_STORAGE_KEY = 'komptia_contacts_draft.' + _contactsDraftUserId();

// Purge des brouillons d'AUTRES utilisateurs (et de l'ancienne clé plate
// non-scopée) laissés sur ce navigateur → on ne garde QUE la clé courante
// (pattern privacy-badge.js). Évite qu'un brouillon orphelin d'un autre compte
// survive indéfiniment dans le storage.
(function _purgeForeignContactDrafts() {
    try {
        for (var i = localStorage.length - 1; i >= 0; i--) {
            var k = localStorage.key(i);
            if (!k) continue;
            var isContactDraft = k === 'komptia_contacts_draft'
                || k.indexOf('komptia_contacts_draft.') === 0;
            if (isContactDraft && k !== DRAFT_STORAGE_KEY) {
                localStorage.removeItem(k);
            }
        }
    } catch (_e) { /* localStorage indispo → no-op */ }
})();

/**
 * Sauvegarde un draft du formulaire actif dans localStorage avant un
 * redirect 401. Permet de restaurer la saisie après re-login. TTL court
 * (10 min) pour ne pas polluer le storage avec des drafts stale.
 */
function saveDraftBeforeRedirect() {
    try {
        var draft = { ts: Date.now() };
        // Modale contact (création / édition) : email + champs.
        var contactModalEl = document.getElementById('contactModal');
        if (contactModalEl && !contactModalEl.classList.contains('hidden')) {
            draft.contact = {
                editingId: editingId,
                email: (document.getElementById('contactEmail') || {}).value || '',
                first_name: (document.getElementById('contactFirstName') || {}).value || '',
                last_name: (document.getElementById('contactLastName') || {}).value || '',
                company: (document.getElementById('contactCompany') || {}).value || '',
                phone: (document.getElementById('contactPhone') || {}).value || '',
                notes: (document.getElementById('contactNotes') || {}).value || '',
            };
        }
        // Modale liste : nom + description + sélection initiale.
        var listModalEl = document.getElementById('listModal');
        if (listModalEl && !listModalEl.classList.contains('hidden')) {
            draft.list = {
                editingListId: editingListId,
                name: (document.getElementById('listName') || {}).value || '',
                description: (document.getElementById('listDescription') || {}).value || '',
                selectedInitialContacts: selectedInitialContacts.map(function (c) { return c.id; }),
            };
        }
        // Modale email : subject + body + cible figée. Le body peut faire
        // jusqu'à 10K chars, perdre ça parce que la session a expiré
        // pendant la rédaction est une frustration majeure.
        var emailModalEl = document.getElementById('emailModal');
        if (emailModalEl && !emailModalEl.classList.contains('hidden') && currentEmailTarget) {
            draft.email = {
                subject: (document.getElementById('emailSubject') || {}).value || '',
                body: (document.getElementById('emailBody') || {}).value || '',
                target: currentEmailTarget,
            };
        }
        if (draft.contact || draft.list || draft.email) {
            localStorage.setItem(DRAFT_STORAGE_KEY, JSON.stringify(draft));
        }
    } catch (_) {
        // localStorage indispo (private mode Safari, quota plein) → on
        // accepte la perte du draft, mieux que crash.
    }
}

/**
 * Restaure un éventuel draft sauvegardé < 10 min. Appelé au boot DOM.
 * Évite la frustration "j'avais saisi 5 champs et j'ai été déconnecté".
 */
function restoreDraftIfRecent() {
    try {
        var raw = localStorage.getItem(DRAFT_STORAGE_KEY);
        if (!raw) return;
        var draft = JSON.parse(raw);
        if (!draft || !draft.ts || Date.now() - draft.ts > 10 * 60 * 1000) {
            localStorage.removeItem(DRAFT_STORAGE_KEY);
            return;
        }
        // Notifie l'utilisateur — il décide de restaurer ou non.
        var label = draft.contact
            ? 'un contact en cours de saisie'
            : (draft.email ? 'un email en cours de rédaction' : 'une liste en cours de saisie');
        if (window.appConfirm) {
            appConfirm('Reprendre ' + label + ' (sauvegardé avant déconnexion) ?', 'Restaurer le brouillon').then(function (ok) {
                if (!ok) { localStorage.removeItem(DRAFT_STORAGE_KEY); return; }
                if (draft.contact) {
                    editingId = draft.contact.editingId;
                    openCreateModal();
                    var f = draft.contact;
                    document.getElementById('contactEmail').value = f.email;
                    document.getElementById('contactFirstName').value = f.first_name;
                    document.getElementById('contactLastName').value = f.last_name;
                    document.getElementById('contactCompany').value = f.company;
                    document.getElementById('contactPhone').value = f.phone;
                    document.getElementById('contactNotes').value = f.notes;
                }
                if (draft.list) {
                    openListModal();
                    document.getElementById('listName').value = draft.list.name;
                    document.getElementById('listDescription').value = draft.list.description;
                    // Les contacts initiaux ne sont pas restaurés (ids peuvent
                    // avoir disparu) — l'utilisateur les re-sélectionne.
                }
                if (draft.email && draft.email.target) {
                    // Restaure la cible email + subject + body. Si la cible
                    // n'existe plus (contact/liste supprimé entre-temps), le
                    // submit lèvera 400 — pas une catastrophe vs perte du draft.
                    currentEmailTarget = draft.email.target;
                    _renderEmailModalRecipients();
                    document.getElementById('emailModalTitle').textContent = 'Envoyer un email (brouillon restauré)';
                    document.getElementById('emailForm').reset();
                    document.getElementById('emailSubject').value = draft.email.subject;
                    document.getElementById('emailBody').value = draft.email.body;
                    updateEmailBodyCount();
                    openOverlay(emailModal);
                }
                localStorage.removeItem(DRAFT_STORAGE_KEY);
            });
        }
    } catch (_) {
        try { localStorage.removeItem(DRAFT_STORAGE_KEY); } catch (_e) {}
    }
}

/**
 * fetch avec garde-fous senior :
 *  - 401 → save draft localStorage + redirect /login?next=…
 *  - timeout par tentative (AbortController) — pas de UI bloquée
 *    indéfiniment sur un serveur qui hang
 *  - retry 1× sur erreur réseau (TypeError) avec backoff
 *  - capture X-Request-ID dans window.__komptiaLastRequestId pour le
 *    bouton "Signaler" du feedback-reporter
 *  - retourne {ok, status, data} uniformément, ne throw jamais
 */
async function safeFetch(url, options, opts) {
    opts = opts || {};
    var maxRetries = (opts.retries === undefined) ? 1 : opts.retries;
    var timeoutMs = opts.timeoutMs || FETCH_TIMEOUT_MS;
    var attempt = 0;
    options = options || {};
    while (true) {
        var controller = new AbortController();
        var timer = setTimeout(function () { controller.abort(); }, timeoutMs);
        try {
            var res = await fetch(url, Object.assign({}, options, { signal: controller.signal }));
            clearTimeout(timer);
            // Stocke le request_id pour le bug-report (dernier appel).
            try { window.__komptiaLastRequestId = res.headers.get('X-Request-ID') || ''; } catch (_) {}
            try { window.__komptiaLastHttpStatus = res.status; } catch (_) {}

            if (res.status === 401) {
                // Session expirée : sauvegarder le draft AVANT redirect.
                saveDraftBeforeRedirect();
                var next = encodeURIComponent(window.location.pathname + window.location.search);
                window.location.href = '/login?next=' + next;
                return { ok: false, status: 401, data: { error: 'Session expirée' }, _redirected: true };
            }
            if (!res.ok) {
                var body;
                try { body = await res.json(); } catch (_e) { body = {}; }
                return { ok: false, status: res.status, data: body };
            }
            var data = await res.json();
            return { ok: true, status: res.status, data: data };
        } catch (err) {
            clearTimeout(timer);
            // Distingue timeout (AbortError) de network down (TypeError).
            // Les deux retentent, mais on log différemment côté console.
            var isTimeout = (err && err.name === 'AbortError');
            if (attempt < maxRetries) {
                attempt += 1;
                await new Promise(function (r) { setTimeout(r, FETCH_RETRY_BACKOFF_MS * attempt); });
                continue;
            }
            return {
                ok: false,
                status: 0,
                data: { error: isTimeout ? 'Délai dépassé' : 'Pas de connexion réseau' },
                _network: true,
                _timeout: isTimeout,
            };
        }
    }
}

function setSubmitting(state, scopeForm) {
    isSubmitting = state;
    // Scoper le disabled au form en cours si fourni (évite de désactiver les
    // submits d'autres modales ouvertes simultanément).
    var roots = scopeForm ? [scopeForm] : [document];
    roots.forEach(function (root) {
        root.querySelectorAll('button[type="submit"], #btnSubmitList, #btnSubmitEmail').forEach(function (btn) {
            btn.disabled = state;
            if (state) btn.classList.add('opacity-50', 'cursor-not-allowed');
            else btn.classList.remove('opacity-50', 'cursor-not-allowed');
        });
    });
}

// Helpers OverlayManager : combine classList.add/remove + manager. Le
// manager gère ensuite trapFocus, inertSiblings, scroll-lock, z-index
// et Escape (top-most LIFO).
function openOverlay(el, opts) {
    if (!el) return;
    el.classList.remove('hidden');
    el.classList.add('flex');
    el.setAttribute('aria-hidden', 'false');
    if (window.OverlayManager) {
        window.OverlayManager.open(el, Object.assign({
            layer: 'modal',
            lockScroll: true,
            trapFocus: true,
            inertSiblings: true
        }, opts || {}));
    }
}

function closeOverlay(el) {
    if (!el) return;
    if (window.OverlayManager) window.OverlayManager.close(el);
    el.classList.add('hidden');
    el.classList.remove('flex');
    el.setAttribute('aria-hidden', 'true');
}

/* ── Contacts lookup cache for edit button ─────────────── */
var contactsCache = {};

/* ── Tabs (WAI-ARIA tablist : aria-selected + tabindex roving) ─── */
function switchTab(tab) {
    var tabs = ['contacts', 'lists'];
    tabs.forEach(function (t) {
        var btn = document.getElementById('tab-' + t);
        var panel = document.getElementById('panel-' + t);
        var actions = document.getElementById('tab-actions-' + t);
        var isActive = (t === tab);
        if (isActive) {
            btn.classList.add('border-brand-600', 'text-brand-600');
            btn.classList.remove('border-transparent', 'text-gray-500');
            btn.setAttribute('aria-selected', 'true');
            btn.setAttribute('tabindex', '0');
            panel.classList.remove('hidden');
            if (actions) actions.classList.remove('hidden');
        } else {
            btn.classList.remove('border-brand-600', 'text-brand-600');
            btn.classList.add('border-transparent', 'text-gray-500');
            btn.setAttribute('aria-selected', 'false');
            btn.setAttribute('tabindex', '-1');
            panel.classList.add('hidden');
            if (actions) actions.classList.add('hidden');
        }
    });
    if (tab === 'lists') loadLists();
}

/* ═══════════════════════ CONTACTS ═══════════════════════ */

// Search debounced — la requête API ne part QUE 300 ms après la dernière
// frappe, donc taper "abc" ne déclenche qu'UN appel (pas 3).
// La page n'est jamais rechargée : seulement le tbody est repaint.
var debounceSearch = debounce(function () { currentPage = 1; loadContacts(); }, 300);

async function loadContacts(page) {
    if (page) currentPage = page;
    var q = document.getElementById('search-input').value;
    var status = document.getElementById('filter-status').value;
    var params = new URLSearchParams({
        q: q,
        status: status,
        page: currentPage,
        per_page: DEFAULT_PER_PAGE
    });
    if (currentSortKey) {
        params.set('sort', currentSortKey);
        params.set('order', currentSortDir);
    }

    var loadingEl = document.getElementById('contacts-loading');
    var errorEl = document.getElementById('contacts-error');
    var contentEl = document.getElementById('contacts-content');
    var tbody = document.getElementById('contacts-body');
    if (loadingEl) loadingEl.classList.remove('hidden');
    if (errorEl) errorEl.classList.add('hidden');
    if (contentEl) contentEl.classList.add('hidden');
    if (tbody) tbody.setAttribute('aria-busy', 'true');

    var resp = await safeFetch('/api/contacts?' + params.toString(), {
        headers: { 'X-Requested-With': 'XMLHttpRequest' }
    });
    if (loadingEl) loadingEl.classList.add('hidden');
    if (tbody) tbody.setAttribute('aria-busy', 'false');

    if (!resp.ok) {
        if (resp._redirected) return;  // 401 déjà géré par safeFetch
        if (errorEl) {
            var msgEl = document.getElementById('contacts-error-message');
            var detailEl = document.getElementById('contacts-error-detail');
            if (resp._network) {
                if (msgEl) msgEl.textContent = 'Pas de connexion réseau';
                if (detailEl) detailEl.textContent = 'Vérifiez votre connexion puis cliquez sur Réessayer.';
            } else {
                if (msgEl) msgEl.textContent = 'Impossible de charger les contacts';
                if (detailEl) detailEl.textContent = 'Erreur ' + resp.status + ' — ' + (resp.data && resp.data.error ? resp.data.error : 'Réessayez ou signalez le problème.');
            }
            errorEl.classList.remove('hidden');
        }
        return;
    }
    if (contentEl) contentEl.classList.remove('hidden');
    var data = resp.data;

    // Cache pour le edit (re-clic sur Modifier sans re-fetch).
    contactsCache = {};
    (data.contacts || []).forEach(function (c) { contactsCache[c.id] = c; });

    var empty = document.getElementById('empty-state');
    var emptyMsg = document.getElementById('empty-state-message');
    var hasFilters = (q && q.length > 0) || status !== 'all';

    updateFilterSummary(data.total, q, status);
    updateSortIndicators();

    if (!data.contacts || data.contacts.length === 0) {
        // Page AU-DELÀ du total (ex: suppression du dernier contact d'une page
        // N>1) : des contacts EXISTENT (pour le filtre courant) mais pas sur
        // cette page. Afficher l'empty-state + vider la pagination = message
        // trompeur + cul-de-sac. On re-clamp à la dernière page valide et on
        // recharge (auto-récupération). ``data.total`` reflète le filtre
        // courant → correct filtré ET non-filtré. Terminaison STRUCTURELLE :
        // re-clamp seulement si la cible est STRICTEMENT < page courante →
        // ``currentPage`` décroît, borné même si total/total_pages incohérent
        // (même garde loop-safe que le fix /reports, cf. review adversariale).
        var clampTarget = Math.max(1, data.total_pages || 1);
        if ((data.total || 0) > 0 && clampTarget < currentPage) {
            currentPage = clampTarget;
            return loadContacts();
        }
        tbody.innerHTML = '';
        // Empty state contextualisé : si filtres actifs, dire qu'aucun résultat
        // ne match (pas "aucun contact n'existe" — qui est trompeur).
        if (emptyMsg) {
            emptyMsg.textContent = hasFilters
                ? 'Aucun contact ne correspond à vos critères'
                : 'Aucun contact pour l\'instant';
        }
        empty.classList.remove('hidden');
        document.getElementById('pagination').innerHTML = '';
        // F7 (review loop) : rafraîchir AUSSI les cartes stats quand 0 contact
        // (sinon elles restent figées sur le placeholder « - » au lieu de « 0 »
        // pour un premier utilisateur). updateStats() a son propre fetch /stats,
        // indépendant de la liste — sûr à appeler ici.
        updateStats();
        return;
    }
    empty.classList.add('hidden');

    tbody.innerHTML = data.contacts.map(function (c) {
        var name = [c.first_name, c.last_name].filter(Boolean).join(' ') || '-';
        // ``Email`` désactivé pour les inactifs (cohérence : on n'envoie pas
        // à un contact que l'utilisateur a explicitement désactivé) et les
        // unsubscribed (RGPD : interdit). Le filtre RGPD est aussi appliqué
        // côté serveur (defense-in-depth), mais on retire l'item pour
        // ne pas laisser croire à l'utilisateur qu'il peut envoyer.
        var canEmail = c.is_active && !c.is_unsubscribed;
        var emailItem = canEmail
            ? '<button type="button" data-action="emailContact" data-contact-id="' + c.id + '" data-contact-email="' + escAttr(c.email) + '" class="actions-menu-item" role="menuitem">' +
                _ICON_EMAIL + 'Envoyer un email</button>'
            : '';
        var toggleLabel = c.is_active ? 'Désactiver' : 'Activer';
        var toggleIcon = c.is_active ? _ICON_PAUSE : _ICON_PLAY;
        return '<tr class="hover:bg-gray-50 dark:hover:bg-gray-800">' +
            '<td class="table-cell font-medium text-gray-900 dark:text-gray-100">' + esc(c.email) + '</td>' +
            '<td class="table-cell text-gray-600 dark:text-gray-400">' + esc(name) + '</td>' +
            '<td class="table-cell text-gray-600 dark:text-gray-400">' + esc(c.company || '-') + '</td>' +
            '<td class="table-cell text-gray-600 dark:text-gray-400">' + esc(c.phone || '-') + '</td>' +
            '<td class="table-cell"><span class="badge ' + (c.is_active ? 'badge-success' : 'badge-neutral') + '">' + (c.is_active ? 'Actif' : 'Inactif') + '</span></td>' +
            '<td class="table-cell">' +
                '<div class="actions-menu">' +
                    '<button type="button" class="actions-menu-trigger" data-action="toggleActionsMenu" aria-label="Actions pour ' + escAttr(c.email) + '" aria-haspopup="menu" aria-expanded="false">' +
                        _ICON_KEBAB +
                    '</button>' +
                    '<div class="actions-menu-dropdown hidden" role="menu">' +
                        emailItem +
                        '<button type="button" data-action="editContact" data-contact-id="' + c.id + '" class="actions-menu-item" role="menuitem">' +
                            _ICON_EDIT + 'Modifier</button>' +
                        '<button type="button" data-action="toggleContact" data-contact-id="' + c.id + '" data-activate="' + !c.is_active + '" class="actions-menu-item" role="menuitem">' +
                            toggleIcon + toggleLabel + '</button>' +
                        '<button type="button" data-action="deleteContact" data-contact-id="' + c.id + '" data-contact-email="' + escAttr(c.email) + '" class="actions-menu-item danger" role="menuitem">' +
                            _ICON_TRASH + 'Supprimer</button>' +
                    '</div>' +
                '</div>' +
            '</td></tr>';
    }).join('');

    renderPagination(data.page, data.total_pages, data.total);
    updateStats();
}

/**
 * Met à jour le résumé "X résultats sur Y" + bouton "Effacer les filtres".
 * Évite à l'utilisateur le piège "il n'y a aucun contact" alors qu'un filtre
 * cache tout — pattern UX classique d'un dashboard pro.
 */
function updateFilterSummary(total, q, status) {
    var summary = document.getElementById('filter-summary');
    var clearBtn = document.getElementById('btn-clear-filters');
    var hasFilters = (q && q.length > 0) || status !== 'all';
    if (summary) {
        if (hasFilters) {
            summary.textContent = total + ' résultat' + (total > 1 ? 's' : '');
        } else {
            summary.textContent = '';
        }
    }
    if (clearBtn) {
        clearBtn.classList.toggle('hidden', !hasFilters);
    }
}

/**
 * Met à jour l'indicateur visuel de tri (▲/▼) + aria-sort sur les <th>.
 * Aria-sort : "ascending" / "descending" / "none" (WAI-ARIA 1.1).
 */
function updateSortIndicators() {
    document.querySelectorAll('th[data-sort-key]').forEach(function (th) {
        var key = th.getAttribute('data-sort-key');
        var indicator = th.querySelector('.sort-indicator');
        if (key === currentSortKey) {
            th.setAttribute('aria-sort', currentSortDir === 'asc' ? 'ascending' : 'descending');
            if (indicator) indicator.textContent = currentSortDir === 'asc' ? '▲' : '▼';
            if (indicator) indicator.classList.remove('text-gray-400');
            if (indicator) indicator.classList.add('text-brand-600');
        } else {
            th.setAttribute('aria-sort', 'none');
            if (indicator) indicator.textContent = '⇅';
            if (indicator) indicator.classList.add('text-gray-400');
            if (indicator) indicator.classList.remove('text-brand-600');
        }
    });
}

/**
 * Click handler tri colonne : 1er click = asc, 2ème = desc, 3ème = remove.
 */
function sortContacts(target) {
    var key = target.getAttribute('data-sort-key');
    if (!key) return;
    if (currentSortKey === key) {
        if (currentSortDir === 'asc') currentSortDir = 'desc';
        else { currentSortKey = ''; currentSortDir = 'asc'; }
    } else {
        currentSortKey = key;
        currentSortDir = 'asc';
    }
    currentPage = 1;
    loadContacts();
}

function clearContactFilters() {
    document.getElementById('search-input').value = '';
    document.getElementById('filter-status').value = 'all';
    currentSortKey = '';
    currentSortDir = 'asc';
    currentPage = 1;
    loadContacts();
}

/**
 * Bouton "Signaler" sur error state — relaie au feedback-reporter global.
 * Pré-rempli avec contexte technique (URL, status, request_id).
 */
function reportContactsError() {
    if (!window.komptiaReportFeedback) {
        showToast('Le système de signalement n\'est pas disponible', 'error');
        return;
    }
    var ctx = '[Page Contacts] Erreur de chargement\n' +
              'URL : ' + window.location.pathname + '\n' +
              'Status : ' + (window.__komptiaLastHttpStatus || 'N/A') + '\n' +
              'Request-ID : ' + (window.__komptiaLastRequestId || 'N/A');
    window.komptiaReportFeedback({ message: ctx });
}

function reportListsError() {
    if (!window.komptiaReportFeedback) {
        showToast('Le système de signalement n\'est pas disponible', 'error');
        return;
    }
    var ctx = '[Page Contacts — Listes de diffusion] Erreur de chargement\n' +
              'URL : ' + window.location.pathname + '\n' +
              'Status : ' + (window.__komptiaLastHttpStatus || 'N/A') + '\n' +
              'Request-ID : ' + (window.__komptiaLastRequestId || 'N/A');
    window.komptiaReportFeedback({ message: ctx });
}

function renderPagination(page, totalPages, total) {
    var html = '';
    if (totalPages > 1) {
        html += '<button class="btn btn-secondary text-xs py-1 px-2" data-action="loadContacts" data-page="' + (page - 1) + '" ' + (page === 1 ? 'disabled' : '') + '>Préc.</button>';
        for (var i = 1; i <= totalPages; i++) {
            if (i === 1 || i === totalPages || Math.abs(i - page) <= 2) {
                html += '<button class="btn ' + (i === page ? 'btn-primary' : 'btn-secondary') + ' text-xs py-1 px-2" data-action="loadContacts" data-page="' + i + '">' + i + '</button>';
            } else if (Math.abs(i - page) === 3) {
                html += '<span class="text-gray-400 text-xs px-1 dark:text-gray-500">...</span>';
            }
        }
        html += '<button class="btn btn-secondary text-xs py-1 px-2" data-action="loadContacts" data-page="' + (page + 1) + '" ' + (page === totalPages ? 'disabled' : '') + '>Suiv.</button>';
        html += '<span class="text-xs text-gray-500 ml-2 dark:text-gray-400">' + total + ' contacts</span>';
    }
    document.getElementById('pagination').innerHTML = html;
}

async function updateStats() {
    var resp = await safeFetch('/api/contacts/stats', {
        headers: { 'X-Requested-With': 'XMLHttpRequest' }
    });
    if (!resp.ok) return;
    var stats = resp.data;
    setStat('stat-total', stats.total);
    setStat('stat-active', stats.active);
    setStat('stat-inactive', stats.inactive);
}

/* ── Contact modals ── */
var modal = document.getElementById('contactModal');

function openCreateModal() {
    editingId = null;
    document.getElementById('modalTitle').textContent = 'Nouveau contact';
    document.getElementById('contactForm').reset();
    document.getElementById('contactId').value = '';
    var errEl = document.getElementById('contactEmail-error');
    if (errEl) errEl.classList.add('hidden');
    openOverlay(modal);
    // Focus initial sur le 1er input — UX clavier classique. (OverlayManager
    // peut le faire via trapFocus mais on le force pour garantir le bon champ.)
    setTimeout(function () { document.getElementById('contactEmail').focus(); }, 50);
}

function editContact(contactId) {
    var c = contactsCache[contactId];
    if (!c) return;
    editingId = c.id;
    document.getElementById('modalTitle').textContent = 'Modifier le contact';
    document.getElementById('contactEmail').value = c.email;
    document.getElementById('contactFirstName').value = c.first_name || '';
    document.getElementById('contactLastName').value = c.last_name || '';
    document.getElementById('contactCompany').value = c.company || '';
    document.getElementById('contactPhone').value = c.phone || '';
    document.getElementById('contactNotes').value = c.notes || '';
    var errEl = document.getElementById('contactEmail-error');
    if (errEl) errEl.classList.add('hidden');
    openOverlay(modal);
    setTimeout(function () { document.getElementById('contactEmail').focus(); }, 50);
}

function closeModal() {
    closeOverlay(modal);
}

document.getElementById('contactForm').addEventListener('submit', async function (e) {
    e.preventDefault();
    if (isSubmitting) return;

    // Validation client : email format + non-vide. Évite un POST aller-retour
    // pour un message d'erreur évident.
    var emailEl = document.getElementById('contactEmail');
    var emailErr = document.getElementById('contactEmail-error');
    var emailVal = emailEl.value.trim();
    if (!emailVal) {
        if (emailErr) { emailErr.textContent = 'L\'email est requis.'; emailErr.classList.remove('hidden'); }
        emailEl.focus();
        return;
    }
    // Regex simplifiée : un @ entouré de caractères, avec un . dans la partie domaine.
    // La validation stricte est côté serveur (email_validator) — celle-ci n'est qu'un garde-fou UX.
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailVal)) {
        if (emailErr) { emailErr.textContent = 'Format d\'email invalide.'; emailErr.classList.remove('hidden'); }
        emailEl.focus();
        return;
    }
    if (emailErr) emailErr.classList.add('hidden');

    setSubmitting(true, this);

    var data = {
        email: emailVal,
        first_name: document.getElementById('contactFirstName').value,
        last_name: document.getElementById('contactLastName').value,
        company: document.getElementById('contactCompany').value,
        phone: document.getElementById('contactPhone').value,
        notes: document.getElementById('contactNotes').value,
    };

    var url = editingId ? '/api/contacts/' + editingId : '/api/contacts';
    var method = editingId ? 'PUT' : 'POST';

    var resp = await safeFetch(url, {
        method: method,
        headers: {
            'Content-Type': 'application/json',
            'X-Xsrftoken': getCookie('_xsrf')
        },
        body: JSON.stringify(data)
    }, { retries: 0 });

    setSubmitting(false, this);

    if (resp._redirected) return;
    if (resp.ok) {
        showToast(editingId ? 'Contact modifié' : 'Contact créé', 'success');
        closeModal();
        loadContacts();
        if (window.__komptiaNotifyContactsChange) window.__komptiaNotifyContactsChange();
    } else if (resp._network) {
        showToast('Pas de connexion réseau — réessayez', 'error');
    } else if (resp.status === 409 && resp.data && resp.data.error) {
        // Mettre l'erreur dans le champ email (cas duplicate).
        if (emailErr) { emailErr.textContent = resp.data.error; emailErr.classList.remove('hidden'); }
        emailEl.focus();
    } else {
        showToast((resp.data && resp.data.error) || 'Erreur', 'error');
    }
});

async function toggleContact(id, activate) {
    var resp = await safeFetch('/api/contacts/' + id, {
        method: 'PUT',
        headers: {
            'Content-Type': 'application/json',
            'X-Xsrftoken': getCookie('_xsrf')
        },
        body: JSON.stringify({ is_active: activate })
    }, { retries: 0 });

    if (resp._redirected) return;
    if (resp.ok) {
        showToast(activate ? 'Contact activé' : 'Contact désactivé', 'success');
        loadContacts();
        if (window.__komptiaNotifyContactsChange) window.__komptiaNotifyContactsChange();
    } else {
        showToast((resp.data && resp.data.error) || 'Erreur lors de la modification', 'error');
    }
}

async function deleteContact(id, email) {
    // Confirm contextualisé : l'email du contact dans la question.
    // Action irréversible (cascade sur contact_list_association).
    var msg = email
        ? 'Supprimer définitivement le contact « ' + email + ' » ?\n\nIl sera retiré de toutes les listes de diffusion.'
        : 'Voulez-vous vraiment supprimer ce contact ?';
    var confirmed = await appConfirm(msg, 'Supprimer le contact');
    if (!confirmed) return;

    var resp = await safeFetch('/api/contacts/' + id, {
        method: 'DELETE',
        headers: { 'X-Xsrftoken': getCookie('_xsrf') }
    }, { retries: 0 });

    if (resp._redirected) return;
    if (resp.ok) {
        showToast('Contact supprimé', 'success');
        loadContacts();
        if (window.__komptiaNotifyContactsChange) window.__komptiaNotifyContactsChange();
    } else {
        showToast((resp.data && resp.data.error) || 'Erreur lors de la suppression', 'error');
    }
}

/* ── Import modal ── */
var importModal = document.getElementById('importModal');

function openImportModal() {
    document.getElementById('importForm').reset();
    openOverlay(importModal);
    setTimeout(function () { document.getElementById('csvFile').focus(); }, 50);
}

function closeImportModal() {
    closeOverlay(importModal);
}

document.getElementById('importForm').addEventListener('submit', async function (e) {
    e.preventDefault();
    if (isSubmitting) return;

    var fileInput = document.getElementById('csvFile');
    var file = fileInput.files[0];
    if (!file) {
        showToast('Sélectionnez un fichier CSV', 'error');
        fileInput.focus();
        return;
    }
    setSubmitting(true, this);

    var formData = new FormData();
    formData.append('file', file);

    var resp = await safeFetch('/api/contacts/import', {
        method: 'POST',
        headers: { 'X-Xsrftoken': getCookie('_xsrf') },
        body: formData
    }, { retries: 0 });

    setSubmitting(false, this);

    if (resp._redirected) return;
    if (resp.ok) {
        var data = resp.data || {};
        var imported = data.imported || 0;
        var skipped = data.skipped || 0;
        var errors = data.errors || 0;
        var truncated = data.truncated || 0;
        var msg = imported + ' contact' + (imported > 1 ? 's' : '') + ' importé' + (imported > 1 ? 's' : '');
        var details = [];
        if (skipped > 0) details.push(skipped + ' doublon' + (skipped > 1 ? 's' : '') + ' ignoré' + (skipped > 1 ? 's' : ''));
        if (errors > 0) details.push(errors + ' erreur' + (errors > 1 ? 's' : ''));
        if (truncated > 0) details.push(truncated + ' tronqué' + (truncated > 1 ? 's' : ''));
        if (details.length > 0) msg += ' (' + details.join(', ') + ')';
        // Si erreurs ou tronqués, signaler en warning pour attirer l'attention.
        var toastType = (errors > 0 || truncated > 0) ? 'warning' : 'success';
        showToast(msg, toastType);
        // Avertissement d'encodage (fallback cp1252) : risque de mojibake
        // silencieux sur les accents — toast distinct pour ne pas le noyer.
        if (data.warning) showToast(data.warning, 'warning');
        closeImportModal();
        loadContacts();
        if (window.__komptiaNotifyContactsChange) window.__komptiaNotifyContactsChange();
    } else if (resp._network) {
        showToast('Pas de connexion réseau — réessayez', 'error');
    } else if (resp.status === 413) {
        showToast('Fichier trop volumineux (max 5 Mo)', 'error');
    } else if (resp.status === 429) {
        showToast('Trop d\'imports successifs — attendez 1 minute', 'error');
    } else {
        showToast((resp.data && resp.data.error) || 'Erreur lors de l\'import', 'error');
    }
});

/* ═══════════════════ DISTRIBUTION LISTS ═══════════════════ */
var listsData = [];
var allListsData = [];
var availableContactsCache = [];
var currentMembersCache = [];

// Tri client (les listes sont chargées entièrement, ~10-100 max).
var currentListsSortKey = '';     // '' | 'name' | 'description' | 'contact_count' | 'is_active'
var currentListsSortDir = 'asc';

async function loadLists() {
    var tbody = document.getElementById('lists-body');
    var loadingEl = document.getElementById('lists-loading');
    var errorEl = document.getElementById('lists-error');
    var contentEl = document.getElementById('lists-content');
    var emptyEl = document.getElementById('lists-empty');
    if (loadingEl) loadingEl.classList.remove('hidden');
    if (errorEl) errorEl.classList.add('hidden');
    // Masque le tableau + l'empty-state pendant le chargement / en erreur,
    // pour n'afficher qu'UN état à la fois (parité onglet Contacts) — sinon
    // le spinner se superpose aux anciennes lignes / "Aucune liste".
    if (contentEl) contentEl.classList.add('hidden');
    if (emptyEl) emptyEl.classList.add('hidden');
    if (tbody) tbody.setAttribute('aria-busy', 'true');

    var resp = await safeFetch('/api/distribution-lists', {
        headers: { 'X-Requested-With': 'XMLHttpRequest' }
    });

    if (loadingEl) loadingEl.classList.add('hidden');
    if (tbody) tbody.setAttribute('aria-busy', 'false');

    if (resp._redirected) return;
    if (!resp.ok) {
        // Parité avec l'onglet Contacts : box d'erreur (réseau vs serveur) +
        // Réessayer / Signaler, au lieu d'un simple toast qui disparaît.
        if (errorEl) {
            var msgEl = document.getElementById('lists-error-message');
            var detailEl = document.getElementById('lists-error-detail');
            if (resp._network) {
                if (msgEl) msgEl.textContent = 'Pas de connexion réseau';
                if (detailEl) detailEl.textContent = 'Vérifiez votre connexion puis cliquez sur Réessayer.';
            } else {
                if (msgEl) msgEl.textContent = 'Impossible de charger les listes';
                if (detailEl) detailEl.textContent = 'Erreur ' + resp.status + ' — ' + (resp.data && resp.data.error ? resp.data.error : 'Réessayez ou signalez le problème.');
            }
            errorEl.classList.remove('hidden');
        } else {
            showToast('Erreur chargement des listes', 'error');
        }
        return;
    }
    if (contentEl) contentEl.classList.remove('hidden');
    var data = resp.data;
    allListsData = data.lists || [];

    setStat('stat-lists-total', allListsData.length);
    setStat('stat-lists-active', allListsData.filter(function (l) { return l.is_active; }).length);
    setStat('stat-lists-contacts', allListsData.reduce(function (s, l) { return s + (l.contact_count || 0); }, 0));

    filterLists();
}

// Search debounced — filterLists ne touche QUE le tbody, pas la BDD ni la page.
var debounceSearchLists = debounce(function () { filterLists(); }, 300);

function filterLists() {
    var query = document.getElementById('search-lists').value.toLowerCase().trim();
    var status = document.getElementById('filter-lists-status').value;

    // Recherche multi-colonnes : nom + description (les deux colonnes
    // affichées qui peuvent contenir du texte pertinent).
    listsData = allListsData.filter(function (l) {
        var matchQuery = !query ||
            l.name.toLowerCase().includes(query) ||
            (l.description && l.description.toLowerCase().includes(query));
        var matchStatus = status === 'all' ||
            (status === 'active' && l.is_active) ||
            (status === 'inactive' && !l.is_active);
        return matchQuery && matchStatus;
    });

    // Tri local sur la colonne sélectionnée.
    if (currentListsSortKey) {
        var dir = currentListsSortDir === 'asc' ? 1 : -1;
        var k = currentListsSortKey;
        listsData.sort(function (a, b) {
            var va = a[k], vb = b[k];
            if (va == null && vb == null) return 0;
            if (va == null) return -dir;  // null en bas en asc
            if (vb == null) return dir;
            if (typeof va === 'string') va = va.toLowerCase();
            if (typeof vb === 'string') vb = vb.toLowerCase();
            if (va < vb) return -dir;
            if (va > vb) return dir;
            return 0;
        });
    }

    renderLists();
}

function sortLists(target) {
    var key = target.getAttribute('data-sort-key');
    if (!key) return;
    if (currentListsSortKey === key) {
        if (currentListsSortDir === 'asc') currentListsSortDir = 'desc';
        else { currentListsSortKey = ''; currentListsSortDir = 'asc'; }
    } else {
        currentListsSortKey = key;
        currentListsSortDir = 'asc';
    }
    filterLists();
}

function updateListsSortIndicators() {
    document.querySelectorAll('#panel-lists th[data-sort-key]').forEach(function (th) {
        var key = th.getAttribute('data-sort-key');
        var indicator = th.querySelector('.sort-indicator');
        if (key === currentListsSortKey) {
            th.setAttribute('aria-sort', currentListsSortDir === 'asc' ? 'ascending' : 'descending');
            if (indicator) {
                indicator.textContent = currentListsSortDir === 'asc' ? '▲' : '▼';
                indicator.classList.remove('text-gray-400');
                indicator.classList.add('text-brand-600');
            }
        } else {
            th.setAttribute('aria-sort', 'none');
            if (indicator) {
                indicator.textContent = '⇅';
                indicator.classList.add('text-gray-400');
                indicator.classList.remove('text-brand-600');
            }
        }
    });
}

function renderLists() {
    var tbody = document.getElementById('lists-body');
    var empty = document.getElementById('lists-empty');

    updateListsSortIndicators();

    if (listsData.length === 0) {
        tbody.innerHTML = '';
        empty.classList.remove('hidden');
    } else {
        empty.classList.add('hidden');
        tbody.innerHTML = listsData.map(function (l) {
            return '<tr class="hover:bg-gray-50 dark:hover:bg-gray-800">' +
                '<td class="table-cell font-medium text-gray-900 dark:text-gray-100">' + esc(l.name) + '</td>' +
                '<td class="table-cell text-gray-600 dark:text-gray-400">' + esc(l.description || '-') + '</td>' +
                '<td class="table-cell"><span class="inline-flex items-center gap-1 text-sm text-gray-700 dark:text-gray-300">' +
                    '<svg class="w-4 h-4 text-gray-400 dark:text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0z"/></svg>' +
                    l.contact_count +
                '</span></td>' +
                '<td class="table-cell"><span class="badge ' + (l.is_active ? 'badge-success' : 'badge-neutral') + '">' + (l.is_active ? 'Active' : 'Inactive') + '</span></td>' +
                '<td class="table-cell">' +
                    '<div class="actions-menu">' +
                        '<button type="button" class="actions-menu-trigger" data-action="toggleActionsMenu" aria-label="Actions pour ' + escAttr(l.name) + '" aria-haspopup="menu" aria-expanded="false">' +
                            _ICON_KEBAB +
                        '</button>' +
                        '<div class="actions-menu-dropdown hidden" role="menu">' +
                            // Email à toute la liste : seulement si liste active ET contient des membres.
                            (l.is_active && (l.contact_count || 0) > 0
                                ? '<button type="button" data-action="emailList" data-list-id="' + l.id + '" data-list-name="' + escAttr(l.name) + '" data-list-count="' + (l.contact_count || 0) + '" class="actions-menu-item" role="menuitem">' +
                                    _ICON_EMAIL + 'Envoyer un email</button>'
                                : '') +
                            '<button type="button" data-action="openMembersModal" data-list-id="' + l.id + '" data-list-name="' + escAttr(l.name) + '" class="actions-menu-item" role="menuitem">' +
                                _ICON_USERS + 'Membres</button>' +
                            '<button type="button" data-action="editList" data-list-id="' + l.id + '" class="actions-menu-item" role="menuitem">' +
                                _ICON_EDIT + 'Modifier</button>' +
                            '<button type="button" data-action="toggleList" data-list-id="' + l.id + '" data-activate="' + !l.is_active + '" class="actions-menu-item" role="menuitem">' +
                                (l.is_active ? _ICON_PAUSE : _ICON_PLAY) + (l.is_active ? 'Désactiver' : 'Activer') + '</button>' +
                            '<button type="button" data-action="deleteList" data-list-id="' + l.id + '" data-list-name="' + escAttr(l.name) + '" data-list-count="' + (l.contact_count || 0) + '" class="actions-menu-item danger" role="menuitem">' +
                                _ICON_TRASH + 'Supprimer</button>' +
                        '</div>' +
                    '</div>' +
                '</td></tr>';
        }).join('');
    }
}

/* ── List modal (create/edit) ── */
var listModal = document.getElementById('listModal');

function openListModal() {
    editingListId = null;
    selectedInitialContacts = [];
    document.getElementById('listModalTitle').textContent = 'Nouvelle liste';
    document.getElementById('submitListBtnText').textContent = 'Créer et ajouter des membres';
    document.getElementById('listForm').reset();
    document.getElementById('searchInitialContact').value = '';
    document.getElementById('searchInitialContact').setAttribute('aria-expanded', 'false');
    document.getElementById('initialContactSuggestions').classList.add('hidden');
    document.getElementById('selectedContactsContainer').classList.add('hidden');
    document.getElementById('initialMembersSection').classList.remove('hidden');
    openOverlay(listModal);
    setTimeout(function () { document.getElementById('listName').focus(); }, 50);
}

function editList(id) {
    var l = allListsData.find(function (x) { return x.id === id; });
    if (!l) return;
    editingListId = id;
    selectedInitialContacts = [];
    document.getElementById('listModalTitle').textContent = 'Modifier la liste';
    document.getElementById('submitListBtnText').textContent = 'Enregistrer';
    document.getElementById('listName').value = l.name;
    document.getElementById('listDescription').value = l.description || '';
    document.getElementById('initialMembersSection').classList.add('hidden');
    openOverlay(listModal);
    setTimeout(function () { document.getElementById('listName').focus(); }, 50);
}

function closeListModal() {
    closeOverlay(listModal);
    selectedInitialContacts = [];
}

// La recherche utilise le helper debounce centralisé. Le BDD-side search
// cherche dans email + first_name + last_name + company (cf. contact_service.py).
var searchInitialContacts = debounce(async function () {
    var input = document.getElementById('searchInitialContact');
    var container = document.getElementById('initialContactSuggestions');
    var query = input.value.trim();

    if (query.length < 2) {
        // Affiche un message hint plutôt que de cacher silencieusement
        // — sinon le user tape "a" puis attend, sans savoir pourquoi rien ne vient.
        if (query.length === 0) {
            container.classList.add('hidden');
            input.setAttribute('aria-expanded', 'false');
        } else {
            container.innerHTML = '<div class="p-3 text-xs text-gray-500 dark:text-gray-400">Tapez au moins 2 caractères…</div>';
            container.classList.remove('hidden');
            input.setAttribute('aria-expanded', 'true');
        }
        return;
    }

    var resp = await safeFetch('/api/contacts?status=active&q=' + encodeURIComponent(query) + '&per_page=50', {
        headers: { 'X-Requested-With': 'XMLHttpRequest' }
    });
    if (!resp.ok) return;
    var contacts = resp.data.contacts || [];

    var selectedIds = new Set(selectedInitialContacts.map(function (c) { return c.id; }));
    var available = contacts.filter(function (c) { return !selectedIds.has(c.id); });

    renderInitialContactSuggestions(available);
    input.setAttribute('aria-expanded', 'true');
}, 300);

function renderInitialContactSuggestions(contacts) {
    var container = document.getElementById('initialContactSuggestions');

    if (contacts.length === 0) {
        container.innerHTML = '<div class="p-3 text-sm text-gray-500 text-center dark:text-gray-400">Aucun contact trouvé</div>';
        container.classList.remove('hidden');
        return;
    }

    container.innerHTML = contacts.map(function (c) {
        var name = [c.first_name, c.last_name].filter(Boolean).join(' ');
        return '<button type="button" data-action="addInitialContact" data-contact-id="' + c.id + '"' +
            ' class="w-full text-left px-3 py-2 hover:bg-gray-50 border-b border-gray-100 last:border-b-0 dark:hover:bg-gray-800 dark:border-gray-800">' +
            '<p class="text-sm font-medium text-gray-900 truncate dark:text-gray-100">' + esc(c.email) + '</p>' +
            (name ? '<p class="text-xs text-gray-500 truncate dark:text-gray-400">' + esc(name) + (c.company ? ' • ' + esc(c.company) : '') + '</p>' : '') +
            '</button>';
    }).join('');

    // Store contacts for lookup
    contacts.forEach(function (c) { contactsCache[c.id] = c; });
    container.classList.remove('hidden');
}

function addInitialContact(contactId) {
    var contact = contactsCache[contactId];
    if (!contact) return;
    if (selectedInitialContacts.find(function (c) { return c.id === contact.id; })) return;

    selectedInitialContacts.push(contact);
    document.getElementById('searchInitialContact').value = '';
    document.getElementById('initialContactSuggestions').classList.add('hidden');
    renderSelectedInitialContacts();
}

function removeInitialContact(contactId) {
    selectedInitialContacts = selectedInitialContacts.filter(function (c) { return c.id !== contactId; });
    renderSelectedInitialContacts();
}

function renderSelectedInitialContacts() {
    var container = document.getElementById('selectedContactsContainer');
    var list = document.getElementById('selectedContactsList');
    var count = document.getElementById('selectedCount');

    count.textContent = selectedInitialContacts.length;

    if (selectedInitialContacts.length === 0) {
        container.classList.add('hidden');
        return;
    }

    container.classList.remove('hidden');
    list.innerHTML = selectedInitialContacts.map(function (c) {
        var name = [c.first_name, c.last_name].filter(Boolean).join(' ');
        return '<div class="flex items-center justify-between py-2 px-3 rounded bg-white hover:bg-gray-50 dark:bg-gray-900 dark:hover:bg-gray-800">' +
            '<div class="flex-1 min-w-0">' +
                '<p class="text-sm font-medium text-gray-900 truncate dark:text-gray-100">' + esc(c.email) + '</p>' +
                (name ? '<p class="text-xs text-gray-500 truncate dark:text-gray-400">' + esc(name) + (c.company ? ' • ' + esc(c.company) : '') + '</p>' : '') +
            '</div>' +
            '<button type="button" data-action="removeInitialContact" data-contact-id="' + c.id + '" class="text-red-500 hover:text-red-700 text-xs font-medium ml-2 dark:text-red-400">Retirer</button>' +
        '</div>';
    }).join('');
}

async function submitListForm() {
    if (isSubmitting) return;
    var formEl = document.getElementById('listForm');
    var nameInput = document.getElementById('listName');
    var name = nameInput.value.trim();

    if (!name) {
        showToast('Le nom de la liste est requis', 'error');
        nameInput.focus();
        return;
    }

    setSubmitting(true, formEl);

    var payload = {
        name: name,
        description: document.getElementById('listDescription').value.trim() || null,
    };

    var url = editingListId ? '/api/distribution-lists/' + editingListId : '/api/distribution-lists';
    var method = editingListId ? 'PUT' : 'POST';

    var resp = await safeFetch(url, {
        method: method,
        headers: {
            'Content-Type': 'application/json',
            'X-Xsrftoken': getCookie('_xsrf')
        },
        body: JSON.stringify(payload)
    }, { retries: 0 });

    if (!resp.ok) {
        setSubmitting(false, formEl);
        if (resp._redirected) return;
        if (resp._network) {
            showToast('Pas de connexion réseau — réessayez', 'error');
        } else {
            showToast((resp.data && resp.data.error) || 'Erreur', 'error');
        }
        return;
    }

    if (editingListId) {
        showToast('Liste modifiée', 'success');
        closeListModal();
        await loadLists();
        if (window.__komptiaNotifyContactsChange) window.__komptiaNotifyContactsChange();
        setSubmitting(false, formEl);
        return;
    }

    var newListId = resp.data.list.id;

    if (selectedInitialContacts.length > 0) {
        try {
            await addInitialMembersToList(newListId);
            showToast('Liste créée avec ' + selectedInitialContacts.length + ' membre(s)', 'success');
        } catch (err) {
            // Session expirée pendant l'ajout : safeFetch a déjà sauvegardé le
            // brouillon et redirigé vers /login. On sort en silence (même
            // convention que les 14 autres call sites : « _redirected → return »)
            // pour éviter un toast trompeur et la cascade close/load/open qui
            // courserait la navigation en cours.
            if (err && err._redirected) return;
            // P6 (audit 2026-05-26) — Avant : message vague qui jetait
            // err.message / err.body.error. Maintenant : on inclut le détail
            // pour que l'user sache pourquoi (contact déjà membre, list pleine).
            var _bodyErr = err && err.body && err.body.error;
            var _detail = _bodyErr || (err && err.message) || 'détail indisponible';
            showToast(
                "Liste créée, mais ajout des membres échoué : " + _detail,
                'warning'
            );
        }
    } else {
        showToast('Liste créée', 'success');
    }

    closeListModal();
    // Pas de setTimeout artificiel : on attend que loadLists soit fini
    // avant d'ouvrir la modal Members (sinon race avec un loadLists() pas
    // encore renvoyé).
    await loadLists();
    if (window.__komptiaNotifyContactsChange) window.__komptiaNotifyContactsChange();
    setSubmitting(false, formEl);
    openMembersModal(newListId, name);
}

async function addInitialMembersToList(listId) {
    if (selectedInitialContacts.length === 0) return;

    var contactIds = selectedInitialContacts.map(function (c) { return c.id; });
    // safeFetch (et non fetch brut) : seule mutation du fichier qui passait à
    // côté du wrapper. On récupère ainsi la même gestion dégradée que les 8
    // autres mutations — 401 → sauvegarde du brouillon + redirection login,
    // réseau coupé → message « Pas de connexion réseau », et capture de
    // X-Request-ID pour le bouton « Signaler ». retries:0 comme les autres
    // écritures (le batch n'est pas rejoué pour éviter un double ajout).
    var resp = await safeFetch('/api/distribution-lists/' + listId + '/members/batch', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-Xsrftoken': getCookie('_xsrf')
        },
        body: JSON.stringify({ contact_ids: contactIds })
    }, { retries: 0 });

    // Contrat conservé : on throw en cas d'échec. Le caller (submitList) attrape
    // et affiche « Liste créée, mais ajout des membres échoué : … » puis ouvre
    // la modal Membres pour réessayer. On throw AUSSI sur le 401 redirigé
    // (resp.ok === false) : sans ça le caller afficherait le faux succès
    // « Liste créée avec N membre(s) » alors que la session a expiré et que les
    // membres n'ont PAS été ajoutés (donnée fausse silencieuse).
    if (!resp.ok) {
        var _msg = (resp.data && resp.data.error)
            || (resp._network ? 'Pas de connexion réseau' : "Erreur lors de l'ajout des membres");
        var _err = new Error(_msg);
        _err.body = resp.data;  // rend vivante la branche err.body.error du caller (P6)
        // 401 : safeFetch a déjà sauvegardé le brouillon + lancé la redirection
        // /login. On propage le flag pour que le caller reste silencieux
        // (convention « _redirected → return » du fichier), sinon il afficherait
        // un toast trompeur + une cascade close/load/open qui course la navigation.
        if (resp._redirected) _err._redirected = true;
        throw _err;
    }
}

async function toggleList(id, activate) {
    var resp = await safeFetch('/api/distribution-lists/' + id, {
        method: 'PUT',
        headers: {
            'Content-Type': 'application/json',
            'X-Xsrftoken': getCookie('_xsrf')
        },
        body: JSON.stringify({ is_active: activate })
    }, { retries: 0 });

    if (resp._redirected) return;
    if (resp.ok) {
        showToast(activate ? 'Liste activée' : 'Liste désactivée', 'success');
        loadLists();
        if (window.__komptiaNotifyContactsChange) window.__komptiaNotifyContactsChange();
    } else {
        showToast((resp.data && resp.data.error) || 'Erreur lors de la modification', 'error');
    }
}

async function deleteList(id, name, count) {
    // Confirm contextualisé : nom de la liste + nombre de membres
    // (l'utilisateur sait à quoi il dit oui).
    var n = parseInt(count) || 0;
    var msg;
    if (n > 0) {
        msg = 'Supprimer la liste « ' + name + ' » ?\n\nElle contient ' + n +
              ' contact' + (n > 1 ? 's' : '') +
              '. Les contacts NE seront PAS supprimés, seulement leur association à cette liste.';
    } else {
        msg = 'Supprimer la liste « ' + name + ' » ?';
    }
    var confirmed = await appConfirm(msg, 'Supprimer la liste');
    if (!confirmed) return;

    var resp = await safeFetch('/api/distribution-lists/' + id, {
        method: 'DELETE',
        headers: { 'X-Xsrftoken': getCookie('_xsrf') }
    }, { retries: 0 });

    if (resp._redirected) return;
    if (resp.ok) {
        showToast('Liste supprimée', 'success');
        loadLists();
        if (window.__komptiaNotifyContactsChange) window.__komptiaNotifyContactsChange();
    } else {
        showToast((resp.data && resp.data.error) || 'Erreur lors de la suppression', 'error');
    }
}

/* ═══════════════════ ENVOI D'EMAIL ═══════════════════ */
var emailModal = document.getElementById('emailModal');
// Cible courante de la modale email : { contactIds: number[], listIds: number[], summary: string }.
// Figée à l'ouverture pour éviter qu'un changement de table pendant la
// rédaction (autre onglet, refresh) altère silencieusement la cible.
var currentEmailTarget = null;

function openEmailModalForContact(contactId, contactEmail) {
    currentEmailTarget = {
        contactIds: [contactId],
        listIds: [],
        summary: '1 contact',
        recipientLabel: contactEmail,
    };
    _renderEmailModalRecipients();
    document.getElementById('emailModalTitle').textContent = 'Envoyer un email';
    document.getElementById('emailForm').reset();
    document.getElementById('emailBodyCount').textContent = '0';
    openOverlay(emailModal);
    setTimeout(function () { document.getElementById('emailSubject').focus(); }, 50);
}

function openEmailModalForList(listId, listName, listCount) {
    var n = parseInt(listCount) || 0;
    currentEmailTarget = {
        contactIds: [],
        listIds: [listId],
        summary: 'Liste « ' + listName + ' » (' + n + ' membre' + (n > 1 ? 's' : '') + ')',
        recipientLabel: listName,
    };
    _renderEmailModalRecipients();
    document.getElementById('emailModalTitle').textContent = 'Envoyer un email à une liste';
    document.getElementById('emailForm').reset();
    document.getElementById('emailBodyCount').textContent = '0';
    openOverlay(emailModal);
    setTimeout(function () { document.getElementById('emailSubject').focus(); }, 50);
}

function closeEmailModal() {
    closeOverlay(emailModal);
    currentEmailTarget = null;
}

/**
 * Rendu des destinataires dans la modale (badges, lecture seule).
 * On affiche une étiquette par cible — pas la liste expandée des membres
 * pour éviter d'exposer des emails dans l'UI tant que c'est pas demandé.
 */
function _renderEmailModalRecipients() {
    var container = document.getElementById('emailRecipientsList');
    var hint = document.getElementById('emailRecipientsHint');
    if (!currentEmailTarget) {
        container.innerHTML = '<span class="text-xs text-gray-500 dark:text-gray-400">Aucun destinataire</span>';
        hint.textContent = '';
        return;
    }
    container.innerHTML = '<span class="badge badge-neutral text-xs">' + esc(currentEmailTarget.recipientLabel) + '</span>';
    hint.textContent = (
        currentEmailTarget.contactIds.length > 0
            ? 'Email envoyé directement à ce contact.'
            : 'Email envoyé à tous les membres actifs de la liste. Les contacts désabonnés (RGPD) sont automatiquement exclus.'
    );
}

async function submitEmailForm() {
    if (isSubmitting) return;
    if (!currentEmailTarget) {
        showToast('Aucun destinataire sélectionné', 'error');
        return;
    }
    var subject = document.getElementById('emailSubject').value.trim();
    var body = document.getElementById('emailBody').value.trim();

    if (!subject) {
        showToast('L\'objet est requis', 'error');
        document.getElementById('emailSubject').focus();
        return;
    }
    if (!body) {
        showToast('Le message est requis', 'error');
        document.getElementById('emailBody').focus();
        return;
    }

    // F6 (review loop) : scope au MODAL, pas au <form> — #btnSubmitEmail est dans
    // le footer HORS du <form id="emailForm">, donc un scope-form ne le
    // désactiverait jamais pendant l'envoi SMTP (double-clic = double email).
    setSubmitting(true, document.getElementById('emailModal'));

    var resp = await safeFetch('/api/contacts/send-email', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-Xsrftoken': getCookie('_xsrf'),
        },
        body: JSON.stringify({
            contact_ids: currentEmailTarget.contactIds,
            list_ids: currentEmailTarget.listIds,
            subject: subject,
            body: body,
        }),
    }, { retries: 0 });

    setSubmitting(false, document.getElementById('emailModal'));

    if (resp._redirected) return;

    if (resp.ok) {
        var data = resp.data || {};
        var msg = 'Email envoyé à ' + (data.recipients_count || 0) + ' destinataire' + (data.recipients_count > 1 ? 's' : '');
        var notes = [];
        if (data.skipped_unsubscribed > 0) {
            notes.push(data.skipped_unsubscribed + ' désabonné' + (data.skipped_unsubscribed > 1 ? 's exclus' : ' exclu'));
        }
        if (data.skipped_invalid_email > 0) {
            notes.push(data.skipped_invalid_email + ' email invalide' + (data.skipped_invalid_email > 1 ? 's' : ''));
        }
        if (notes.length > 0) msg += ' (' + notes.join(', ') + ')';
        showToast(msg, notes.length > 0 ? 'warning' : 'success');
        closeEmailModal();
    } else if (resp._network) {
        showToast('Pas de connexion réseau — réessayez', 'error');
    } else if (resp.status === 429) {
        showToast('Trop d\'emails envoyés récemment — patientez 1 heure', 'error');
    } else {
        showToast((resp.data && resp.data.error) || 'Erreur lors de l\'envoi', 'error');
    }
}

// Compteur live pour le textarea body.
function updateEmailBodyCount() {
    var ta = document.getElementById('emailBody');
    var counter = document.getElementById('emailBodyCount');
    if (ta && counter) counter.textContent = String(ta.value.length);
}

/* ── Members modal ── */
var membersModal = document.getElementById('membersModal');

async function openMembersModal(listId, listName) {
    currentMembersListId = listId;
    // textContent (safe — pas innerHTML) : un nom de liste avec HTML
    // (ex: ``<img src=x>``) reste rendu littéralement.
    document.getElementById('membersModalTitle').textContent = 'Membres — ' + listName;
    document.getElementById('searchContactToAdd').value = '';
    document.getElementById('searchContactToAdd').setAttribute('aria-expanded', 'false');
    document.getElementById('searchMembers').value = '';
    document.getElementById('contactSuggestions').innerHTML = '';
    document.getElementById('contactSuggestions').classList.add('hidden');
    openOverlay(membersModal);
    setTimeout(function () { document.getElementById('searchContactToAdd').focus(); }, 50);

    await loadMembers(listId);
}

function closeMembersModal() {
    closeOverlay(membersModal);
    currentMembersListId = null;
    availableContactsCache = [];
    currentMembersCache = [];
    loadLists();
}

async function loadMembers(listId) {
    var resp = await safeFetch('/api/distribution-lists/' + listId, {
        headers: { 'X-Requested-With': 'XMLHttpRequest' }
    });
    if (resp._redirected) return;
    if (!resp.ok) { showToast('Erreur chargement des membres', 'error'); return; }
    currentMembersCache = resp.data.contacts || [];
    renderMembersList();
}

function renderMembersList(filter) {
    filter = filter || '';
    var contacts = filter
        ? currentMembersCache.filter(function (c) {
            var query = filter.toLowerCase();
            return c.email.toLowerCase().includes(query) ||
                   (c.first_name && c.first_name.toLowerCase().includes(query)) ||
                   (c.last_name && c.last_name.toLowerCase().includes(query)) ||
                   (c.company && c.company.toLowerCase().includes(query));
          })
        : currentMembersCache;

    document.getElementById('membersCount').textContent = currentMembersCache.length;
    var container = document.getElementById('membersList');
    var empty = document.getElementById('membersEmpty');

    if (currentMembersCache.length === 0) {
        container.innerHTML = '';
        empty.classList.remove('hidden');
    } else {
        empty.classList.add('hidden');
        if (contacts.length === 0) {
            container.innerHTML = '<div class="text-center py-4 text-sm text-gray-500 dark:text-gray-400">Aucun résultat</div>';
        } else {
            container.innerHTML = contacts.map(function (c) {
                var name = [c.first_name, c.last_name].filter(Boolean).join(' ');
                return '<div class="flex items-center justify-between py-2 px-3 rounded hover:bg-gray-50 dark:hover:bg-gray-800">' +
                    '<div class="flex-1 min-w-0">' +
                        '<p class="text-sm font-medium text-gray-900 truncate dark:text-gray-100">' + esc(c.email) + '</p>' +
                        (name ? '<p class="text-xs text-gray-500 truncate dark:text-gray-400">' + esc(name) + (c.company ? ' — ' + esc(c.company) : '') + '</p>' : '') +
                    '</div>' +
                    '<button data-action="removeMember" data-list-id="' + currentMembersListId + '" data-contact-id="' + c.id + '" class="text-red-500 hover:text-red-700 text-xs font-medium ml-2 whitespace-nowrap dark:text-red-400">Retirer</button>' +
                '</div>';
            }).join('');
        }
    }
}

// Filtre debounced de la liste des membres (recherche locale, pas de fetch).
var filterMembersList = debounce(function () {
    var query = document.getElementById('searchMembers').value;
    renderMembersList(query);
}, 200);

// Recherche debounced des contacts à ajouter — multi-colonnes côté serveur
// (email + first_name + last_name + company). Aucun rechargement de page.
var searchContactsToAdd = debounce(async function () {
    var input = document.getElementById('searchContactToAdd');
    var container = document.getElementById('contactSuggestions');
    var query = input.value.trim();

    if (query.length < 2) {
        if (query.length === 0) {
            container.classList.add('hidden');
            input.setAttribute('aria-expanded', 'false');
        } else {
            container.innerHTML = '<div class="p-3 text-xs text-gray-500 dark:text-gray-400">Tapez au moins 2 caractères…</div>';
            container.classList.remove('hidden');
            input.setAttribute('aria-expanded', 'true');
        }
        return;
    }

    var resp = await safeFetch('/api/contacts?status=active&q=' + encodeURIComponent(query) + '&per_page=50', {
        headers: { 'X-Requested-With': 'XMLHttpRequest' }
    });
    if (!resp.ok) return;
    var contacts = resp.data.contacts || [];

    var memberIds = new Set(currentMembersCache.map(function (c) { return c.id; }));
    availableContactsCache = contacts.filter(function (c) { return !memberIds.has(c.id); });

    renderContactSuggestions();
    input.setAttribute('aria-expanded', 'true');
}, 300);

function renderContactSuggestions() {
    var container = document.getElementById('contactSuggestions');

    if (availableContactsCache.length === 0) {
        container.innerHTML = '<div class="p-3 text-sm text-gray-500 text-center dark:text-gray-400">Aucun contact trouvé</div>';
        container.classList.remove('hidden');
        return;
    }

    container.innerHTML = availableContactsCache.map(function (c) {
        var name = [c.first_name, c.last_name].filter(Boolean).join(' ');
        return '<button type="button" data-action="addMemberToList" data-contact-id="' + c.id + '"' +
            ' class="w-full text-left px-3 py-2 hover:bg-gray-50 border-b border-gray-100 last:border-b-0 dark:hover:bg-gray-800 dark:border-gray-800">' +
            '<p class="text-sm font-medium text-gray-900 truncate dark:text-gray-100">' + esc(c.email) + '</p>' +
            (name ? '<p class="text-xs text-gray-500 truncate dark:text-gray-400">' + esc(name) + (c.company ? ' • ' + esc(c.company) : '') + '</p>' : '') +
            '</button>';
    }).join('');

    container.classList.remove('hidden');
}

async function showAllContactsToAdd() {
    // Charge le max possible (CONTACTS_MAX_PER_PAGE=100 côté backend).
    // Si l'utilisateur a >100 contacts actifs, le toast lui dit d'utiliser
    // la search — pas de truncation silencieuse.
    var resp = await safeFetch('/api/contacts?status=active&per_page=100', {
        headers: { 'X-Requested-With': 'XMLHttpRequest' }
    });
    if (resp._redirected) return;
    if (!resp.ok) { showToast('Erreur chargement des contacts', 'error'); return; }
    var contacts = resp.data.contacts || [];
    var total = resp.data.total || contacts.length;

    var memberIds = new Set(currentMembersCache.map(function (c) { return c.id; }));
    availableContactsCache = contacts.filter(function (c) { return !memberIds.has(c.id); });

    if (availableContactsCache.length === 0) {
        showToast('Tous les contacts actifs sont déjà dans cette liste', 'info');
        return;
    }

    document.getElementById('searchContactToAdd').value = '';
    document.getElementById('searchContactToAdd').setAttribute('aria-expanded', 'true');
    renderContactSuggestions();
    var msg = availableContactsCache.length + ' contact' + (availableContactsCache.length > 1 ? 's' : '') + ' disponible' + (availableContactsCache.length > 1 ? 's' : '');
    if (total > 100) {
        msg += ' (' + total + ' au total — utilisez la recherche pour les autres)';
    }
    showToast(msg, 'info');
}

async function addMemberToList(contactId) {
    if (!contactId || !currentMembersListId) return;

    var resp = await safeFetch('/api/distribution-lists/' + currentMembersListId + '/members', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-Xsrftoken': getCookie('_xsrf')
        },
        body: JSON.stringify({ contact_id: parseInt(contactId) })
    }, { retries: 0 });

    if (resp._redirected) return;
    if (resp.ok) {
        // ``was_already_member`` (P1 backend) permet de différencier
        // "ajouté" (vert) vs "déjà membre" (jaune) sans parser le message FR.
        var alreadyMember = resp.data && resp.data.was_already_member;
        showToast(
            alreadyMember ? 'Contact déjà membre de la liste' : 'Contact ajouté à la liste',
            alreadyMember ? 'warning' : 'success'
        );
        document.getElementById('searchContactToAdd').value = '';
        document.getElementById('contactSuggestions').classList.add('hidden');
        document.getElementById('searchContactToAdd').setAttribute('aria-expanded', 'false');
        await loadMembers(currentMembersListId);
        if (window.__komptiaNotifyContactsChange) window.__komptiaNotifyContactsChange();
    } else {
        showToast((resp.data && resp.data.error) || 'Erreur', 'error');
    }
}

async function removeMember(listId, contactId) {
    var resp = await safeFetch('/api/distribution-lists/' + listId + '/members/' + contactId, {
        method: 'DELETE',
        headers: { 'X-Xsrftoken': getCookie('_xsrf') }
    }, { retries: 0 });

    if (resp._redirected) return;
    if (resp.ok) {
        showToast('Contact retiré de la liste', 'success');
        await loadMembers(listId);
        if (window.__komptiaNotifyContactsChange) window.__komptiaNotifyContactsChange();
    } else {
        showToast((resp.data && resp.data.error) || 'Erreur lors du retrait', 'error');
    }
}

/* ═══════════════════ MODAL UTILITIES ═══════════════════ */

// Close modals on backdrop click — déléguer aux fonctions close* dédiées
// pour que le cleanup (caches, resets) soit identique à la fermeture par bouton.
modal.addEventListener('click', function (e) { if (e.target === modal) closeModal(); });
importModal.addEventListener('click', function (e) { if (e.target === importModal) closeImportModal(); });
listModal.addEventListener('click', function (e) { if (e.target === listModal) closeListModal(); });
membersModal.addEventListener('click', function (e) { if (e.target === membersModal) closeMembersModal(); });
emailModal.addEventListener('click', function (e) { if (e.target === emailModal) closeEmailModal(); });

// Escape est géré globalement par OverlayManager (ferme le top-most du stack).
// L'ancien listener local a été retiré pour éviter les fermetures en cascade
// quand plusieurs modals sont empilées.

// Close contact suggestions when clicking outside
document.addEventListener('click', function (e) {
    var searchInput = document.getElementById('searchContactToAdd');
    var suggestions = document.getElementById('contactSuggestions');
    if (searchInput && suggestions && !searchInput.contains(e.target) && !suggestions.contains(e.target)) {
        suggestions.classList.add('hidden');
    }

    var initialSearchInput = document.getElementById('searchInitialContact');
    var initialSuggestions = document.getElementById('initialContactSuggestions');
    if (initialSearchInput && initialSuggestions && !initialSearchInput.contains(e.target) && !initialSuggestions.contains(e.target)) {
        initialSuggestions.classList.add('hidden');
    }
});

/* ═══════════════════ EVENT LISTENERS ═══════════════════ */

// Static button event listeners
document.getElementById('btnOpenImportModal').addEventListener('click', openImportModal);
document.getElementById('btnOpenCreateModal').addEventListener('click', openCreateModal);
document.getElementById('btnOpenListModal').addEventListener('click', openListModal);
document.getElementById('btnSubmitList').addEventListener('click', submitListForm);
document.getElementById('btnShowAllContacts').addEventListener('click', showAllContactsToAdd);
document.getElementById('btnSubmitEmail').addEventListener('click', submitEmailForm);
document.getElementById('emailBody').addEventListener('input', updateEmailBodyCount);
var btnClearFilters = document.getElementById('btn-clear-filters');
if (btnClearFilters) btnClearFilters.addEventListener('click', clearContactFilters);

// Tabs : click + flèches gauche/droite (WAI-ARIA tablist roving tabindex).
function attachTabListeners(tabId) {
    var btn = document.getElementById(tabId);
    if (!btn) return;
    btn.addEventListener('click', function (e) { switchTab(e.currentTarget.dataset.tab); });
    btn.addEventListener('keydown', function (e) {
        if (e.key === 'ArrowRight' || e.key === 'ArrowLeft') {
            e.preventDefault();
            var other = tabId === 'tab-contacts' ? 'tab-lists' : 'tab-contacts';
            var otherEl = document.getElementById(other);
            switchTab(otherEl.dataset.tab);
            otherEl.focus();
        }
    });
}
attachTabListeners('tab-contacts');
attachTabListeners('tab-lists');

// Search and filters (debounced — AUCUN reload de page)
document.getElementById('search-input').addEventListener('input', debounceSearch);
document.getElementById('filter-status').addEventListener('change', function () { currentPage = 1; loadContacts(); });
document.getElementById('search-lists').addEventListener('input', debounceSearchLists);
document.getElementById('filter-lists-status').addEventListener('change', filterLists);
document.getElementById('searchInitialContact').addEventListener('input', searchInitialContacts);
document.getElementById('searchContactToAdd').addEventListener('input', searchContactsToAdd);
document.getElementById('searchMembers').addEventListener('input', filterMembersList);

// Event delegation for dynamic content (RBAC : tous les boutons gérés
// ici sont déjà rendus côté serveur uniquement aux rôles autorisés).
var actionMap = {
    closeModal: function () { closeModal(); },
    closeImportModal: function () { closeImportModal(); },
    closeListModal: function () { closeListModal(); },
    closeMembersModal: function () { closeMembersModal(); },
    closeEmailModal: function () { closeEmailModal(); },
    toggleActionsMenu: function (t) { toggleActionsMenu(t); },
    emailContact: function (t) { openEmailModalForContact(parseInt(t.dataset.contactId), t.dataset.contactEmail); },
    emailList: function (t) { openEmailModalForList(parseInt(t.dataset.listId), t.dataset.listName, t.dataset.listCount); },
    openCreateModal: function () { openCreateModal(); },
    openImportModal: function () { openImportModal(); },
    openListModal: function () { openListModal(); },
    editContact: function (t) { editContact(parseInt(t.dataset.contactId)); },
    toggleContact: function (t) { toggleContact(parseInt(t.dataset.contactId), t.dataset.activate === 'true'); },
    deleteContact: function (t) { deleteContact(parseInt(t.dataset.contactId), t.dataset.contactEmail); },
    loadContacts: function (t) { loadContacts(parseInt(t.dataset.page)); },
    sortContacts: function (t) { sortContacts(t); },
    sortLists: function (t) { sortLists(t); },
    openMembersModal: function (t) { openMembersModal(parseInt(t.dataset.listId), t.dataset.listName); },
    editList: function (t) { editList(parseInt(t.dataset.listId)); },
    toggleList: function (t) { toggleList(parseInt(t.dataset.listId), t.dataset.activate === 'true'); },
    deleteList: function (t) { deleteList(parseInt(t.dataset.listId), t.dataset.listName, t.dataset.listCount); },
    addInitialContact: function (t) { addInitialContact(parseInt(t.dataset.contactId)); },
    removeInitialContact: function (t) { removeInitialContact(parseInt(t.dataset.contactId)); },
    addMemberToList: function (t) { addMemberToList(parseInt(t.dataset.contactId)); },
    removeMember: function (t) { removeMember(parseInt(t.dataset.listId), parseInt(t.dataset.contactId)); },
    retryContacts: function () { loadContacts(); },
    reportContactsError: function () { reportContactsError(); },
    retryLists: function () { loadLists(); },
    reportListsError: function () { reportListsError(); },
};

document.addEventListener('click', function (e) {
    var target = e.target.closest('[data-action]');
    // Click hors d'un menu d'actions ET hors d'un trigger : ferme tous les
    // dropdowns ouverts. Couvre le pattern "ouvre menu → click ailleurs".
    if (!target || target.dataset.action !== 'toggleActionsMenu') {
        if (!e.target.closest('.actions-menu-dropdown')) {
            _closeAllActionsMenus();
        }
    }
    if (!target) return;
    var handler = actionMap[target.dataset.action];
    if (handler) {
        handler(target);
        // Click sur un item du menu (pas le trigger) : ferme le menu après
        // exécution pour ne pas laisser le dropdown béant.
        if (target.dataset.action !== 'toggleActionsMenu' &&
            target.closest('.actions-menu-dropdown')) {
            _closeAllActionsMenus();
        }
    }
});

// Fermeture des menus sur Escape (cohérent avec OverlayManager qui ferme
// le top-most modal — ici on cible spécifiquement les dropdowns kebab).
document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') _closeAllActionsMenus();
});

// Sync multi-onglet : si un autre onglet du même user a modifié des
// données (création/suppression/import), on rafraîchit pour ne pas
// laisser un onglet stale.
//
// Throttle : si 50 onglets ouverts → 49 reload simultanés sur chaque
// mutation. On limite à 1 reload toutes les 2s par onglet (le dernier
// message gagne — coalesce).
var lastBroadcastReloadAt = 0;
var BROADCAST_RELOAD_THROTTLE_MS = 2000;
if ('BroadcastChannel' in window) {
    try {
        var contactsChannel = new BroadcastChannel('komptia_contacts');
        contactsChannel.addEventListener('message', function (e) {
            if (!e || !e.data || !e.data.type) return;
            if (e.data.type !== 'contacts_changed') return;
            var now = Date.now();
            if (now - lastBroadcastReloadAt < BROADCAST_RELOAD_THROTTLE_MS) return;
            lastBroadcastReloadAt = now;
            loadContacts();
            if (!document.getElementById('panel-lists').classList.contains('hidden')) {
                loadLists();
            }
        });
        // Notifie les autres onglets après chaque mutation locale réussie.
        // Appelé depuis : create/update/delete/toggle contact, import CSV,
        // create/update/delete/toggle list, add/remove/batch members.
        window.__komptiaNotifyContactsChange = function () {
            try { contactsChannel.postMessage({ type: 'contacts_changed' }); } catch (_) {}
        };
        // Cleanup à la fermeture pour libérer le handle.
        window.addEventListener('beforeunload', function () {
            try { contactsChannel.close(); } catch (_) {}
        });
    } catch (_) { /* Safari < 15.4 sans BroadcastChannel : silently skip */ }
}

/* ── Init ── */
restoreDraftIfRecent();  // Si un draft a été sauvegardé avant 401 redirect.
loadContacts();

}); // end DOMContentLoaded
