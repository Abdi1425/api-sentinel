
'use strict';

// ========================================
// API SENTINEL - INVESTIGATIONS
// ========================================

const $ = id => document.getElementById(id);

let investigations = [];
let currentUser = null;
let canEditInvestigations = false;

// ========================================
// HELPERS
// ========================================

function formatDate(value) {
    if (!value) return '—';

    const date = new Date(value);

    return Number.isNaN(date.getTime())
        ? '—'
        : date.toLocaleString();
}

function createCell(row, value) {
    const cell = document.createElement('td');
    cell.textContent = String(value ?? '—');
    row.appendChild(cell);
    return cell;
}

function setMessage(id, message) {
    const element = $(id);

    if (element) {
        element.textContent = message;
    }
}

function setVisible(element, visible) {
    if (!element) return;

    element.hidden = !visible;
    element.style.display = visible ? '' : 'none';
}

// ========================================
// API REQUEST HELPER
// ========================================

async function apiRequest(url, options = {}) {
    const response = await fetch(url, {
        credentials: 'same-origin',
        cache: 'no-store',
        ...options
    });

    let data;

    try {
        data = await response.json();
    } catch {
        data = {};
    }

    if (response.status === 401) {
        const error = new Error(
            'Your session has expired. Please sign in again.'
        );

        error.status = 401;
        throw error;
    }

    if (response.status === 403) {
        const error = new Error(
            'You do not have permission to perform this action.'
        );

        error.status = 403;
        throw error;
    }

    if (!response.ok) {
        const error = new Error(
            data.message ||
            data.error ||
            `Request failed: ${response.status}`
        );

        error.status = response.status;
        throw error;
    }

    return data;
}

// ========================================
// AUTHENTICATION AND RBAC
// ========================================

async function loadCurrentUser() {
    const data = await apiRequest('/api/auth/me');

    if (!data.success || !data.user) {
        throw new Error('Unable to identify current user.');
    }

    currentUser = data.user;

    const role = currentUser.role;

    if (!['admin', 'analyst', 'viewer'].includes(role)) {
        throw new Error('Unsupported account role.');
    }

    canEditInvestigations =
        role === 'admin' || role === 'analyst';

    // Hide User Management for non-admin accounts.
    document.querySelectorAll('a[href]').forEach(link => {
        const href = link.getAttribute('href') || '';
        const path = href.split('?')[0].split('#')[0];

        if (path === '/users.html' || path === 'users.html') {
            setVisible(link, role === 'admin');
        }
    });

    // Configure read-only investigation controls.
    const status = $('investigation-status');
    const category = $('investigation-category');
    const notes = $('investigation-notes');

    if (status) {
        status.disabled = !canEditInvestigations;
    }

    if (category) {
        category.disabled = !canEditInvestigations;
    }

    if (notes) {
        notes.readOnly = !canEditInvestigations;
    }

    const saveButton = document.querySelector(
        '#investigation-form button[type="submit"]'
    );

    setVisible(saveButton, canEditInvestigations);

    console.log(
        `API Sentinel: signed in as ${currentUser.username} (${role})`
    );
}

// ========================================
// INVESTIGATION METRICS
// ========================================

function updateMetrics() {
    const counts = {
        total: investigations.length,
        open: 0,
        investigating: 0,
        resolved: 0
    };

    investigations.forEach(item => {
        if (item.status === 'open') {
            counts.open++;
        }

        if (item.status === 'investigating') {
            counts.investigating++;
        }

        if (item.status === 'resolved') {
            counts.resolved++;
        }
    });

    setMessage('investigation-total', counts.total);
    setMessage('investigation-open', counts.open);
    setMessage('investigation-active', counts.investigating);
    setMessage('investigation-resolved', counts.resolved);
}

// ========================================
// RENDER INVESTIGATIONS
// ========================================

function renderInvestigations() {
    const body = $('investigations-table-body');

    if (!body) return;

    body.replaceChildren();

    const search = (
        $('investigation-search')?.value || ''
    ).toLowerCase().trim();

    const selectedStatus =
        $('investigation-status-filter')?.value || 'all';

    const filtered = investigations.filter(item => {
        const matchesStatus =
            selectedStatus === 'all' ||
            item.status === selectedStatus;

        const searchable = [
            item.id,
            item.application_name,
            item.ip_address,
            item.alert_type,
            item.description,
            item.status
        ].join(' ').toLowerCase();

        return matchesStatus && searchable.includes(search);
    });

    if (!filtered.length) {
        const row = document.createElement('tr');

        createCell(
            row,
            'No matching investigations'
        ).colSpan = 7;

        body.appendChild(row);
        return;
    }

    for (const item of filtered) {
        const row = document.createElement('tr');

        createCell(row, `#${item.id}`);
        createCell(row, item.application_name || 'Unknown');

        createCell(
            row,
            item.ip_address || 'Not recorded'
        );

        createCell(row, item.alert_type || 'Unknown');
        createCell(row, item.severity || 'Unknown');

        createCell(
            row,
            String(item.status || 'unknown')
                .replaceAll('_', ' ')
        );

        const actionCell = document.createElement('td');
        const button = document.createElement('button');

        button.type = 'button';
        button.className = 'refresh-button';

        button.textContent = canEditInvestigations
            ? 'Investigate'
            : 'View Details';

        button.addEventListener('click', () => {
            openInvestigation(item.id);
        });

        actionCell.appendChild(button);
        row.appendChild(actionCell);
        body.appendChild(row);
    }
}

// ========================================
// LOAD INVESTIGATIONS
// ========================================

async function loadInvestigations() {
    const data = await apiRequest('/api/investigations');

    investigations = Array.isArray(data.investigations)
        ? data.investigations
        : [];

    updateMetrics();
    renderInvestigations();

    setMessage(
        'last-updated',
        `Updated ${new Date().toLocaleTimeString()}`
    );
}

// ========================================
// SUSPICIOUS IP MONITORING
// ========================================

async function loadSuspiciousIPs() {
    const data = await apiRequest(
        '/api/investigations/suspicious-ips'
    );

    const body = $('suspicious-ips-table-body');

    if (!body) return;

    body.replaceChildren();

    const ips = Array.isArray(data.suspicious_ips)
        ? data.suspicious_ips
        : [];

    if (!ips.length) {
        const row = document.createElement('tr');

        createCell(
            row,
            'No failed-login sources recorded'
        ).colSpan = 4;

        body.appendChild(row);
        return;
    }

    for (const ip of ips) {
        const row = document.createElement('tr');

        createCell(row, ip.ip_address || 'Unknown');
        createCell(row, ip.application_name || 'Unknown');
        createCell(row, ip.failed_attempts || 0);
        createCell(row, formatDate(ip.last_seen));

        body.appendChild(row);
    }
}

// ========================================
// OPEN INVESTIGATION
// ========================================

async function openInvestigation(id) {
    try {
        const data = await apiRequest(
            `/api/investigations/${encodeURIComponent(id)}`
        );

        const item = data.investigation;

        if (!item) {
            throw new Error('Investigation not found.');
        }

        const idInput = $('investigation-id');
        const status = $('investigation-status');
        const category = $('investigation-category');
        const notes = $('investigation-notes');

        if (idInput) {
            idInput.value = item.id;
        }

        if (status) {
            status.value = item.status || 'open';
        }

        if (category) {
            category.value = item.category || 'uncategorized';
        }

        if (notes) {
            notes.value = item.resolution_notes || '';
        }

        setMessage(
            'investigation-editor-title',
            canEditInvestigations
                ? `Investigate Alert #${item.id}`
                : `View Alert #${item.id}`
        );

        setMessage(
            'investigation-message',
            canEditInvestigations
                ? 'You can update this investigation.'
                : 'Read-only access: you cannot modify investigations.'
        );

        const editor = $('investigation-editor');

        setVisible(editor, true);

        editor?.scrollIntoView({
            behavior: 'smooth',
            block: 'start'
        });

    } catch (error) {
        console.error('Unable to open investigation:', error);

        setMessage(
            'system-status-text',
            `Error: ${error.message}`
        );
    }
}

// ========================================
// SAVE INVESTIGATION
// ========================================

async function saveInvestigation(event) {
    event.preventDefault();

    if (!canEditInvestigations) {
        setMessage(
            'investigation-message',
            'Access denied: Viewers cannot edit investigations.'
        );
        return;
    }

    const id = $('investigation-id')?.value;

    if (!id) {
        setMessage(
            'investigation-message',
            'Select an investigation first.'
        );
        return;
    }

    const saveButton = document.querySelector(
        '#investigation-form button[type="submit"]'
    );

    if (saveButton) {
        saveButton.disabled = true;
    }

    setMessage(
        'investigation-message',
        'Saving investigation...'
    );

    try {
        await apiRequest(
            `/api/investigations/${encodeURIComponent(id)}`,
            {
                method: 'PATCH',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    status: $('investigation-status').value,
                    category: $('investigation-category').value,
                    resolution_notes:
                        $('investigation-notes').value
                })
            }
        );

        setMessage(
            'investigation-message',
            'Investigation saved successfully.'
        );

        await loadInvestigations();

    } catch (error) {
        setMessage(
            'investigation-message',
            error.message
        );

    } finally {
        if (saveButton) {
            saveButton.disabled = false;
        }
    }
}

// ========================================
// REFRESH INVESTIGATIONS
// ========================================

async function refreshPage() {
    setMessage('system-status-text', 'Loading investigations...');

    const results = await Promise.allSettled([
        loadInvestigations(),
        loadSuspiciousIPs()
    ]);

    const failures = results.filter(
        result => result.status === 'rejected'
    );

    if (failures.length === 0) {
        setMessage('system-status-text', 'Connected');
        return;
    }

    failures.forEach(result => {
        console.error(
            'Investigation data loading error:',
            result.reason
        );
    });

    setMessage(
        'system-status-text',
        'Some investigation data could not be loaded.'
    );
}

// ========================================
// LOGOUT
// ========================================

async function logout() {
    try {
        const response = await fetch('/api/auth/logout', {
            method: 'POST',
            credentials: 'same-origin'
        });

        if (!response.ok) {
            throw new Error('Sign out failed.');
        }

        window.location.replace('/login.html');

    } catch (error) {
        console.error('Logout failed:', error);
        alert(error.message);
    }
}

// ========================================
// INITIALIZE PAGE
// ========================================

document.addEventListener('DOMContentLoaded', async () => {
    const search = $('investigation-search');
    const filter = $('investigation-status-filter');
    const form = $('investigation-form');
    const cancelButton = $('investigation-cancel');
    const refreshButton = $('refresh-btn');
    const logoutButton = $('logout-btn');

    search?.addEventListener(
        'input',
        renderInvestigations
    );

    filter?.addEventListener(
        'change',
        renderInvestigations
    );

    form?.addEventListener(
        'submit',
        saveInvestigation
    );

    cancelButton?.addEventListener('click', () => {
        setVisible($('investigation-editor'), false);
    });

    refreshButton?.addEventListener(
        'click',
        refreshPage
    );

    logoutButton?.addEventListener(
        'click',
        logout
    );

    try {
        await loadCurrentUser();
        await refreshPage();

    } catch (error) {
        console.error(
            'Investigation initialization failed:',
            error
        );

        if (error.status === 401) {
            window.location.replace('/login.html');
            return;
        }

        setMessage(
            'system-status-text',
            `Unable to initialize: ${error.message}`
        );
    }
});
