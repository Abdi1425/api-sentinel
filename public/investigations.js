
const $ = (id) => document.getElementById(id);

let investigations = [];
let currentUser = null;
let canEditInvestigations = false;

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

// ========================================
// API REQUEST HELPER
// ========================================
async function apiRequest(url, options = {}) {
    const response = await fetch(url, {
        credentials: 'same-origin',
        ...options
    });

    if (response.status === 401) {
        window.location.replace('/login.html');
        throw new Error('Session expired. Please log in again.');
    }

    const data = await response.json();

    if (!response.ok) {
        throw new Error(
            data.message ||
            data.error ||
            'Request failed'
        );
    }

    return data;
}

// ========================================
// LOAD AUTHENTICATED USER AND ROLE
// ========================================
async function loadCurrentUser() {
    const data = await apiRequest('/api/auth/me');

    currentUser = data.user;

    canEditInvestigations = [
        'admin',
        'analyst'
    ].includes(currentUser.role);

    // User Management is available to administrators only.
    document.querySelectorAll(
        'a[href="/users.html"]'
    ).forEach(link => {
        link.hidden = currentUser.role !== 'admin';
    });

    // Viewers can inspect investigation details,
    // but cannot change their values.
    $('investigation-status').disabled =
        !canEditInvestigations;

    $('investigation-category').disabled =
        !canEditInvestigations;

    $('investigation-notes').readOnly =
        !canEditInvestigations;

    const saveButton = document.querySelector(
        '#investigation-form button[type="submit"]'
    );

    if (saveButton) {
        saveButton.hidden = !canEditInvestigations;
    }
}

// ========================================
// UPDATE METRICS
// ========================================
function updateMetrics() {
    $('investigation-total').textContent =
        investigations.length;

    $('investigation-open').textContent =
        investigations.filter(
            item => item.status === 'open'
        ).length;

    $('investigation-active').textContent =
        investigations.filter(
            item => item.status === 'investigating'
        ).length;

    $('investigation-resolved').textContent =
        investigations.filter(
            item => item.status === 'resolved'
        ).length;
}

// ========================================
// RENDER INVESTIGATIONS
// ========================================
function renderInvestigations() {
    const body = $('investigations-table-body');
    body.replaceChildren();

    const search = $('investigation-search')
        .value.toLowerCase().trim();

    const status = $('investigation-status-filter').value;

    const filtered = investigations.filter(item => {
        const matchesStatus =
            status === 'all' || item.status === status;

        const searchable = [
            item.id,
            item.application_name,
            item.ip_address,
            item.alert_type,
            item.description
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
        createCell(row, item.application_name);
        createCell(row, item.ip_address);
        createCell(row, item.alert_type);
        createCell(row, item.severity);
        createCell(
            row,
            item.status?.replaceAll('_', ' ')
        );

        const actionCell = document.createElement('td');
        const button = document.createElement('button');

        button.type = 'button';
        button.className = 'refresh-button';

        button.textContent = canEditInvestigations
            ? 'Investigate'
            : 'View Details';

        button.addEventListener(
            'click',
            () => openInvestigation(item.id)
        );

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

    investigations = data.investigations || [];

    updateMetrics();
    renderInvestigations();

    $('last-updated').textContent =
        `Updated ${new Date().toLocaleTimeString()}`;
}

// ========================================
// SUSPICIOUS IP MONITORING
// ========================================
async function loadSuspiciousIPs() {
    const data = await apiRequest(
        '/api/investigations/suspicious-ips'
    );

    const body = $('suspicious-ips-table-body');
    body.replaceChildren();

    const ips = data.suspicious_ips || [];

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

        createCell(row, ip.ip_address);
        createCell(row, ip.application_name);
        createCell(row, ip.failed_attempts);
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
            `/api/investigations/${id}`
        );

        const item = data.investigation;

        $('investigation-id').value = item.id;

        $('investigation-status').value =
            item.status || 'open';

        $('investigation-category').value =
            item.category || 'uncategorized';

        $('investigation-notes').value =
            item.resolution_notes || '';

        $('investigation-editor-title').textContent =
            canEditInvestigations
                ? `Investigate Alert #${item.id}`
                : `View Alert #${item.id}`;

        $('investigation-message').textContent =
            canEditInvestigations
                ? 'You can update this investigation.'
                : 'Read-only access: you cannot modify investigations.';

        $('investigation-editor').hidden = false;

        $('investigation-editor').scrollIntoView({
            behavior: 'smooth',
            block: 'start'
        });

    } catch (error) {
        alert(error.message);
    }
}

// ========================================
// SAVE INVESTIGATION
// ========================================
async function saveInvestigation(event) {
    event.preventDefault();

    // Frontend safeguard; backend RBAC is authoritative.
    if (!canEditInvestigations) {
        $('investigation-message').textContent =
            'You do not have permission to edit investigations.';
        return;
    }

    const id = $('investigation-id').value;
    const message = $('investigation-message');

    message.textContent = 'Saving investigation...';

    const saveButton = document.querySelector(
        '#investigation-form button[type="submit"]'
    );

    if (saveButton) {
        saveButton.disabled = true;
    }

    try {
        await apiRequest(
            `/api/investigations/${id}`,
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

        message.textContent =
            'Investigation saved successfully.';

        await loadInvestigations();

    } catch (error) {
        message.textContent = error.message;

    } finally {
        if (saveButton) {
            saveButton.disabled = false;
        }
    }
}

// ========================================
// REFRESH PAGE
// ========================================
async function refreshPage() {
    try {
        await Promise.all([
            loadInvestigations(),
            loadSuspiciousIPs()
        ]);

        $('system-status-text').textContent =
            'Connected';

    } catch (error) {
        console.error(
            'Investigation loading failed:',
            error
        );

        $('system-status-text').textContent =
            'Connection error';
    }
}

// ========================================
// LOGOUT
// ========================================
async function logout() {
    try {
        const response = await fetch(
            '/api/auth/logout',
            {
                method: 'POST',
                credentials: 'same-origin'
            }
        );

        if (!response.ok) {
            throw new Error('Sign out failed');
        }

        window.location.replace('/login.html');

    } catch (error) {
        alert(error.message);
    }
}

// ========================================
// INITIALIZE PAGE
// ========================================
document.addEventListener('DOMContentLoaded', async () => {
    $('investigation-search').addEventListener(
        'input',
        renderInvestigations
    );

    $('investigation-status-filter').addEventListener(
        'change',
        renderInvestigations
    );

    $('investigation-form').addEventListener(
        'submit',
        saveInvestigation
    );

    $('investigation-cancel').addEventListener(
        'click',
        () => {
            $('investigation-editor').hidden = true;
        }
    );

    $('refresh-btn').addEventListener(
        'click',
        refreshPage
    );

    $('logout-btn').addEventListener(
        'click',
        logout
    );

    try {
        // Identify role before rendering investigation controls.
        await loadCurrentUser();
        await refreshPage();

    } catch (error) {
        console.error(
            'Investigation initialization failed:',
            error
        );

        $('system-status-text').textContent =
            'Unable to initialize';
    }
});
