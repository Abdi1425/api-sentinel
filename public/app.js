
'use strict';

// ========================================
// API SENTINEL - SECURITY DASHBOARD
// ========================================

let securityAlerts = [];
let refreshInProgress = false;

const severityColors = {
    critical: '#ef4444',
    high: '#fb7185',
    medium: '#fbbf24',
    low: '#34d399',
    unknown: '#64748b'
};

document.addEventListener('DOMContentLoaded', () => {
    // Initial dashboard loading
    refreshDashboard();

    // Manual refresh
    document
        .getElementById('refresh-btn')
        ?.addEventListener('click', refreshDashboard);

    // Filter security alerts
    document
        .getElementById('severity-filter')
        ?.addEventListener('change', displaySecurityAlerts);

    // Sidebar navigation
    initializeNavigation();

    // Refresh dashboard every 30 seconds
    setInterval(refreshDashboard, 30000);
});

// ========================================
// 1. REFRESH DASHBOARD
// ========================================

async function refreshDashboard() {
    if (refreshInProgress) return;

    refreshInProgress = true;

    const refreshButton = document.getElementById('refresh-btn');

    if (refreshButton) {
        refreshButton.disabled = true;
        refreshButton.textContent = '↻ Refreshing...';
    }

    try {
        await Promise.all([
            loadDashboardStats(),
            loadSecurityAlerts(),
            checkSystemHealth()
        ]);

        const updated = document.getElementById('last-updated');

        if (updated) {
            updated.textContent =
                `Last checked: ${new Date().toLocaleTimeString()}`;
        }
    } finally {
        refreshInProgress = false;

        if (refreshButton) {
            refreshButton.disabled = false;
            refreshButton.textContent = '↻ Refresh';
        }
    }
}

// ========================================
// 2. FETCH DASHBOARD STATISTICS
// ========================================

async function loadDashboardStats() {
    const totalEvents = document.getElementById('total-events');
    const failedLogins = document.getElementById('failed-logins');
    const totalAlerts = document.getElementById('total-alerts');
    const successRate = document.getElementById('success-rate');

    try {
        const response = await fetch('/api/stats', {
            method: 'GET',
            credentials: 'same-origin'
        });

        if (response.status === 401) {
            [totalEvents, failedLogins, totalAlerts, successRate]
                .forEach(element => {
                    if (element) element.textContent = 'Login required';
                });

            showActivityMessage('Administrator login required.');
            return;
        }

        if (!response.ok) {
            throw new Error(`Statistics API error: ${response.status}`);
        }

        const stats = await response.json();

        const events = Math.max(0, Number(stats.totalEvents) || 0);
        const failures = Math.max(0, Number(stats.failedLogins) || 0);
        const alerts = Math.max(0, Number(stats.totalAlerts) || 0);

        // Estimated success count from current aggregate data.
        // A dedicated LOGIN_SUCCESS count will be more accurate.
        const estimatedSuccess = Math.max(0, events - failures);

        const rate = events > 0
            ? ((estimatedSuccess / events) * 100).toFixed(1)
            : null;

        totalEvents.textContent = events.toLocaleString();
        failedLogins.textContent = failures.toLocaleString();
        totalAlerts.textContent = alerts.toLocaleString();

        successRate.textContent = rate === null
            ? 'N/A'
            : `${rate}%`;

        renderActivityChart(estimatedSuccess, failures);

    } catch (error) {
        console.error('Statistics loading failed:', error);

        [totalEvents, failedLogins, totalAlerts, successRate]
            .forEach(element => {
                if (element) element.textContent = 'Error';
            });

        showActivityMessage('Unable to load authentication activity.');
    }
}

// ========================================
// 3. AUTHENTICATION ACTIVITY CHART
// ========================================

function showActivityMessage(message) {
    const container = document.getElementById('activity-chart');
    if (!container) return;

    container.replaceChildren();

    const text = document.createElement('p');
    text.className = 'chart-empty';
    text.textContent = message;

    container.appendChild(text);
}

function renderActivityChart(successCount, failureCount) {
    const container = document.getElementById('activity-chart');
    if (!container) return;

    container.replaceChildren();

    const maximum = Math.max(successCount, failureCount, 1);

    const bars = document.createElement('div');
    bars.className = 'activity-bars';

    const data = [
        {
            label: 'Estimated successful',
            value: successCount,
            type: 'success'
        },
        {
            label: 'Failed',
            value: failureCount,
            type: 'failed'
        }
    ];

    data.forEach(item => {
        const group = document.createElement('div');
        group.className = 'activity-bar-group';

        const value = document.createElement('span');
        value.className = 'activity-bar-value';
        value.textContent = item.value.toLocaleString();

        const bar = document.createElement('div');
        bar.className = `activity-bar ${item.type}`;
        bar.style.height =
            `${Math.max(4, (item.value / maximum) * 135)}px`;

        bar.setAttribute(
            'aria-label',
            `${item.label}: ${item.value}`
        );

        const label = document.createElement('span');
        label.className = 'activity-bar-label';
        label.textContent = item.type === 'success'
            ? 'Successful*'
            : 'Failed';

        group.append(value, bar, label);
        bars.appendChild(group);
    });

    container.appendChild(bars);
}

// ========================================
// 4. FETCH SECURITY ALERTS
// ========================================

async function loadSecurityAlerts() {
    const container = document.getElementById('alerts-container');
    if (!container) return;

    try {
        const response = await fetch('/api/alerts', {
            method: 'GET',
            credentials: 'same-origin'
        });

        if (response.status === 401) {
            securityAlerts = [];
            container.textContent =
                'Administrator session required. Please log in again.';
            renderSeverityChart([]);
            return;
        }

        if (!response.ok) {
            throw new Error(`Alerts API error: ${response.status}`);
        }

        const data = await response.json();

        securityAlerts = Array.isArray(data.alerts)
            ? data.alerts
            : [];

        displaySecurityAlerts();
        renderSeverityChart(securityAlerts);

    } catch (error) {
        console.error('Alert loading failed:', error);

        container.textContent =
            'Unable to retrieve security alerts.';

        renderSeverityChart([]);
    }
}

// ========================================
// 5. DISPLAY AND FILTER ALERTS
// ========================================

function displaySecurityAlerts() {
    const container = document.getElementById('alerts-container');
    const filter = document.getElementById('severity-filter');

    if (!container) return;

    const selectedSeverity = filter?.value || 'all';

    const filteredAlerts = securityAlerts.filter(alert => {
        const severity = String(
            alert.severity || 'unknown'
        ).toLowerCase();

        return selectedSeverity === 'all' ||
            severity === selectedSeverity;
    });

    container.replaceChildren();

    if (filteredAlerts.length === 0) {
        const empty = document.createElement('p');
        empty.className = 'chart-empty';
        empty.textContent = securityAlerts.length === 0
            ? 'No security alerts detected.'
            : 'No alerts match the selected severity.';

        container.appendChild(empty);
        return;
    }

    filteredAlerts.forEach(alert => {
        const severity = String(
            alert.severity || 'unknown'
        ).toLowerCase();

        const article = document.createElement('article');
        article.className = 'alert-card';

        if (severityColors[severity]) {
            article.classList.add(`severity-${severity}`);
        }

        const title = document.createElement('h3');
        title.textContent = String(
            alert.alert_type || 'UNKNOWN_ALERT'
        ).replaceAll('_', ' ');

        const description = document.createElement('p');
        description.textContent =
            alert.description || 'No description available.';

        const severityText = document.createElement('p');
        severityText.className = 'alert-severity';
        severityText.textContent =
            `Severity: ${severity.toUpperCase()}`;

        const status = document.createElement('p');
        status.textContent =
            `Status: ${alert.status || 'unknown'}`;

        const application = document.createElement('p');
        application.textContent =
            `Application ID: ${alert.application_id ?? 'N/A'}`;

        const detected = document.createElement('p');
        const date = new Date(alert.created_at);

        detected.textContent = Number.isNaN(date.getTime())
            ? 'Detected: Unknown'
            : `Detected: ${date.toLocaleString()}`;

        article.append(
            title,
            description,
            severityText,
            status,
            application,
            detected
        );

        container.appendChild(article);
    });
}

// ========================================
// 6. THREAT SEVERITY CHART
// ========================================

function renderSeverityChart(alerts) {
    const container = document.getElementById('severity-chart');
    if (!container) return;

    container.replaceChildren();

    if (alerts.length === 0) {
        const empty = document.createElement('p');
        empty.className = 'chart-empty';
        empty.textContent = 'No threat severity data available.';
        container.appendChild(empty);
        return;
    }

    const counts = {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        unknown: 0
    };

    alerts.forEach(alert => {
        const severity = String(
            alert.severity || 'unknown'
        ).toLowerCase();

        if (Object.hasOwn(counts, severity)) {
            counts[severity]++;
        } else {
            counts.unknown++;
        }
    });

    const total = alerts.length;
    const segments = [];
    let start = 0;

    Object.entries(counts).forEach(([severity, count]) => {
        if (count === 0) return;

        const end = start + (count / total) * 100;

        segments.push(
            `${severityColors[severity]} ${start}% ${end}%`
        );

        start = end;
    });

    const content = document.createElement('div');
    content.className = 'severity-content';

    const donut = document.createElement('div');
    donut.className = 'severity-donut';
    donut.style.background =
        `conic-gradient(${segments.join(', ')})`;

    const inner = document.createElement('div');
    inner.className = 'severity-donut-inner';

    const totalValue = document.createElement('strong');
    totalValue.textContent = total.toLocaleString();

    const totalLabel = document.createElement('span');
    totalLabel.textContent = 'Recent Alerts';

    inner.append(totalValue, totalLabel);
    donut.appendChild(inner);

    const legend = document.createElement('div');
    legend.className = 'severity-legend';

    Object.entries(counts).forEach(([severity, count]) => {
        if (count === 0) return;

        const item = document.createElement('div');
        item.className = 'severity-legend-item';

        const name = document.createElement('span');
        name.textContent =
            `${severity.charAt(0).toUpperCase() + severity.slice(1)}`;

        name.style.color = severityColors[severity];

        const value = document.createElement('strong');
        value.textContent = count.toLocaleString();

        item.append(name, value);
        legend.appendChild(item);
    });

    content.append(donut, legend);
    container.appendChild(content);
}

// ========================================
// 7. SYSTEM HEALTH CHECK
// ========================================

async function checkSystemHealth() {
    const status = document.getElementById('system-status-text');
    const indicator = document.querySelector('.live-indicator');

    try {
        const response = await fetch('/api/health', {
            cache: 'no-store'
        });

        if (!response.ok) {
            throw new Error('Health check failed');
        }

        const data = await response.json();

        const online =
            data.status === 'online' &&
            data.database === 'connected';

        if (status) {
            status.textContent = online
                ? 'API & database online'
                : 'Service degraded';
        }

        if (indicator) {
            indicator.style.color = online
                ? '#34d399'
                : '#fbbf24';

            indicator.querySelector('.status-dot')
                ?.style.setProperty(
                    'background',
                    online ? '#34d399' : '#fbbf24'
                );
        }

    } catch (error) {
        console.error('System health check failed:', error);

        if (status) {
            status.textContent = 'Connection unavailable';
        }

        if (indicator) {
            indicator.style.color = '#fb7185';
        }
    }
}

// ========================================
// 8. SIDEBAR NAVIGATION
// ========================================

function initializeNavigation() {
    const links = document.querySelectorAll('.nav-link');

    links.forEach(link => {
        link.addEventListener('click', () => {
            links.forEach(item => {
                item.classList.remove('active');
            });

            link.classList.add('active');
        });
    });
}

document.getElementById('logout-btn')?.addEventListener('click', async () => {
    const logoutButton = document.getElementById('logout-btn');

    logoutButton.disabled = true;
    logoutButton.textContent = 'Signing out...';

    try {
        const response = await fetch('/api/auth/logout', {
            method: 'POST',
            credentials: 'same-origin'
        });

        if (!response.ok) {
            throw new Error('Logout failed');
        }

        window.location.replace('/login.html');
    } catch (error) {
        console.error('Logout error:', error);
        alert('Unable to sign out. Please try again.');

        logoutButton.disabled = false;
        logoutButton.textContent = '⏻ Sign Out';
    }
});

