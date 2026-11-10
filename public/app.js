
document.addEventListener('DOMContentLoaded', () => {
    loadDashboardStats();
    loadSecurityAlerts();
});

// ========================================
// 1. LOAD DASHBOARD STATISTICS
// ========================================

async function loadDashboardStats() {
    const totalEvents = document.getElementById('total-events');
    const failedLogins = document.getElementById('failed-logins');
    const totalAlerts = document.getElementById('total-alerts');

    try {
        const response = await fetch('/api/stats', {
            method: 'GET',
            credentials: 'same-origin'
        });

        // Do not redirect automatically when unauthorized
        if (response.status === 401) {
            console.warn('Statistics API: Unauthorized');

            totalEvents.textContent = 'Login required';
            failedLogins.textContent = 'Login required';
            totalAlerts.textContent = 'Login required';

            return;
        }

        if (!response.ok) {
            throw new Error(
                `Statistics API failed: ${response.status}`
            );
        }

        const stats = await response.json();

        totalEvents.textContent = stats.totalEvents ?? 0;
        failedLogins.textContent = stats.failedLogins ?? 0;
        totalAlerts.textContent = stats.totalAlerts ?? 0;

    } catch (error) {
        console.error('Statistics error:', error);

        totalEvents.textContent = 'Error';
        failedLogins.textContent = 'Error';
        totalAlerts.textContent = 'Error';
    }
}

// ========================================
// 2. LOAD SECURITY ALERTS
// ========================================

async function loadSecurityAlerts() {
    const alertsContainer = document.getElementById('alerts-container');

    alertsContainer.textContent = 'Loading security alerts...';

    try {
        const response = await fetch('/api/alerts', {
            method: 'GET',
            credentials: 'same-origin'
        });

        // Prevent repeated login redirects
        if (response.status === 401) {
            console.warn('Alerts API: Unauthorized');

            alertsContainer.textContent =
                'Session not recognized. Please log in again.';

            return;
        }

        if (!response.ok) {
            throw new Error(
                `Alerts API failed: ${response.status}`
            );
        }

        const data = await response.json();

        alertsContainer.replaceChildren();

        if (!Array.isArray(data.alerts) || data.alerts.length === 0) {
            alertsContainer.textContent =
                'No security alerts detected.';
            return;
        }

        // Display security alerts
        data.alerts.forEach(alert => {
            const article = document.createElement('article');
            article.className = 'alert-card';

            // Alert type
            const heading = document.createElement('h3');
            heading.textContent = String(
                alert.alert_type || 'UNKNOWN_ALERT'
            ).replaceAll('_', ' ');

            // Alert description
            const description = document.createElement('p');
            description.textContent =
                alert.description || 'No description available.';

            // Alert severity
            const severity = document.createElement('p');
            severity.className = 'alert-severity';
            severity.textContent =
                `Severity: ${String(alert.severity || 'unknown').toUpperCase()}`;

            // Alert status
            const status = document.createElement('p');
            status.textContent =
                `Status: ${alert.status || 'unknown'}`;

            // Application ID
            const application = document.createElement('p');
            application.textContent =
                `Application ID: ${alert.application_id ?? 'N/A'}`;

            // Detection date
            const date = document.createElement('p');
            const detectedAt = new Date(alert.created_at);

            date.textContent = Number.isNaN(detectedAt.getTime())
                ? 'Detected: Unknown'
                : `Detected: ${detectedAt.toLocaleString()}`;

            // Add alert information
            article.append(
                heading,
                description,
                severity,
                status,
                application,
                date
            );

            alertsContainer.appendChild(article);
        });

    } catch (error) {
        console.error('Dashboard alert error:', error);

        alertsContainer.textContent =
            'Unable to load security alerts.';
    }
}
