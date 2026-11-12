
const pool = require('../config/db');

async function detectBruteForce(applicationId, ipAddress) {
    // Count failed logins within the last five minutes
    const result = await pool.query(
        `SELECT COUNT(*) AS failed_attempts
         FROM login_events
         WHERE application_id = $1
           AND ip_address = $2
           AND event_type = 'LOGIN_FAILURE'
           AND received_at >= NOW() - INTERVAL '5 minutes'`,
        [applicationId, ipAddress]
    );

    const failedAttempts = Number(result.rows[0].failed_attempts);

    // Trigger detection after five failed attempts
    if (failedAttempts < 5) {
        return failedAttempts;
    }

    // Avoid duplicate recent alerts for the same application and IP
    const existingAlert = await pool.query(
        `SELECT id
         FROM threat_alerts
         WHERE application_id = $1
           AND ip_address = $2::inet
           AND alert_type = 'BRUTE_FORCE_ATTEMPT'
           AND created_at >= NOW() - INTERVAL '5 minutes'
         LIMIT 1`,
        [applicationId, ipAddress]
    );

    if (existingAlert.rows.length > 0) {
        return failedAttempts;
    }

    // Create an alert with a structured source IP and category
    const alert = await pool.query(
        `INSERT INTO threat_alerts (
            application_id,
            alert_type,
            description,
            severity,
            status,
            ip_address,
            category
        )
        VALUES ($1, $2, $3, $4, $5, $6::inet, $7)
        RETURNING id, ip_address, severity, status`,
        [
            applicationId,
            'BRUTE_FORCE_ATTEMPT',
            `Detected ${failedAttempts} failed login attempts from IP ${ipAddress} within 5 minutes`,
            'high',
            'open',
            ipAddress,
            'brute_force'
        ]
    );

    console.log(
        `Security alert #${alert.rows[0].id}: ` +
        `Possible brute-force attack from ${ipAddress}`
    );

    return failedAttempts;
}

module.exports = { detectBruteForce };
