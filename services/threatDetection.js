const pool = require('../config/db');

async function detectBruteForce(applicationId, ipAddress) {
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

   if (failedAttempts >= 5) {
    const existingAlert = await pool.query(
    `SELECT id
     FROM threat_alerts
     WHERE application_id = $1
       AND alert_type = 'BRUTE_FORCE_ATTEMPT'
       AND description LIKE $2
       AND created_at >= NOW() - INTERVAL '5 minutes'
     LIMIT 1`,
    [applicationId, `%from IP ${ipAddress} within 5 minutes`]
);

if (existingAlert.rows.length > 0) {
    return failedAttempts;
}
    await pool.query(
        `INSERT INTO threat_alerts
         (application_id, alert_type, description, severity, status)
         VALUES ($1, $2, $3, $4, $5)`,
        [
            applicationId,
            'BRUTE_FORCE_ATTEMPT',
            `Detected ${failedAttempts} failed login attempts from IP ${ipAddress} within 5 minutes`,
            'high',
            'open'
        ]
    );

    console.log(`Security alert: Possible brute-force attack from ${ipAddress}`);
}

return failedAttempts;
}

module.exports = { detectBruteForce };