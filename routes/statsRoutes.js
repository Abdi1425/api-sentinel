
const express = require('express');
const pool = require('../config/db');
const requireAdmin = require('../middleware/adminAuth');

const router = express.Router();

// Only logged-in administrators can access statistics
router.get('/', requireAdmin, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT
                (SELECT COUNT(*) FROM login_events) AS total_events,
                (SELECT COUNT(*)
                 FROM login_events
                 WHERE event_type = 'LOGIN_FAILURE') AS failed_logins,
                (SELECT COUNT(*) FROM threat_alerts) AS total_alerts
        `);

        const stats = result.rows[0];

        return res.status(200).json({
            totalEvents: Number(stats.total_events),
            failedLogins: Number(stats.failed_logins),
            totalAlerts: Number(stats.total_alerts)
        });

    } catch (error) {
        console.error('Statistics retrieval failed:', error);

        return res.status(500).json({
            error: 'Failed to retrieve dashboard statistics'
        });
    }
});

module.exports = router;
