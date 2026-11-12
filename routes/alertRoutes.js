
const express = require('express');
const crypto = require('crypto');
const pool = require('../config/db');
const requireRole = require('../middleware/roleAuth');

const router = express.Router();

// ========================================
// VERIFY ADMINISTRATOR API KEY
// ========================================
function hasValidAdminApiKey(req) {
    const providedKey = req.headers['x-admin-key'];
    const expectedKey = process.env.ADMIN_API_KEY;

    if (
        typeof providedKey !== 'string' ||
        typeof expectedKey !== 'string' ||
        !expectedKey
    ) {
        return false;
    }

    const providedHash = crypto
        .createHash('sha256')
        .update(providedKey)
        .digest();

    const expectedHash = crypto
        .createHash('sha256')
        .update(expectedKey)
        .digest();

    return crypto.timingSafeEqual(
        providedHash,
        expectedHash
    );
}

// ========================================
// VERIFY SECURITY ALERT ACCESS
// ========================================
function verifyAlertAccess(req, res, next) {

    // Allow requests with the administrator API key.
    if (hasValidAdminApiKey(req)) {
        req.authUser = {
            id: null,
            username: 'admin-api-key',
            role: 'admin'
        };

        return next();
    }

    // Otherwise, require a valid authenticated session.
    // Database account status and role are revalidated.
    return requireRole(
        'admin',
        'analyst',
        'viewer'
    )(req, res, next);
}

// ========================================
// GET /api/alerts
// ========================================
// Retrieve the latest security alerts.
router.get('/', verifyAlertAccess, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT
                id,
                application_id,
                alert_type,
                description,
                severity,
                status,
                created_at
            FROM threat_alerts
            ORDER BY created_at DESC
            LIMIT 100
        `);

        return res.status(200).json({
            total: result.rows.length,
            alerts: result.rows
        });

    } catch (error) {
        console.error(
            'Failed to retrieve alerts:',
            error
        );

        return res.status(500).json({
            error: 'Failed to retrieve security alerts'
        });
    }
});

module.exports = router;
