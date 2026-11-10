
const express = require('express');
const crypto = require('crypto');
const pool = require('../config/db');

const router = express.Router();

// Verify administrator authentication
function verifyAdmin(req, res, next) {

    // Method 1: Administrator session
    if (req.session && req.session.isAdmin === true) {
        return next();
    }

    // Method 2: Administrator API key
    const providedKey = req.headers['x-admin-key'];
    const expectedKey = process.env.ADMIN_API_KEY;

    if (
        typeof providedKey === 'string' &&
        typeof expectedKey === 'string' &&
        Buffer.byteLength(providedKey) === Buffer.byteLength(expectedKey) &&
        crypto.timingSafeEqual(
            Buffer.from(providedKey),
            Buffer.from(expectedKey)
        )
    ) {
        return next();
    }

    // Reject unauthorized requests
    return res.status(401).json({
        error: 'Unauthorized. Administrator authentication required.'
    });
}

// Retrieve the latest security alerts
router.get('/', verifyAdmin, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT
                id,
                application_id,
                alert_type,
                description,
                severity,
                status,
                created_at
             FROM threat_alerts
             ORDER BY created_at DESC
             LIMIT 100`
        );

        return res.status(200).json({
            total: result.rows.length,
            alerts: result.rows
        });

    } catch (error) {
        console.error(
            'Failed to retrieve alerts:',
            error.message
        );

        return res.status(500).json({
            error: 'Failed to retrieve security alerts'
        });
    }
});

module.exports = router;
