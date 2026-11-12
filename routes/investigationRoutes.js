
const express = require('express');
const pool = require('../config/db');
const requireRole = require('../middleware/roleAuth');

const router = express.Router();

// ========================================
// ROLE PERMISSIONS
// ========================================

// Admin, Analyst, and Viewer can read investigations.
const canView = requireRole(
    'admin',
    'analyst',
    'viewer'
);

// Only Admin and Analyst can update investigations.
const canInvestigate = requireRole(
    'admin',
    'analyst'
);

// ========================================
// GET /api/investigations
// ========================================

router.get('/', canView, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT
                ta.id,
                ta.application_id,
                a.name AS application_name,
                ta.alert_type,
                ta.description,
                ta.ip_address::text AS ip_address,
                ta.severity,
                ta.status,
                ta.category,
                ta.assigned_to,
                ta.resolution_notes,
                ta.created_at,
                ta.updated_at,
                ta.resolved_at
            FROM threat_alerts ta
            JOIN applications a
                ON a.id = ta.application_id
            ORDER BY ta.created_at DESC
            LIMIT 100
        `);

        return res.json({
            success: true,
            total: result.rows.length,
            investigations: result.rows
        });

    } catch (error) {
        console.error(
            'Failed to retrieve investigations:',
            error
        );

        return res.status(500).json({
            success: false,
            message: 'Unable to retrieve investigations'
        });
    }
});

// ========================================
// GET /api/investigations/suspicious-ips
// ========================================

router.get('/suspicious-ips', canView, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT
                le.ip_address,
                le.application_id,
                a.name AS application_name,
                COUNT(*)::integer AS failed_attempts,
                MAX(le.received_at) AS last_seen
            FROM login_events le
            JOIN applications a
                ON a.id = le.application_id
            WHERE le.event_type = 'LOGIN_FAILURE'
            GROUP BY
                le.ip_address,
                le.application_id,
                a.name
            ORDER BY
                failed_attempts DESC,
                last_seen DESC
            LIMIT 50
        `);

        return res.json({
            success: true,
            suspicious_ips: result.rows
        });

    } catch (error) {
        console.error(
            'Failed to retrieve suspicious IPs:',
            error
        );

        return res.status(500).json({
            success: false,
            message: 'Unable to retrieve suspicious IP addresses'
        });
    }
});

// ========================================
// GET /api/investigations/:id
// ========================================

router.get('/:id', canView, async (req, res) => {
    const id = Number(req.params.id);

    if (!Number.isSafeInteger(id) || id <= 0) {
        return res.status(400).json({
            success: false,
            message: 'Invalid investigation ID'
        });
    }

    try {
        const result = await pool.query(
            `SELECT
                ta.*,
                ta.ip_address::text AS ip_address,
                a.name AS application_name
             FROM threat_alerts ta
             JOIN applications a
                ON a.id = ta.application_id
             WHERE ta.id = $1::bigint`,
            [id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Investigation not found'
            });
        }

        return res.json({
            success: true,
            investigation: result.rows[0]
        });

    } catch (error) {
        console.error(
            'Failed to retrieve investigation:',
            error
        );

        return res.status(500).json({
            success: false,
            message: 'Unable to retrieve investigation'
        });
    }
});

// ========================================
// PATCH /api/investigations/:id
// ========================================
// Only Admin and Analyst can update investigations.

router.patch('/:id', canInvestigate, async (req, res) => {
    const id = Number(req.params.id);

    if (!Number.isSafeInteger(id) || id <= 0) {
        return res.status(400).json({
            success: false,
            message: 'Invalid investigation ID'
        });
    }

    const {
        status,
        category,
        resolution_notes
    } = req.body || {};

    const allowedStatuses = [
        'open',
        'investigating',
        'resolved',
        'false_positive'
    ];

    const allowedCategories = [
        'uncategorized',
        'brute_force',
        'suspicious_login',
        'credential_stuffing',
        'other'
    ];

    if (!allowedStatuses.includes(status)) {
        return res.status(400).json({
            success: false,
            message: 'Invalid investigation status'
        });
    }

    if (!allowedCategories.includes(category)) {
        return res.status(400).json({
            success: false,
            message: 'Invalid investigation category'
        });
    }

    if (
        typeof resolution_notes !== 'string' ||
        resolution_notes.length > 5000
    ) {
        return res.status(400).json({
            success: false,
            message:
                'Resolution notes must be a string of at most 5000 characters'
        });
    }

    try {
        const result = await pool.query(
            `UPDATE threat_alerts
             SET
                status = $1::varchar,
                category = $2::varchar,
                resolution_notes = $3::text,
                updated_at = NOW(),
                resolved_at = CASE
                    WHEN $1::varchar IN (
                        'resolved',
                        'false_positive'
                    )
                    THEN COALESCE(resolved_at, NOW())
                    ELSE NULL
                END
             WHERE id = $4::bigint
             RETURNING
                id,
                status,
                category,
                resolution_notes,
                updated_at,
                resolved_at`,
            [
                status,
                category,
                resolution_notes,
                id
            ]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Investigation not found'
            });
        }

        return res.json({
            success: true,
            message: 'Investigation updated successfully',
            investigation: result.rows[0]
        });

    } catch (error) {
        console.error(
            'Failed to update investigation:',
            error
        );

        return res.status(500).json({
            success: false,
            message: 'Unable to update investigation'
        });
    }
});

module.exports = router;
