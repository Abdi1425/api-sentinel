
const express = require('express');
const crypto = require('crypto');
const pool = require('../config/db');
const requireRole = require('../middleware/roleAuth');

const router = express.Router();

const canView = requireRole('admin', 'analyst', 'viewer');
const adminOnly = requireRole('admin');

function generateApiKey() {
    const apiKey = 'as_live_' + crypto.randomBytes(32).toString('hex');

    const keyHash = crypto
        .createHash('sha256')
        .update(apiKey)
        .digest('hex');

    return {
        apiKey,
        keyHash,
        keyPrefix: apiKey.substring(0, 16)
    };
}

// GET /api/applications
// All authenticated roles can view applications.
router.get('/', canView, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT
                a.id,
                a.name,
                a.description,
                a.status,
                a.created_at,
                COUNT(k.id)::integer AS total_keys,
                COUNT(k.id) FILTER (
                    WHERE k.revoked = false
                )::integer AS active_keys
            FROM applications a
            LEFT JOIN api_keys k
                ON k.application_id = a.id
            GROUP BY
                a.id,
                a.name,
                a.description,
                a.status,
                a.created_at
            ORDER BY a.created_at DESC
        `);

        return res.json({
            success: true,
            total: result.rows.length,
            applications: result.rows
        });

    } catch (error) {
        console.error('Failed to fetch applications:', error);

        return res.status(500).json({
            success: false,
            error: 'Failed to fetch applications'
        });
    }
});

// POST /api/applications
// Only administrators can register applications.
router.post('/', adminOnly, async (req, res) => {
    const { name, description } = req.body || {};

    if (typeof name !== 'string' || !name.trim()) {
        return res.status(400).json({
            success: false,
            error: 'Application name is required'
        });
    }

    if (name.trim().length > 150) {
        return res.status(400).json({
            success: false,
            error: 'Application name is too long'
        });
    }

    if (
        description !== undefined &&
        description !== null &&
        typeof description !== 'string'
    ) {
        return res.status(400).json({
            success: false,
            error: 'Description must be a string'
        });
    }

    const client = await pool.connect();

    try {
        await client.query('BEGIN');

        const { apiKey, keyHash, keyPrefix } = generateApiKey();

        const result = await client.query(
            `INSERT INTO applications (name, description)
             VALUES ($1, $2)
             RETURNING id, name, description, status, created_at`,
            [name.trim(), description?.trim() || null]
        );

        const application = result.rows[0];

        await client.query(
            `INSERT INTO api_keys
                (application_id, key_prefix, key_hash)
             VALUES ($1, $2, $3)`,
            [application.id, keyPrefix, keyHash]
        );

        await client.query('COMMIT');

        res.set('Cache-Control', 'no-store');

        return res.status(201).json({
            success: true,
            message: 'Application registered successfully',
            application,
            api_key: apiKey,
            warning: 'Save this API key securely. It will not be displayed again.'
        });

    } catch (error) {
        await client.query('ROLLBACK');

        console.error('Application registration failed:', error);

        return res.status(500).json({
            success: false,
            error: 'Failed to register application'
        });

    } finally {
        client.release();
    }
});

// POST /api/applications/:id/keys
// Only administrators can generate API keys.
router.post('/:id/keys', adminOnly, async (req, res) => {
    const applicationId = Number(req.params.id);

    if (!Number.isSafeInteger(applicationId) || applicationId <= 0) {
        return res.status(400).json({
            success: false,
            error: 'Invalid application ID'
        });
    }

    try {
        const applicationResult = await pool.query(
            `SELECT id, name
             FROM applications
             WHERE id = $1 AND status = 'active'`,
            [applicationId]
        );

        if (applicationResult.rows.length === 0) {
            return res.status(404).json({
                success: false,
                error: 'Active application not found'
            });
        }

        const { apiKey, keyHash, keyPrefix } = generateApiKey();

        await pool.query(
            `INSERT INTO api_keys
                (application_id, key_prefix, key_hash)
             VALUES ($1, $2, $3)`,
            [applicationId, keyPrefix, keyHash]
        );

        res.set('Cache-Control', 'no-store');

        return res.status(201).json({
            success: true,
            message: 'New API key generated successfully',
            application: applicationResult.rows[0].name,
            api_key: apiKey,
            warning: 'Save this key securely. It cannot be retrieved again.'
        });

    } catch (error) {
        console.error('API key generation failed:', error);

        return res.status(500).json({
            success: false,
            error: 'Failed to generate API key'
        });
    }
});

module.exports = router;
