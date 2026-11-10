
const express = require('express');
const crypto = require('crypto');
const pool = require('../config/db');

const router = express.Router();

// Protect application registration with an admin secret
const verifyAdmin = (req, res, next) => {
    const suppliedKey = req.headers['x-admin-key'];
    const expectedKey = process.env.ADMIN_API_KEY;

    if (!suppliedKey || !expectedKey) {
        return res.status(401).json({
            error: 'Unauthorized'
        });
    }

    const suppliedBuffer = Buffer.from(suppliedKey);
    const expectedBuffer = Buffer.from(expectedKey);

    if (
        suppliedBuffer.length !== expectedBuffer.length ||
        !crypto.timingSafeEqual(suppliedBuffer, expectedBuffer)
    ) {
        return res.status(401).json({
            error: 'Invalid admin credentials'
        });
    }

    next();
};

// Register a new application
router.post('/', verifyAdmin, async (req, res) => {
    const { name, description } = req.body;

    if (!name || typeof name !== 'string' || !name.trim()) {
        return res.status(400).json({
            error: 'Application name is required'
        });
    }

    const client = await pool.connect();

    try {
        await client.query('BEGIN');

        // Create a unique API key
        const apiKey = 'as_live_' + crypto.randomBytes(32).toString('hex');

        // Store only its SHA-256 hash
        const keyHash = crypto
            .createHash('sha256')
            .update(apiKey)
            .digest('hex');

        const keyPrefix = apiKey.substring(0, 16);

        // Register the application
        const applicationResult = await client.query(
            `INSERT INTO applications (name, description)
             VALUES ($1, $2)
             RETURNING id, name, description, status, created_at`,
            [name.trim(), description || null]
        );

        const application = applicationResult.rows[0];

        // Store the API key hash
        await client.query(
            `INSERT INTO api_keys
             (application_id, key_prefix, key_hash)
             VALUES ($1, $2, $3)`,
            [application.id, keyPrefix, keyHash]
        );

        await client.query('COMMIT');

        // Show the original API key only once
        res.status(201).json({
            message: 'Application registered successfully',
            application,
            api_key: apiKey,
            warning: 'Save this API key securely. It will not be displayed again.'
        });

    } catch (error) {
        await client.query('ROLLBACK');

        console.error('Application registration failed:', error);

        res.status(500).json({
            error: 'Failed to register application'
        });

    } finally {
        client.release();
    }
});

router.post('/:id/keys', verifyAdmin, async (req, res) => {
    const applicationId = Number(req.params.id);

    if (!Number.isInteger(applicationId) || applicationId <= 0) {
        return res.status(400).json({
            error: 'Invalid application ID'
        });
    }

    try {
        // Confirm that the application exists and is active
        const application = await pool.query(
            `SELECT id, name FROM applications
             WHERE id = $1 AND status = 'active'`,
            [applicationId]
        );

        if (application.rows.length === 0) {
            return res.status(404).json({
                error: 'Active application not found'
            });
        }

        // Generate a new API key
        const apiKey = 'as_live_' + crypto.randomBytes(32).toString('hex');

        // Hash it before storing it
        const keyHash = crypto
            .createHash('sha256')
            .update(apiKey)
            .digest('hex');

        const keyPrefix = apiKey.substring(0, 16);

        await pool.query(
            `INSERT INTO api_keys
             (application_id, key_prefix, key_hash)
             VALUES ($1, $2, $3)`,
            [applicationId, keyPrefix, keyHash]
        );

        res.status(201).json({
            message: 'New API key generated successfully',
            application: application.rows[0].name,
            api_key: apiKey,
            warning: 'Save this key securely. It cannot be retrieved again.'
        });

    } catch (error) {
        console.error('API key generation failed:', error);

        res.status(500).json({
            error: 'Failed to generate API key'
        });
    }
});


module.exports = router;
