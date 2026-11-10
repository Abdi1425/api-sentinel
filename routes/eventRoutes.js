
const express = require('express');
const net = require('net');
const pool = require('../config/db');
const apiKeyAuth = require('../middleware/apiKeyAuth');
const { detectBruteForce } = require('../services/threatDetection');
const router = express.Router();

// All event submissions must come from an authenticated application
router.post('/', apiKeyAuth, async (req, res) => {
    const {
        event,
        user_reference,
        ip_address,
        user_agent,
        timestamp
    } = req.body;

    // Validate required fields
    if (
        !event ||
        !user_reference ||
        !ip_address ||
        !timestamp
    ) {
        return res.status(400).json({
            error: 'event, user_reference, ip_address and timestamp are required'
        });
    }

    // Only accept the two supported event types
    if (!['LOGIN_SUCCESS', 'LOGIN_FAILURE'].includes(event)) {
        return res.status(400).json({
            error: 'Invalid event type'
        });
    }

    if (
        typeof user_reference !== 'string' ||
        user_reference.trim().length === 0 ||
        user_reference.length > 150
    ) {
        return res.status(400).json({
            error: 'Invalid user reference'
        });
    }

    // Validate IPv4 or IPv6 address
    if (typeof ip_address !== 'string' || net.isIP(ip_address) === 0) {
        return res.status(400).json({
            error: 'Invalid IP address'
        });
    }

    // Validate timestamp
    const occurredAt = new Date(timestamp);

    if (
        typeof timestamp !== 'string' ||
        Number.isNaN(occurredAt.getTime())
    ) {
        return res.status(400).json({
            error: 'Invalid timestamp'
        });
    }

    try {
        const result = await pool.query(
            `INSERT INTO login_events
             (application_id, user_reference, event_type,
              ip_address, user_agent, occurred_at)
             VALUES ($1, $2, $3, $4, $5, $6)
             RETURNING id, application_id, event_type,
                       occurred_at, received_at`,
            [
                req.application.id,
                user_reference.trim(),
                event,
                ip_address,
                typeof user_agent === 'string'
                    ? user_agent.slice(0, 1000)
                    : null,
                occurredAt
            ]
        );
        if (event === 'LOGIN_FAILURE') {
    const failedAttempts = await detectBruteForce(
        req.application.id,
        ip_address
    );

    console.log(`Failed login attempts from ${ip_address}: ${failedAttempts}`);
}
        res.status(201).json({
            message: 'Login event recorded successfully',
            application: req.application.name,
            event: result.rows[0]
        });

    } catch (error) {
        console.error('Login event recording failed:', error);

        res.status(500).json({
            error: 'Failed to record login event'
        });
    }
});

module.exports = router;
