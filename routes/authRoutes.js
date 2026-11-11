
const express = require('express');
const crypto = require('crypto');

const router = express.Router();

// ========================================
// ADMINISTRATOR LOGIN
// ========================================

router.post('/login', (req, res, next) => {
    const { username, password } = req.body || {};

    // Load administrator credentials
    const expectedUsername = process.env.ADMIN_USERNAME;
    const expectedPassword = process.env.ADMIN_PASSWORD;

    // Verify that credentials are configured
    if (!expectedUsername || !expectedPassword) {
        return res.status(503).json({
            error: 'Administrator credentials not configured'
        });
    }

    // Validate request body
    if (
        typeof username !== 'string' ||
        typeof password !== 'string'
    ) {
        return res.status(400).json({
            error: 'Username and password are required'
        });
    }

    // Hash supplied and expected passwords
    const suppliedHash = crypto
        .createHash('sha256')
        .update(password)
        .digest();

    const expectedHash = crypto
        .createHash('sha256')
        .update(expectedPassword)
        .digest();

    // Compare password hashes securely
    const passwordMatches = crypto.timingSafeEqual(
        suppliedHash,
        expectedHash
    );

    // Reject invalid credentials
    if (
        username !== expectedUsername ||
        !passwordMatches
    ) {
        return res.status(401).json({
            error: 'Invalid username or password'
        });
    }

    // Regenerate session to prevent session fixation
    req.session.regenerate((error) => {
        if (error) {
            return next(error);
        }

        // Mark session as authenticated
        req.session.isAdmin = true;

        // Save session before responding
        req.session.save((saveError) => {
            if (saveError) {
                return next(saveError);
            }

            return res.status(200).json({
                success: true,
                message: 'Administrator login successful'
            });
        });
    });
});

module.exports = router;
