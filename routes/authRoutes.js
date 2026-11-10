
const express = require('express');
const crypto = require('crypto');

const router = express.Router();

router.post('/login', (req, res, next) => {
    const { username, password } = req.body || {};

    const expectedUsername = process.env.ADMIN_USERNAME;
    const expectedPassword = process.env.ADMIN_PASSWORD;

    if (!expectedUsername || !expectedPassword) {
        return res.status(503).json({
            error: 'Administrator credentials not configured'
        });
    }

    if (typeof username !== 'string' || typeof password !== 'string') {
        return res.status(400).json({
            error: 'Username and password are required'
        });
    }

    const suppliedHash = crypto.createHash('sha256')
        .update(password)
        .digest();

    const expectedHash = crypto.createHash('sha256')
        .update(expectedPassword)
        .digest();

    const passwordMatches = crypto.timingSafeEqual(
        suppliedHash,
        expectedHash
    );

    if (username !== expectedUsername || !passwordMatches) {
        return res.status(401).json({
            error: 'Invalid username or password'
        });
    }

    req.session.regenerate((error) => {
        if (error) return next(error);

        req.session.isAdmin = true;

        res.status(200).json({
            message: 'Administrator login successful'
        });
    });
});

module.exports = router;
