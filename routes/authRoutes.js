
const express = require('express');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const pool = require('../config/db');

const router = express.Router();

const INVALID_CREDENTIALS = 'Invalid username or password';

// Prevent timing differences from revealing whether a user exists.
const dummyHashPromise = bcrypt.hash(
    'api-sentinel-dummy-password',
    12
);

// Save an authenticated identity in a fresh session.
function establishSession(req, res, next, user) {
    req.session.regenerate((error) => {
        if (error) return next(error);

        req.session.userId = user.id;
        req.session.username = user.username;
        req.session.role = user.role;
        req.session.isAdmin = user.role === 'admin';

        req.session.save((saveError) => {
            if (saveError) return next(saveError);

            return res.status(200).json({
                success: true,
                message: 'Login successful',
                user: {
                    id: user.id,
                    username: user.username,
                    role: user.role
                }
            });
        });
    });
}

// ========================================
// LOGIN
// ========================================
router.post('/login', async (req, res, next) => {
    const { username, password } = req.body || {};

    if (
        typeof username !== 'string' ||
        typeof password !== 'string' ||
        !username.trim() ||
        !password ||
        username.length > 100 ||
        password.length > 1024
    ) {
        return res.status(400).json({
            success: false,
            error: 'Valid username and password are required'
        });
    }

    const loginUsername = username.trim();

    try {
        // 1. Preserve the original environment administrator.
        const expectedUsername = process.env.ADMIN_USERNAME;
        const expectedPassword = process.env.ADMIN_PASSWORD;

        if (expectedUsername && expectedPassword) {
            const suppliedHash = crypto
                .createHash('sha256')
                .update(password)
                .digest();

            const expectedHash = crypto
                .createHash('sha256')
                .update(expectedPassword)
                .digest();

            const matches = crypto.timingSafeEqual(
                suppliedHash,
                expectedHash
            );

            if (
                loginUsername === expectedUsername &&
                matches
            ) {
                return establishSession(req, res, next, {
                    id: null,
                    username: expectedUsername,
                    role: 'admin'
                });
            }
        }

        // 2. Authenticate database-backed users.
        const result = await pool.query(
            `SELECT
                id,
                username,
                password_hash,
                role,
                status
             FROM system_users
             WHERE LOWER(username) = LOWER($1)
             LIMIT 1`,
            [loginUsername]
        );

        const user = result.rows[0];

        const hash = user
            ? user.password_hash
            : await dummyHashPromise;

        const passwordMatches = await bcrypt.compare(
            password,
            hash
        );

        if (
            !user ||
            !passwordMatches ||
            user.status !== 'active'
        ) {
            return res.status(401).json({
                success: false,
                error: INVALID_CREDENTIALS
            });
        }

        await pool.query(
            `UPDATE system_users
             SET last_login = NOW()
             WHERE id = $1`,
            [user.id]
        );

        return establishSession(req, res, next, user);

    } catch (error) {
        console.error('Authentication failed:', error);
        return next(error);
    }
});

// ========================================
// CURRENT SESSION
// ========================================
router.get('/me', async (req, res, next) => {
    if (!req.session || !req.session.role) {
        return res.status(401).json({
            success: false,
            error: 'Not authenticated'
        });
    }

    try {
        if (req.session.userId !== null) {
            const result = await pool.query(
                `SELECT id, username, role, status
                 FROM system_users
                 WHERE id = $1`,
                [req.session.userId]
            );

            const user = result.rows[0];

            if (
                !user ||
                user.status !== 'active'
            ) {
                return res.status(401).json({
                    success: false,
                    error: 'Account inactive or unavailable'
                });
            }

            return res.json({
                success: true,
                user: {
                    id: user.id,
                    username: user.username,
                    role: user.role
                }
            });
        }

        return res.json({
            success: true,
            user: {
                id: null,
                username: req.session.username,
                role: 'admin'
            }
        });

    } catch (error) {
        return next(error);
    }
});

// ========================================
// LOGOUT
// ========================================
router.post('/logout', (req, res, next) => {
    if (!req.session) {
        return res.status(200).json({
            success: true,
            message: 'Signed out successfully'
        });
    }

    req.session.destroy((error) => {
        if (error) return next(error);

        res.clearCookie('sentinel.sid', {
            path: '/',
            httpOnly: true,
            sameSite: 'lax',
            secure: process.env.NODE_ENV === 'production'
        });

        return res.status(200).json({
            success: true,
            message: 'Signed out successfully'
        });
    });
});

module.exports = router;
