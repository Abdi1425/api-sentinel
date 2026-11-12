
const express = require('express');
const bcrypt = require('bcrypt');
const pool = require('../config/db');
const requireAdmin = require('../middleware/adminAuth');

const router = express.Router();

// Every endpoint in this router is administrator-only.
router.use(requireAdmin);

const ROLES = ['admin', 'analyst', 'viewer'];
const STATUSES = ['active', 'inactive'];

const USER_FIELDS = `
    id,
    full_name,
    username,
    email,
    role,
    status,
    created_at,
    updated_at,
    last_login
`;

function validId(value) {
    const id = Number(value);
    return Number.isSafeInteger(id) && id > 0 ? id : null;
}

function validPassword(password) {
    return (
        typeof password === 'string' &&
        password.length >= 12 &&
        Buffer.byteLength(password, 'utf8') <= 72
    );
}

function validUserDetails(fullName, username, email) {
    return (
        typeof fullName === 'string' &&
        fullName.trim().length > 0 &&
        fullName.trim().length <= 150 &&
        typeof username === 'string' &&
        /^[a-zA-Z0-9_.-]{3,100}$/.test(username) &&
        typeof email === 'string' &&
        email.length <= 255 &&
        /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
    );
}

function databaseError(res, error, action) {
    if (error.code === '23505') {
        return res.status(409).json({
            success: false,
            message: 'Username or email already exists'
        });
    }

    console.error(`Failed to ${action}:`, error);

    return res.status(500).json({
        success: false,
        message: `Unable to ${action}`
    });
}

// ========================================
// GET /api/users
// ========================================

router.get('/', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT ${USER_FIELDS}
            FROM system_users
            ORDER BY created_at DESC
        `);

        return res.json({
            success: true,
            total: result.rows.length,
            users: result.rows
        });

    } catch (error) {
        return databaseError(res, error, 'retrieve users');
    }
});

// ========================================
// POST /api/users
// ========================================

router.post('/', async (req, res) => {
    const {
        full_name,
        username,
        email,
        password,
        role
    } = req.body || {};

    if (
        !validUserDetails(full_name, username, email) ||
        !validPassword(password) ||
        !ROLES.includes(role)
    ) {
        return res.status(400).json({
            success: false,
            message: 'Invalid user details, role, or password. Password must be at least 12 characters and at most 72 UTF-8 bytes.'
        });
    }

    try {
        const passwordHash = await bcrypt.hash(password, 12);

        const result = await pool.query(
            `INSERT INTO system_users
                (full_name, username, email, password_hash, role)
             VALUES ($1, $2, $3, $4, $5)
             RETURNING ${USER_FIELDS}`,
            [
                full_name.trim(),
                username.trim(),
                email.trim().toLowerCase(),
                passwordHash,
                role
            ]
        );

        return res.status(201).json({
            success: true,
            message: 'User created successfully',
            user: result.rows[0]
        });

    } catch (error) {
        return databaseError(res, error, 'create user');
    }
});

// ========================================
// PATCH /api/users/:id
// ========================================
// Update user details, role, and account status.

router.patch('/:id', async (req, res) => {
    const id = validId(req.params.id);

    if (!id) {
        return res.status(400).json({
            success: false,
            message: 'Invalid user ID'
        });
    }

    const {
        full_name,
        username,
        email,
        role,
        status
    } = req.body || {};

    if (
        !validUserDetails(full_name, username, email) ||
        !ROLES.includes(role) ||
        !STATUSES.includes(status)
    ) {
        return res.status(400).json({
            success: false,
            message: 'Invalid user details, role, or status'
        });
    }

    // Prevent an administrator from removing their own access.
    if (
        req.authUser?.id === id &&
        (role !== 'admin' || status !== 'active')
    ) {
        return res.status(403).json({
            success: false,
            message: 'You cannot deactivate or demote your own administrator account'
        });
    }

    try {
        const result = await pool.query(
            `UPDATE system_users
             SET
                full_name = $1::varchar,
                username = $2::varchar,
                email = $3::varchar,
                role = $4::varchar,
                status = $5::varchar,
                updated_at = NOW()
             WHERE id = $6::integer
             RETURNING ${USER_FIELDS}`,
            [
                full_name.trim(),
                username.trim(),
                email.trim().toLowerCase(),
                role,
                status,
                id
            ]
        );

        if (!result.rows.length) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        return res.json({
            success: true,
            message: 'User updated successfully',
            user: result.rows[0]
        });

    } catch (error) {
        return databaseError(res, error, 'update user');
    }
});

// ========================================
// PATCH /api/users/:id/password
// ========================================
// Administrator resets another user's password.

router.patch('/:id/password', async (req, res) => {
    const id = validId(req.params.id);

    if (!id) {
        return res.status(400).json({
            success: false,
            message: 'Invalid user ID'
        });
    }

    const { password } = req.body || {};

    if (!validPassword(password)) {
        return res.status(400).json({
            success: false,
            message: 'Password must be at least 12 characters and at most 72 UTF-8 bytes'
        });
    }

    // Password changes for the currently signed-in admin
    // should use a separate authenticated change-password flow.
    if (req.authUser?.id === id) {
        return res.status(403).json({
            success: false,
            message: 'Use the account password-change flow to change your own password'
        });
    }

    try {
        const passwordHash = await bcrypt.hash(password, 12);

        const result = await pool.query(
            `UPDATE system_users
             SET
                password_hash = $1,
                updated_at = NOW()
             WHERE id = $2::integer
             RETURNING id, username`,
            [passwordHash, id]
        );

        if (!result.rows.length) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        return res.json({
            success: true,
            message: 'Password reset successfully',
            user: result.rows[0]
        });

    } catch (error) {
        return databaseError(res, error, 'reset password');
    }
});

module.exports = router;
