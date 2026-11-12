
const pool = require('../config/db');

const requireRole = (...allowedRoles) => {
    return async (req, res, next) => {
        try {
            if (!req.session || !req.session.role) {
                return res.status(401).json({
                    success: false,
                    message: 'Authentication required'
                });
            }

            let role;

            if (Number.isInteger(req.session.userId)) {
                const result = await pool.query(
                    `SELECT id, username, role, status
                     FROM system_users
                     WHERE id = $1`,
                    [req.session.userId]
                );

                const user = result.rows[0];

                if (!user || user.status !== 'active') {
                    return res.status(401).json({
                        success: false,
                        message: 'Account inactive or unavailable'
                    });
                }

                role = user.role;

                req.authUser = {
                    id: user.id,
                    username: user.username,
                    role: user.role
                };

            } else if (
                req.session.userId === null &&
                req.session.isAdmin === true &&
                req.session.username === process.env.ADMIN_USERNAME
            ) {
                role = 'admin';

                req.authUser = {
                    id: null,
                    username: req.session.username,
                    role: 'admin'
                };

            } else {
                return res.status(401).json({
                    success: false,
                    message: 'Invalid session'
                });
            }

            if (!allowedRoles.includes(role)) {
                return res.status(403).json({
                    success: false,
                    message: 'Insufficient permissions'
                });
            }

            next();

        } catch (error) {
            console.error('Authorization error:', error);

            return res.status(500).json({
                success: false,
                message: 'Authorization failed'
            });
        }
    };
};

module.exports = requireRole;
