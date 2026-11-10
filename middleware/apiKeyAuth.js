
const crypto = require('crypto');
const pool = require('../config/db');

const apiKeyAuth = async (req, res, next) => {
    try {
        // Read the API key from the request header
        const apiKey = req.headers['x-api-key'];

        if (!apiKey) {
            return res.status(401).json({
                error: 'API key is required'
            });
        }

        // Hash the supplied key
        const keyHash = crypto
            .createHash('sha256')
            .update(apiKey)
            .digest('hex');

        // Find a valid key belonging to an active application
        const result = await pool.query(
            `SELECT
                api_keys.id AS key_id,
                applications.id AS application_id,
                applications.name AS application_name
             FROM api_keys
             INNER JOIN applications
                ON api_keys.application_id = applications.id
             WHERE api_keys.key_hash = $1
               AND api_keys.revoked = FALSE
               AND applications.status = 'active'`,
            [keyHash]
        );

        if (result.rows.length === 0) {
            return res.status(401).json({
                error: 'Invalid or revoked API key'
            });
        }

        // Make the authenticated application available to later routes
        req.application = {
            id: result.rows[0].application_id,
            name: result.rows[0].application_name
        };

        next();

    } catch (error) {
        console.error('API key authentication failed:', error.message);

        return res.status(500).json({
            error: 'Authentication service error'
        });
    }
};

module.exports = apiKeyAuth;
