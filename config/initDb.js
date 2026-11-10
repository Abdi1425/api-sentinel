
const pool = require('./db');

const initializeDatabase = async () => {
    try {
        // 1. Applications that connect to API Sentinel
        await pool.query(`
            CREATE TABLE IF NOT EXISTS applications (
                id SERIAL PRIMARY KEY,
                name VARCHAR(100) NOT NULL,
                description TEXT,
                status VARCHAR(20) DEFAULT 'active',
                created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
            );
        `);

        // 2. API credentials for external applications
        await pool.query(`
            CREATE TABLE IF NOT EXISTS api_keys (
                id SERIAL PRIMARY KEY,
                application_id INTEGER NOT NULL
                    REFERENCES applications(id) ON DELETE CASCADE,
                key_prefix VARCHAR(20) NOT NULL,
                key_hash TEXT NOT NULL UNIQUE,
                revoked BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
            );
        `);

        // 3. Successful and failed authentication events
        await pool.query(`
            CREATE TABLE IF NOT EXISTS login_events (
                id BIGSERIAL PRIMARY KEY,
                application_id INTEGER NOT NULL
                    REFERENCES applications(id) ON DELETE CASCADE,
                user_reference VARCHAR(150) NOT NULL,
                event_type VARCHAR(20) NOT NULL
                    CHECK (event_type IN ('LOGIN_SUCCESS', 'LOGIN_FAILURE')),
                ip_address VARCHAR(45) NOT NULL,
                user_agent TEXT,
                occurred_at TIMESTAMPTZ NOT NULL,
                received_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
            );
        `);

        // 4. Security alerts
        await pool.query(`
            CREATE TABLE IF NOT EXISTS threat_alerts (
                id BIGSERIAL PRIMARY KEY,
                application_id INTEGER NOT NULL
                    REFERENCES applications(id) ON DELETE CASCADE,
                alert_type VARCHAR(100) NOT NULL,
                description TEXT NOT NULL,
                severity VARCHAR(20) DEFAULT 'medium',
                status VARCHAR(20) DEFAULT 'open',
                created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
            );
        `);

        // Indexes for faster security monitoring
        await pool.query(`
            CREATE INDEX IF NOT EXISTS idx_events_ip_time
            ON login_events(ip_address, occurred_at);

            CREATE INDEX IF NOT EXISTS idx_events_app
            ON login_events(application_id);

            CREATE INDEX IF NOT EXISTS idx_alerts_app
            ON threat_alerts(application_id);
        `);

        console.log('API Sentinel database initialized successfully.');

    } catch (error) {
        console.error('Database initialization failed:', error);
        throw error;
    }
};

module.exports = initializeDatabase;
