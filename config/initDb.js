
const pool = require('./db');

const initializeDatabase = async () => {
    try {
        // =====================================================
        // 1. APPLICATIONS
        // =====================================================
        await pool.query(`
            CREATE TABLE IF NOT EXISTS applications (
                id SERIAL PRIMARY KEY,
                name VARCHAR(100) NOT NULL,
                description TEXT,
                status VARCHAR(20) DEFAULT 'active',
                created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
            );
        `);

        // =====================================================
        // 2. API KEYS
        // =====================================================
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

        // =====================================================
        // 3. LOGIN EVENTS
        // =====================================================
        await pool.query(`
            CREATE TABLE IF NOT EXISTS login_events (
                id BIGSERIAL PRIMARY KEY,
                application_id INTEGER NOT NULL
                    REFERENCES applications(id) ON DELETE CASCADE,
                user_reference VARCHAR(150) NOT NULL,
                event_type VARCHAR(20) NOT NULL
                    CHECK (
                        event_type IN (
                            'LOGIN_SUCCESS',
                            'LOGIN_FAILURE'
                        )
                    ),
                ip_address VARCHAR(45) NOT NULL,
                user_agent TEXT,
                occurred_at TIMESTAMPTZ NOT NULL,
                received_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
            );
        `);

        // =====================================================
        // 4. SECURITY ALERTS
        // =====================================================
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

        // =====================================================
        // 5. USER MANAGEMENT
        // =====================================================
        // Stores administrator, analyst and viewer accounts.
        // Passwords must be securely hashed before insertion.
        await pool.query(`
            CREATE TABLE IF NOT EXISTS system_users (
                id SERIAL PRIMARY KEY,

                full_name VARCHAR(150) NOT NULL,

                username VARCHAR(100) NOT NULL UNIQUE,

                email VARCHAR(255) NOT NULL UNIQUE,

                password_hash TEXT NOT NULL,

                role VARCHAR(20) NOT NULL DEFAULT 'viewer'
                    CHECK (
                        role IN (
                            'admin',
                            'analyst',
                            'viewer'
                        )
                    ),

                status VARCHAR(20) NOT NULL DEFAULT 'active'
                    CHECK (
                        status IN (
                            'active',
                            'inactive'
                        )
                    ),

                created_at TIMESTAMPTZ NOT NULL
                    DEFAULT CURRENT_TIMESTAMP,

                updated_at TIMESTAMPTZ NOT NULL
                    DEFAULT CURRENT_TIMESTAMP,

                last_login TIMESTAMPTZ
            );
        `);

        // =====================================================
        // 6. INVESTIGATION MANAGEMENT
        // =====================================================
        // Preserve existing alerts while adding investigation
        // fields to the threat_alerts table.
        await pool.query(`
            ALTER TABLE threat_alerts
                ADD COLUMN IF NOT EXISTS ip_address INET,
                ADD COLUMN IF NOT EXISTS category VARCHAR(50)
                    DEFAULT 'uncategorized',
                ADD COLUMN IF NOT EXISTS assigned_to INTEGER,
                ADD COLUMN IF NOT EXISTS resolution_notes TEXT,
                ADD COLUMN IF NOT EXISTS resolved_at TIMESTAMPTZ,
                ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ
                    DEFAULT CURRENT_TIMESTAMP;
        `);

        // Link investigation assignments to system users.
        // The constraint is added only if it does not exist.
        await pool.query(`
            DO $$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1
                    FROM pg_constraint
                    WHERE conname = 'fk_alert_assigned_user'
                      AND conrelid = 'threat_alerts'::regclass
                ) THEN
                    ALTER TABLE threat_alerts
                    ADD CONSTRAINT fk_alert_assigned_user
                    FOREIGN KEY (assigned_to)
                    REFERENCES system_users(id)
                    ON DELETE SET NULL;
                END IF;
            END
            $$;
        `);

        // =====================================================
        // 7. USER MANAGEMENT INDEXES
        // =====================================================
        await pool.query(`
            CREATE INDEX IF NOT EXISTS idx_system_users_role
            ON system_users(role);
        `);

        await pool.query(`
            CREATE INDEX IF NOT EXISTS idx_system_users_status
            ON system_users(status);
        `);

        // =====================================================
        // 8. INVESTIGATION INDEXES
        // =====================================================
        await pool.query(`
            CREATE INDEX IF NOT EXISTS idx_alerts_ip
            ON threat_alerts(ip_address);
        `);

        await pool.query(`
            CREATE INDEX IF NOT EXISTS idx_alerts_status
            ON threat_alerts(status);
        `);

        await pool.query(`
            CREATE INDEX IF NOT EXISTS idx_alerts_assigned
            ON threat_alerts(assigned_to);
        `);

        // =====================================================
        // 9. SECURITY MONITORING INDEXES
        // =====================================================
        await pool.query(`
            CREATE INDEX IF NOT EXISTS idx_events_ip_time
            ON login_events(ip_address, occurred_at);
        `);

        await pool.query(`
            CREATE INDEX IF NOT EXISTS idx_events_app
            ON login_events(application_id);
        `);

        await pool.query(`
            CREATE INDEX IF NOT EXISTS idx_alerts_app
            ON threat_alerts(application_id);
        `);

        // Additional index for brute-force detection
        await pool.query(`
            CREATE INDEX IF NOT EXISTS idx_events_app_ip_received
            ON login_events(
                application_id,
                ip_address,
                received_at
            )
            WHERE event_type = 'LOGIN_FAILURE';
        `);

        console.log(
            'API Sentinel database initialized successfully.'
        );

    } catch (error) {
        console.error(
            'Database initialization failed:',
            error
        );

        throw error;
    }
};

module.exports = initializeDatabase;
