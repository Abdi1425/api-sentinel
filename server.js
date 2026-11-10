
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const session = require('express-session');
const statsRoutes = require('./routes/statsRoutes');
require('dotenv').config();

// Database
const pool = require('./config/db');
const initializeDatabase = require('./config/initDb');

// Routes
const applicationRoutes = require('./routes/applicationRoutes');
const eventRoutes = require('./routes/eventRoutes');
const alertRoutes = require('./routes/alertRoutes');
const authRoutes = require('./routes/authRoutes');

// Initialize Express
const app = express();

// 1. Security and request middleware
app.use(helmet());
app.use(cors());
app.use(express.json());
app.use('/api/stats', statsRoutes);


// 2. Validate session configuration
if (!process.env.SESSION_SECRET) {
    throw new Error('SESSION_SECRET is missing from .env');
}

// 3. Session middleware
// Must be registered BEFORE authentication routes
app.use(session({
    name: 'sentinel.sid',
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: 60 * 60 * 1000
    }
}));

// 4. Frontend
app.use(express.static('public'));

// 5. API routes
app.use('/api/auth', authRoutes);
app.use('/api/applications', applicationRoutes);
app.use('/api/events', eventRoutes);
app.use('/api/alerts', alertRoutes);

// 6. Database health check
app.get('/api/health', async (req, res) => {
    try {
        await pool.query('SELECT NOW()');

        res.status(200).json({
            status: 'online',
            database: 'connected',
            project: 'API Sentinel'
        });

    } catch (error) {
        console.error('DATABASE ERROR:', error);

        res.status(500).json({
            status: 'error',
            message: 'Database connection failed'
        });
    }
});

// 7. Start server
const PORT = process.env.PORT || 3000;

const startServer = async () => {
    try {
        await initializeDatabase();

        app.listen(PORT, () => {
            console.log(
                `API Sentinel running at http://localhost:${PORT}`
            );
        });

    } catch (error) {
        console.error('Failed to start application:', error);
        process.exit(1);
    }
};

startServer();
