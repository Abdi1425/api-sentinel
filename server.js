
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const session = require('express-session');
const path = require('path');
require('dotenv').config();

// ========================================
// DATABASE
// ========================================

const pool = require('./config/db');
const initializeDatabase = require('./config/initDb');

// ========================================
// ROUTES
// ========================================

const applicationRoutes = require('./routes/applicationRoutes');
const eventRoutes = require('./routes/eventRoutes');
const alertRoutes = require('./routes/alertRoutes');
const authRoutes = require('./routes/authRoutes');
const statsRoutes = require('./routes/statsRoutes');
const investigationRoutes = require('./routes/investigationRoutes');
const userRoutes = require('./routes/userRoutes');

// ========================================
// EXPRESS APPLICATION
// ========================================

const app = express();
const publicDirectory = path.join(__dirname, 'public');

// ========================================
// SECURITY MIDDLEWARE
// ========================================

app.disable('x-powered-by');

app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '100kb' }));

if (!process.env.SESSION_SECRET) {
    throw new Error('SESSION_SECRET is missing from .env');
}

// ========================================
// SESSION CONFIGURATION
// ========================================

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

// ========================================
// PAGE AUTHENTICATION
// ========================================

async function requirePageAuth(req, res, next) {
    try {
        const userId = req.session?.userId;

        // Database-backed user
        if (Number.isInteger(userId)) {
            const result = await pool.query(
                `SELECT id, username, role, status
                 FROM system_users
                 WHERE id = $1`,
                [userId]
            );

            const user = result.rows[0];

            if (!user || user.status !== 'active') {
                return res.redirect('/login.html');
            }

            if (!['admin', 'analyst', 'viewer'].includes(user.role)) {
                return res.status(403).send('Access denied');
            }

            req.pageUser = user;
            return next();
        }

        // Environment administrator
        if (
            userId === null &&
            req.session?.isAdmin === true &&
            req.session?.role === 'admin' &&
            req.session?.username === process.env.ADMIN_USERNAME
        ) {
            req.pageUser = {
                id: null,
                username: req.session.username,
                role: 'admin'
            };

            return next();
        }

        return res.redirect('/login.html');

    } catch (error) {
        console.error('Page authentication error:', error);

        return res.status(500).send(
            'Unable to verify authentication'
        );
    }
}

// ========================================
// ADMIN PAGE AUTHORIZATION
// ========================================

function requireAdminPage(req, res, next) {
    if (req.pageUser?.role !== 'admin') {
        return res.status(403).send(
            'Access denied: administrator privileges required'
        );
    }

    next();
}

// ========================================
// PUBLIC LOGIN PAGE
// ========================================

app.get('/login.html', (req, res) => {
    res.sendFile(path.join(publicDirectory, 'login.html'));
});

// ========================================
// PROTECTED DASHBOARD PAGES
// ========================================

app.get(
    ['/', '/index.html'],
    requirePageAuth,
    (req, res) => {
        res.set('Cache-Control', 'no-store');

        res.sendFile(
            path.join(publicDirectory, 'index.html')
        );
    }
);

app.get(
    '/investigations.html',
    requirePageAuth,
    (req, res) => {
        res.set('Cache-Control', 'no-store');

        res.sendFile(
            path.join(publicDirectory, 'investigations.html')
        );
    }
);

app.get(
    '/users.html',
    requirePageAuth,
    requireAdminPage,
    (req, res) => {
        res.set('Cache-Control', 'no-store');

        res.sendFile(
            path.join(publicDirectory, 'users.html')
        );
    }
);

// ========================================
// STATIC ASSETS
// ========================================

// Allow CSS, JavaScript and images to load.
// HTML documents are served only by explicit routes above.
app.use(express.static(publicDirectory, {
    index: false,
    dotfiles: 'deny',
    setHeaders: (res, filePath) => {
        res.setHeader('X-Content-Type-Options', 'nosniff');

        if (path.extname(filePath).toLowerCase() === '.html') {
            res.setHeader('Cache-Control', 'no-store');
        }
    }
}));

// Block other direct HTML requests.
app.use((req, res, next) => {
    if (
        req.method === 'GET' &&
        req.path.toLowerCase().endsWith('.html')
    ) {
        return res.status(404).send('Page not found');
    }

    next();
});

// ========================================
// API ROUTES
// ========================================

app.use('/api/auth', authRoutes);
app.use('/api/applications', applicationRoutes);
app.use('/api/events', eventRoutes);
app.use('/api/alerts', alertRoutes);
app.use('/api/stats', statsRoutes);
app.use('/api/investigations', investigationRoutes);
app.use('/api/users', userRoutes);

// ========================================
// DATABASE HEALTH CHECK
// ========================================

app.get('/api/health', async (req, res) => {
    try {
        await pool.query('SELECT NOW()');

        return res.status(200).json({
            status: 'online',
            database: 'connected',
            project: 'API Sentinel'
        });

    } catch (error) {
        console.error('DATABASE ERROR:', error);

        return res.status(500).json({
            status: 'error',
            message: 'Database connection failed'
        });
    }
});

// ========================================
// START SERVER
// ========================================

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
