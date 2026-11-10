const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
require('dotenv').config();

const pool = require('./config/db');

const app = express();

app.use(helmet());
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

app.get('/api/health', async (req, res) => {
    try {
        await pool.query('SELECT NOW()');

        res.json({
            status: 'online',
            database: 'connected',
            project: 'API Sentinel'
        });
    } catch (error) {
        res.status(500).json({
            status: 'error',
            message: 'Database connection failed'
        });
    }
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`API Sentinel running at http://localhost:${PORT}`);
});