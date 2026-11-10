const { Pool } = require('pg');
require('dotenv').config();

console.log("Checking DATABASE_URL:", process.env.DATABASE_URL ? "Loaded successfully!" : "UNDEFINED!");

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    }
});

// Test the connection immediately on startup
pool.query('SELECT NOW()')
    .then(res => {
        console.log('PostgreSQL connected successfully at:', res.rows[0].now);
    })
    .catch(err => {
        console.error('CRITICAL: Failed to connect to PostgreSQL:', err.message);
    });

pool.on('error', (error) => {
    console.error('Unexpected database error on idle client:', error);
});

module.exports = pool;