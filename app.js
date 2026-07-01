require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const argon2 = require('argon2');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);
const validator = require('validator');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();
app.use(express.static('public'));

// 1. Security Headers & Middleware
app.use(helmet()); // Sets protective HTTP headers
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// 2. Database Connection
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
});

// 3. Secure Session Management
app.use(session({
    store: new pgSession({
        pool: pool,
        tableName: 'session'
    }),
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    name: '__Host-sessId', // Mitigates session fixation / cookie tossing
    cookie: {
        httpOnly: true, // Prevents XSS from reading the cookie
        secure: process.env.NODE_ENV === 'production', // Requires HTTPS in prod
        sameSite: 'lax', // Protects against CSRF
        maxAge: 1000 * 60 * 60 * 2 // 2 hours
    }
}));

// 4. Rate Limiting (Brute Force Protection)
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 20, // Limit each IP to 20 requests per window
    message: 'Too many login or registration attempts. Please try again later.'
});

// Auth Middleware to protect routes
const isAuthenticated = (req, res, next) => {
    if (req.session && req.session.userId) {
        return next();
    }
    return res.status(401).json({ error: 'Unauthorized. Please log in.' });
};

// --- ROUTES ---

// A. User Registration
app.post('/api/register', authLimiter, async (req, res) => {
    const { email, password } = req.body;

    // Basic Input Validation
    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required.' });
    }
    if (!validator.isEmail(email)) {
        return res.status(400).json({ error: 'Invalid email format.' });
    }
    if (!validator.isLength(password, { min: 8, max: 64 })) {
        return res.status(400).json({ error: 'Password must be between 8 and 64 characters.' });
    }

    try {
        // Hash password using Argon2id
        const hashedPassword = await argon2.hash(password, {
            type: argon2.argon2id
        });

        // SQL Injection Protection: Parameterized Query ($1, $2)
        const queryText = 'INSERT INTO users(email, password_hash) VALUES($1, $2) RETURNING id';
        const result = await pool.query(queryText, [email.toLowerCase().trim(), hashedPassword]);

        res.status(201).json({ message: 'User registered successfully!', userId: result.rows[0].id });
    } catch (err) {
        if (err.code === '23505') { // PostgreSQL unique violation error code
            return res.status(400).json({ error: 'Email is already registered.' });
        }
        console.error(err);
        res.status(500).json({ error: 'Internal server error.' });
    }
});

// B. User Login
app.post('/api/login', authLimiter, async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required.' });
    }

    try {
        // SQL Injection Protection: Parameterized Query
        const queryText = 'SELECT * FROM users WHERE email = $1';
        const result = await pool.query(queryText, [email.toLowerCase().trim()]);

        if (result.rows.length === 0) {
            // Generic error message to prevent username enumeration
            return res.status(401).json({ error: 'Invalid email or password.' });
        }

        const user = result.rows[0];

        // Verify the Argon2 hash
        const validPassword = await argon2.verify(user.password_hash, password);
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid email or password.' });
        }

        // Establish Session
        req.session.userId = user.id;
        req.session.email = user.email;

        res.json({ message: 'Login successful!' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal server error.' });
    }
});

// C. User Logout
app.post('/api/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.status(500).json({ error: 'Could not log out.' });
        }
        res.clearCookie('__Host-sessId');
        res.json({ message: 'Logout successful!' });
    });
});

// D. Dashboard (Protected Route)
app.get('/api/dashboard', isAuthenticated, (req, res) => {
    res.json({ 
        message: `Welcome to your secure dashboard, user #${req.session.userId}!`,
        email: req.session.email 
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Secure server running on port ${PORT}`));