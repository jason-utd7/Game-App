const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const helmet = require('helmet');
const session = require('express-session');
const morgan = require('morgan');
const csurf = require('csurf');
const { check, validationResult } = require('express-validator');
const path = require('path');

const app = express();
const port = 3000;

const db = new sqlite3.Database('database.db');
db.run('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)');
db.run('CREATE TABLE IF NOT EXISTS posts (id INTEGER PRIMARY KEY, content TEXT)');

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
    secret: 'IrelandForever123#',
    resave: false,
    saveUninitialized: true,
    cookie: {
        secure: true, // Set to true if using HTTPS
        httpOnly: true,
        maxAge: 60000, // Set an appropriate session timeout
    },
}));
app.use(csurf());
app.use(morgan('combined'));
app.use(helmet.contentSecurityPolicy({
    directives: {
        defaultSrc: ["'none'"],
        imgSrc: ["'self'", 'data:']
    }
}));

// Route to handle user registration securely
app.post('/register', [
    check('username').notEmpty().trim().escape(),
    check('password').notEmpty().trim().escape(),
], async (req, res) => {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { username, password } = req.body;

    // Insecure: Store password in plain text without hashing
    db.run('INSERT INTO users (username, password) VALUES (?, ?)', [username, password], (err) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.send('<p>Registration successful!</p>');
    });
});

// Route for user login with parameterized query
app.post('/login', [
    check('username').notEmpty().trim().escape(),
    check('password').notEmpty().trim().escape(),
], (req, res) => {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { username, password } = req.body;

    // Use parameterized query to prevent SQL injection
    const query = 'SELECT * FROM users WHERE username = ? AND password = ?';
    
    db.all(query, [username, password], (err, rows) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }

        if (rows.length > 0) {
            return res.json({ message: 'Login successful!' });
        } else {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
    });
});

// Intentionally vulnerable to XSS
app.get('/search', (req, res) => {
    const query = req.query.q;

    // Insecure: Directly inject user input into the HTML response without sanitization
    res.send(`<p>You searched for: ${query}</p><script>alert('XSS Vulnerability');</script>`);
});

// No authentication check for /admin route
app.get('/admin', (req, res) => {
    // Insecure: No proper authentication check
    db.all('SELECT id, username FROM users', (err, rows) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }

        return res.json(rows);
    });
});

// Sanitize user input to prevent XSS
app.get('/search', [
    check('q').notEmpty().trim().escape(),
], (req, res) => {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const query = sanitizeInput(req.query.q);
    res.send(`<p>You searched for: ${query}</p>`);
});

app.get('/profile', [
    check('username').notEmpty().trim().escape(),
], (req, res) => {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const username = sanitizeInput(req.query.username);
    res.send(`<p>Hello, ${username}!</p>`);
});

app.post('/post', [
    check('content').notEmpty().trim().escape(),
], (req, res) => {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const postContent = sanitizeInput(req.body.content);
    db.run('INSERT INTO posts (content) VALUES (?)', [postContent], (err) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }

        return res.json({ message: 'Post created successfully!' });
    });
});

// SQL Injection Testing
app.get('/test-sql-injection', (req, res) => {
    const username = req.query.username;
    const password = req.query.password;

    // Insecure: Constructing SQL query without proper validation
    const query = `SELECT * FROM users WHERE username='${username}' AND password='${password}'`;

    db.all(query, (err, rows) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }

        if (rows.length > 0) {
            return res.json({ message: 'Login successful!' });
        } else {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
    });
});

// XSS Testing
app.get('/test-xss', (req, res) => {
    const query = req.query.q;

    // Insecure: Directly inject user input into the HTML response without sanitization
    res.send(`<p>You searched for: ${query}</p>`);
});

// Logout route
app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.send('<p>Logout successful!</p>');
    });
});

// Start the server
app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
});
