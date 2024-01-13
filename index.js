const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const helmet = require('helmet');
const session = require('express-session');
const morgan = require('morgan');
const csurf = require('csurf');
const path = require('path');

const app = express();
const port = 3000;

const db = new sqlite3.Database('database.db');
db.run('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)');
db.run('CREATE TABLE IF NOT EXISTS posts (id INTEGER PRIMARY KEY, content TEXT)');

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
    secret: 'your_secret_key',
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
app.post('/register', async (req, res) => {
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
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    // Insecure: No parameterization, susceptible to SQL injection
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
