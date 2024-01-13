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
    const hashedPassword = await bcrypt.hash(password, 10);

    db.run('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword], (err) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.send('<p>Registration successful!</p>');
    });
});

// Route for user login with parameterized query
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const query = 'SELECT * FROM users WHERE username=?';

    db.get(query, [username], async (err, row) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }

        if (row) {
            const isPasswordValid = await bcrypt.compare(password, row.password);

            if (isPasswordValid) {
                return res.json({ message: 'Login successful!' });
            }
        }

        return res.status(401).json({ error: 'Invalid credentials' });
    });
});

// Sanitize user input to prevent XSS
app.get('/search', (req, res) => {
    const query = sanitizeInput(req.query.q);
    res.send(`<p>You searched for: ${query}</p>`);
});

app.get('/profile', (req, res) => {
    const username = sanitizeInput(req.query.username);
    res.send(`<p>Hello, ${username}!</p>`);
});

app.post('/post', (req, res) => {
    const postContent = sanitizeInput(req.body.content);
    db.run('INSERT INTO posts (content) VALUES (?)', [postContent], (err) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.send('<p>Post created successfully!</p>');
    });
});

// Implement authentication middleware to protect sensitive routes
const authenticateUser = (req, res, next) => {
    // Implement your authentication logic here
    // For example, you can use tokens, sessions, or JWTs
    const isAuthenticated = true; // Replace with your authentication check
    if (isAuthenticated) {
        return next();
    } else {
        return res.status(401).json({ error: 'Unauthorized' });
    }
};

// Secure the /admin route with authentication middleware
app.get('/admin', authenticateUser, (req, res) => {
    // Only authenticated users can access this route
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

// Function to sanitize user input to prevent XSS
function sanitizeInput(input) {
    // Implement your sanitation logic here
    // You can use libraries like DOMPurify or create your own sanitation methods
    return input;
}
