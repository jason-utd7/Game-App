const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const session = require('express-session');
const csurf = require('csurf');
const helmet = require('helmet');
const morgan = require('morgan');
const bodyParser = require('body-parser');
const path = require('path');
const bcrypt = require('bcrypt');
const he = require('he'); // Import HTML entities library
const crypto = require('crypto');
const SQLiteStore = require('connect-sqlite3')(session);

const app = express();
const port = 3000;
const nonce = crypto.randomBytes(16).toString('base64');

app.use(
  session({
    store: new SQLiteStore({
      db: 'sessions.db',
      concurrentDB: true,
    }),
    secret: 'my_secret_key',
    resave: false,
    saveUninitialized: true,
    cookie: {
      secure: true, // Set to true for HTTPS only
      httpOnly: true,
      maxAge: 60000,
    },
  })
);

// Set Content-Security-Policy using helmet
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'none'"],
        scriptSrc: ["'self'", `nonce-${nonce}`],
        imgSrc: ["'self'", 'data:'],
      },
    },
  })
);

const db = new sqlite3.Database('database.db');
db.run('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)');

app.use(helmet()); // Enhances security by setting various HTTP headers
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(csurf()); // CSRF protection middleware
app.use(morgan('combined')); // HTTP request logger
app.use(express.static(__dirname));

// Content Security Policy (CSP) header
app.use((req, res, next) => {
  res.setHeader('Content-Security-Policy', `default-src 'none'; script-src 'self' 'nonce-${nonce}'; img-src 'self' data:;`);
  res.locals.nonce = nonce; // Make nonce available to templates or routes
  next();
});

// Insecure Version
app.post('/insecure/login', (req, res) => {
  const { username, password } = req.body;
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

app.get('/register', (req, res) => {
  res.sendFile(path.join(__dirname, 'register.html'));
});

app.get('/explore', (req, res) => {
  res.sendFile(path.join(__dirname, 'explore.html'));
});

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'admin.html'));
});

// XSS Vulnerabilities
app.get('/insecure/search', (req, res) => {
  const query = req.query.q;
  // Sanitize and escape user input to prevent XSS
  const sanitizedQuery = he.encode(query);
  res.send(`<p>You searched for: ${sanitizedQuery}</p>`);
});

app.get('/insecure/profile', (req, res) => {
  const username = req.query.username;
  res.send(`<p>Hello, ${username}!</p>`);
});

app.post('/insecure/post', (req, res) => {
  const postContent = req.body.content;
  // TODO: Sanitize and validate user-generated content before storing in the database
  db.run(`INSERT INTO posts (content) VALUES ('${postContent}')`);
  res.send('<p>Post created successfully!</p>');
});

// Sensitive Data Exposure
app.post('/insecure/register', async (req, res) => {
  const { username, password } = req.body;

  try {
    // Hash and salt the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Store the hashed password in the database
    db.run('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword]);

    res.send('<p>Registration successful!</p>');
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Insecure route for demonstration purposes
app.post('/insecure/insertUser', (req, res) => {
  const { username, password } = req.body;

  // Hash and salt the password (similar to what you do during user registration)
  const hashedPassword = bcrypt.hashSync(password, 10);

  // Insert the new user into the 'users' table
  const insertQuery = 'INSERT INTO users (username, password) VALUES (?, ?)';
  db.run(insertQuery, [username, hashedPassword], (err) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    return res.json({ message: 'User inserted into the database' });
  });
});

// Secure Version

// CSRF Protection
app.get('/secure/dashboard', csurf(), (req, res) => {
  res.send(`<form action="/secure/update" method="post">
                <input type="text" name="data" value="New data">
                <input type="hidden" name="_csrf" value="${req.csrfToken()}">
                <button type="submit">Update Data</button>
              </form>`);
});

app.post('/secure/update', csurf(), (req, res) => {
  if (!req.session || !req.session.secret || req.body._csrf !== req.csrfToken()) {
    return res.status(403).send('CSRF token invalid');
  }

  const newData = req.body.data;
  // TODO: Process the request securely, avoiding vulnerabilities
  res.send('Data updated successfully!');
});

// Proper Session Management
app.post('/secure/login', (req, res) => {
  // TODO: Handle secure login and session management
  res.send('Secure login completed!');
});

// Routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Error-handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Internal Server Error' });
});

// Start the server
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
