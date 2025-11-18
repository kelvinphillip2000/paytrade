const express = require('express');
const session = require('express-session');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const path = require('path');
const bodyParser = require('body-parser');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
    secret: 'your-secret-key-change-in-production',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }
}));

// Database configuration
const dbConfig = {
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASS || '',
    database: process.env.DB_NAME || 'iqoptions_forex'
};

// Utility function to generate random IDs
function generateId(length = 6) {
    return crypto.randomBytes(Math.ceil(length / 2)).toString('hex').slice(0, length).toUpperCase();
}

// Database connection middleware
app.use(async (req, res, next) => {
    try {
        req.db = await mysql.createConnection(dbConfig);
        next();
    } catch (error) {
        console.error('Database connection error:', error);
        res.status(500).send('Database connection error');
    }
});

// Serve static files from various directories
app.use('/css', express.static(path.join(__dirname, 'css')));
app.use('/js', express.static(path.join(__dirname, 'js')));
app.use('/img', express.static(path.join(__dirname, 'img')));
app.use('/fonts', express.static(path.join(__dirname, 'fonts')));
app.use('/access/css', express.static(path.join(__dirname, 'access/css')));
app.use('/access/fonts', express.static(path.join(__dirname, 'access/fonts')));
app.use('/access/js', express.static(path.join(__dirname, 'access/js')));
app.use('/dashboard/plugins', express.static(path.join(__dirname, 'dashboard/plugins')));

// Template engine setup for dynamic content
app.engine('html', require('ejs').renderFile);
app.set('view engine', 'html');
app.set('views', path.join(__dirname));

// Routes

// Home page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// About page
app.get('/about.php', (req, res) => {
    res.sendFile(path.join(__dirname, 'about.php'));
});

// Packages page
app.get('/packages.php', (req, res) => {
    res.sendFile(path.join(__dirname, 'packages.php'));
});

// Terms page
app.get('/terms.php', (req, res) => {
    res.sendFile(path.join(__dirname, 'terms.php'));
});

// Login page
app.get('/access/login.php', (req, res) => {
    res.sendFile(path.join(__dirname, 'access/login.html'));
});

// Register page
app.get('/access/register.php', (req, res) => {
    res.sendFile(path.join(__dirname, 'access/register.html'));
});

// Forgot password page
app.get('/access/forget_password.php', (req, res) => {
    res.sendFile(path.join(__dirname, 'access/forget_password.html'));
});

// Admin login page
app.get('/access/adminlogin.php', (req, res) => {
    res.sendFile(path.join(__dirname, 'access/adminlogin.html'));
});

// Process registration
app.post('/controller/registration.php', async (req, res) => {
    try {
        const { name, email, country, password, cpassword, terms } = req.body;
        
        if (password !== cpassword) {
            req.session.alertMsg = '<div class="alert alert-danger">Passwords do not match!</div>';
            return res.redirect('/access/register.php');
        }
        
        if (!terms) {
            req.session.alertMsg = '<div class="alert alert-danger">You must accept the terms and conditions!</div>';
            return res.redirect('/access/register.php');
        }
        
        // Check if email already exists
        const [existingUsers] = await req.db.execute('SELECT * FROM members WHERE email = ?', [email]);
        
        if (existingUsers.length > 0) {
            req.session.alertMsg = '<div class="alert alert-danger">Email already registered!</div>';
            return res.redirect('/access/register.php');
        }
        
        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);
        const accountId = generateId();
        const token = generateId(12);
        
        // Insert new user
        await req.db.execute(
            'INSERT INTO members (account_id, name, email, country, password, token, status, date) VALUES (?, ?, ?, ?, ?, ?, 0, ?)',
            [accountId, name, email, country, hashedPassword, token, new Date().toLocaleString()]
        );
        
        // Set session variables for email verification
        req.session.reg_name = name;
        req.session.reg_email = email;
        req.session.reg_client_id = accountId;
        req.session.reg_token = `https://iqoptionsforex.com/controller/verification.php?token=${token}`;
        
        res.redirect('/successful_reg.php');
        
    } catch (error) {
        console.error('Registration error:', error);
        req.session.alertMsg = '<div class="alert alert-danger">Registration failed. Please try again.</div>';
        res.redirect('/access/register.php');
    }
});

// Process login
app.post('/controller/process_login.php', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        const [users] = await req.db.execute('SELECT * FROM members WHERE email = ?', [email]);
        
        if (users.length === 0) {
            req.session.alertMsg = '<div class="alert alert-danger">Invalid email or password!</div>';
            return res.redirect('/access/login.php');
        }
        
        const user = users[0];
        
        // Check if account is verified
        if (user.status === 0) {
            req.session.alertMsg = '<div class="alert alert-danger">Please verify your email address first!</div>';
            return res.redirect('/access/login.php');
        }
        
        // Verify password
        const isValidPassword = await bcrypt.compare(password, user.password);
        
        if (!isValidPassword) {
            req.session.alertMsg = '<div class="alert alert-danger">Invalid email or password!</div>';
            return res.redirect('/access/login.php');
        }
        
        // Set session
        req.session.user = user;
        req.session.loggedin = true;
        
        res.redirect('/dashboard/home.php');
        
    } catch (error) {
        console.error('Login error:', error);
        req.session.alertMsg = '<div class="alert alert-danger">Login failed. Please try again.</div>';
        res.redirect('/access/login.php');
    }
});

// Process admin login
app.post('/access/adminlogin.php', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        const [admins] = await req.db.execute('SELECT * FROM admin WHERE email = ? AND password = ?', [email, password]);
        
        if (admins.length === 0) {
            req.session.alertMsg = '<div class="alert alert-danger">Invalid admin credentials!</div>';
            return res.redirect('/access/adminlogin.php');
        }
        
        const admin = admins[0];
        
        req.session.admin = admin.email;
        req.session.admin_id = admin.id;
        req.session.admin_loggedin = true;
        
        res.redirect('/dashboard/admin_dashboard.php');
        
    } catch (error) {
        console.error('Admin login error:', error);
        req.session.alertMsg = '<div class="alert alert-danger">Admin login failed!</div>';
        res.redirect('/access/adminlogin.php');
    }
});

// Process forgot password
app.post('/controller/process_forget_password.php', async (req, res) => {
    try {
        const { email } = req.body;
        
        const [users] = await req.db.execute('SELECT * FROM members WHERE email = ?', [email]);
        
        if (users.length === 0) {
            req.session.alertMsg = '<div class="alert alert-danger">Email not found!</div>';
            return res.redirect('/access/forget_password.php');
        }
        
        const user = users[0];
        const reference_number = generateId(8);
        
        // In a real application, you would send an email here
        // For now, we'll just set session variables
        
        req.session.fullname = user.name;
        req.session.reference_number = reference_number;
        
        res.redirect('/success_recovery.php');
        
    } catch (error) {
        console.error('Forgot password error:', error);
        req.session.alertMsg = '<div class="alert alert-danger">Password recovery failed!</div>';
        res.redirect('/access/forget_password.php');
    }
});

// Process contact form
app.post('/controller/process_contact.php', async (req, res) => {
    try {
        const { name, email, message } = req.body;
        
        // Here you would typically save the contact form data to database
        // and/or send an email notification
        
        req.session.contactMsg = '<div class="alert alert-success">Thank you for your message! We will get back to you soon.</div>';
        res.redirect('/');
        
    } catch (error) {
        console.error('Contact form error:', error);
        req.session.contactMsg = '<div class="alert alert-danger">Failed to send message. Please try again.</div>';
        res.redirect('/');
    }
});

// Dashboard routes (protected)
app.get('/dashboard/home.php', requireAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'dashboard/home.html'));
});

app.get('/dashboard/profile.php', requireAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'dashboard/profile.html'));
});

app.get('/dashboard/wallet.php', requireAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'dashboard/wallet.html'));
});

app.get('/dashboard/transactions.php', requireAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'dashboard/transactions.html'));
});

// Admin dashboard routes
app.get('/dashboard/admin_dashboard.php', requireAdminAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'dashboard/admin_dashboard.html'));
});

// Success pages
app.get('/successful_reg.php', (req, res) => {
    if (!req.session.reg_name) {
        return res.redirect('/access/register.php');
    }
    res.sendFile(path.join(__dirname, 'successful_reg.html'));
});

app.get('/success_recovery.php', (req, res) => {
    if (!req.session.fullname) {
        return res.redirect('/access/forget_password.php');
    }
    res.sendFile(path.join(__dirname, 'success_recovery.html'));
});

// Logout routes
app.get('/controller/logout.php', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

// Middleware to require authentication
function requireAuth(req, res, next) {
    if (req.session.loggedin) {
        next();
    } else {
        res.redirect('/access/login.php');
    }
}

// Middleware to require admin authentication
function requireAdminAuth(req, res, next) {
    if (req.session.admin_loggedin) {
        next();
    } else {
        res.redirect('/access/adminlogin.php');
    }
}

// API endpoints for dashboard data
app.get('/api/user/profile', requireAuth, async (req, res) => {
    try {
        const [users] = await req.db.execute('SELECT * FROM members WHERE id = ?', [req.session.user.id]);
        res.json(users[0] || {});
    } catch (error) {
        console.error('Profile API error:', error);
        res.status(500).json({ error: 'Failed to fetch profile' });
    }
});

app.get('/api/user/trades', requireAuth, async (req, res) => {
    try {
        const [trades] = await req.db.execute(
            'SELECT * FROM trades WHERE client_id = ? ORDER BY date DESC LIMIT 10',
            [req.session.user.account_id]
        );
        res.json(trades);
    } catch (error) {
        console.error('Trades API error:', error);
        res.status(500).json({ error: 'Failed to fetch trades' });
    }
});

app.get('/api/user/withdrawals', requireAuth, async (req, res) => {
    try {
        const [withdrawals] = await req.db.execute(
            'SELECT * FROM withrawals WHERE account_id = ? ORDER BY date DESC',
            [req.session.user.account_id]
        );
        res.json(withdrawals);
    } catch (error) {
        console.error('Withdrawals API error:', error);
        res.status(500).json({ error: 'Failed to fetch withdrawals' });
    }
});

// Start server
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`Visit: http://localhost:${PORT}`);
});

// Graceful shutdown
process.on('SIGINT', async () => {
    console.log('\nShutting down server...');
    process.exit(0);
});
