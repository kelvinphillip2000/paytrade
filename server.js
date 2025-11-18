const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const path = require('path');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 7860;

// Get the correct directory path for Hugging Face
const projectRoot = process.cwd();

// Middleware (HuggingFace compatible)
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(projectRoot)); // Serve everything from root directory

// Session middleware with file storage for production
const FileStore = require('session-file-store')(session);
app.use(session({
    secret: process.env.SESSION_SECRET || 'huggingface-space-secret-key-' + crypto.randomBytes(32).toString('hex'),
    resave: false,
    saveUninitialized: false,
    store: new FileStore({
        path: path.join(projectRoot, 'sessions')
    }),
    cookie: { 
        secure: false,
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
}));

// JSON file for persistent user storage
const dataDir = path.join(projectRoot, 'data');
const usersFile = path.join(dataDir, 'users.json');
const tradesFile = path.join(dataDir, 'trades.json');
const withdrawalsFile = path.join(dataDir, 'withdrawals.json');

// Ensure data directory exists
if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
}

// Load data from JSON files
function loadUsers() {
    try {
        if (fs.existsSync(usersFile)) {
            const data = fs.readFileSync(usersFile, 'utf8');
            return JSON.parse(data);
        }
    } catch (error) {
        console.error('Error loading users:', error);
    }
    return [];
}

function loadTrades() {
    try {
        if (fs.existsSync(tradesFile)) {
            const data = fs.readFileSync(tradesFile, 'utf8');
            return JSON.parse(data);
        }
    } catch (error) {
        console.error('Error loading trades:', error);
    }
    return [];
}

function loadWithdrawals() {
    try {
        if (fs.existsSync(withdrawalsFile)) {
            const data = fs.readFileSync(withdrawalsFile, 'utf8');
            return JSON.parse(data);
        }
    } catch (error) {
        console.error('Error loading withdrawals:', error);
    }
    return [];
}

// Save data to JSON files
function saveUsers() {
    try {
        fs.writeFileSync(usersFile, JSON.stringify(users, null, 2));
        console.log('💾 Users saved to file. Total users:', users.length);
    } catch (error) {
        console.error('Error saving users:', error);
    }
}

function saveTrades() {
    try {
        fs.writeFileSync(tradesFile, JSON.stringify(trades, null, 2));
        console.log('💾 Trades saved to file. Total trades:', trades.length);
    } catch (error) {
        console.error('Error saving trades:', error);
    }
}

function saveWithdrawals() {
    try {
        fs.writeFileSync(withdrawalsFile, JSON.stringify(withdrawals, null, 2));
        console.log('💾 Withdrawals saved to file. Total withdrawals:', withdrawals.length);
    } catch (error) {
        console.error('Error saving withdrawals:', error);
    }
}

// Initialize data from files
let users = loadUsers();
let trades = loadTrades();
let withdrawals = loadWithdrawals();

// Add demo admin user if no users exist
if (users.length === 0) {
    const demoUser = {
        id: 1,
        account_id: 'ADMIN01',
        name: 'Demo User',
        email: 'demo@iqoptionsforex.com',
        phone: '+1234567890',
        plan: 'Gold Package',
        country: 'United States',
        bank: 'Demo Bank',
        account_name: 'Demo User',
        account_number: '123456789',
        ssn: '',
        pobox: '',
        token: 'demo-token',
        status: 1,
        date: new Date().toLocaleString(),
        password: '$2a$10$8K1p/a0dRTlR0dS1.2TkOuB6QnQzJf8VY9qXkZJ7nQrJvL5YfH6W', // password: demo123
        balance: '5000.00',
        profit: '1250.00'
    };
    users.push(demoUser);
    saveUsers();
    console.log('✅ Created demo user');
}

// Utility function to generate random IDs
function generateId(length = 6) {
    return crypto.randomBytes(Math.ceil(length / 2)).toString('hex').slice(0, length).toUpperCase();
}

// Generate transaction ID
function generateTransactionId() {
    return 'TRX' + Date.now().toString().slice(-9) + Math.random().toString(36).substr(2, 3).toUpperCase();
}

// Safe file sending function
function safeSendFile(res, filePath, fallbackPath = null) {
    const fullPath = path.join(projectRoot, filePath);
    
    if (fs.existsSync(fullPath)) {
        res.sendFile(fullPath);
    } else if (fallbackPath && fs.existsSync(path.join(projectRoot, fallbackPath))) {
        res.sendFile(path.join(projectRoot, fallbackPath));
    } else {
        res.status(404).send(`
            <html>
                <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px;">
                    <h2>Page Not Found</h2>
                    <p>The requested page could not be found.</p>
                    <p><a href="/">Return to Homepage</a></p>
                </body>
            </html>
        `);
    }
}

// Routes

// Serve main pages
app.get('/', (req, res) => {
    safeSendFile(res, 'index.html', 'index.php');
});

app.get('/about.php', (req, res) => {
    safeSendFile(res, 'about.php');
});

app.get('/packages.php', (req, res) => {
    safeSendFile(res, 'packages.php');
});

app.get('/terms.php', (req, res) => {
    safeSendFile(res, 'terms.php');
});

app.get('/successful_reg.php', (req, res) => {
    safeSendFile(res, 'successful_reg.php');
});

app.get('/success_recovery.php', (req, res) => {
    safeSendFile(res, 'success_recovery.php');
});

// Auth pages
app.get('/access/login.php', (req, res) => {
    safeSendFile(res, 'access/login.php', 'access/login.html');
});

app.get('/access/register.php', (req, res) => {
    safeSendFile(res, 'access/register.php', 'access/register.html');
});

app.get('/access/forget_password.php', (req, res) => {
    safeSendFile(res, 'access/forget_password.php', 'access/forget_password.html');
});

app.get('/access/adminlogin.php', (req, res) => {
    safeSendFile(res, 'access/adminlogin.php', 'access/adminlogin.html');
});

// Dashboard pages
app.get('/dashboard/home.php', requireAuth, (req, res) => {
    safeSendFile(res, 'dashboard/home.php', 'dashboard/home.html');
});

app.get('/dashboard/profile.php', requireAuth, (req, res) => {
    safeSendFile(res, 'dashboard/profile.php', 'dashboard/profile.html');
});

app.get('/dashboard/wallet.php', requireAuth, (req, res) => {
    safeSendFile(res, 'dashboard/wallet.php', 'dashboard/wallet.html');
});

app.get('/dashboard/transactions.php', requireAuth, (req, res) => {
    safeSendFile(res, 'dashboard/transactions.php', 'dashboard/transactions.html');
});

app.get('/dashboard/admin_dashboard.php', requireAdminAuth, (req, res) => {
    safeSendFile(res, 'dashboard/admin_dashboard.php', 'dashboard/admin_dashboard.html');
});

// API Routes

// Health check endpoint (HuggingFace compatible)
app.get("/api/health", (req, res) => {
    res.json({ 
        status: "OK", 
        timestamp: new Date().toISOString(),
        usersCount: users.length,
        tradesCount: trades.length,
        withdrawalsCount: withdrawals.length,
        storage: "json-file",
        environment: "huggingface"
    });
});

// User registration
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
        const existingUser = users.find(user => user.email === email);
        if (existingUser) {
            req.session.alertMsg = '<div class="alert alert-danger">Email already registered!</div>';
            return res.redirect('/access/register.php');
        }
        
        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);
        const accountId = generateId();
        const token = generateId(12);
        
        // Create new user
        const newUser = {
            id: users.length + 1,
            account_id: accountId,
            name: name,
            email: email,
            phone: '',
            plan: '',
            country: country,
            bank: '',
            account_name: '',
            account_number: '',
            ssn: '',
            pobox: '',
            token: token,
            status: 1, // Auto-verify for demo
            date: new Date().toLocaleString(),
            password: hashedPassword,
            balance: '0.00',
            profit: '0.00'
        };
        
        users.push(newUser);
        saveUsers();
        
        // Set session variables
        req.session.reg_name = name;
        req.session.reg_email = email;
        req.session.reg_client_id = accountId;
        
        res.redirect('/successful_reg.php');
        
    } catch (error) {
        console.error('Registration error:', error);
        req.session.alertMsg = '<div class="alert alert-danger">Registration failed. Please try again.</div>';
        res.redirect('/access/register.php');
    }
});

// User login
app.post('/controller/process_login.php', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        const user = users.find(u => u.email === email);
        
        if (!user) {
            req.session.alertMsg = '<div class="alert alert-danger">Invalid email or password!</div>';
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

// Admin login
app.post('/access/adminlogin.php', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        // Demo admin credentials
        const adminEmail = 'admin@iqoptionsforex.com';
        const adminPassword = 'admin123';
        
        if (email === adminEmail && password === adminPassword) {
            req.session.admin = adminEmail;
            req.session.admin_id = 1;
            req.session.admin_loggedin = true;
            res.redirect('/dashboard/admin_dashboard.php');
        } else {
            req.session.alertMsg = '<div class="alert alert-danger">Invalid admin credentials!</div>';
            res.redirect('/access/adminlogin.php');
        }
        
    } catch (error) {
        console.error('Admin login error:', error);
        req.session.alertMsg = '<div class="alert alert-danger">Admin login failed!</div>';
        res.redirect('/access/adminlogin.php');
    }
});

// Forgot password
app.post('/controller/process_forget_password.php', async (req, res) => {
    try {
        const { email } = req.body;
        
        const user = users.find(u => u.email === email);
        
        if (!user) {
            req.session.alertMsg = '<div class="alert alert-danger">Email not found!</div>';
            return res.redirect('/access/forget_password.php');
        }
        
        const reference_number = generateId(8);
        
        req.session.fullname = user.name;
        req.session.reference_number = reference_number;
        
        res.redirect('/success_recovery.php');
        
    } catch (error) {
        console.error('Forgot password error:', error);
        req.session.alertMsg = '<div class="alert alert-danger">Password recovery failed!</div>';
        res.redirect('/access/forget_password.php');
    }
});

// Contact form
app.post('/controller/process_contact.php', async (req, res) => {
    try {
        const { name, email, message } = req.body;
        
        // In a real app, you'd save this to a database
        console.log('Contact form submission:', { name, email, message });
        
        req.session.contactMsg = '<div class="alert alert-success">Thank you for your message! We will get back to you soon.</div>';
        res.redirect('/');
        
    } catch (error) {
        console.error('Contact form error:', error);
        req.session.contactMsg = '<div class="alert alert-danger">Failed to send message. Please try again.</div>';
        res.redirect('/');
    }
});

// API endpoints for dashboard data
app.get('/api/user/profile', requireAuth, async (req, res) => {
    try {
        const user = users.find(u => u.id === req.session.user.id);
        res.json(user || {});
    } catch (error) {
        console.error('Profile API error:', error);
        res.status(500).json({ error: 'Failed to fetch profile' });
    }
});

app.get('/api/user/trades', requireAuth, async (req, res) => {
    try {
        const userTrades = trades.filter(trade => trade.client_id === req.session.user.account_id)
                                .sort((a, b) => new Date(b.date) - new Date(a.date))
                                .slice(0, 10);
        res.json(userTrades);
    } catch (error) {
        console.error('Trades API error:', error);
        res.status(500).json({ error: 'Failed to fetch trades' });
    }
});

app.get('/api/user/withdrawals', requireAuth, async (req, res) => {
    try {
        const userWithdrawals = withdrawals.filter(w => w.account_id === req.session.user.account_id)
                                          .sort((a, b) => new Date(b.date) - new Date(a.date));
        res.json(userWithdrawals);
    } catch (error) {
        console.error('Withdrawals API error:', error);
        res.status(500).json({ error: 'Failed to fetch withdrawals' });
    }
});

// Update user profile
app.post('/api/user/update-profile', requireAuth, async (req, res) => {
    try {
        const { phone, bank, account_name, account_number, ssn, pobox } = req.body;
        const userIndex = users.findIndex(u => u.id === req.session.user.id);
        
        if (userIndex !== -1) {
            users[userIndex].phone = phone || '';
            users[userIndex].bank = bank || '';
            users[userIndex].account_name = account_name || '';
            users[userIndex].account_number = account_number || '';
            users[userIndex].ssn = ssn || '';
            users[userIndex].pobox = pobox || '';
            
            saveUsers();
            
            // Update session
            req.session.user = users[userIndex];
            
            res.json({ success: true, message: 'Profile updated successfully!' });
        } else {
            res.status(404).json({ success: false, message: 'User not found' });
        }
    } catch (error) {
        console.error('Update profile error:', error);
        res.status(500).json({ success: false, message: 'Failed to update profile' });
    }
});

// Create demo trade (for testing)
app.post('/api/demo/trade', requireAuth, async (req, res) => {
    try {
        const { amount, plan } = req.body;
        const user = users.find(u => u.id === req.session.user.id);
        
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }
        
        const profit = parseFloat(amount) * 0.1; // 10% profit for demo
        const newTrade = {
            id: trades.length + 1,
            date: new Date().toLocaleString(),
            transact_id: generateTransactionId(),
            client_id: user.account_id,
            status: 'Completed',
            balance: (parseFloat(user.balance || 0) + parseFloat(amount) + profit).toFixed(2),
            profit: profit.toFixed(2),
            bonus: '0'
        };
        
        trades.push(newTrade);
        saveTrades();
        
        // Update user balance
        const userIndex = users.findIndex(u => u.id === req.session.user.id);
        users[userIndex].balance = newTrade.balance;
        users[userIndex].profit = (parseFloat(user.profit || 0) + profit).toFixed(2);
        saveUsers();
        
        req.session.user = users[userIndex];
        
        res.json({ 
            success: true, 
            trade: newTrade,
            message: 'Trade completed successfully!' 
        });
        
    } catch (error) {
        console.error('Demo trade error:', error);
        res.status(500).json({ success: false, message: 'Trade failed' });
    }
});

// Logout
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

// Serve any PHP file as static (fallback)
app.get('*.php', (req, res) => {
    const filePath = path.join(projectRoot, req.path);
    if (fs.existsSync(filePath)) {
        res.sendFile(filePath);
    } else {
        res.status(404).send(`
            <html>
                <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px;">
                    <h2>Page Not Found</h2>
                    <p>The requested page could not be found.</p>
                    <p><a href="/">Return to Homepage</a></p>
                </body>
            </html>
        `);
    }
});

// 404 handler for API routes
app.use('/api/*', (req, res) => {
    res.status(404).json({
        success: false,
        message: 'API endpoint not found'
    });
});

// Global error handler
app.use((err, req, res, next) => {
    console.error('Server error:', err);
    res.status(500).send(`
        <html>
            <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px;">
                <h2>Server Error</h2>
                <p>Something went wrong. Please try again later.</p>
                <p><a href="/">Return to Homepage</a></p>
            </body>
        </html>
    `);
});

// Start server (HuggingFace compatible)
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 iqoptions forex Server running on port ${PORT}`);
    console.log(`📁 Working directory: ${projectRoot}`);
    console.log(`📊 Loaded ${users.length} users from storage`);
    console.log(`📈 Loaded ${trades.length} trades from storage`);
    console.log(`💰 Loaded ${withdrawals.length} withdrawals from storage`);
    console.log(`🌐 Main Website: http://localhost:${PORT}`);
    console.log(`🔐 Login: http://localhost:${PORT}/access/login.php`);
    console.log(`📱 Register: http://localhost:${PORT}/access/register.php`);
    console.log(`🔍 Health check: http://localhost:${PORT}/api/health`);
    console.log('✅ Server is ready for HuggingFace Space!');
});

// Export for HuggingFace
module.exports = app;
