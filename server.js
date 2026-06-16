const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const path = require('path');

const app = express();
const SECRET_KEY = process.env.SECRET_KEY || 'your-super-secret-key-change-this';
const ADMIN_KEY = process.env.ADMIN_KEY || 'admin-secret-key-flap-per';

// Middleware
app.use(bodyParser.json());
app.use(cors());
app.use(express.static('public'));

// In-memory database (replace with real DB in production)
let users = {};
let transactions = {};

// Serve index.html
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// SIGNUP
app.post('/api/auth/signup', (req, res) => {
  const { email, password, name } = req.body;

  if (!email || !password || !name) {
    return res.status(400).json({ error: 'All fields required' });
  }

  if (users[email]) {
    return res.status(400).json({ error: 'Email already exists' });
  }

  const hashedPassword = bcrypt.hashSync(password, 10);
  const userId = uuidv4();

  users[email] = {
    id: userId,
    name,
    email,
    password: hashedPassword,
    balance: 0,
    createdAt: new Date()
  };

  transactions[email] = [];

  const token = jwt.sign({ email, userId }, SECRET_KEY, { expiresIn: '24h' });

  res.status(201).json({
    message: 'Account created successfully',
    token,
    user: { id: userId, name, email, balance: 0 }
  });
});

// LOGIN
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password required' });
  }

  const user = users[email];

  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(401).json({ error: 'Invalid email or password' });
  }

  const token = jwt.sign({ email, userId: user.id }, SECRET_KEY, { expiresIn: '24h' });

  res.json({
    message: 'Login successful',
    token,
    user: { id: user.id, name: user.name, email: user.email, balance: user.balance }
  });
});

// Middleware to verify token
const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

// GET USER PROFILE
app.get('/api/user/profile', verifyToken, (req, res) => {
  const user = users[req.user.email];

  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }

  res.json({
    id: user.id,
    name: user.name,
    email: user.email,
    balance: user.balance,
    createdAt: user.createdAt
  });
});

// GET TRANSACTIONS
app.get('/api/user/transactions', verifyToken, (req, res) => {
  const userTransactions = transactions[req.user.email] || [];
  res.json(userTransactions);
});

// ADMIN: ADD FUNDS TO USER ACCOUNT
app.post('/api/admin/add-funds', (req, res) => {
  const { adminKey, email, amount, description } = req.body;

  // Verify admin key
  if (adminKey !== ADMIN_KEY) {
    return res.status(403).json({ error: 'Unauthorized: Invalid admin key' });
  }

  const user = users[email];

  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }

  if (amount <= 0) {
    return res.status(400).json({ error: 'Amount must be positive' });
  }

  user.balance += amount;

  const transaction = {
    id: uuidv4(),
    type: 'credit',
    amount,
    description: description || 'Admin deposit',
    timestamp: new Date(),
    balance: user.balance
  };

  if (!transactions[email]) {
    transactions[email] = [];
  }

  transactions[email].push(transaction);

  res.json({
    message: 'Funds added successfully',
    user: { email: user.email, name: user.name, balance: user.balance },
    transaction
  });
});

// ADMIN: VIEW ALL USERS
app.get('/api/admin/users', (req, res) => {
  const adminKey = req.headers['x-admin-key'];

  if (adminKey !== ADMIN_KEY) {
    return res.status(403).json({ error: 'Unauthorized: Invalid admin key' });
  }

  const allUsers = Object.values(users).map(user => ({
    id: user.id,
    name: user.name,
    email: user.email,
    balance: user.balance,
    createdAt: user.createdAt
  }));

  res.json(allUsers);
});

// START SERVER
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🏦 Bank Server running on port ${PORT}`);
});
