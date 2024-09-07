const express = require('express');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

dotenv.config();

const app = express();
app.use(express.json());

// MongoDB connection
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('Connected to MongoDB'))
.catch((err) => console.error('MongoDB connection error:', err));

// User model
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  status: { type: String, enum: ['pending', 'active'], default: 'pending' }
});

const User = mongoose.model('User', userSchema);

// Activation Key model
const activationKeySchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  key: { type: String, required: true, unique: true },
  createdAt: { type: Date, default: Date.now, expires: '24h' } // Key expires after 24 hours
});

const ActivationKey = mongoose.model('ActivationKey', activationKeySchema);

// API routes
const apiRouter = express.Router();

// Signup route
apiRouter.post('/signup', async (req, res) => {
  try {
    const { email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ email, password: hashedPassword });
    await user.save();
    res.status(201).json({ message: 'User created successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Error creating user' });
  }
});

// Login route
apiRouter.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  } catch (error) {
    res.status(500).json({ error: 'Error logging in' });
  }
});

// Is activated route
apiRouter.get('/is_activated', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ error: 'No token provided' });
    }
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json({ isActivated: user.status === 'active' });
  } catch (error) {
    res.status(500).json({ error: 'Error checking activation status' });
  }
});

// Activate route
apiRouter.post('/activate', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ error: 'No token provided' });
    }
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    if (req.body.active === true) {
      user.status = 'active';
      await user.save();
      res.json({ message: 'User activated successfully' });
    } else {
      res.status(400).json({ error: 'Invalid activation request' });
    }
  } catch (error) {
    res.status(500).json({ error: 'Error activating user' });
  }
});

// Generate Activation Key route
apiRouter.post('/generate-activation-key', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }

    // Generate a random activation key
    const key = crypto.randomBytes(32).toString('hex');

    // Check if an activation key already exists for this email
    let activationKey = await ActivationKey.findOne({ email });

    if (activationKey) {
      // Update the existing key
      activationKey.key = key;
      activationKey.createdAt = new Date();
    } else {
      // Create a new activation key
      activationKey = new ActivationKey({ email, key });
    }

    await activationKey.save();

    res.status(201).json({ message: 'Activation key generated successfully', key });
  } catch (error) {
    res.status(500).json({ error: 'Error generating activation key' });
  }
});

// Fetch Activation Key route
apiRouter.get('/fetch-activation-key', async (req, res) => {
  try {
    const { key } = req.query;
    if (!key) {
      return res.status(400).json({ error: 'Key is required' });
    }

    const activationKey = await ActivationKey.findOne({ key });

    res.json({ exists: !!activationKey });
  } catch (error) {
    res.status(500).json({ error: 'Error fetching activation key' });
  }
});

// Use the API router with the /api/v1 prefix
app.use('/api/v1', apiRouter);

const PORT = process.env.PORT || 8004;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

// For Vercel deployment
module.exports = app;