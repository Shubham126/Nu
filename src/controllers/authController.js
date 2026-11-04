const User = require('../models/User');
const jwt = require('jsonwebtoken');
const { OAuth2Client } = require('google-auth-library');

const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// Generate JWT Helper
const generateToken = (userId) => {
  return jwt.sign({ id: userId }, process.env.JWT_SECRET, {
    expiresIn: '7d',
  });
};

// @desc    Register a new user
// @route   POST /api/auth/register
exports.register = async (req, res) => {
  try {
    const { name, username, email, password, adminSecret } = req.body;

    if (!name || !username || !email || !password) {
      return res.status(400).json({ message: 'All fields are required.' });
    }

    // Check if email or username already exists
    const existingUser = await User.findOne({
      $or: [{ email: email.toLowerCase() }, { username: username.toLowerCase() }],
    });

    if (existingUser) {
      return res.status(400).json({ message: 'Username or email already in use.' });
    }

    // Optional admin creation if ADMIN_SECRET_KEY matches
    const isAdmin = adminSecret && adminSecret === process.env.ADMIN_SECRET_KEY;

    const user = await User.create({
      name,
      username,
      email,
      password,
      isAdmin,
    });

    res.status(201).json({
      success: true,
      token: generateToken(user._id),
      user: {
        id: user._id,
        name: user.name,
        username: user.username,
        email: user.email,
        isAdmin: user.isAdmin,
      },
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// @desc    Login with username or email
// @route   POST /api/auth/login
exports.login = async (req, res) => {
  try {
    const { identifier, password } = req.body;

    if (!identifier || !password) {
      return res.status(400).json({ message: 'Please provide identifier and password.' });
    }

    // Match identifier against either username or email
    const user = await User.findOne({
      $or: [
        { email: identifier.toLowerCase() },
        { username: identifier.toLowerCase() },
      ],
    });

    if (!user || !user.password) {
      return res.status(401).json({ message: 'Invalid credentials.' });
    }

    const isMatch = await user.matchPassword(password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid credentials.' });
    }

    res.status(200).json({
      success: true,
      token: generateToken(user._id),
      user: {
        id: user._id,
        name: user.name,
        username: user.username,
        email: user.email,
        isAdmin: user.isAdmin,
      },
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// @desc    Admin login
// @route   POST /api/auth/admin-login
exports.adminLogin = async (req, res) => {
  try {
    const { identifier, password } = req.body;

    if (!identifier || !password) {
      return res.status(400).json({ message: 'Please provide admin credentials.' });
    }

    const user = await User.findOne({
      $or: [
        { email: identifier.toLowerCase() },
        { username: identifier.toLowerCase() },
      ],
    });

    if (!user || !user.password) {
      return res.status(401).json({ message: 'Invalid credentials.' });
    }

    const isMatch = await user.matchPassword(password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid credentials.' });
    }

    if (!user.isAdmin) {
      return res.status(403).json({ message: 'Access denied: Administrator accounts only.' });
    }

    res.status(200).json({
      success: true,
      token: generateToken(user._id),
      user: {
        id: user._id,
        name: user.name,
        username: user.username,
        email: user.email,
        isAdmin: true,
      },
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// @desc    Authenticate with Google OAuth ID Token
// @route   POST /api/auth/google
exports.googleAuth = async (req, res) => {
  try {
    const { token } = req.body;

    if (!token) {
      return res.status(400).json({ message: 'Google credential token is missing.' });
    }

    // Verify token with Google's public keys
    const ticket = await googleClient.verifyIdToken({
      idToken: token,
      audience: process.env.GOOGLE_CLIENT_ID,
    });

    const payload = ticket.getPayload();
    const { sub: googleId, email, name } = payload;

    // Check if user exists by googleId or email
    let user = await User.findOne({ $or: [{ googleId }, { email: email.toLowerCase() }] });

    if (user) {
      if (!user.googleId) {
        user.googleId = googleId;
        await user.save();
      }
    } else {
      // Create user if signing in via Google for the first time
      const baseUsername = email.split('@')[0].replace(/[^a-zA-Z0-9]/g, '');
      const uniqueUsername = `${baseUsername}_${Math.floor(1000 + Math.random() * 9000)}`;

      user = await User.create({
        name: name || 'Google User',
        username: uniqueUsername,
        email: email.toLowerCase(),
        googleId,
        isAdmin: false,
      });
    }

    res.status(200).json({
      success: true,
      token: generateToken(user._id),
      user: {
        id: user._id,
        name: user.name,
        username: user.username,
        email: user.email,
        isAdmin: user.isAdmin,
      },
    });
  } catch (error) {
    res.status(400).json({ message: 'Invalid Google token: ' + error.message });
  }
};