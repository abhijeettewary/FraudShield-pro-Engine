const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const User = require('../models/user');

const JWT_SECRET = process.env.JWT_SECRET || 'fraudshield_dev_secret_key';
const revokedTokens = new Set();

const authRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 25,
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: 'Too many authentication attempts. Please try again in 15 minutes.' }
});

function signToken(user) {
  return jwt.sign(
    {
      id: user._id.toString(),
      email: user.email,
      name: user.name,
      role: user.role,
      accountNumber: user.accountNumber || null,
      tokenVersion: user.tokenVersion || 0
    },
    JWT_SECRET,
    { expiresIn: '4h' }
  );
}

function setAuthCookie(res, token) {
  res.cookie('fs_token', token, {
    httpOnly: true,
    sameSite: 'strict',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 4 * 60 * 60 * 1000
  });
}

function revokeToken(token) {
  if (token) revokedTokens.add(token);
}

async function requireAuth(req, res, next) {
  const token = req.cookies?.fs_token;
  if (!token || revokedTokens.has(token)) {
    return res.status(401).json({ message: 'Authentication required. Please sign in.' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.id).select('tokenVersion role accountNumber name email');
    if (!user || (user.tokenVersion || 0) !== (decoded.tokenVersion || 0)) {
      return res.status(401).json({ message: 'Session invalidated. Please sign in again.' });
    }
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ message: 'Session expired or invalid. Please sign in again.' });
  }
}

function requireRole(role) {
  return (req, res, next) => {
    if (!req.user || req.user.role !== role) {
      return res.status(403).json({ message: `Access denied. ${role} privileges required.` });
    }
    next();
  };
}

module.exports = {
  authRateLimiter,
  signToken,
  setAuthCookie,
  revokeToken,
  requireAuth,
  requireRole
};