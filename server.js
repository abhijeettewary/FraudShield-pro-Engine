const dns = require('dns');
dns.setServers(['8.8.8.8', '8.8.4.4']);

require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const path = require('path');

const User = require('./models/user');
const Transaction = require('./models/transaction');
const Watchlist = require('./models/watchlist');
const Beneficiary = require('./models/beneficiary');
const LedgerEntry = require('./models/ledgerEntry');
const SecurityEvent = require('./models/securityEvent');
const DeviceReputation = require('./models/deviceReputation');
const { evaluateTransaction, getRiskPolicy, updateRiskPolicy } = require('./utils/fraudEngine');
const mlModel = require('./utils/mlModel');
const { buildFraudGraph } = require('./utils/graphEngine');
const { upsertDeviceReputation, evaluateLoginATO, evaluateSessionPaymentATO } = require('./utils/atoEngine');
const { evaluateScamRisk } = require('./utils/scamShield');
const { generateInvestigationDossier } = require('./utils/aiInvestigator');
const {
  authRateLimiter,
  signToken,
  setAuthCookie,
  revokeToken,
  requireAuth,
  requireRole
} = require('./middleware/auth');

const app = express();

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'", 'https://cdn.jsdelivr.net', 'https://unpkg.com'],
        scriptSrcAttr: ["'unsafe-inline'"],
        styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
        fontSrc: ["'self'", 'https://fonts.gstatic.com'],
        connectSrc: ["'self'", 'https://free.freeipapi.com']
      }
    }
  })
);

app.use(express.json({ limit: '50kb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

const PORT = process.env.PORT || 5000;
const MONGO_URI = process.env.MONGO_URI;

mongoose
  .connect(MONGO_URI, { serverSelectionTimeoutMS: 5000 })
  .then(async () => {
    console.log('Connected to MongoDB');
    const pastTx = await Transaction.find({ status: { $in: ['Safe', 'Fraudulent'] } });
    const meta = mlModel.trainModel(pastTx);
    console.log(
      `ML Random Forest ready (${meta.totalSamples} samples: ${meta.kaggleSamples} Kaggle + ${meta.dbSamples} MongoDB)`
    );
  })
  .catch((err) => console.error('MongoDB connection error:', err.message));

function generateAccountNumber() {
  return 'FSP-' + Math.floor(10000000 + Math.random() * 90000000);
}

function validateAuthInput({ name, email, password }, isRegister = false) {
  if (isRegister && (!name || name.trim().length < 2)) {
    return 'Full name must be at least 2 characters.';
  }
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!email || !emailRegex.test(email.trim())) {
    return 'Please enter a valid email address.';
  }
  if (!password || password.length < 6) {
    return 'Password must be at least 6 characters.';
  }
  return null;
}

// --- ATOMIC LEDGER TRANSFER HELPER ---
async function executeAtomicTransfer({ senderId, receiverAccountNumber, amount, description, txRef, idempotencyKey }) {
  const session = await mongoose.startSession();
  try {
    let result;
    await session.withTransaction(async () => {
      if (idempotencyKey) {
        const dup = await LedgerEntry.findOne({ idempotencyKey }).session(session);
        if (dup) throw new Error('DUPLICATE_REQUEST');
      }

      const sender = await User.findOneAndUpdate(
        { _id: senderId, balance: { $gte: amount } },
        { $inc: { balance: -amount } },
        { new: true, session }
      );
      if (!sender) throw new Error('INSUFFICIENT_FUNDS');

      const receiver = await User.findOneAndUpdate(
        { accountNumber: receiverAccountNumber, role: 'customer' },
        { $inc: { balance: amount } },
        { new: true, session }
      );
      if (!receiver) throw new Error('RECEIVER_NOT_FOUND');

      await LedgerEntry.create(
        [
          {
            transactionRef: txRef,
            idempotencyKey,
            accountNumber: sender.accountNumber,
            counterpartyAccount: receiver.accountNumber,
            counterpartyName: receiver.name,
            type: 'DEBIT',
            amount,
            balanceAfter: sender.balance,
            description: description || `Transfer to ${receiver.name}`
          },
          {
            transactionRef: txRef,
            idempotencyKey: idempotencyKey ? `${idempotencyKey}_CREDIT` : undefined,
            accountNumber: receiver.accountNumber,
            counterpartyAccount: sender.accountNumber,
            counterpartyName: sender.name,
            type: 'CREDIT',
            amount,
            balanceAfter: receiver.balance,
            description: description || `Received from ${sender.name}`
          }
        ],
        { session, ordered: true }
      );

      const ben = await Beneficiary.findOneAndUpdate(
        { ownerId: sender._id, beneficiaryAccountNumber: receiver.accountNumber },
        { $inc: { successfulTxCount: 1 } },
        { new: true, session }
      );
      if (ben && ben.successfulTxCount >= 2 && ben.trustLevel === 'New') {
        ben.trustLevel = 'Established';
        await ben.save({ session });
      }

      result = { senderBalance: sender.balance, receiverName: receiver.name };
    });
    return result;
  } finally {
    session.endSession();
  }
}

// --- PORTAL ROUTES ---
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/customer', (req, res) => res.sendFile(path.join(__dirname, 'public', 'customer.html')));
app.get('/analyst', (req, res) => res.sendFile(path.join(__dirname, 'public', 'analyst.html')));

// --- AUTH ROUTES ---
async function handleRegister(req, res, role) {
  try {
    const validationErr = validateAuthInput(req.body, true);
    if (validationErr) return res.status(400).json({ message: validationErr });

    const { name, email, password, deviceId, location } = req.body;
    const cleanEmail = email.toLowerCase().trim();
    const exists = await User.findOne({ email: cleanEmail });
    if (exists) return res.status(409).json({ message: 'An account with this email already exists.' });

    const passwordHash = await bcrypt.hash(password, 12);
    const userData = { name: name.trim(), email: cleanEmail, passwordHash, role };

    if (role === 'customer') {
      userData.accountNumber = generateAccountNumber();
      userData.balance = 50000;
      userData.lastLoginAt = new Date();
      userData.lastLoginLocation = location || 'India';
      if (deviceId) {
        userData.trustedDevices = [{ deviceId, label: 'Primary Browser', addedAt: new Date(), lastUsedAt: new Date() }];
        userData.loginHistory = [{ deviceId, location: location || 'India', timestamp: new Date(), suspicious: false }];
      }
    }

    const user = new User(userData);
    await user.save();

    if (role === 'customer' && deviceId) {
      await upsertDeviceReputation(deviceId, user.accountNumber, 'seen');
    }

    const token = signToken(user);
    setAuthCookie(res, token);

    res.status(201).json({
      id: user._id,
      name: user.name,
      email: user.email,
      role: user.role,
      accountNumber: user.accountNumber || null,
      balance: role === 'customer' ? user.balance : undefined
    });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ message: 'Registration failed.' });
  }
}

async function handleLogin(req, res, expectedRole) {
  try {
    const validationErr = validateAuthInput(req.body, false);
    if (validationErr) return res.status(400).json({ message: validationErr });

    const { email, password, deviceId, location } = req.body;
    const user = await User.findOne({ email: email.toLowerCase().trim() });
    if (!user || user.role !== expectedRole) {
      return res.status(401).json({ message: 'Invalid credentials for this portal.' });
    }

    const isValid = await bcrypt.compare(password, user.passwordHash);
    if (!isValid) {
      if (expectedRole === 'customer') {
        user.failedLoginAttempts = (user.failedLoginAttempts || 0) + 1;
        user.lastFailedLoginAt = new Date();
        await user.save();
        if (deviceId) await upsertDeviceReputation(deviceId, user.accountNumber, 'failed_login');

        if (user.failedLoginAttempts >= 3) {
          await SecurityEvent.create({
            userId: user._id,
            accountNumber: user.accountNumber,
            category: 'SUSPICIOUS_LOGIN',
            severity: 'high',
            message: `${user.failedLoginAttempts} consecutive failed login attempts from device ${deviceId || 'Unknown'} (${location || 'Unknown'}).`,
            deviceId: deviceId || 'Unknown',
            location: location || 'Unknown'
          });
        }
      }
      return res.status(401).json({ message: 'Invalid credentials for this portal.' });
    }

    if (expectedRole === 'customer') {
      const cleanDev = deviceId || 'DEV-WEB';
      const cleanLoc = location || 'India';
      const deviceRep = await upsertDeviceReputation(cleanDev, user.accountNumber, 'seen');
      const { atoRisk, reasons } = evaluateLoginATO(user, { deviceId: cleanDev, location: cleanLoc, deviceRep });

      const known = user.trustedDevices.find((d) => d.deviceId === cleanDev);
      if (known) known.lastUsedAt = new Date();
      else if (user.trustedDevices.length === 0) {
        user.trustedDevices.push({ deviceId: cleanDev, label: 'Primary Browser', addedAt: new Date(), lastUsedAt: new Date() });
      }

      user.loginHistory.unshift({
        deviceId: cleanDev,
        location: cleanLoc,
        timestamp: new Date(),
        suspicious: atoRisk >= 30
      });
      user.loginHistory = user.loginHistory.slice(0, 15);
      user.failedLoginAttempts = 0;
      user.lastLoginAt = new Date();
      user.lastLoginLocation = cleanLoc;

      if (atoRisk >= 70) {
        user.restriction = {
          status: 'TEMP_RESTRICTED',
          reason: `High-risk ATO login detected: ${reasons.join('; ')}`,
          expiresAt: new Date(Date.now() + 15 * 60 * 1000)
        };
        await SecurityEvent.create({
          userId: user._id,
          accountNumber: user.accountNumber,
          category: 'TEMPORARY_RESTRICTION',
          severity: 'high',
          message: `15-min temporary payment cooldown applied. ${reasons.join('; ')}.`,
          deviceId: cleanDev,
          location: cleanLoc
        });
      } else if (atoRisk >= 30) {
        await SecurityEvent.create({
          userId: user._id,
          accountNumber: user.accountNumber,
          category: 'SUSPICIOUS_LOGIN',
          severity: 'medium',
          message: `Suspicious login (ATO Risk ${atoRisk}/100): ${reasons.join('; ')}.`,
          deviceId: cleanDev,
          location: cleanLoc
        });
      }

      await user.save();
    }

    const token = signToken(user);
    setAuthCookie(res, token);

    res.json({
      id: user._id,
      name: user.name,
      email: user.email,
      role: user.role,
      accountNumber: user.accountNumber || null,
      balance: expectedRole === 'customer' ? user.balance : undefined
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ message: 'Login failed.' });
  }
}

app.post('/api/auth/customer/register', authRateLimiter, (req, res) => handleRegister(req, res, 'customer'));
app.post('/api/auth/customer/login', authRateLimiter, (req, res) => handleLogin(req, res, 'customer'));
app.post('/api/auth/analyst/register', authRateLimiter, (req, res) => handleRegister(req, res, 'analyst'));
app.post('/api/auth/analyst/login', authRateLimiter, (req, res) => handleLogin(req, res, 'analyst'));

app.post('/api/auth/logout', (req, res) => {
  revokeToken(req.cookies?.fs_token);
  res.clearCookie('fs_token', { httpOnly: true, sameSite: 'strict' });
  res.json({ message: 'Logged out.' });
});

app.get('/api/auth/me', requireAuth, async (req, res) => {
  const user = await User.findById(req.user.id).select('-passwordHash');
  if (!user) return res.status(404).json({ message: 'User not found.' });
  res.json(user);
});

// --- CUSTOMER BANKING ROUTES ---
app.get('/api/customer/dashboard', requireAuth, requireRole('customer'), async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-passwordHash');
    const ledger = await LedgerEntry.find({ accountNumber: user.accountNumber }).sort({ createdAt: -1 }).limit(30);
    const beneficiaries = await Beneficiary.find({ ownerId: user._id }).sort({ createdAt: -1 });
    const alerts = await SecurityEvent.find({ userId: user._id }).sort({ createdAt: -1 }).limit(15);
    const recentScans = await Transaction.find({ userId: user.accountNumber }).sort({ createdAt: -1 }).limit(15);

    res.json({
      profile: {
        name: user.name,
        email: user.email,
        accountNumber: user.accountNumber,
        balance: user.balance,
        restriction: user.restriction
      },
      ledger,
      beneficiaries,
      alerts,
      recentScans
    });
  } catch (err) {
    res.status(500).json({ message: 'Failed to load customer dashboard.' });
  }
});

app.post('/api/customer/beneficiaries', requireAuth, requireRole('customer'), async (req, res) => {
  try {
    const { accountNumber, nickname } = req.body;
    const cleanAcc = (accountNumber || '').trim().toUpperCase();
    if (!cleanAcc) return res.status(400).json({ message: 'Beneficiary account number is required.' });
    if (cleanAcc === req.user.accountNumber) {
      return res.status(400).json({ message: 'You cannot add your own account as a beneficiary.' });
    }

    const target = await User.findOne({ accountNumber: cleanAcc, role: 'customer' });
    if (!target) return res.status(404).json({ message: 'No registered customer found with that account number.' });

    const ben = await Beneficiary.create({
      ownerId: req.user.id,
      beneficiaryUserId: target._id,
      beneficiaryName: target.name,
      beneficiaryAccountNumber: target.accountNumber,
      nickname: (nickname || '').trim(),
      trustLevel: 'New'
    });

    await User.findByIdAndUpdate(req.user.id, { lastBeneficiaryAddedAt: new Date() });
    res.status(201).json(ben);
  } catch (err) {
    if (err.code === 11000) return res.status(409).json({ message: 'Beneficiary already saved.' });
    res.status(500).json({ message: 'Failed to add beneficiary.' });
  }
});

app.delete('/api/customer/beneficiaries/:id', requireAuth, requireRole('customer'), async (req, res) => {
  await Beneficiary.deleteOne({ _id: req.params.id, ownerId: req.user.id });
  res.json({ message: 'Beneficiary removed.' });
});

// --- SCAMSHIELD PRE-PAYMENT CHECK ---
app.post('/api/customer/scam-check', requireAuth, requireRole('customer'), async (req, res) => {
  try {
    const { beneficiaryAccountNumber, amount, description } = req.body;
    const numAmount = Number(amount);
    const cleanAcc = (beneficiaryAccountNumber || '').trim().toUpperCase();

    if (!cleanAcc || !numAmount || numAmount <= 0) {
      return res.status(400).json({ message: 'Valid recipient account and amount are required.' });
    }

    const sender = await User.findById(req.user.id);
    const receiver = await User.findOne({ accountNumber: cleanAcc, role: 'customer' });
    if (!receiver) return res.status(404).json({ message: 'Recipient account not found.' });
    if (receiver.accountNumber === sender.accountNumber) {
      return res.status(400).json({ message: 'Cannot transfer to your own account.' });
    }

    const savedBen = await Beneficiary.findOne({
      ownerId: sender._id,
      beneficiaryAccountNumber: receiver.accountNumber
    });

    const userHistory = await LedgerEntry.find({
      accountNumber: sender.accountNumber,
      type: 'DEBIT'
    }).sort({ createdAt: -1 }).limit(20).select('amount');

    const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const recentToBenCount = await LedgerEntry.countDocuments({
      accountNumber: sender.accountNumber,
      counterpartyAccount: receiver.accountNumber,
      type: 'DEBIT',
      createdAt: { $gte: oneDayAgo }
    });

    const inboundSenders = await LedgerEntry.distinct('counterpartyAccount', {
      accountNumber: receiver.accountNumber,
      type: 'CREDIT'
    });

    const receiverFlaggedCount = await Transaction.countDocuments({
      userId: receiver.accountNumber,
      status: 'Fraudulent'
    });

    const result = evaluateScamRisk({
      sender,
      receiver,
      savedBen,
      amount: numAmount,
      description,
      userHistory,
      recentToBenCount,
      receiverInboundSenders: inboundSenders.length,
      receiverFlaggedCount
    });

    res.json(result);
  } catch (err) {
    console.error('ScamShield error:', err);
    res.status(500).json({ message: 'ScamShield pre-check failed.' });
  }
});

// Customer-to-Customer Simulated Transfer
app.post('/api/customer/transfer', requireAuth, requireRole('customer'), async (req, res) => {
  try {
    const { beneficiaryAccountNumber, amount, merchantCategory, description, location, deviceType, deviceId, idempotencyKey } = req.body;
    const numAmount = Number(amount);
    if (!beneficiaryAccountNumber || !numAmount || numAmount <= 0) {
      return res.status(400).json({ message: 'Valid beneficiary and positive amount are required.' });
    }

    const sender = await User.findById(req.user.id);
    if (sender.restriction?.status === 'COMPROMISED') {
      return res.status(403).json({ message: 'Account is currently restricted for security review.' });
    }
    if (sender.restriction?.status === 'TEMP_RESTRICTED' && sender.restriction.expiresAt > new Date()) {
      return res.status(403).json({ message: `Temporary payment restriction active: ${sender.restriction.reason}` });
    }
    if (sender.balance < numAmount) {
      return res.status(400).json({ message: 'Insufficient simulated balance.' });
    }

    const receiver = await User.findOne({ accountNumber: beneficiaryAccountNumber.trim().toUpperCase(), role: 'customer' });
    if (!receiver) return res.status(404).json({ message: 'Recipient account not found.' });
    if (receiver.accountNumber === sender.accountNumber) {
      return res.status(400).json({ message: 'Cannot transfer to your own account.' });
    }

    const savedBen = await Beneficiary.findOne({ ownerId: sender._id, beneficiaryAccountNumber: receiver.accountNumber });
    const isNewBeneficiary = !savedBen || savedBen.trustLevel === 'New';

    const cleanUser = sender.accountNumber;
    const cleanDevice = (deviceId || 'DEV-WEB').trim();
    const cleanLoc = (location || 'India').trim();
    const hourOfDay = new Date().getHours();
    const accountAgeDays = Math.floor((Date.now() - new Date(sender.createdAt).getTime()) / (1000 * 60 * 60 * 24));

    const deviceRep = await upsertDeviceReputation(cleanDevice, cleanUser, 'seen');
    const atoEval = evaluateSessionPaymentATO(sender, numAmount, deviceRep);

    const oneMinAgo = new Date(Date.now() - 60 * 1000);
    const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);
    const recent1MinTx = await Transaction.find({ userId: cleanUser, createdAt: { $gte: oneMinAgo } }).select('amount');
    const recent1HourTx = await Transaction.find({ userId: cleanUser, createdAt: { $gte: oneHourAgo } }).select('amount');
    const userHistory = await Transaction.find({ userId: cleanUser, status: { $ne: 'Fraudulent' } })
      .sort({ createdAt: -1 })
      .limit(30)
      .select('amount location createdAt');
    const ringLinkedUsers = await Transaction.distinct('userId', { deviceId: cleanDevice, userId: { $ne: cleanUser } });
    const learnedRules = await Watchlist.find({
      $or: [
        { type: 'user', value: cleanUser },
        { type: 'device', value: cleanDevice },
        { type: 'location', value: cleanLoc.toLowerCase() }
      ]
    });

    const mlProbability = mlModel.predictFraudProbability({
      amount: numAmount,
      merchantCategory: merchantCategory || 'Wire Transfer',
      location: cleanLoc,
      deviceType: deviceType || 'Web Browser',
      hourOfDay,
      accountAgeDays
    });

    const analysis = evaluateTransaction(
      {
        amount: numAmount,
        merchantCategory: merchantCategory || 'Wire Transfer',
        location: cleanLoc,
        deviceType: deviceType || 'Web Browser',
        deviceId: cleanDevice,
        hourOfDay,
        accountAgeDays
      },
      {
        userHistory,
        recent1MinTx,
        recent1HourTx,
        ringLinkedUsers,
        learnedRules,
        userBalance: sender.balance,
        isNewBeneficiary,
        knownDevices: sender.trustedDevices || []
      },
      mlProbability
    );

    const hybridRiskScore = Math.min(100, analysis.riskScore + atoEval.atoBoost);
    const policy = getRiskPolicy();
    const status =
      hybridRiskScore >= policy.fraudThreshold
        ? 'Fraudulent'
        : hybridRiskScore >= policy.suspiciousThreshold
        ? 'Suspicious'
        : 'Safe';
    const flaggedReasons = [...analysis.flaggedReasons, ...atoEval.reasons];

    const txRef = 'TXN-' + Date.now().toString().slice(-6);
    const txDoc = await Transaction.create({
      transactionId: txRef,
      userId: cleanUser,
      amount: numAmount,
      merchantCategory: merchantCategory || 'Wire Transfer',
      location: cleanLoc,
      deviceType: deviceType || 'Web Browser',
      deviceId: cleanDevice,
      hourOfDay,
      accountAgeDays,
      zScore: analysis.zScore,
      ringLinkedUsers,
      riskScore: hybridRiskScore,
      mlProbability,
      status,
      analystReview:
        status === 'Fraudulent'
          ? 'Auto-Blocked by Risk Engine'
          : status === 'Suspicious'
          ? `Pending OTP (To: ${receiver.accountNumber})`
          : `Auto-Cleared (To: ${receiver.accountNumber})`,
      flaggedReasons
    });

    if (status === 'Safe') {
      const ledgerRes = await executeAtomicTransfer({
        senderId: sender._id,
        receiverAccountNumber: receiver.accountNumber,
        amount: numAmount,
        description: description || `Transfer to ${receiver.name}`,
        txRef,
        idempotencyKey
      });
      await upsertDeviceReputation(cleanDevice, cleanUser, 'legit');
      return res.status(201).json({ transaction: txDoc, newBalance: ledgerRes.senderBalance, recipientName: receiver.name });
    }

    if (status === 'Suspicious') {
      await SecurityEvent.create({
        userId: sender._id,
        accountNumber: sender.accountNumber,
        category: 'RESTRICTED_PAYMENT',
        severity: 'medium',
        message: `Transfer of ₹${numAmount.toLocaleString('en-IN')} to ${receiver.name} paused for Step-Up OTP (Risk ${hybridRiskScore}/100).`,
        transactionRef: txRef,
        deviceId: cleanDevice,
        location: cleanLoc
      });
      return res.status(201).json({
        transaction: txDoc,
        pendingRecipient: receiver.accountNumber,
        recipientName: receiver.name,
        idempotencyKey
      });
    }

    await upsertDeviceReputation(cleanDevice, cleanUser, 'fraud');
    await Watchlist.findOneAndUpdate(
      { type: 'device', value: cleanDevice },
      { action: 'watchlist', reason: 'Auto-blocked on ' + txRef, $inc: { hits: 1 }, updatedAt: new Date() },
      { upsert: true }
    );
    await SecurityEvent.create({
      userId: sender._id,
      accountNumber: sender.accountNumber,
      category: 'BLOCKED_TRANSACTION',
      severity: 'high',
      message: `Blocked high-risk transfer of ₹${numAmount.toLocaleString('en-IN')} to ${receiver.name} (Risk ${hybridRiskScore}/100).`,
      transactionRef: txRef,
      deviceId: cleanDevice,
      location: cleanLoc
    });

    return res.status(201).json({ transaction: txDoc, recipientName: receiver.name });
  } catch (err) {
    console.error('Transfer error:', err);
    if (err.message === 'DUPLICATE_REQUEST') return res.status(409).json({ message: 'Duplicate transfer request blocked.' });
    if (err.message === 'INSUFFICIENT_FUNDS') return res.status(400).json({ message: 'Insufficient simulated balance.' });
    res.status(500).json({ message: 'Transfer processing failed.' });
  }
});

// Step-Up OTP Resolution
app.patch('/api/customer/transfer/:id/step-up', requireAuth, requireRole('customer'), async (req, res) => {
  try {
    const { action, receiverAccountNumber, description, idempotencyKey } = req.body;
    const tx = await Transaction.findById(req.params.id);
    if (!tx || tx.userId !== req.user.accountNumber) return res.status(404).json({ message: 'Transaction not found.' });
    if (tx.status !== 'Suspicious') return res.status(400).json({ message: 'Transaction is no longer pending.' });

    if (action === 'verify' && tx.ringLinkedUsers && tx.ringLinkedUsers.length >= 2) {
      tx.status = 'Fraudulent';
      tx.analystReview = 'Blocked: Policy Override (Fraud Ring)';
      await tx.save();
      return res.status(403).json({ message: 'Transfer blocked by security policy despite OTP.' });
    }

    if (action === 'verify') {
      const ledgerRes = await executeAtomicTransfer({
        senderId: req.user.id,
        receiverAccountNumber,
        amount: tx.amount,
        description: description || 'OTP Verified Transfer',
        txRef: tx.transactionId,
        idempotencyKey
      });
      tx.status = 'Safe';
      tx.analystReview = 'Customer OTP Verified';
      await tx.save();
      await upsertDeviceReputation(tx.deviceId, tx.userId, 'legit');

      await Watchlist.findOneAndUpdate(
        { type: 'user', value: tx.userId },
        { action: 'trusted', reason: 'OTP verified on ' + tx.transactionId, $inc: { hits: 1 }, updatedAt: new Date() },
        { upsert: true }
      );
      return res.json({ transaction: tx, newBalance: ledgerRes.senderBalance });
    } else {
      tx.status = 'Fraudulent';
      tx.analystReview = 'Customer Denied (Auto-Blocked)';
      await tx.save();
      await upsertDeviceReputation(tx.deviceId, tx.userId, 'fraud');

      await Watchlist.findOneAndUpdate(
        { type: 'device', value: tx.deviceId },
        { action: 'watchlist', reason: 'Customer denied ' + tx.transactionId, $inc: { hits: 1 }, updatedAt: new Date() },
        { upsert: true }
      );
      await SecurityEvent.create({
        userId: req.user.id,
        accountNumber: req.user.accountNumber,
        category: 'BLOCKED_TRANSACTION',
        severity: 'high',
        message: `You denied transfer ${tx.transactionId}. Device ${tx.deviceId} has been watchlisted.`,
        transactionRef: tx.transactionId,
        deviceId: tx.deviceId
      });
      return res.json({ transaction: tx });
    }
  } catch (err) {
    console.error('Step-up error:', err);
    if (err.message === 'INSUFFICIENT_FUNDS') return res.status(400).json({ message: 'Insufficient balance to complete transfer.' });
    res.status(500).json({ message: 'Step-up verification failed.' });
  }
});

// --- CUSTOMER SECURITY CENTER ROUTES ---
app.get('/api/customer/security', requireAuth, requireRole('customer'), async (req, res) => {
  const user = await User.findById(req.user.id).select('trustedDevices loginHistory restriction');
  const alerts = await SecurityEvent.find({ userId: req.user.id }).sort({ createdAt: -1 }).limit(20);
  res.json({
    trustedDevices: user.trustedDevices || [],
    loginHistory: user.loginHistory || [],
    restriction: user.restriction || { status: 'NONE' },
    alerts
  });
});

app.delete('/api/customer/security/devices/:deviceId', requireAuth, requireRole('customer'), async (req, res) => {
  await User.findByIdAndUpdate(req.user.id, {
    $pull: { trustedDevices: { deviceId: req.params.deviceId } }
  });
  res.json({ message: 'Trusted device removed.' });
});

app.post('/api/customer/security/change-password', requireAuth, requireRole('customer'), async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!newPassword || newPassword.length < 6) return res.status(400).json({ message: 'New password must be at least 6 characters.' });
  const user = await User.findById(req.user.id);
  const ok = await bcrypt.compare(currentPassword || '', user.passwordHash);
  if (!ok) return res.status(401).json({ message: 'Current password is incorrect.' });

  user.passwordHash = await bcrypt.hash(newPassword, 12);
  user.tokenVersion = (user.tokenVersion || 0) + 1;
  user.lastPasswordChangeAt = new Date();
  await user.save();

  const newToken = signToken(user);
  setAuthCookie(res, newToken);
  res.json({ message: 'Password updated and other sessions logged out.' });
});

app.post('/api/customer/security/logout-all', requireAuth, requireRole('customer'), async (req, res) => {
  const user = await User.findByIdAndUpdate(req.user.id, { $inc: { tokenVersion: 1 } }, { new: true });
  const newToken = signToken(user);
  setAuthCookie(res, newToken);
  res.json({ message: 'All other sessions have been logged out.' });
});

app.post('/api/customer/security/report/:txRef', requireAuth, requireRole('customer'), async (req, res) => {
  await SecurityEvent.create({
    userId: req.user.id,
    accountNumber: req.user.accountNumber,
    category: 'UNAUTHORIZED_REPORT',
    severity: 'high',
    message: `Customer reported transaction ${req.params.txRef} as unauthorized. Escalated to SOC Analysts.`,
    transactionRef: req.params.txRef
  });
  res.status(201).json({ message: 'Unauthorized transaction reported to Fraud Operations.' });
});

// --- TRANSACTION SIMULATOR ROUTE (ACCESSIBLE FROM LIVE PAYMENT SIMULATOR) ---
app.post('/api/transactions/analyze', requireAuth, async (req, res) => {
  try {
    const { userId, amount, merchantCategory, location, deviceType, deviceId, hourOfDay, accountAgeDays } = req.body;
    const cleanUser = (userId || '').trim();
    const cleanDevice = (deviceId || 'DEV-UNKNOWN').trim();
    const cleanLoc = (location || 'India').trim();

    const oneMinAgo = new Date(Date.now() - 60 * 1000);
    const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);
    const recent1MinTx = await Transaction.find({ userId: cleanUser, createdAt: { $gte: oneMinAgo } }).select('amount');
    const recent1HourTx = await Transaction.find({ userId: cleanUser, createdAt: { $gte: oneHourAgo } }).select('amount');
    const userHistory = await Transaction.find({ userId: cleanUser, status: { $ne: 'Fraudulent' } })
      .sort({ createdAt: -1 })
      .limit(30)
      .select('amount location createdAt');
    const ringLinkedUsers = await Transaction.distinct('userId', { deviceId: cleanDevice, userId: { $ne: cleanUser } });
    const learnedRules = await Watchlist.find({
      $or: [
        { type: 'user', value: cleanUser },
        { type: 'device', value: cleanDevice },
        { type: 'location', value: cleanLoc.toLowerCase() }
      ]
    });

    const mlProbability = mlModel.predictFraudProbability({
      amount: Number(amount),
      merchantCategory,
      location: cleanLoc,
      deviceType,
      hourOfDay: Number(hourOfDay),
      accountAgeDays: Number(accountAgeDays) || 0
    });

    const analysis = evaluateTransaction(
      {
        amount: Number(amount),
        merchantCategory,
        location: cleanLoc,
        deviceType,
        deviceId: cleanDevice,
        hourOfDay: Number(hourOfDay),
        accountAgeDays: Number(accountAgeDays) || 0
      },
      { userHistory, recent1MinTx, recent1HourTx, ringLinkedUsers, learnedRules },
      mlProbability
    );

    const savedTx = await Transaction.create({
      transactionId: 'TXN-' + Date.now().toString().slice(-6),
      userId: cleanUser,
      amount: Number(amount),
      merchantCategory,
      location: cleanLoc,
      deviceType,
      deviceId: cleanDevice,
      hourOfDay: Number(hourOfDay),
      accountAgeDays: Number(accountAgeDays) || 0,
      zScore: analysis.zScore,
      ringLinkedUsers,
      riskScore: analysis.riskScore,
      mlProbability,
      status: analysis.status,
      analystReview:
        analysis.status === 'Fraudulent'
          ? 'Auto-Blocked by Risk Engine'
          : analysis.status === 'Suspicious'
          ? 'Pending Review'
          : 'Auto-Cleared',
      flaggedReasons: analysis.flaggedReasons
    });

    await upsertDeviceReputation(cleanDevice, cleanUser, savedTx.status === 'Fraudulent' ? 'fraud' : 'legit');

    if (savedTx.status === 'Fraudulent') {
      await Watchlist.findOneAndUpdate(
        { type: 'device', value: cleanDevice },
        { action: 'watchlist', reason: 'Auto-blocked on ' + savedTx.transactionId, $inc: { hits: 1 }, updatedAt: new Date() },
        { upsert: true }
      );
    }

    res.status(201).json(savedTx);
  } catch (err) {
    console.error('Analyze error:', err);
    res.status(500).json({ message: 'Analysis failed.' });
  }
});

// --- ANALYST SOC ROUTES ---
app.get('/api/transactions', requireAuth, requireRole('analyst'), async (req, res) => {
  const transactions = await Transaction.find().sort({ createdAt: -1 });
  const watchlist = await Watchlist.find().sort({ updatedAt: -1 });
  const safeCount = transactions.filter((t) => t.status === 'Safe').length;
  const suspiciousCount = transactions.filter((t) => t.status === 'Suspicious').length;
  const fraudCount = transactions.filter((t) => t.status === 'Fraudulent').length;
  const blockedAmount = transactions.filter((t) => t.status === 'Fraudulent').reduce((s, t) => s + t.amount, 0);

  const categoryStats = {};
  transactions.forEach((t) => {
    if (t.status !== 'Safe') categoryStats[t.merchantCategory] = (categoryStats[t.merchantCategory] || 0) + 1;
  });

  res.json({
    metrics: { totalCount: transactions.length, safeCount, suspiciousCount, fraudCount, blockedAmount },
    categoryStats,
    transactions,
    watchlist
  });
});

app.delete('/api/watchlist/:id', requireAuth, requireRole('analyst'), async (req, res) => {
  await Watchlist.findByIdAndDelete(req.params.id);
  res.json({ message: 'Rule removed.' });
});

app.get('/api/ml/status', requireAuth, requireRole('analyst'), (req, res) => res.json(mlModel.getModelMeta()));

app.post('/api/ml/retrain', requireAuth, requireRole('analyst'), async (req, res) => {
  const resolvedTx = await Transaction.find({ status: { $in: ['Safe', 'Fraudulent'] } });
  res.json(mlModel.trainModel(resolvedTx));
});

app.get('/api/ml/evaluation', requireAuth, requireRole('analyst'), (req, res) => {
  res.json({
    evaluation: mlModel.getEvaluationReport(),
    policy: getRiskPolicy()
  });
});

app.patch('/api/ml/policy', requireAuth, requireRole('analyst'), (req, res) => {
  const updated = updateRiskPolicy(req.body);
  res.json({ message: 'Risk policy updated.', policy: updated });
});

app.get('/api/analyst/graph', requireAuth, requireRole('analyst'), async (req, res) => {
  try {
    const transactions = await Transaction.find().sort({ createdAt: -1 }).limit(200);
    const ledgerEntries = await LedgerEntry.find().sort({ createdAt: -1 }).limit(200);
    const graphData = buildFraudGraph(transactions, ledgerEntries);
    res.json(graphData);
  } catch (err) {
    res.status(500).json({ message: 'Failed to build fraud network graph.' });
  }
});

app.get('/api/analyst/ato', requireAuth, requireRole('analyst'), async (req, res) => {
  try {
    const devices = await DeviceReputation.find().sort({ riskScore: -1, lastSeen: -1 }).limit(50);
    const events = await SecurityEvent.find().sort({ createdAt: -1 }).limit(50);
    const restrictedUsers = await User.find({
      role: 'customer',
      'restriction.status': { $ne: 'NONE' }
    }).select('name email accountNumber restriction');

    res.json({
      summary: {
        totalDevices: devices.length,
        highRiskDevices: devices.filter((d) => d.trustStatus === 'Blacklisted' || d.trustStatus === 'Suspicious').length,
        atoAlerts: events.filter((e) => ['SUSPICIOUS_LOGIN', 'TEMPORARY_RESTRICTION', 'UNAUTHORIZED_REPORT'].includes(e.category)).length,
        restrictedCount: restrictedUsers.length
      },
      devices,
      events,
      restrictedUsers
    });
  } catch (err) {
    res.status(500).json({ message: 'Failed to load ATO intelligence.' });
  }
});

app.patch('/api/analyst/devices/:deviceId/status', requireAuth, requireRole('analyst'), async (req, res) => {
  const { trustStatus } = req.body;
  if (!['Trusted', 'Neutral', 'Suspicious', 'Blacklisted'].includes(trustStatus)) {
    return res.status(400).json({ message: 'Invalid trust status.' });
  }
  const updated = await DeviceReputation.findOneAndUpdate(
    { deviceId: req.params.deviceId },
    { trustStatus },
    { new: true }
  );
  res.json(updated);
});

app.patch('/api/analyst/users/:id/restriction', requireAuth, requireRole('analyst'), async (req, res) => {
  const { status, reason } = req.body;
  const user = await User.findByIdAndUpdate(
    req.params.id,
    {
      restriction: {
        status: status || 'NONE',
        reason: reason || '',
        expiresAt: status === 'TEMP_RESTRICTED' ? new Date(Date.now() + 15 * 60 * 1000) : null
      }
    },
    { new: true }
  ).select('name accountNumber restriction');
  res.json(user);
});

// --- AI INVESTIGATOR & EXPLAINABLE CASE RESOLUTION ---
app.get('/api/analyst/investigate/:id', requireAuth, requireRole('analyst'), async (req, res) => {
  try {
    const tx = await Transaction.findById(req.params.id);
    if (!tx) return res.status(404).json({ message: 'Transaction not found.' });

    const deviceRep = await DeviceReputation.findOne({ deviceId: tx.deviceId });
    const recentEvents = await SecurityEvent.find({ accountNumber: tx.userId }).sort({ createdAt: -1 }).limit(8);
    const userHistoryCount = await Transaction.countDocuments({ userId: tx.userId });

    const dossier = generateInvestigationDossier({ tx, deviceRep, recentEvents, userHistoryCount });
    res.json(dossier);
  } catch (err) {
    console.error('Investigate error:', err);
    res.status(500).json({ message: 'Failed to generate AI investigation dossier.' });
  }
});

app.patch('/api/analyst/cases/:id/resolve', requireAuth, requireRole('analyst'), async (req, res) => {
  try {
    const { decision } = req.body;
    const tx = await Transaction.findById(req.params.id);
    if (!tx) return res.status(404).json({ message: 'Transaction not found.' });

    if (decision === 'confirm_fraud') {
      tx.status = 'Fraudulent';
      tx.analystReview = `Confirmed Fraud by ${req.user.name}`;
      await tx.save();
      await upsertDeviceReputation(tx.deviceId, tx.userId, 'fraud');
      await Watchlist.findOneAndUpdate(
        { type: 'device', value: tx.deviceId },
        { action: 'watchlist', reason: `Confirmed fraud on ${tx.transactionId}`, $inc: { hits: 1 }, updatedAt: new Date() },
        { upsert: true }
      );
    } else if (decision === 'false_positive') {
      tx.status = 'Safe';
      tx.analystReview = `Cleared (False Positive) by ${req.user.name}`;
      await tx.save();
      await upsertDeviceReputation(tx.deviceId, tx.userId, 'legit');
      await Watchlist.findOneAndUpdate(
        { type: 'user', value: tx.userId },
        { action: 'trusted', reason: `Analyst cleared ${tx.transactionId}`, $inc: { hits: 1 }, updatedAt: new Date() },
        { upsert: true }
      );
    } else {
      return res.status(400).json({ message: 'Invalid resolution decision.' });
    }

    res.json({ message: 'Case resolved and self-learning memory updated.', transaction: tx });
  } catch (err) {
    res.status(500).json({ message: 'Case resolution failed.' });
  }
});

app.listen(PORT, () => console.log(`FraudShield Pro running at http://localhost:${PORT}`));