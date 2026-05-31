const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const dotenv = require('dotenv');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const crypto = require('crypto');
const nodemailer = require('nodemailer');

// ✅ dotenv MUST come before anything that reads process.env
dotenv.config();

const paystack = require('paystack-api')(process.env.PAYSTACK_SECRET_KEY);

console.log('Paystack Secret Key loaded:', process.env.PAYSTACK_SECRET_KEY ? 'YES' : 'NO');

const app = express();

// ─── WEBHOOK ROUTE (must come BEFORE express.json()) ─────────────────────────
app.post('/api/donations/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  try {
    const hash = crypto
      .createHmac('sha512', process.env.PAYSTACK_SECRET_KEY)
      .update(req.body)
      .digest('hex');

    if (hash !== req.headers['x-paystack-signature']) {
      console.warn('Webhook signature mismatch — ignoring request');
      return res.status(401).send('Invalid signature');
    }

    const event = JSON.parse(req.body);
    console.log('Paystack webhook event received:', event.event);

    if (event.event === 'charge.success') {
      const { reference, amount, metadata } = event.data;

      const exists = await Donation.findOne({ reference });
      if (!exists) {
        await Donation.create({
          amount: amount / 100,
          donor: metadata?.userId || null,
          reference,
        });
        console.log(`Donation recorded via webhook: ₦${amount / 100} (ref: ${reference})`);
      } else {
        console.log(`Duplicate webhook ignored for ref: ${reference}`);
      }
    }

    res.sendStatus(200);
  } catch (err) {
    console.error('Webhook processing error:', err);
    res.sendStatus(500);
  }
});

// ─── Standard middleware ──────────────────────────────────────────────────────
app.use(express.json());

app.use(cors({
  origin: [
    'https://kghs-frontend.onrender.com',
    'https://kghsalumnae.org',
    'https://www.kghsalumnae.org',
  ],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
}));

const transporter = nodemailer.createTransport({
  host: 'smtp-relay.brevo.com',
  port: 587,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

const sendEmail = require('./utils/sendEmail');

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const storage = new CloudinaryStorage({
  cloudinary,
  params: async (req, file) => {
    const isPDF = file.mimetype === 'application/pdf';
    return {
      folder: 'kghs',
      resource_type: isPDF ? 'raw' : 'image',
      format: isPDF ? 'pdf' : undefined,
    };
  },
});
const upload = multer({ storage });

mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.log(err));

// ─── Schemas ──────────────────────────────────────────────────────────────────

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  name: String,
  graduationYear: Number,
  bio: String,
  location: String,
  profilePic: String,
  role: { type: String, default: 'alumni' },
  isApproved: { type: Boolean, default: false },
  resetPasswordToken: { type: String },
  resetPasswordExpires: { type: Date },
});
const User = mongoose.model('User', userSchema);

const eventSchema = new mongoose.Schema({
  title: String,
  description: String,
  date: Date,
  location: String,
  type: { type: String, enum: ['gathering', 'birthday', 'reunion', 'memorial'], default: 'gathering' },
  creator: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
});
const Event = mongoose.model('Event', eventSchema);

const newsSchema = new mongoose.Schema({
  title: String,
  content: String,
  image: String,
  images: [String],
  author: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  date: { type: Date, default: Date.now },
});
const News = mongoose.model('News', newsSchema);

const forumThreadSchema = new mongoose.Schema({
  title: String,
  content: String,
  author: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  date: { type: Date, default: Date.now },
  replies: [{
    content: String,
    author: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    date: { type: Date, default: Date.now },
  }],
});
const ForumThread = mongoose.model('ForumThread', forumThreadSchema);

const gallerySchema = new mongoose.Schema({
  url: String,
  caption: String,
  uploader: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  date: { type: Date, default: Date.now },
});
const Gallery = mongoose.model('Gallery', gallerySchema);

const donationSchema = new mongoose.Schema({
  amount: Number,
  donor: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  reference: { type: String, unique: true, sparse: true },
  date: { type: Date, default: Date.now },
});
const Donation = mongoose.model('Donation', donationSchema);

const boardMinuteSchema = new mongoose.Schema({
  title: { type: String, required: true },
  fileUrl: { type: String, required: true },
  date: { type: Date, default: Date.now },
});
const BoardMinute = mongoose.model('BoardMinute', boardMinuteSchema);

// ─── Middleware ───────────────────────────────────────────────────────────────

const authMiddleware = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ msg: 'No token' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ msg: 'Invalid token' });
  }
};

const adminMiddleware = async (req, res, next) => {
  const user = await User.findById(req.user.id);
  if (!user || user.role !== 'admin') return res.status(403).json({ msg: 'Admin access required' });
  next();
};

// ─── Auth Routes ──────────────────────────────────────────────────────────────

app.post('/api/auth/signup', async (req, res) => {
  const { email, password, name, graduationYear } = req.body;
  try {
    let user = await User.findOne({ email });
    if (user) return res.status(400).json({ msg: 'User already exists' });

    const currentYear = new Date().getFullYear();
    if (graduationYear < 1950 || graduationYear > currentYear + 10) {
      return res.status(400).json({ msg: 'Invalid graduation year' });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    user = new User({ email, password: hashedPassword, name, graduationYear, isApproved: false });
    await user.save();

    res.json({ msg: 'Signup successful! Your account is pending admin approval. You will receive an email when approved.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: 'Server error' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ msg: 'Invalid credentials' });

    if (!user.isApproved) {
      return res.status(403).json({ msg: 'Your account is pending approval. Please check your email.' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ msg: 'Invalid credentials' });

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user._id, email: user.email, name: user.name, role: user.role } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: 'Server error' });
  }
});

app.post('/api/auth/forgot-password', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ msg: 'Please provide your email' });

  try {
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) return res.json({ msg: 'If your email is registered, you will receive a reset link shortly' });

    const resetToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    user.resetPasswordToken = resetToken;
    user.resetPasswordExpires = Date.now() + 3600000;
    await user.save();

    const resetUrl = `https://kghsalumnae.org/reset-password/${resetToken}`;

    try {
      await sendEmail({
        to: user.email,
        toName: user.name || '',
        subject: 'KGHS Alumni Foundation - Password Reset Request',
        htmlContent: `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; padding: 30px; background: #fff5fb; border-radius: 15px; box-shadow: 0 10px 30px rgba(255,192,203,0.2);">
            <h1 style="color: #ff69b4; text-align: center;">Password Reset Request</h1>
            <p style="font-size: 18px; color: #333;">Dear ${user.name || 'Sister'},</p>
            <p style="font-size: 16px; line-height: 1.6; color: #555;">We received a request to reset your password for your KGHS Alumni account.</p>
            <p style="font-size: 16px; line-height: 1.6; color: #555;">Click the button below to set a new password. This link expires in <strong>1 hour</strong>.</p>
            <div style="text-align: center; margin: 40px 0;">
              <a href="${resetUrl}" style="background: #ff69b4; color: white; padding: 18px 40px; text-decoration: none; border-radius: 50px; font-size: 18px; font-weight: bold; display: inline-block;">Reset My Password</a>
            </div>
            <p style="color: #777; font-size: 14px; line-height: 1.6;">If you didn't request this, please ignore this email — your password will remain unchanged.<br><br>With love,<br><strong>The KGHS Alumni Team</strong></p>
          </div>
        `,
      });
      console.log('Password reset email sent to:', user.email);
    } catch (emailErr) {
      console.error('Failed to send reset email:', emailErr);
    }

    res.json({ msg: 'If your email is registered, you will receive a reset link shortly' });
  } catch (err) {
    console.error('Forgot password error:', err);
    res.status(500).json({ msg: 'Server error. Please try again later.' });
  }
});

app.post('/api/auth/reset-password/:token', async (req, res) => {
  const { password } = req.body;
  if (!password || password.length < 6) return res.status(400).json({ msg: 'Password must be at least 6 characters' });

  try {
    const user = await User.findOne({
      resetPasswordToken: req.params.token,
      resetPasswordExpires: { $gt: Date.now() },
    });

    if (!user) return res.status(400).json({ msg: 'Invalid or expired reset link' });

    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(password, salt);
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();

    console.log('Password successfully reset for:', user.email);
    res.json({ msg: 'Password reset successful! You can now log in.' });
  } catch (err) {
    console.error('Reset password error:', err);
    res.status(500).json({ msg: 'Server error. Please try again.' });
  }
});

// ─── Profile Routes ───────────────────────────────────────────────────────────

app.get('/api/profile', authMiddleware, async (req, res) => {
  const user = await User.findById(req.user.id).select('-password');
  res.json(user);
});

app.put('/api/profile', authMiddleware, upload.single('profilePic'), async (req, res) => {
  const { name, graduationYear, bio, location } = req.body;
  const updateData = { name, graduationYear, bio, location };
  if (req.file) updateData.profilePic = req.file.path;
  const user = await User.findByIdAndUpdate(req.user.id, updateData, { new: true }).select('-password');
  res.json(user);
});

// ─── Alumni Directory ─────────────────────────────────────────────────────────

app.get('/api/directory', authMiddleware, async (req, res) => {
  const { year, location } = req.query;
  const filter = { isApproved: true };
  if (year) filter.graduationYear = year;
  if (location) filter.location = { $regex: location, $options: 'i' };
  const users = await User.find(filter).select('-password -isApproved');
  res.json(users);
});

// ─── Events ───────────────────────────────────────────────────────────────────

app.get('/api/events', async (req, res) => {
  const events = await Event.find().populate('creator', 'name').sort({ date: -1 });
  res.json(events);
});

app.post('/api/events', authMiddleware, async (req, res) => {
  const event = new Event({ ...req.body, creator: req.user.id });
  await event.save();
  res.json(event);
});

// ─── News ─────────────────────────────────────────────────────────────────────

app.get('/api/news', async (req, res) => {
  const news = await News.find().populate('author', 'name').sort({ date: -1 });
  res.json(news);
});

app.post('/api/news', authMiddleware, adminMiddleware, upload.array('images', 3), async (req, res) => {
  try {
    const imageUrls = req.files ? req.files.map(f => f.path) : [];
    const newsItem = new News({ title: req.body.title, content: req.body.content, author: req.user.id, images: imageUrls });
    await newsItem.save();
    const populated = await newsItem.populate('author', 'name');
    res.json(populated);
  } catch (err) {
    console.error('News post error:', err);
    res.status(500).json({ msg: 'Failed to create news', error: err.message });
  }
});

app.get('/api/news/:id', async (req, res) => {
  try {
    const newsItem = await News.findById(req.params.id).populate('author', 'name');
    if (!newsItem) return res.status(404).json({ message: 'News not found' });
    res.json(newsItem);
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// ─── Forums ───────────────────────────────────────────────────────────────────

app.get('/api/forums', async (req, res) => {
  const threads = await ForumThread.find().populate('author', 'name').sort({ date: -1 });
  res.json(threads);
});

app.post('/api/forums', authMiddleware, async (req, res) => {
  const thread = new ForumThread({ ...req.body, author: req.user.id });
  await thread.save();
  res.json(thread);
});

app.post('/api/forums/:id/reply', authMiddleware, async (req, res) => {
  const thread = await ForumThread.findById(req.params.id);
  thread.replies.push({ content: req.body.content, author: req.user.id });
  await thread.save();
  res.json(thread);
});

// ─── Gallery ──────────────────────────────────────────────────────────────────

app.get('/api/gallery', async (req, res) => {
  const images = await Gallery.find().populate('uploader', 'name').sort({ date: -1 });
  res.json(images);
});

app.post('/api/gallery', authMiddleware, upload.single('image'), async (req, res) => {
  const image = new Gallery({ url: req.file.path, caption: req.body.caption, uploader: req.user.id });
  await image.save();
  res.json(image);
});

// ─── Donations ────────────────────────────────────────────────────────────────

app.post('/api/donations/create-payment', authMiddleware, async (req, res) => {
  const { amount, currency = 'NGN' } = req.body;

  try {
    if (!amount || amount < 1) {
      return res.status(400).json({ msg: 'Invalid amount' });
    }

    // ✅ Fetch full user to get their real email
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ msg: 'User not found' });

    const validCurrency = currency.toUpperCase() === 'USD' ? 'USD' : 'NGN';

    const response = await paystack.transaction.initialize({
      amount: Math.round(amount * 100),
      email: user.email,  // ✅ real alumni email, not fallback
      currency: validCurrency,
      reference: `kghs-don-${Date.now()}-${Math.random().toString(36).substring(7)}`,
      callback_url: 'https://kghsalumnae.org/donations/success',
      metadata: {
        userId: user._id,
        userName: user.name,
        currency: validCurrency,
      },
    });

    res.json({ authorization_url: response.data.authorization_url });
  } catch (err) {
    console.error('Paystack initialization error:', err.response?.data || err.message || err);
    const errorMessage = err.response?.data?.message || err.message || 'Unknown error';
    res.status(500).json({ msg: 'Payment initialization failed', details: errorMessage });
  }
});

app.get('/api/donations/verify/:reference', authMiddleware, async (req, res) => {
  try {
    const response = await paystack.transaction.verify(req.params.reference);

    if (response.data.status === 'success') {
      const exists = await Donation.findOne({ reference: req.params.reference });
      if (!exists) {
        const donation = new Donation({
          amount: response.data.amount / 100,
          donor: req.user.id,
          reference: req.params.reference,
        });
        await donation.save();
        console.log(`Donation recorded via verify: ₦${response.data.amount / 100} (ref: ${req.params.reference})`);
      } else {
        console.log(`Donation already recorded via webhook for ref: ${req.params.reference}`);
      }
      res.json({ success: true, message: 'Donation successful!' });
    } else {
      res.status(400).json({ success: false, message: 'Payment not completed' });
    }
  } catch (err) {
    console.error('Paystack verification error:', err.response?.data || err.message);
    res.status(500).json({ msg: 'Verification failed' });
  }
});

app.get('/api/donations', authMiddleware, adminMiddleware, async (req, res) => {
  const donations = await Donation.find().populate('donor', 'name').sort({ date: -1 });
  res.json(donations);
});

app.get('/api/public/donations', async (req, res) => {
  try {
    const donations = await Donation.find().select('amount date');
    res.json(donations);
  } catch (err) {
    res.status(500).json({ msg: 'Server error' });
  }
});

// ─── Board Minutes ────────────────────────────────────────────────────────────

app.get('/api/board-minutes', async (req, res) => {
  try {
    const minutes = await BoardMinute.find().sort({ date: -1 });
    res.json(minutes);
  } catch (err) {
    console.error('Error fetching board minutes:', err);
    res.status(500).json({ success: false, message: 'Server error while fetching board minutes' });
  }
});

app.post('/api/board-minutes', authMiddleware, adminMiddleware, upload.single('file'), async (req, res) => {
  try {
    console.log('╔════════════════════════════════════════════════════╗');
    console.log('📄 BOARD MINUTES UPLOAD REQUEST');
    console.log('Time:', new Date().toISOString());
    console.log('Admin user ID:', req.user?.id || '(not set)');
    console.log('File received?', !!req.file);
    if (req.file) {
      console.log('  • Original name:', req.file.originalname);
      console.log('  • Size:', `${(req.file.size / 1024).toFixed(2)} KB`);
      console.log('  • MIME type:', req.file.mimetype);
      console.log('  • Cloudinary path:', req.file.path || '(not generated)');
    } else {
      console.log('  ❌ NO FILE RECEIVED');
    }
    console.log('Title:', req.body.title || '(missing)');
    console.log('╚════════════════════════════════════════════════════╝');

    if (!req.file) return res.status(400).json({ success: false, message: 'PDF file is required (field name must be "file")' });
    if (req.file.size > 10 * 1024 * 1024) return res.status(400).json({ success: false, message: 'File too large. Maximum allowed size is 10MB' });
    if (!req.file.mimetype.includes('pdf')) return res.status(400).json({ success: false, message: 'Only PDF files are allowed' });
    if (!req.body.title?.trim()) return res.status(400).json({ success: false, message: 'Title is required' });

    const minute = new BoardMinute({ title: req.body.title.trim(), fileUrl: req.file.path });
    await minute.save();

    res.status(201).json({ success: true, message: 'Board minutes uploaded successfully', data: minute });
  } catch (err) {
    console.error('Board minutes upload error:', err);
    res.status(500).json({ success: false, message: 'Failed to upload board minutes', error: err.message });
  }
});

// ─── Admin Routes ─────────────────────────────────────────────────────────────

app.get('/api/admin/users', authMiddleware, adminMiddleware, async (req, res) => {
  const users = await User.find().select('-password');
  res.json(users);
});

app.put('/api/admin/users/:id', authMiddleware, adminMiddleware, async (req, res) => {
  const { isApproved } = req.body;
  try {
    const user = await User.findByIdAndUpdate(req.params.id, { isApproved }, { new: true }).select('-password');

    if (isApproved) {
      try {
        await sendEmail({
          to: user.email,
          toName: user.name || '',
          subject: '🎉 Your KGHS Alumni Account Has Been Approved!',
          htmlContent: `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; padding: 30px; background: #fff; border-radius: 15px; box-shadow: 0 10px 30px rgba(255,192,203,0.2);">
              <h1 style="color: #FFC0CB; text-align: center;">Welcome to the Family!</h1>
              <p style="font-size: 18px; color: #333;">Dear ${user.name},</p>
              <p style="font-size: 16px; line-height: 1.6; color: #555;">Congratulations! Your KGHS Alumni Network account has been <strong>approved</strong>.</p>
              <p style="font-size: 16px; line-height: 1.6; color: #555;">You can now log in and connect with fellow graduates, share memories, and stay updated on events.</p>
              <div style="text-align: center; margin: 40px 0;">
                <a href="https://kghsalumnae.org/login" style="background: #FFC0CB; color: white; padding: 15px 40px; text-decoration: none; border-radius: 50px; font-size: 18px; font-weight: bold;">Log In Now</a>
              </div>
              <p style="color: #777; font-size: 14px; text-align: center;">Warm regards,<br><strong>The KGHS Alumni Team</strong></p>
            </div>
          `,
        });
        console.log('Approval email sent to:', user.email);
      } catch (emailErr) {
        console.error('Failed to send approval email:', emailErr);
      }
    }

    res.json(user);
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: 'Server error' });
  }
});

// ─── Start Server ─────────────────────────────────────────────────────────────

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
