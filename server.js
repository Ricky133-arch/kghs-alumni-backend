const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const dotenv = require('dotenv');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const paystack = require('paystack-api')(process.env.PAYSTACK_SECRET_KEY);
const nodemailer = require('nodemailer');

dotenv.config();
console.log('Paystack Secret Key loaded:', process.env.PAYSTACK_SECRET_KEY ? 'YES' : 'NO');
console.log('Paystack Secret Key value:', process.env.PAYSTACK_SECRET_KEY);
const app = express();
app.use(express.json());

// === FIXED: Proper CORS for live frontend ===
app.use(cors({
  origin: 'https://kghs-frontend.onrender.com', // Your live frontend URL
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

// === FIXED: Reliable email with Brevo (formerly Sendinblue) ===
const transporter = nodemailer.createTransport({
  host: 'smtp-relay.brevo.com',
  port: 587,
  auth: {
    user: process.env.EMAIL_USER,     // Your Brevo sender email
    pass: process.env.EMAIL_PASS,     // Your Brevo SMTP key
  },
});

// Cloudinary Config
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// Multer for Uploads (supports images and PDFs)
const storage = new CloudinaryStorage({
  cloudinary,
  params: {
    folder: 'kghs',
    resource_type: 'auto', // Important: allows PDFs and images
  },
});
const upload = multer({ storage });

// MongoDB Connect
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.log(err));

// Schemas
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
});
const User = mongoose.model('User', userSchema);

const eventSchema = new mongoose.Schema({
  title: String,
  description: String,
  date: Date,
  location: String,
  creator: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
});
const Event = mongoose.model('Event', eventSchema);

const newsSchema = new mongoose.Schema({
  title: String,
  content: String,
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
    date: { type: Date, default: Date.now } 
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
  date: { type: Date, default: Date.now },
});
const Donation = mongoose.model('Donation', donationSchema);

// === BOARD MINUTES SCHEMA ===
const boardMinuteSchema = new mongoose.Schema({
  title: { type: String, required: true },
  fileUrl: { type: String, required: true }, // Cloudinary PDF URL
  date: { type: Date, default: Date.now },
});
const BoardMinute = mongoose.model('BoardMinute', boardMinuteSchema);

// Auth Middleware
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

// Admin Middleware
const adminMiddleware = async (req, res, next) => {
  const user = await User.findById(req.user.id);
  if (!user || user.role !== 'admin') return res.status(403).json({ msg: 'Admin access required' });
  next();
};

// Auth Routes
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

    user = new User({
      email,
      password: hashedPassword,
      name,
      graduationYear,
      isApproved: false,
    });
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
    res.json({ 
      token, 
      user: { 
        id: user._id, 
        email: user.email, 
        name: user.name, 
        role: user.role 
      } 
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: 'Server error' });
  }
});

// Profile Routes
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

// Alumni Directory
app.get('/api/directory', authMiddleware, async (req, res) => {
  const { year, location } = req.query;
  const filter = { isApproved: true };
  if (year) filter.graduationYear = year;
  if (location) filter.location = { $regex: location, $options: 'i' };

  const users = await User.find(filter).select('-password -isApproved');
  res.json(users);
});

// Events
app.get('/api/events', async (req, res) => {
  const events = await Event.find().populate('creator', 'name').sort({ date: -1 });
  res.json(events);
});

app.post('/api/events', authMiddleware, async (req, res) => {
  const event = new Event({ ...req.body, creator: req.user.id });
  await event.save();
  res.json(event);
});

// News
app.get('/api/news', async (req, res) => {
  const news = await News.find().populate('author', 'name').sort({ date: -1 });
  res.json(news);
});

app.post('/api/news', authMiddleware, adminMiddleware, async (req, res) => {
  const newsItem = new News({ ...req.body, author: req.user.id });
  await newsItem.save();
  res.json(newsItem);
});

// Forums
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

// Gallery
app.get('/api/gallery', async (req, res) => {
  const images = await Gallery.find().populate('uploader', 'name').sort({ date: -1 });
  res.json(images);
});

app.post('/api/gallery', authMiddleware, upload.single('image'), async (req, res) => {
  const image = new Gallery({ 
    url: req.file.path, 
    caption: req.body.caption, 
    uploader: req.user.id 
  });
  await image.save();
  res.json(image);
});

// Paystack Donations - Improved with detailed error logging
app.post('/api/donations/create-payment', authMiddleware, async (req, res) => {
  const { amount, currency = 'NGN' } = req.body;

  try {
    if (!amount || amount < 1) {
      return res.status(400).json({ msg: 'Invalid amount' });
    }

    const validCurrency = currency.toUpperCase() === 'USD' ? 'USD' : 'NGN';

    const response = await paystack.transaction.initialize({
      amount: Math.round(amount * 100),
      email: req.user.email || 'alumni@kghs.com',
      currency: validCurrency,
      reference: `kghs-don-${Date.now()}-${Math.random().toString(36).substring(7)}`,
      callback_url: 'http://localhost:5174/donations/success',
      metadata: { 
        userId: req.user.id,
        currency: validCurrency
      },
    });

    res.json({ authorization_url: response.data.authorization_url });
  } catch (err) {
    // Log full error in server terminal
    console.error('Paystack initialization error:', err.response?.data || err.message || err);

    // Send useful error to frontend
    const errorMessage = err.response?.data?.message || err.message || 'Unknown error';
    res.status(500).json({ 
      msg: 'Payment initialization failed', 
      details: errorMessage 
    });
  }
});

app.get('/api/donations/verify/:reference', authMiddleware, async (req, res) => {
  try {
    const response = await paystack.transaction.verify(req.params.reference);
    if (response.data.status === 'success') {
      const donation = new Donation({
        amount: response.data.amount / 100,
        donor: req.user.id,
      });
      await donation.save();
      res.json({ success: true, message: 'Donation successful!' });
    } else {
      res.status(400).json({ success: false });
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
// === BOARD MINUTES ROUTES ===
app.get('/api/board-minutes', authMiddleware, async (req, res) => {
  try {
    const minutes = await BoardMinute.find().sort({ date: -1 });
    res.json(minutes);
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: 'Server error' });
  }
});

app.post('/api/board-minutes', authMiddleware, adminMiddleware, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ msg: 'PDF file is required' });
    if (!req.body.title) return res.status(400).json({ msg: 'Title is required' });

    const minute = new BoardMinute({
      title: req.body.title,
      fileUrl: req.file.path, // Cloudinary URL
    });

    await minute.save();
    res.json(minute);
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: 'Upload failed' });
  }
});
// Admin Routes
app.get('/api/admin/users', authMiddleware, adminMiddleware, async (req, res) => {
  const users = await User.find().select('-password');
  res.json(users);
});

app.put('/api/admin/users/:id', authMiddleware, adminMiddleware, async (req, res) => {
  const { isApproved } = req.body;
  try {
    const user = await User.findByIdAndUpdate(req.params.id, { isApproved }, { new: true }).select('-password');

    if (isApproved) {
      const mailOptions = {
        from: process.env.EMAIL_USER,
        to: user.email,
        subject: '🎉 Your KGHS Alumni Account Has Been Approved!',
        html: `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; padding: 30px; background: #fff; border-radius: 15px; box-shadow: 0 10px 30px rgba(255,192,203,0.2);">
            <h1 style="color: #FFC0CB; text-align: center;">Welcome to the Family!</h1>
            <p style="font-size: 18px; color: #333;">Dear ${user.name},</p>
            <p style="font-size: 16px; line-height: 1.6; color: #555;">
              Congratulations! Your KGHS Alumni Network account has been <strong>approved</strong>.
            </p>
            <p style="font-size: 16px; line-height: 1.6; color: #555;">
              You can now log in and connect with fellow graduates, share memories, and stay updated on events.
            </p>
            <div style="text-align: center; margin: 40px 0;">
              <a href="https://kghs-frontend.onrender.com/login" style="background: #FFC0CB; color: white; padding: 15px 40px; text-decoration: none; border-radius: 50px; font-size: 18px; font-weight: bold;">
                Log In Now
              </a>
            </div>
            <p style="color: #777; font-size: 14px; text-align: center;">
              Warm regards,<br><strong>The KGHS Alumni Team</strong>
            </p>
          </div>
        `,
      };
      await transporter.sendMail(mailOptions);
    }

    res.json(user);
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: 'Server error' });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));