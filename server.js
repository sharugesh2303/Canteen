const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { nanoid } = require('nanoid');
const path = require('path');
const multer = require('multer');
const Razorpay = require('razorpay');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const cron = require('node-cron');

// 1. Load environment variables from .env file
require('dotenv').config();

// --- Import Models & Middleware ---
const Student = require('./models/Student');
const MenuItem = require('./models/MenuItem');
const Order = require('./models/Order');
const Admin = require('./models/Admin');
const Feedback = require('./models/Feedback');
const Advertisement = require('./models/Advertisement');
const auth = require('./middleware/auth');
const adminAuth = require('./middleware/adminAuth');

// 2. Read keys securely from process.env
const mongoURI = process.env.MONGO_URI;
const RAZORPAY_KEY_ID = process.env.RAZORPAY_KEY_ID;
const RAZORPAY_KEY_SECRET = process.env.RAZORPAY_KEY_SECRET;
const JWT_SECRET = process.env.JWT_SECRET;
const GMAIL_USER = process.env.GMAIL_USER;
const GMAIL_APP_PASSWORD = process.env.GMAIL_APP_PASSWORD;

// Safety check for critical environment variables
if (!JWT_SECRET) {
    console.error("FATAL ERROR: JWT_SECRET is not defined in the .env file.");
    process.exit(1);
}
if (!mongoURI) {
    console.error("FATAL ERROR: MONGO_URI is not defined in the .env file.");
    process.exit(1);
}

const app = express();
const PORT = process.env.PORT || 5000;

// --- Middleware Setup ---

// --- MODIFIED ---
// 1. Moved CORS to be the FIRST middleware.
// 2. This single block handles all requests, including OPTIONS.
app.use(cors({
  origin: "*", // Allow all origins (for development)
  methods: ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"], // Allow all methods
  allowedHeaders: ["Content-Type", "x-auth-token", "Authorization"] // Allow necessary headers
}));

// --- MODIFIED --- Removed the bad app.options('*', cors()); line

app.use(express.json()); // This must come AFTER cors
app.use((req, res, next) => { console.log(`Incoming Request: ${req.method} ${req.url}`); next(); });
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));


// --- Nodemailer Transporter Setup ---
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: GMAIL_USER,
        pass: GMAIL_APP_PASSWORD,
    }
});

const storage = multer.diskStorage({
    destination: (req, file, cb) => { cb(null, path.join(__dirname, 'uploads/')); },
    filename: (req, file, cb) => { cb(null, Date.now() + path.extname(file.originalname)); }
});
const upload = multer({ storage: storage });

// --- Database Connection ---
mongoose.connect(mongoURI)
    .then(() => console.log('MongoDB Connected...'))
    .catch(err => console.error('--- Mongoose Connection ERROR: ---', err));

// --- Initialize Razorpay ---
const razorpay = new Razorpay({
    key_id: RAZORPAY_KEY_ID,
    key_secret: RAZORPAY_KEY_SECRET,
});

// =========================================================
// !!! AUTOMATED BILL CLEANUP LOGIC !!!
// =========================================================
const cleanupExpiredBills = async () => {
    try {
        const thirtyMinutesAgo = new Date(Date.now() - 30 * 60 * 1000);
        const expiredBills = await Order.find({ status: 'Pending', orderDate: { $lt: thirtyMinutesAgo } });
        if (expiredBills.length === 0) {
            console.log('No expired pending bills found to clean up.');
            return;
        }
        const cleanupPromises = expiredBills.map(async (bill) => {
            await Promise.all(bill.items.map(async (item) => {
                await MenuItem.findByIdAndUpdate(item._id, { $inc: { stock: item.quantity } });
            }));
            await Order.findByIdAndDelete(bill._id);
        });
        await Promise.all(cleanupPromises);
        console.log(`SUCCESS: Cleaned up ${expiredBills.length} expired pending bills and reverted stock.`);
    } catch (err) {
        console.error("ERROR during automated cleanup:", err.message);
    }
};
cron.schedule('*/30 * * * *', () => {
  console.log('Running automated expired bill cleanup...');
  cleanupExpiredBills();
});

// ================== API ROUTES ==================

// --- DATABASE CONNECTION TEST ROUTE ---
app.get('/api/test-db', async (req, res) => { try { await mongoose.connection.db.admin().ping(); res.status(200).send("Database connection is alive!"); } catch (err) { res.status(500).send("Failed to connect to the database."); } });

// --- Admin Auth & Management Routes ---
app.post('/api/admin/login', async (req, res) => { const { email, password } = req.body; try { const admin = await Admin.findOne({ email }); if (!admin) { return res.status(400).json({ message: 'Invalid credentials.' }); } const isMatch = await bcrypt.compare(password, admin.password); if (!isMatch) { return res.status(400).json({ message: 'Invalid credentials.' }); } const payload = { admin: { id: admin.id } }; jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' }, (err, token) => { if (err) throw err; res.status(200).json({ message: "Admin login successful!", token: token }); }); } catch (err) { console.error(err.message); res.status(500).send('Server Error'); } });
app.get('/api/admin/orders', adminAuth, async (req, res) => { try { const thirtyMinutesAgo = new Date(Date.now() - 30 * 60 * 1000); const orders = await Order.find({ $or: [{ status: { $ne: 'Pending' } }, { status: 'Pending', orderDate: { $gte: thirtyMinutesAgo } }] }).sort({ orderDate: -1 }).populate('student', 'name'); res.json(orders); } catch (err) { console.error(err.message); res.status(500).send('Server Error'); } });
app.get('/api/admin/daily-summary', adminAuth, async (req, res) => { try { const { date } = req.query; if (!date) { return res.status(400).json({ message: 'Date query parameter is required.' }); } const startOfDay = new Date(date); startOfDay.setHours(0, 0, 0, 0); const endOfDay = new Date(date); endOfDay.setHours(23, 59, 59, 999); const orders = await Order.find({ $or: [{ status: 'Delivered' }, { status: 'Paid' }, { status: 'Ready' }], orderDate: { $gte: startOfDay, $lte: endOfDay } }).sort({ orderDate: 1 }); const summary = { totalOrders: orders.length, totalRevenue: orders.reduce((sum, order) => sum + order.totalAmount, 0), billDetails: orders.map(order => ({ billNumber: order.billNumber, studentName: order.studentName, totalAmount: order.totalAmount, paymentMethod: order.paymentMethod, status: order.status, orderDate: order.orderDate })) }; res.json(summary); } catch (err) { console.error(err.message); res.status(500).send('Server Error'); } });

// --- Student Auth Routes ---
const otpStore = {};
app.post('/api/auth/register-email-otp', async (req, res) => { const { name, email } = req.body; try { let student = await Student.findOne({ email }); if (student) { return res.status(400).json({ message: 'A student with this email already exists.' }); } const otp = Math.floor(100000 + Math.random() * 900000).toString(); otpStore[email] = { otp, name, email, timestamp: Date.now() }; const mailOptions = { from: GMAIL_USER, to: email, subject: 'JJ Canteen OTP Verification', html: `Your one-time password (OTP) is: <strong>${otp}</strong>. It is valid for 10 minutes.` }; await transporter.sendMail(mailOptions); console.log(`OTP sent to ${email}`); res.status(200).json({ message: 'OTP sent to your email. Please verify.' }); } catch (err) { console.error("Error sending OTP email:", err.message); res.status(500).send('Server Error: Failed to send OTP.'); } });
app.post('/api/auth/verify-email-otp', async (req, res) => { const { email, otp, password } = req.body; if (!otpStore[email] || otpStore[email].otp !== otp) { return res.status(400).json({ message: 'Invalid or expired OTP.' }); } const { name } = otpStore[email]; delete otpStore[email]; try { let student = new Student({ name, password, email }); const salt = await bcrypt.genSalt(10); student.password = await bcrypt.hash(password, salt); await student.save(); res.status(201).json({ message: 'Registration successful!' }); } catch (err) { console.error(err.message); res.status(500).send('Server Error'); } });
app.post('/api/auth/login', async (req, res) => { const { email, password } = req.body; try { const student = await Student.findOne({ email }); if (!student) { return res.status(400).json({ message: 'Invalid credentials.' }); } const isMatch = await bcrypt.compare(password, student.password); if (!isMatch) { return res.status(400).json({ message: 'Invalid credentials.' }); } const payload = { student: { id: student.id } }; jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' }, (err, token) => { if (err) throw err; res.status(200).json({ message: "Login successful!", token: token, student: { id: student.id, name: student.name, email: student.email, favorites: student.favorites } }); }); } catch (err) { console.error(err.message); res.status(500).send('Server Error'); } });
app.post('/api/student/favorites/:itemId', auth, async (req, res) => { try { const studentId = req.student.id; const itemId = req.params.itemId; const updatedStudent = await Student.findByIdAndUpdate(studentId, { $addToSet: { favorites: itemId } }, { new: true }); res.json(updatedStudent.favorites); } catch (err) { console.error("Error adding favorite:", err.message); res.status(500).send('Server Error'); } });
app.delete('/api/student/favorites/:itemId', auth, async (req, res) => { try { const studentId = req.student.id; const itemId = req.params.itemId; const updatedStudent = await Student.findByIdAndUpdate(studentId, { $pull: { favorites: itemId } }, { new: true }); res.json(updatedStudent.favorites); } catch (err) { console.error("Error removing favorite:", err.message); res.status(500).send('Server Error'); } });

// --- Menu Routes ---
app.get('/api/menu', async (req, res) => { try { const menuItems = await MenuItem.find({ isAvailable: true }); res.json(menuItems); } catch (err) { console.error(err.message); res.status(500).send('Server Error'); } });
app.get('/api/admin/menu', adminAuth, async (req, res) => { try { const menuItems = await MenuItem.find({}); res.json(menuItems); } catch (err) { console.error(err.message); res.status(500).send('Server Error'); } });
app.post('/api/menu', adminAuth, upload.single('image'), async (req, res) => { const { name, price, category, stock } = req.body; const isAvailable = Number(stock) > 0;
    // --- Using relative path instead of localhost
    const imageUrl = req.file ? `/uploads/${req.file.filename}` : ''; 
    try { const newItem = new MenuItem({ name, price, category, imageUrl, stock, isAvailable }); const item = await newItem.save(); res.json(item); } catch (err) { console.error(err.message); res.status(500).send('Server Error'); } });
app.put('/api/menu/:id', adminAuth, upload.single('image'), async (req, res) => { const { name, price, category, stock } = req.body; const isAvailable = Number(stock) > 0; const updateData = { name, price, category, stock, isAvailable }; 
    // --- Using relative path instead of localhost
    if (req.file) { updateData.imageUrl = `/uploads/${req.file.filename}`; } 
    try { const updatedItem = await MenuItem.findByIdAndUpdate(req.params.id, updateData, { new: true }); if (!updatedItem) return res.status(404).json({ msg: 'Menu item not found' }); res.json(updatedItem); } catch (err) { console.error(err.message); res.status(500).send('Server Error'); } });
app.delete('/api/menu/:id', adminAuth, async (req, res) => { try { const item = await MenuItem.findByIdAndDelete(req.params.id); if (!item) return res.status(404).json({ msg: 'Menu item not found' }); res.json({ msg: 'Menu item removed' }); } catch (err) { console.error(err.message); res.status(500).send('Server Error'); } });

// --- Order & Payment Routes ---
const processOrderStock = async (items) => { for (const item of items) { const menuItem = await MenuItem.findById(item._id); if (!menuItem || menuItem.stock < item.quantity) { throw new Error(`Not enough stock for ${item.name}. Only ${menuItem.stock} left.`); } menuItem.stock -= item.quantity; if (menuItem.stock <= 0) { menuItem.isAvailable = false; } await menuItem.save(); } };

app.post('/api/payment/orders', auth, async (req, res) => { try { const { amount } = req.body; const options = { amount: Math.round(amount * 100), currency: "INR", receipt: `receipt_order_${nanoid(8)}` }; const order = await razorpay.orders.create(options); if (!order) return res.status(500).send("Error creating Razorpay order"); res.json(order); } catch (err) { console.error("--- PAYMENT ORDER CREATION FAILED ---", err); res.status(500).send('Server Error'); } });
app.post('/api/payment/verify', auth, async (req, res) => { try { const { razorpay_order_id, razorpay_payment_id, razorpay_signature, orderPayload } = req.body; const sha = crypto.createHmac("sha256", RAZORPAY_KEY_SECRET); sha.update(`${razorpay_order_id}|${razorpay_payment_id}`); const digest = sha.digest("hex"); if (digest !== razorpay_signature) { return res.status(400).json({ msg: "Transaction is not legit!" }); } const { items, totalAmount } = orderPayload; await processOrderStock(items); const studentId = req.student.id; const student = await Student.findById(studentId); const billNumber = `JJ-${nanoid(8).toUpperCase()}`; const newOrder = new Order({ billNumber, student: studentId, studentName: student.name, email: student.email, items, totalAmount, paymentMethod: 'UPI', status: 'Paid', razorpayPaymentId: razorpay_payment_id }); const savedOrder = await newOrder.save(); res.status(201).json({ message: 'Payment successful!', order: savedOrder }); } catch (err) { console.error("UPI Order Error:", err.message); res.status(400).json({ message: err.message }); } });

app.get('/api/orders/my-history', auth, async (req, res) => { try { const studentId = req.student.id; const thirtyMinutesAgo = new Date(Date.now() - 30 * 60 * 1000); const orders = await Order.find({ student: studentId, status: { $ne: 'Delivered' }, $or: [{ status: 'Paid' }, { status: 'Ready' }, { status: 'Pending', orderDate: { $gte: thirtyMinutesAgo } }] }).sort({ orderDate: -1 }); res.json(orders); } catch (err) { console.error("Error fetching order history:", err.message); res.status(500).send('Server Error'); } });
app.patch('/api/admin/orders/:id/mark-ready', adminAuth, async (req, res) => {
    try {
        const order = await Order.findById(req.params.id);
        if (!order) {
            return res.status(404).json({ msg: 'Order not found' });
        }
        if (order.status !== 'Paid') {
            return res.status(400).json({ msg: 'Only paid orders can be marked as ready.' });
        }
        order.status = 'Ready';
        await order.save();
        res.json(order);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

// --- FEEDBACK API ROUTES ---
app.post('/api/feedback', auth, async (req, res) => { const { feedbackText } = req.body; if (!feedbackText) { return res.status(400).json({ message: 'Feedback text is required.' }); } try { const student = await Student.findById(req.student.id).select('name'); const newFeedback = new Feedback({ student: req.student.id, studentName: student.name, feedbackText }); await newFeedback.save(); res.status(201).json({ message: 'Feedback submitted successfully!' }); } catch (err) { console.error("Error submitting feedback:", err.message); res.status(500).send('Server Error'); } });

app.get('/api/admin/feedback', adminAuth, async (req, res) => { try { const feedbacks = await Feedback.find().sort({ createdAt: -1 }); res.json(feedbacks); } catch (err) { console.error("Error fetching feedback:", err.message); res.status(500).send('Server Error'); } });

// =========================================================
// !!!         	ADVERTISEMENT API ROUTES 	          !!!
// =========================================================
app.get('/api/advertisements/active', async (req, res) => {
    try {
        const activeAds = await Advertisement.find({ isActive: true });
        res.json(activeAds);
    } catch (err) {
        console.error("Error fetching active ads:", err.message);
        res.status(500).send('Server Error');
    }
});
app.get('/api/admin/advertisements', adminAuth, async (req, res) => {
    try {
        const allAds = await Advertisement.find().sort({ uploadedAt: -1 });
        res.json(allAds);
    } catch (err) {
        console.error("Error fetching all ads:", err.message);
        res.status(500).send('Server Error');
    }
});
app.post('/api/admin/advertisements', adminAuth, upload.single('image'), async (req, res) => {
    if (!req.file) {
        return res.status(400).json({ message: 'Image file is required.' });
    }
    try {
        // --- Using relative path instead of localhost
        const imageUrl = `/uploads/${req.file.filename}`;
        const newAd = new Advertisement({ imageUrl, isActive: true });
        await newAd.save();
        res.status(201).json(newAd);
    } catch (err) {
        console.error("Error uploading ad:", err.message);
        res.status(500).send('Server Error');
    }
});
app.delete('/api/admin/advertisements/:id', adminAuth, async (req, res) => {
    try {
        const ad = await Advertisement.findByIdAndDelete(req.params.id);
        if (!ad) return res.status(404).json({ msg: 'Advertisement not found' });
        res.json({ msg: 'Advertisement removed' });
    } catch (err) {
        console.error("Error deleting ad:", err.message);
        res.status(500).send('Server Error');
    }
});
app.patch('/api/admin/advertisements/:id/toggle', adminAuth, async (req, res) => {
    try {
        const ad = await Advertisement.findById(req.params.id);
        if (!ad) return res.status(404).json({ msg: 'Advertisement not found' });
        ad.isActive = !ad.isActive;
        await ad.save();
        res.json(ad);
    } catch (err) {
        console.error("Error toggling ad status:", err.message);
        res.status(500).send('Server Error');
    }
});

// ================================================

// --- Start the server
// This host binding allows the server to be accessible from your local network
const HOST = '0.0.0.0';
app.listen(PORT, HOST, () => {
    console.log(`Server is running on http://${HOST}:${PORT}`);
    console.log(`(Also accessible on http://localhost:${PORT} from this machine)`);
});