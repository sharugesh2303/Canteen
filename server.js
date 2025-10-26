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
const fs = require('fs');

// 1. Load environment variables from .env file
require('dotenv').config();

// --- Import Models & Middleware ---
const Student = require('./models/Student');
const MenuItem = require('./models/MenuItem');
const Order = require('./models/Order');
const Admin = require('./models/Admin');
const Feedback = require('./models/Feedback');
const Advertisement = require('./models/Advertisement');
const SubCategory = require('./models/SubCategory');
const DeliveryStaff = require('./models/DeliveryStaff');
const auth = require('./middleware/auth');
const adminAuth = require('./middleware/adminAuth');
const deliveryAuth = require('./middleware/deliveryAuth');

// --- CanteenStatus Model Definition ---
const CanteenStatus = mongoose.models.CanteenStatus || mongoose.model('CanteenStatus', new mongoose.Schema({
    key: { type: String, default: 'GLOBAL_STATUS', unique: true },
    isOpen: { type: Boolean, default: true, required: true },
}));

// --- GLOBAL SERVICE HOURS STORE ---
let serviceHoursStore = {
    breakfastStart: '08:00',
    breakfastEnd: '11:00',
    lunchStart: '12:00',
    lunchEnd: '15:00',
};

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
const PORT = process.env.PORT || 10000;

// --- Nodemailer Transporter Setup ---
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: GMAIL_USER,
        pass: GMAIL_APP_PASSWORD,
    }
});

// --- Middleware Setup ---

// CORS Whitelist
const whitelist = [
    'https://chefui.vercel.app',
    'https://jj-canteen-admin.vercel.app', 
    'https://jjcetcanteen.vercel.app', // FINAL STUDENT FRONTEND URL
    'http://localhost:5173',                
    'http://localhost:5174',                
    'http://localhost:5175',                
];

const corsOptions = {
    origin: function (origin, callback) {
        if (whitelist.indexOf(origin) !== -1 || !origin) {
            callback(null, true);
        } else {
            console.warn(`CORS block: Origin not allowed - ${origin}`);
            callback(new Error(`Not allowed by CORS: ${origin}`));
        }
    },
    credentials: true,
};
app.use(cors(corsOptions));

app.use(express.json());
app.use((req, res, next) => { console.log(`Incoming Request: ${req.method} ${req.url}`); next(); });

app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

const storage = multer.diskStorage({
    destination: (req, file, cb) => { cb(null, path.join(__dirname, 'uploads/')); },
    filename: (req, file, cb) => { cb(null, Date.now() + path.extname(file.originalname)); }
});
const upload = multer({ storage: storage });

// --- Database Connection ---
mongoose.connect(mongoURI)
    .then(() => {
        console.log('MongoDB Connected...');
        CanteenStatus.findOneAndUpdate(
            { key: 'GLOBAL_STATUS' },
            { $setOnInsert: { isOpen: true } },
            { upsert: true, new: true, setDefaultsOnInsert: true }
        ).then(status => console.log(`Canteen Status initialized: ${status.isOpen ? 'OPEN' : 'CLOSED'}`)).catch(err => console.error("Status init error:", err));
    })
    .catch(err => console.error('--- Mongoose Connection ERROR: ---', err));

// --- Razorpay Initialization ---
if (!RAZORPAY_KEY_ID || !RAZORPAY_KEY_SECRET) {
    console.error("FATAL ERROR: Razorpay keys are MISSING or empty. Payment will not work.");
    process.exit(1);
}
const razorpay = new Razorpay({
    key_id: RAZORPAY_KEY_ID,
    key_secret: RAZORPAY_KEY_SECRET,
});

// --- Automated Cleanup Logic (omitted for brevity) ---
const cleanupExpiredBills = async () => {
    try {
        const thirtyMinutesAgo = new Date(Date.now() - 30 * 60 * 1000);
        const expiredBills = await Order.find({
            status: 'Pending',
            orderDate: { $lt: thirtyMinutesAgo }
        });
        if (expiredBills.length === 0) return;
        const cleanupPromises = expiredBills.map(async (bill) => {
            await Promise.all(bill.items.map(async (item) => {
                if (item._id) {
                    await MenuItem.findByIdAndUpdate(item._id, { $inc: { stock: item.quantity } });
                } else {
                    console.warn(`Skipping stock update for item without _id in bill ${bill.billNumber}`);
                }
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
app.get('/api/test-db', async (req, res) => {
    try {
        await mongoose.connection.db.admin().ping();
        res.status(200).send("Database connection is alive!");
    } catch (err) {
        res.status(500).send("Failed to connect to the database.");
    }
});

// --- NEW: SERVICE HOURS API ROUTES ---
app.get('/api/service-hours/public', async (req, res) => {
    res.json(serviceHoursStore);
});

app.patch('/api/admin/service-hours', adminAuth, async (req, res) => {
    const { breakfastStart, breakfastEnd, lunchStart, lunchEnd } = req.body;

    if (breakfastStart && breakfastEnd && lunchStart && lunchEnd) {
        serviceHoursStore = { breakfastStart, breakfastEnd, lunchStart, lunchEnd };
        console.log(`Service hours updated by admin: ${JSON.stringify(serviceHoursStore)}`);
        return res.status(200).json(serviceHoursStore);
    }

    return res.status(400).json({ message: 'Missing one or more required time fields.' });
});
// --- End Service Hours ---

// --- NEW: Canteen Status Routes ---
app.get('/api/canteen-status/public', async (req, res) => {
    try {
        const status = await CanteenStatus.findOne({ key: 'GLOBAL_STATUS' });
        res.json({ isOpen: status ? status.isOpen : true });
    } catch (err) {
        console.error("Error fetching public status:", err.message);
        res.status(500).json({ isOpen: true, message: 'Server error, assuming open.' });
    }
});

app.patch('/api/admin/canteen-status', adminAuth, async (req, res) => {
    const { isOpen: explicitStatus } = req.body;

    try {
        let newStatus;
        if (typeof explicitStatus === 'boolean') {
            newStatus = explicitStatus;
        } else {
            const currentStatus = await CanteenStatus.findOne({ key: 'GLOBAL_STATUS' });
            newStatus = currentStatus ? !currentStatus.isOpen : true;
        }

        const updatedStatus = await CanteenStatus.findOneAndUpdate(
            { key: 'GLOBAL_STATUS' },
            { isOpen: newStatus },
            { new: true, upsert: true }
        );

        console.log(`Canteen status set to: ${updatedStatus.isOpen ? 'OPEN' : 'CLOSED'}`);
        res.json({ isOpen: updatedStatus.isOpen });

    } catch (err) {
        console.error("Error updating canteen status:", err.message);
        res.status(500).send('Server Error');
    }
});
// --- End Canteen Status ---

// --- Admin Auth & Management Routes ---
app.post('/api/admin/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const admin = await Admin.findOne({ email }).select('+password');

        if (!admin) {
            return res.status(400).json({ message: 'Invalid credentials.' });
        }
        const isMatch = await bcrypt.compare(password, admin.password);

        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid credentials.' });
        }
        const payload = { admin: { id: admin.id } };
        jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' }, (err, token) => {
            if (err) throw err;
            res.status(200).json({ message: "Admin login successful!", token: token });
        });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

// Admin Orders
app.get('/api/admin/orders', adminAuth, async (req, res) => {
    try {
        const thirtyMinutesAgo = new Date(Date.now() - 30 * 60 * 1000);
        const orders = await Order.find({
            $or: [
                { status: { $ne: 'Pending' } },
                { status: 'Pending', orderDate: { $gte: thirtyMinutesAgo } }
            ]
        }).sort({ orderDate: -1 }).populate('student', 'name');
        res.json(orders);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

// Admin Daily Summary
app.get('/api/admin/daily-summary', adminAuth, async (req, res) => {
    try {
        const { date } = req.query;
        if (!date) { return res.status(400).json({ message: 'Date query parameter is required.' }); }
        const startOfDay = new Date(date);
        startOfDay.setHours(0, 0, 0, 0);
        const endOfDay = new Date(date);
        endOfDay.setHours(23, 59, 59, 999);
        const orders = await Order.find({
            $or: [
                { status: 'Delivered' },
                { status: 'Paid' },
                { status: 'Ready' }
            ],
            orderDate: { $gte: startOfDay, $lte: endOfDay }
        }).sort({ orderDate: 1 });
        const summary = {
            totalOrders: orders.length,
            totalRevenue: orders.reduce((sum, order) => sum + order.totalAmount, 0),
            billDetails: orders.map(order => ({
                billNumber: order.billNumber,
                studentName: order.studentName,
                totalAmount: order.totalAmount,
                paymentMethod: order.paymentMethod,
                status: order.status,
                orderDate: order.orderDate
            }))
        };
        res.json(summary);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

// Mark COD as Paid
app.patch('/api/admin/orders/:id/mark-paid', adminAuth, async (req, res) => { try { const order = await Order.findById(req.params.id); if (!order) { return res.status(404).json({ msg: 'Order not found' }); } if (order.paymentMethod !== 'Cash on Delivery' || order.status !== 'Pending') { return res.status(400).json({ msg: 'Only pending COD orders can be marked as paid.' }); } order.status = 'Paid'; await order.save(); res.json(order); } catch (err) { console.error(err.message); res.status(500).send('Server Error'); } });

// --- DELIVERY STAFF ROUTES ---
app.post('/api/delivery/register', async (req, res) => {
    const { username, password } = req.body;
    try {
        let staff = await DeliveryStaff.findOne({ username });
        if (staff) {
            return res.status(400).json({ message: 'Delivery staff with this username already exists.' });
        }
        staff = new DeliveryStaff({ username, password });
        const salt = await bcrypt.genSalt(10);
        staff.password = await bcrypt.hash(password, salt);
        await staff.save();
        res.status(201).json({ message: 'Delivery staff registered successfully!' });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

app.post('/api/delivery/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const staff = await DeliveryStaff.findOne({ username }).select('+password');
        if (!staff) {
            return res.status(400).json({ message: 'Invalid credentials.' });
        }
        const isMatch = await bcrypt.compare(password, staff.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid credentials.' });
        }
        const payload = { staff: { id: staff.id, username: staff.username } };
        jwt.sign(payload, JWT_SECRET, { expiresIn: '8h' }, (err, token) => {
            if (err) throw err;
            res.status(200).json({
                message: "Delivery login successful!",
                token: token,
                staff: { id: staff.id, username: staff.username }
            });
        });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

app.get('/api/delivery/my-stats', deliveryAuth, async (req, res) => {
    try {
        const staffId = req.staff.id;
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        const dailyCount = await Order.countDocuments({
            deliveredBy: staffId,
            status: 'Delivered',
            deliveredAt: { $gte: today }
        });
        res.json({ dailyCount });
    } catch (err) {
        console.error("Error fetching delivery stats:", err.message);
        res.status(500).send('Server Error');
    }
});

app.put('/api/orders/:billNumber/delivered', deliveryAuth, async (req, res) => {
    const { billNumber } = req.params;
    try {
        const order = await Order.findOne({ billNumber: billNumber.trim() });
        if (!order) {
            return res.status(404).json({ message: `Order with Bill Number ${billNumber} not found.` });
        }
        if (order.status === 'Delivered') {
            return res.status(400).json({ message: `Order #${billNumber} is already delivered.` });
        }
        if (order.status !== 'Ready') {
            return res.status(400).json({ message: `Order #${billNumber} must be 'Ready' to be delivered.` });
        }
        order.status = 'Delivered';
        order.deliveredAt = new Date();
        order.deliveredBy = req.staff.id;
        await order.save();
        res.json({ message: `Order #${billNumber} successfully marked as delivered.`, order });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

app.get('/api/orders/bill/:billNumber', deliveryAuth, async (req, res) => { const { billNumber } = req.params; try { const order = await Order.findOne({ billNumber: billNumber.trim() }); if (!order) { return res.status(404).json({ message: `Order with Bill Number ${billNumber} not found.` }); } res.json(order); } catch (err) { console.error(`Error fetching order ${billNumber}:`, err.message); res.status(500).send('Server Error'); } });
// --- END DELIVERY STAFF ROUTES ---

// --- Student Auth Routes ---
const otpStore = {};
app.post('/api/auth/register-email-otp', async (req, res) => { const { name, email } = req.body; try { let student = await Student.findOne({ email }); if (student) { return res.status(400).json({ message: 'A student with this email already exists.' }); } const otp = Math.floor(100000 + Math.random() * 900000).toString(); otpStore[email] = { otp, name, email, timestamp: Date.now() }; const mailOptions = { from: GMAIL_USER, to: email, subject: 'JJ Canteen OTP Verification', html: `Your one-time password (OTP) is: <strong>${otp}</strong>. It is valid for 10 minutes.` }; await transporter.sendMail(mailOptions); console.log(`OTP sent to ${email}`); res.status(200).json({ message: 'OTP sent to your email. Please verify.' }); } catch (err) { console.error("Error sending OTP email:", err.message); res.status(500).send('Server Error: Failed to send OTP.'); } });
app.post('/api/auth/verify-email-otp', async (req, res) => { const { email, otp, password } = req.body; if (!otpStore[email] || otpStore[email].otp !== otp) { return res.status(400).json({ message: 'Invalid or expired OTP.' }); } const { name } = otpStore[email]; delete otpStore[email]; try { let student = new Student({ name, password, email }); const salt = await bcrypt.genSalt(10); student.password = await bcrypt.hash(password, salt); await student.save(); res.status(201).json({ message: 'Registration successful!' }); } catch (err) { console.error(err.message); res.status(500).send('Server Error'); } });
app.post('/api/auth/login', async (req, res) => { const { email, password } = req.body; try { const student = await Student.findOne({ email }).select('+password'); if (!student) { return res.status(400).json({ message: 'Invalid credentials.' }); } const isMatch = await bcrypt.compare(password, student.password); if (!isMatch) { return res.status(400).json({ message: 'Invalid credentials.' }); } const payload = { student: { id: student.id } }; jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' }, (err, token) => { if (err) throw err; res.status(200).json({ message: "Login successful!", token: token, student: { id: student.id, name: student.name, email: student.email, favorites: student.favorites } }); }); } catch (err) { console.error(err.message); res.status(500).send('Server Error'); } });
app.post('/api/student/favorites/:itemId', auth, async (req, res) => { try { const studentId = req.student.id; const itemId = req.params.itemId; const updatedStudent = await Student.findByIdAndUpdate(studentId, { $addToSet: { favorites: itemId } }, { new: true }); res.json(updatedStudent.favorites); } catch (err) { console.error("Error adding favorite:", err.message); res.status(500).send('Server Error'); } });
app.delete('/api/student/favorites/:itemId', auth, async (req, res) => { try { const studentId = req.student.id; const itemId = req.params.itemId; const updatedStudent = await Student.findByIdAndUpdate(studentId, { $pull: { favorites: itemId } }, { new: true }); res.json(updatedStudent.favorites); } catch (err) { console.error("Error removing favorite:", err.message); res.status(500).send('Server Error'); } });
// --- End Student Auth ---


// --- Menu Routes ---
app.get('/api/menu', async (req, res) => {
    try {
        const status = await CanteenStatus.findOne({ key: 'GLOBAL_STATUS' });
        if (status && !status.isOpen) {
            return res.status(200).json([]);
        }

        const menuItems = await MenuItem.find({ stock: { $gt: 0 } })
            .populate('subCategory', 'name imageUrl');
        res.json(menuItems);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

// Admin get menu
app.get('/api/admin/menu', adminAuth, async (req, res) => {
    try {
        const menuItems = await MenuItem.find({})
            .populate('subCategory', 'name imageUrl');
        res.json(menuItems);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

// Admin get single menu item
app.get('/api/admin/menu/:id', adminAuth, async (req, res) => {
    try {
        const { id } = req.params;
        // Validate if id is a valid ObjectId
        if (!mongoose.Types.ObjectId.isValid(id)) {
            return res.status(400).json({ message: 'Invalid menu item ID format.' });
        }
        const item = await MenuItem.findById(id).populate('subCategory', 'name imageUrl');
        if (!item) {
            return res.status(404).json({ message: 'Menu item not found.' });
        }
        const startOfDay = new Date();
        startOfDay.setHours(0, 0, 0, 0);
        const orders = await Order.find({
            'items._id': id,
            orderDate: { $gte: startOfDay },
            status: { $ne: 'Pending' } // Consider only completed/paid orders for 'sold' count
        });
        let totalSoldToday = 0;
        orders.forEach(order => {
            const soldItem = order.items.find(i => i._id && i._id.toString() === id); // Add check for i._id
            if (soldItem) {
                totalSoldToday += soldItem.quantity;
            }
        });
        res.json({
            ...item._doc, // Use _doc to get plain object if needed, otherwise item is fine
            soldToday: totalSoldToday,
            remainingStock: item.stock
        });
    } catch (err) {
        console.error(`Error fetching menu item ${req.params.id}:`, err.message);
        // Avoid sending generic 'Server Error' if it's a client issue like invalid ID
        if (err.kind === 'ObjectId') {
            return res.status(400).json({ message: 'Invalid menu item ID format.' });
        }
        res.status(500).send('Server Error');
    }
});

// List of allowed categories, updated to include 'Essentials'
const allowedCategories = ['Snacks', 'Breakfast', 'Lunch', 'Drinks', 'Stationery', 'Essentials'];

// Create menu item
app.post('/api/menu', adminAuth, upload.single('image'), async (req, res) => {
    const { name, price, category, stock, subCategory } = req.body;

    // Basic Validation
    if (!name || !price || !category || stock === undefined) {
        return res.status(400).json({ msg: 'Missing required fields: name, price, category, stock.' });
    }
    // 🟢 ADDED: Validate category field
    if (!allowedCategories.includes(category)) {
        return res.status(400).json({ msg: `Invalid category: ${category}. Must be one of: ${allowedCategories.join(', ')}` });
    }
    if (category === 'Snacks' && !subCategory) {
        return res.status(400).json({ msg: 'Subcategory is required when category is Snacks.' });
    }


    const stockNumber = parseInt(stock, 10);
    if (isNaN(stockNumber) || stockNumber < 0) {
        return res.status(400).json({ msg: 'Stock must be a non-negative number.' });
    }

    const imageUrl = req.file ? `/uploads/${req.file.filename}` : '';

    try {
        const newItem = new MenuItem({
            name,
            price: parseFloat(price), // Ensure price is stored as number
            category,
            imageUrl,
            stock: stockNumber,
            // Only include subCategory if it's provided and valid
            subCategory: (subCategory && mongoose.Types.ObjectId.isValid(subCategory)) ? subCategory : null
        });
        const item = await newItem.save();
        // Populate after saving if needed for response
        await item.populate('subCategory', 'name imageUrl');
        res.status(201).json(item);
    } catch (err) {
        console.error("Error creating menu item:", err.message);
        // Provide more specific error if possible (e.g., validation error)
        if (err.name === 'ValidationError') {
            return res.status(400).json({ msg: err.message });
        }
        res.status(500).send('Server Error');
    }
});

// Update menu item
app.put('/api/menu/:id', adminAuth, upload.single('image'), async (req, res) => {
    const { name, price, category, stock, subCategory } = req.body;
    const { id } = req.params;

    // Validate ID
    if (!mongoose.Types.ObjectId.isValid(id)) {
        return res.status(400).json({ msg: 'Invalid menu item ID format.' });
    }
    // Basic Validation
    if (!name || !price || !category || stock === undefined) {
        return res.status(400).json({ msg: 'Missing required fields: name, price, category, stock.' });
    }
    // 🟢 ADDED: Validate category field
    if (!allowedCategories.includes(category)) {
        return res.status(400).json({ msg: `Invalid category: ${category}. Must be one of: ${allowedCategories.join(', ')}` });
    }
    if (category === 'Snacks' && !subCategory) {
        return res.status(400).json({ msg: 'Subcategory is required when category is Snacks.' });
    }


    const stockNumber = parseInt(stock, 10);
    if (isNaN(stockNumber) || stockNumber < 0) {
        return res.status(400).json({ msg: 'Stock must be a non-negative number.' });
    }

    const updateData = {
        name,
        price: parseFloat(price),
        category,
        stock: stockNumber,
        // Handle subCategory carefully - set to null if empty or invalid
        subCategory: (subCategory && mongoose.Types.ObjectId.isValid(subCategory)) ? subCategory : null
    };

    if (req.file) {
        updateData.imageUrl = `/uploads/${req.file.filename}`;
    }
    try {
        const updatedItem = await MenuItem.findByIdAndUpdate(id, updateData, { new: true });
        if (!updatedItem) return res.status(404).json({ msg: 'Menu item not found' });

        // Populate after update if needed for response
        await updatedItem.populate('subCategory', 'name imageUrl');
        res.json(updatedItem);
    } catch (err) {
        console.error(`Error updating menu item ${id}:`, err.message);
        if (err.name === 'ValidationError') {
            return res.status(400).json({ msg: err.message });
        }
        res.status(500).send('Server Error');
    }
});

// Delete menu item
app.delete('/api/menu/:id', adminAuth, async (req, res) => { try { const item = await MenuItem.findByIdAndDelete(req.params.id); if (!item) return res.status(404).json({ msg: 'Menu item not found' }); res.json({ msg: 'Menu item removed' }); } catch (err) { console.error(err.message); res.status(500).send('Server Error'); } });
// --- End Menu Routes ---

// --- Order & Payment Routes ---

// Process stock function
const processOrderStock = async (items) => {
    for (const item of items) {
        if (!item._id) { // Safety check
            throw new Error(`Invalid item data: Missing _id for ${item.name || 'unknown item'}`);
        }
        const menuItem = await MenuItem.findById(item._id);
        if (!menuItem || menuItem.stock < item.quantity) {
            const availableStock = menuItem ? menuItem.stock : 0;
            throw new Error(`Not enough stock for ${item.name || 'item'}. Only ${availableStock} left.`);
        }
        menuItem.stock -= item.quantity;
        await menuItem.save();
    }
};

// Create Payment Order
app.post('/api/payment/orders', auth, async (req, res) => {

    const status = await CanteenStatus.findOne({ key: 'GLOBAL_STATUS' });
    if (status && !status.isOpen) {
        return res.status(400).json({ message: 'Order rejected: Canteen is currently closed.' });
    }

    const { amount, items } = req.body;

    if (!amount || amount <= 0 || !items || items.length === 0) {
        console.error("Payment Order Failed: Missing amount or items in request body.");
        return res.status(400).json({ message: 'Invalid payment request: amount and items required.' });
    }

    const paymentAmount = Number(amount);
    if (isNaN(paymentAmount)) {
        console.error("Payment Order Failed: Amount is not a valid number.");
        return res.status(400).json({ message: 'Invalid payment request: amount must be a number.' });
    }

    try {
        const options = {
            amount: Math.round(paymentAmount * 100),
            currency: "INR",
            receipt: `receipt_order_${nanoid(8)}`
        };

        const order = await razorpay.orders.create(options);

        if (!order) {
            console.error("Razorpay order creation failed unexpectedly.");
            return res.status(500).send("Error creating Razorpay order");
        }

        res.json(order);
    } catch (err) {
        console.error("--- PAYMENT ORDER CREATION FAILED (RAZORPAY/API ERROR) ---", err);
        res.status(500).json({ message: 'Payment processing failed on server.', details: err.message });
    }
});

// Verify Payment
app.post('/api/payment/verify', auth, async (req, res) => { try { const { razorpay_order_id, razorpay_payment_id, razorpay_signature, orderPayload } = req.body; const sha = crypto.createHmac("sha256", RAZORPAY_KEY_SECRET); sha.update(`${razorpay_order_id}|${razorpay_payment_id}`); const digest = sha.digest("hex"); if (digest !== razorpay_signature) { return res.status(400).json({ msg: "Transaction is not legit!" }); } const { items, totalAmount } = orderPayload; await processOrderStock(items); const studentId = req.student.id; const student = await Student.findById(studentId); const billNumber = `JJ-${nanoid(8).toUpperCase()}`; const newOrder = new Order({ billNumber, student: studentId, studentName: student.name, email: student.email, items, totalAmount, paymentMethod: 'UPI', status: 'Paid', razorpayPaymentId: razorpay_payment_id }); const savedOrder = await newOrder.save(); res.status(201).json({ message: 'Payment successful!', order: savedOrder }); } catch (err) { console.error("UPI Order Error:", err.message); res.status(400).json({ message: err.message }); } });

// COD Order
app.post('/api/orders/cod', auth, async (req, res) => { try { const { items, totalAmount } = req.body; await processOrderStock(items); const studentId = req.student.id; const student = await Student.findById(studentId); const billNumber = `JJ-${nanoid(8).toUpperCase()}`; const newOrder = new Order({ billNumber, student: studentId, studentName: student.name, email: student.email, items, totalAmount, paymentMethod: 'Cash on Delivery', status: 'Pending' }); const savedOrder = await newOrder.save(); res.status(201).json(savedOrder); } catch (err) { console.error("COD Order Error:", err.message); res.status(400).json({ message: err.message }); } });

// Student Order History
app.get('/api/orders/my-history', auth, async (req, res) => {
    try {
        const studentId = req.student.id;
        const thirtyMinutesAgo = new Date(Date.now() - 30 * 60 * 1000);

        const orders = await Order.find({
            student: studentId,
            status: { $ne: 'Delivered' },
            $or: [
                { status: 'Paid' },
                { status: 'Ready' },
                { status: 'Pending', orderDate: { $gte: thirtyMinutesAgo } }
            ]
        }).sort({ orderDate: -1 });

        res.json(orders);
    } catch (err) {
        console.error("Error fetching order history:", err.message);
        res.status(500).send('Server Error');
    }
});

// 🟢 NEW: Student Get Single Order Details Route
app.get('/api/orders/:id', auth, async (req, res) => {
    try {
        const { id } = req.params;
        const studentId = req.student.id;

        // Validate ID format
        if (!mongoose.Types.ObjectId.isValid(id)) {
            return res.status(400).json({ msg: 'Invalid Order ID format.' });
        }

        // Fetch the order, ensuring it belongs to the authenticated student
        const order = await Order.findOne({ _id: id, student: studentId });

        if (!order) {
            return res.status(404).json({ msg: 'Order not found or access denied.' });
        }

        res.json(order);
    } catch (err) {
        console.error(`Error fetching order ${req.params.id} for student ${req.student.id}:`, err.message);
        res.status(500).send('Server Error');
    }
});


// --- NEW: Order Status Routes (Chef Actions) ---

// 🔑 FIX APPLIED: Changed parameter from :id to :billNumber and used Order.findOne()
app.patch('/api/admin/orders/:billNumber/mark-ready', adminAuth, async (req, res) => {
    const { billNumber } = req.params;
    try {
        // Find order by Bill Number, as seen in the Chef Queue image
        const order = await Order.findOne({ billNumber: billNumber.trim() });

        if (!order) {
            // If the Bill Number is not found, return 404
            return res.status(404).json({ msg: `Order #${billNumber} not found.` });
        }

        if (order.status !== 'Paid') {
            return res.status(400).json({ msg: 'Only PAID orders can be marked as ready.' });
        }

        order.status = 'Ready';
        await order.save();
        res.json(order);
    } catch (err) {
        console.error("Error marking order as ready:", err.message);
        res.status(500).send('Server Error');
    }
});

app.patch('/api/admin/orders/:id/mark-delivered', adminAuth, async (req, res) => {
    try {
        const order = await Order.findById(req.params.id);
        if (!order) { return res.status(404).json({ msg: 'Order not found' }); }
        if (order.status !== 'Ready') { return res.status(400).json({ msg: 'Only ready orders can be marked as delivered.' }); }
        order.status = 'Delivered';
        order.deliveredAt = new Date();
        await order.save();
        console.log(`Order ${order.billNumber} marked as Delivered.`);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});
// --- End Order Status ---


// --- NEW: CHEF/STAFF API ROUTES (Alias for Admin) ---
app.post('/api/staff/login', async (req, res) => {
    console.log("Attempting login via /api/staff/login alias...");
    const { email, password } = req.body;

    try {
        // This route correctly uses select('+password')
        const admin = await Admin.findOne({ email }).select('+password');

        if (!admin) {
            return res.status(400).json({ message: 'Invalid credentials.' });
        }

        const isMatch = await bcrypt.compare(password, admin.password);

        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid credentials.' });
        }

        const payload = { admin: { id: admin.id } };

        jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' }, (err, token) => {
            if (err) throw err;
            res.status(200).json({ message: "Staff login successful!", token: token });
        });

    } catch (err) {
        console.error("STAFF (ADMIN) LOGIN ERROR:", err.message);
        res.status(500).send('Server Error');
    }
});

// Chef/Staff Order Dashboard - Shows orders that need preparation or are ready
app.get('/api/staff/orders', adminAuth, async (req, res) => {
    try {
        const orders = await Order.find({
            $or: [
                { status: 'Paid' }, // Needs preparation (from student or admin mark-paid)
                { status: 'Ready' } // Prepared, awaiting delivery
            ]
        })
            .sort({ orderDate: 1 }) // Show oldest orders first
            .populate('student', 'name');

        res.json(orders);
    } catch (err) {
        console.error("Error fetching staff orders:", err.message);
        res.status(500).send('Server Error');
    }
});
// --- End Chef Routes ---


// --- NEW: FEEDBACK API ROUTES ---
app.post('/api/feedback', auth, async (req, res) => { const { feedbackText } = req.body; if (!feedbackText) { return res.status(400).json({ message: 'Feedback text is required.' }); } try {
    const status = await CanteenStatus.findOne({ key: 'GLOBAL_STATUS' });
    if (status && !status.isOpen) {
        return res.status(400).json({ message: 'Feedback submission is disabled when the canteen is closed.' });
    }

    const student = await Student.findById(req.student.id).select('name'); const newFeedback = new Feedback({ student: req.student.id, studentName: student.name, feedbackText }); await newFeedback.save(); res.status(201).json({ message: 'Feedback submitted successfully!' }); } catch (err) { console.error("Error submitting feedback:", err.message); res.status(500).send('Server Error'); } });
app.get('/api/admin/feedback', adminAuth, async (req, res) => { try { const feedbacks = await Feedback.find().populate('student', 'name registerNumber').sort({ createdAt: -1 }); res.json(feedbacks); } catch (err) { console.error("Error fetching feedback:", err.message); res.status(500).send('Server Error'); } }); // <-- Corrected line

// --- Feedback "Mark as Read" Routes ---
app.patch('/api/admin/feedback/:id/read', adminAuth, async (req, res) => {
    try {
        const feedback = await Feedback.findById(req.params.id);
        if (!feedback) {
            return res.status(404).json({ msg: 'Feedback not found' });
        }
        if (feedback.isRead) {
            return res.json(feedback); // Already read, just return it
        }
        feedback.isRead = true;
        await feedback.save();
        res.json(feedback);
    } catch (err) {
        console.error("Error marking feedback as read:", err.message);
        res.status(500).send('Server Error');
    }
});
app.post('/api/admin/feedback/mark-all-read', adminAuth, async (req, res) => {
    try {
        const result = await Feedback.updateMany(
            { isRead: false },
            { $set: { isRead: true } }
        );
        console.log(`Marked ${result.modifiedCount} feedback items as read.`);
        res.json({ msg: `Marked ${result.modifiedCount} feedback items as read.` });
    } catch (err) {
        console.error("Error marking all feedback as read:", err.message);
        res.status(500).send('Server Error');
    }
});
// --- End Feedback Routes ---


// --- NEW: ADVERTISEMENT API ROUTES ---
app.get('/api/advertisements/active', async (req, res) => {
    try {
        const status = await CanteenStatus.findOne({ key: 'GLOBAL_STATUS' });
        if (status && !status.isOpen) {
            return res.status(200).json([]);
        }
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
        console.error("Error toggling ad status:", err.message);
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
// --- End Advertisement Routes ---


// --- NEW: SUBCATEGORY API ROUTES ---
app.post('/api/admin/subcategories', [adminAuth, upload.single('image')], async (req, res) => {
    const { name } = req.body;

    if (!req.file) {
        return res.status(400).json({ msg: 'Please upload an image' });
    }
    if (!name || name.trim() === '') { // Added trim check
        return res.status(400).json({ msg: 'Please provide a non-empty name' });
    }

    const imageUrl = `/uploads/${req.file.filename}`;

    try {
        // Case-insensitive check for existing name
        let sub = await SubCategory.findOne({ name: { $regex: new RegExp(`^${name.trim()}$`, 'i') } });
        if (sub) {
            // OPTIONAL: Delete the newly uploaded file since subcategory already exists
            fs.unlinkSync(req.file.path);
            return res.status(400).json({ msg: 'Subcategory with this name already exists.' });
        }
        sub = new SubCategory({
            name: name.trim(), // Trim name before saving
            imageUrl: imageUrl
        });
        await sub.save();
        res.status(201).json(sub);
    } catch (err) {
        console.error("Error creating subcategory:", err.message);
        if (err.name === 'ValidationError') {
            return res.status(400).json({ msg: err.message });
        }
        res.status(500).send('Server Error');
    }
});

app.get('/api/subcategories', async (req, res) => {
    try {
        const subcategories = await SubCategory.find().sort({ name: 1 });
        res.json(subcategories);
    } catch (err) {
        console.error("Error fetching subcategories:", err.message);
        res.status(500).send('Server Error');
    }
});

// Edit SubCategory Name AND Image
app.put('/api/admin/subcategories/:id', [adminAuth, upload.single('image')], async (req, res) => {
    const { name } = req.body;
    const { id } = req.params;

    if (!name || name.trim() === '') {
        if (req.file) { fs.unlinkSync(req.file.path); }
        return res.status(400).json({ msg: 'Please provide a non-empty name' });
    }
    if (!mongoose.Types.ObjectId.isValid(id)) {
        if (req.file) { fs.unlinkSync(req.file.path); }
        return res.status(400).json({ msg: 'Invalid subcategory ID format.' });
    }

    try {
        // 1. Check for duplicate name, excluding the current document
        const existingSub = await SubCategory.findOne({
            name: { $regex: new RegExp(`^${name.trim()}$`, 'i') },
            _id: { $ne: id } 
        });
        if (existingSub) {
            if (req.file) { fs.unlinkSync(req.file.path); }
            return res.status(400).json({ msg: 'Another subcategory with this name already exists.' });
        }

        // 2. Prepare update data
        const updateData = { name: name.trim() };
        let oldImagePath = null; 

        if (req.file) {
            // New image uploaded, save the new path
            updateData.imageUrl = `/uploads/${req.file.filename}`;
            
            // Get the old document to delete the old image later
            const oldSub = await SubCategory.findById(id).select('imageUrl');
            if (oldSub) { oldImagePath = oldSub.imageUrl; }
        }

        // 3. Perform update
        const updatedSub = await SubCategory.findByIdAndUpdate(
            id,
            updateData,
            { new: true }
        );

        if (!updatedSub) {
            // Delete new file if update failed (e.g., 404)
            if (req.file) { fs.unlinkSync(req.file.path); }
            return res.status(404).json({ msg: 'Subcategory not found' });
        }
        
        // 4. Delete old image file after successful database update
        if (oldImagePath && oldImagePath.startsWith('/uploads/')) {
             try {
                 const fullPath = path.join(__dirname, oldImagePath);
                 if (fs.existsSync(fullPath)) {
                     fs.unlinkSync(fullPath);
                     console.log(`Successfully deleted old image: ${oldImagePath}`);
                 }
             } catch (deleteError) {
                 console.error(`Warning: Failed to delete old image file ${oldImagePath}:`, deleteError.message);
                 // We ignore this error as the DB update was successful
             }
         }

        res.json(updatedSub);
    } catch (err) {
        console.error(`Error updating subcategory ${id}:`, err.message);
        // If the request was multipart/form-data and failed here, multer saved the file, so delete it.
        if (req.file) { fs.unlinkSync(req.file.path); } 
        if (err.name === 'ValidationError') {
            return res.status(400).json({ msg: err.message });
        }
        res.status(500).send('Server Error');
    }
});

// Delete SubCategory
// DELETE /api/admin/subcategories/:id
app.delete('/api/admin/subcategories/:id', adminAuth, async (req, res) => {
    const { id } = req.params;

    if (!mongoose.Types.ObjectId.isValid(id)) {
        return res.status(400).json({ msg: 'Invalid subcategory ID format.' });
    }

    try {
        // 1. Check if any MenuItems are using this SubCategory
        const itemsUsingSub = await MenuItem.find({ subCategory: id }).limit(1); 

        if (itemsUsingSub.length > 0) {
            return res.status(400).json({ msg: 'Cannot delete subcategory. Menu items are still assigned to it.' });
        }

        // 2. If no items are using it, proceed with deletion
        const sub = await SubCategory.findByIdAndDelete(id);

        if (!sub) {
            return res.status(404).json({ msg: 'Subcategory not found' });
        }

        // 3. OPTIONAL: Delete the image file associated with the subcategory from /uploads
        if (sub.imageUrl && sub.imageUrl.startsWith('/uploads/')) {
            try {
                const fullPath = path.join(__dirname, sub.imageUrl);
                if (fs.existsSync(fullPath)) {
                    fs.unlinkSync(fullPath);
                    console.log(`Successfully deleted old image: ${sub.imageUrl}`);
                }
            } catch (deleteError) {
                console.error(`Warning: Failed to delete old image file ${sub.imageUrl}:`, deleteError.message);
            }
        }

        res.json({ msg: 'Subcategory deleted successfully' });

    } catch (err) {
        console.error(`Error deleting subcategory ${id}:`, err.message);
        res.status(500).send('Server Error');
    }
});

// Start the server
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server is running on http://0.0.0.0:${PORT}`);
});