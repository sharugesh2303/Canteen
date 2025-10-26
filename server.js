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

// --- Import Models & Middleware (ASSUMING THESE FILES EXIST) ---
// NOTE: These imports assume you have corresponding files (e.g., ./models/Student)
const Student = require('./models/Student');
const MenuItem = require('./models/MenuItem');
const Order = require('./models/Order');
const Admin = require('./models/Admin');
const Feedback = require('./models/Feedback');
const Advertisement = require('./models/Advertisement');
const SubCategory = require('./models/SubCategory');
const DeliveryStaff = require('./models/DeliveryStaff');
const auth = require('./middleware/auth'); // Student Auth
const adminAuth = require('./middleware/adminAuth'); // Admin/Chef Auth
const deliveryAuth = require('./middleware/deliveryAuth'); // Delivery Staff Auth

// --- CanteenStatus Model Definition ---
const CanteenStatus = mongoose.models.CanteenStatus || mongoose.model('CanteenStatus', new mongoose.Schema({
    key: { type: String, default: 'GLOBAL_STATUS', unique: true },
    isOpen: { type: Boolean, default: true, required: true },
}));

// --- GLOBAL SERVICE HOURS STORE (In-memory) ---
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
if (!JWT_SECRET || !mongoURI) {
    console.error("FATAL ERROR: JWT_SECRET or MONGO_URI is missing.");
    process.exit(1);
}

const app = express();
const PORT = process.env.PORT || 10000;

// --- Nodemailer Transporter Setup ---
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: { user: GMAIL_USER, pass: GMAIL_APP_PASSWORD }
});

// --- Middleware Setup ---
const whitelist = [
    'https://chefui.vercel.app', 'https://jj-canteen-admin.vercel.app', 
    'https://jjcetcanteen.vercel.app', 'https://jcetcanteen.vercel.app', 
    'http://localhost:5173', 'http://localhost:5174', 'http://localhost:5175'
];
const corsOptions = {
    origin: function (origin, callback) {
        if (whitelist.indexOf(origin) !== -1 || !origin) { callback(null, true); } 
        else { 
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
mongoose.connect(mongoURI).then(() => {
    console.log('MongoDB Connected...');
    CanteenStatus.findOneAndUpdate(
        { key: 'GLOBAL_STATUS' },
        { $setOnInsert: { isOpen: true } },
        { upsert: true, new: true, setDefaultsOnInsert: true }
    ).then(status => console.log(`Canteen Status initialized: ${status.isOpen ? 'OPEN' : 'CLOSED'}`)).catch(err => console.error("Status init error:", err));
}).catch(err => console.error('--- Mongoose Connection ERROR: ---', err));

// --- Razorpay Initialization ---
if (!RAZORPAY_KEY_ID || !RAZORPAY_KEY_SECRET) {
    console.error("FATAL ERROR: Razorpay keys are MISSING or empty. Payment will not work.");
    process.exit(1);
}
const razorpay = new Razorpay({ key_id: RAZORPAY_KEY_ID, key_secret: RAZORPAY_KEY_SECRET });

// --- Order Stock Process Helper ---
const processOrderStock = async (items) => {
    for (const item of items) {
        if (!item._id) { throw new Error(`Invalid item data: Missing _id for ${item.name || 'unknown item'}`); }
        const menuItem = await MenuItem.findById(item._id);
        if (!menuItem || menuItem.stock < item.quantity) {
            const availableStock = menuItem ? menuItem.stock : 0;
            throw new Error(`Not enough stock for ${item.name || 'item'}. Only ${availableStock} left.`);
        }
        menuItem.stock -= item.quantity;
        await menuItem.save();
    }
};

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

// --- SERVICE HOURS API ROUTES ---
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

// --- Canteen Status Routes ---
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

// Admin Orders (for Chef/Admin Dashboard)
app.get('/api/admin/orders', adminAuth, async (req, res) => {
    try {
        const thirtyMinutesAgo = new Date(Date.now() - 30 * 60 * 1000);
        const orders = await Order.find({
            $or: [
                { status: { $ne: 'Pending' } },
                { status: 'Pending', orderDate: { $gte: thirtyMinutesAgo } }
            ]
        })
        .sort({ orderDate: -1 })
        .populate('student', 'name email'); 
        
        // Map data to ensure studentName is available for the frontend table
        const ordersData = orders.map(order => ({
            ...order.toObject(),
            studentName: order.studentName || (order.student ? order.student.name : 'N/A')
        }));
        
        res.json(ordersData);
    } catch (err) {
        console.error("Error fetching admin orders:", err.message);
        res.status(500).send('Server Error');
    }
});

// Admin Daily Summary (omitted for brevity)
app.get('/api/admin/daily-summary', adminAuth, async (req, res) => { /* ... */ });

// Mark COD as Paid (omitted for brevity)
app.patch('/api/admin/orders/:id/mark-paid', adminAuth, async (req, res) => { /* ... */ });

// --- DELIVERY STAFF ROUTES (omitted for brevity) ---
app.post('/api/delivery/register', async (req, res) => { /* ... */ });
app.post('/api/delivery/login', async (req, res) => { /* ... */ });
app.get('/api/delivery/my-stats', deliveryAuth, async (req, res) => { /* ... */ });
app.put('/api/orders/:billNumber/delivered', deliveryAuth, async (req, res) => { /* ... */ });
app.get('/api/orders/bill/:billNumber', deliveryAuth, async (req, res) => { /* ... */ });

// --- Student Auth Routes (omitted for brevity) ---
const otpStore = {};
app.post('/api/auth/register-email-otp', async (req, res) => { /* ... */ });
app.post('/api/auth/verify-email-otp', async (req, res) => { /* ... */ });
app.post('/api/auth/login', async (req, res) => { /* ... */ });
app.post('/api/student/favorites/:itemId', auth, async (req, res) => { /* ... */ });
app.delete('/api/student/favorites/:itemId', auth, async (req, res) => { /* ... */ });

// --- Menu Routes (omitted for brevity) ---
const allowedCategories = ['Snacks', 'Breakfast', 'Lunch', 'Drinks', 'Stationery', 'Essentials'];
app.get('/api/menu', async (req, res) => { /* ... */ });
app.get('/api/admin/menu', adminAuth, async (req, res) => { /* ... */ });
app.get('/api/admin/menu/:id', adminAuth, async (req, res) => { /* ... */ });
app.post('/api/menu', adminAuth, upload.single('image'), async (req, res) => { /* ... */ });
app.put('/api/menu/:id', adminAuth, upload.single('image'), async (req, res) => { /* ... */ });
app.delete('/api/menu/:id', adminAuth, async (req, res) => { /* ... */ });

// --- Order & Payment Routes (omitted for brevity) ---
app.post('/api/payment/orders', auth, async (req, res) => { /* ... */ });
app.post('/api/payment/verify', auth, async (req, res) => { /* ... */ });
app.post('/api/orders/cod', auth, async (req, res) => { /* ... */ });
app.get('/api/orders/my-history', auth, async (req, res) => { /* ... */ });
app.get('/api/orders/:id', auth, async (req, res) => { /* ... */ });


// --- CHEF ACTION: Mark Order as Ready (FIXED TO RETURN UPDATED OBJECT) ---
app.patch('/api/admin/orders/:id/mark-ready', adminAuth, async (req, res) => {
    const { id } = req.params;
    try {
        // We use findByIdAndUpdate with { new: true } to atomically update and return the latest version.
        const updatedOrder = await Order.findByIdAndUpdate(
            id, 
            { $set: { status: 'Ready' } },
            { new: true } // CRITICAL: returns the *newly updated* document
        )
        .populate('student', 'name email'); // Populate student data before returning

        if (!updatedOrder) {
            return res.status(404).json({ msg: 'Order not found or status already marked.' });
        }
        
        // Return the fully updated object for instant frontend refresh
        res.json(updatedOrder); 
    } catch (err) {
        console.error("Error marking order as ready:", err.message);
        res.status(500).send('Server Error');
    }
});

// --- CHEF ACTION: Mark Order as Delivered (FIXED TO RETURN UPDATED OBJECT) ---
app.patch('/api/admin/orders/:id/mark-delivered', adminAuth, async (req, res) => {
    const { id } = req.params;
    try {
        // We use findByIdAndUpdate with { new: true } to atomically update and return the latest version.
        const updatedOrder = await Order.findByIdAndUpdate(
            id, 
            { 
                $set: { 
                    status: 'Delivered', 
                    deliveredAt: new Date()
                } 
            },
            { new: true } // CRITICAL: returns the *newly updated* document
        )
        .populate('student', 'name email'); // Populate student data before returning

        if (!updatedOrder) {
            return res.status(404).json({ msg: 'Order not found or already marked.' });
        }
        
        // Return the fully updated object for instant frontend refresh
        res.json(updatedOrder); 
    } catch (err) {
        console.error(`Error marking order ${id} as delivered:`, err.message);
        res.status(500).send('Server Error');
    }
});

// --- NEW: CHEF/STAFF API ROUTES (Alias for Admin, omitted for brevity) ---
app.post('/api/staff/login', async (req, res) => { /* ... */ });
app.get('/api/staff/orders', adminAuth, async (req, res) => { /* ... */ });

// --- FEEDBACK & ADVERTISEMENT ROUTES (omitted for brevity) ---
app.post('/api/feedback', auth, async (req, res) => { /* ... */ });
app.get('/api/admin/feedback', adminAuth, async (req, res) => { /* ... */ });
app.post('/api/admin/advertisements', adminAuth, upload.single('image'), async (req, res) => { /* ... */ });
app.delete('/api/admin/advertisements/:id', adminAuth, async (req, res) => { /* ... */ });

// --- SUBCATEGORY API ROUTES (omitted for brevity) ---
app.post('/api/admin/subcategories', [adminAuth, upload.single('image')], async (req, res) => { /* ... */ });
app.get('/api/subcategories', async (req, res) => { /* ... */ });

// Start the server
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server is running on http://0.0.0.0:${PORT}`);
});