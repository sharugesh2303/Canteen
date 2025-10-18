// models/MenuItem.js
const mongoose = require('mongoose');

const MenuItemSchema = new mongoose.Schema({
    // ... your existing fields: name, price, category, imageUrl, isAvailable
    name: { type: String, required: true },
    price: { type: Number, required: true },
    category: { type: String, required: true },
    imageUrl: { type: String },
    isAvailable: { type: Boolean, default: true },
    // --- ADD THIS LINE ---
    stock: { type: Number, required: true, default: 0 }
});

module.exports = mongoose.model('MenuItem', MenuItemSchema);