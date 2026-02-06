package com.sg.canteen.ui.cart

import kotlin.math.roundToInt

/**
 * Data model for an item in the shopping cart.
 * Designed for Jetpack Compose (immutable fields for safe state updates).
 */
data class CartItem(
    val id: String,
    val name: String,

    // ✅ Base Price (Original MRP per unit)
    val price: Int,

    val imageUrl: String?,

    // ✅ Changed to 'val' to ensure Compose detects state changes via .copy()
    val quantity: Int,

    // ✅ Offer % (e.g., 10 for 10% off)
    val offerPercent: Int = 0
) {
    /**
     * 💰 Calculation: Unit Price after applying the discount.
     * Uses Float math before rounding to ensure accuracy.
     */
    val unitPriceAfterDiscount: Int
        get() = if (offerPercent > 0) {
            (price - (price * (offerPercent / 100f))).roundToInt()
        } else {
            price
        }

    /**
     * 🧾 Line Total: Total cost for this item (Discounted Unit Price * Quantity).
     */
    val totalItemPrice: Int
        get() = unitPriceAfterDiscount * quantity

    /**
     * 🎉 Savings: Total amount saved for this specific item entry.
     */
    val itemSavings: Int
        get() = (price - unitPriceAfterDiscount) * quantity
}