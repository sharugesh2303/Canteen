package com.sg.canteen.ui.cart

import androidx.compose.runtime.State
import androidx.compose.runtime.derivedStateOf
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.setValue
import kotlin.math.roundToInt

/* ======================================================
    CART STATE (UI SINGLETON)
    Manages global cart logic and location tracking
====================================================== */
object CartState {

    // ✅ State List for dynamic UI updates
    val cartItems = mutableStateListOf<CartItem>()

    // ✅ Track current ordering location (Canteen/Cafeteria)
    var currentCartLocation by mutableStateOf<String?>(null)
        private set

    /* ================= ADD ITEM ================= */
    fun addItem(
        id: String,
        name: String,
        actualPrice: Int,
        imageUrl: String?,
        offerPercent: Int = 0,
        location: String
    ) {
        // Handle Location Lock: Cannot mix Canteen and Cafeteria in one order
        if (currentCartLocation != null && currentCartLocation != location) {
            clearCart()
        }
        currentCartLocation = location

        val index = cartItems.indexOfFirst { it.id == id }

        if (index >= 0) {
            val item = cartItems[index]
            // Update quantity and ensure the offer percentage is refreshed if it changed
            cartItems[index] = item.copy(
                quantity = item.quantity + 1,
                offerPercent = offerPercent
            )
        } else {
            cartItems.add(
                CartItem(
                    id = id,
                    name = name,
                    price = actualPrice,
                    imageUrl = imageUrl,
                    quantity = 1,
                    offerPercent = offerPercent
                )
            )
        }
    }

    /* ================= PRICE HELPERS ================= */

    /**
     * Calculates the unit price after applying the discount percentage.
     */
    fun finalUnitPrice(item: CartItem): Int {
        val base = item.price
        val offer = item.offerPercent
        return if (offer > 0) {
            // Calculate discounted price: Base - (Base * percentage)
            (base - (base * offer / 100f)).roundToInt()
        } else {
            base
        }
    }

    /**
     * Total price for a specific line item (discounted price * quantity).
     */
    fun subTotal(item: CartItem): Int {
        return finalUnitPrice(item) * item.quantity
    }

    /**
     * Total amount saved on a specific line item due to offers.
     */
    fun savings(item: CartItem): Int {
        val savedPerUnit = item.price - finalUnitPrice(item)
        return savedPerUnit * item.quantity
    }

    /* ================= QUANTITY MANAGEMENT ================= */

    fun increaseQuantity(id: String) {
        val index = cartItems.indexOfFirst { it.id == id }
        if (index >= 0) {
            val item = cartItems[index]
            cartItems[index] = item.copy(quantity = item.quantity + 1)
        }
    }

    fun decreaseQuantity(id: String) {
        val index = cartItems.indexOfFirst { it.id == id }
        if (index >= 0) {
            val item = cartItems[index]
            if (item.quantity > 1) {
                cartItems[index] = item.copy(quantity = item.quantity - 1)
            } else {
                cartItems.removeAt(index)
                if (cartItems.isEmpty()) currentCartLocation = null
            }
        }
    }

    /* ================= TOTALS ================= */

    fun clearCart() {
        cartItems.clear()
        currentCartLocation = null
    }

    /**
     * Sum of all item subtotals (using discounted prices).
     */
    fun totalPrice(): Int {
        return cartItems.sumOf { subTotal(it) }
    }

    /**
     * Sum of all savings across all items.
     */
    fun totalSavings(): Int {
        return cartItems.sumOf { savings(it) }
    }

    // ✅ Derived state for efficient UI item count badges
    val totalItemCount: State<Int> = derivedStateOf {
        cartItems.sumOf { it.quantity }
    }
}