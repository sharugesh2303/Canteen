package com.sg.canteen.ui.cart

import androidx.compose.runtime.State
import androidx.compose.runtime.derivedStateOf
import androidx.compose.runtime.mutableStateListOf

object CartState {

    val cartItems = mutableStateListOf<CartItem>()

    /* ================= ADD ITEM ================= */
    fun addItem(
        id: String,
        name: String,
        finalPrice: Int,
        imageUrl: String?,
        originalPrice: Int? = null,
        offerPercent: Int = 0   // ✅ NEW PARAMETER
    ) {
        val index = cartItems.indexOfFirst { it.id == id }

        if (index >= 0) {
            val item = cartItems[index]
            cartItems[index] = item.copy(quantity = item.quantity + 1)
        } else {
            cartItems.add(
                CartItem(
                    id = id,
                    name = name,
                    price = finalPrice,
                    imageUrl = imageUrl,
                    quantity = 1,
                    originalPrice = originalPrice,
                    offerPercent = offerPercent   // ✅ SAVE OFFER %
                )
            )
        }
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
            }
        }
    }

    /* ================= TOTALS & SAVINGS ================= */

    fun clearCart() {
        cartItems.clear()
    }

    fun totalPrice(): Int {
        return cartItems.sumOf { it.price * it.quantity }
    }

    fun totalSavings(): Int {
        return cartItems.sumOf { item ->
            val original = item.originalPrice ?: item.price
            if (original > item.price) {
                (original - item.price) * item.quantity
            } else 0
        }
    }

    val totalItemCount: State<Int> = derivedStateOf {
        cartItems.sumOf { it.quantity }
    }
}
