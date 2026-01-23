package com.sg.canteen.ui.cart

import androidx.compose.runtime.State
import androidx.compose.runtime.derivedStateOf
import androidx.compose.runtime.mutableStateListOf
import kotlin.math.roundToInt

object CartState {

    val cartItems = mutableStateListOf<CartItem>()

    /* ================= ADD ITEM ================= */
    fun addItem(
        id: String,
        name: String,
        actualPrice: Int,          // ✅ ORIGINAL / BASE PRICE ONLY
        imageUrl: String?,
        offerPercent: Int = 0      // ✅ OFFER %
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
                    price = actualPrice,          // ✅ base/original price
                    imageUrl = imageUrl,
                    quantity = 1,
                    offerPercent = offerPercent
                )
            )
        }
    }

    /* ================= PRICE HELPERS ================= */

    // ✅ final unit price after discount
    fun finalUnitPrice(item: CartItem): Int {
        val base = item.price
        val offer = item.offerPercent
        return if (offer > 0) {
            (base - (base * offer / 100f)).roundToInt()
        } else {
            base
        }
    }

    // ✅ subtotal per item
    fun subTotal(item: CartItem): Int {
        return finalUnitPrice(item) * item.quantity
    }

    // ✅ savings per item
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
            }
        }
    }

    /* ================= TOTALS & SAVINGS ================= */

    fun clearCart() {
        cartItems.clear()
    }

    fun totalPrice(): Int {
        return cartItems.sumOf { item ->
            subTotal(item)   // ✅ discount applied only once here
        }
    }

    fun totalSavings(): Int {
        return cartItems.sumOf { item ->
            savings(item)
        }
    }

    val totalItemCount: State<Int> = derivedStateOf {
        cartItems.sumOf { it.quantity }
    }
}
