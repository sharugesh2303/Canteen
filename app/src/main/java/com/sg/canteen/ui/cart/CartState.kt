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
        actualPrice: Int,          // ✅ ORIGINAL PRICE ONLY
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
                    price = actualPrice,           // ✅ store only original price
                    imageUrl = imageUrl,
                    quantity = 1,
                    originalPrice = actualPrice,   // ✅ keep original
                    offerPercent = offerPercent
                )
            )
        }
    }

    /* ================= PRICE CALCULATION ================= */

    private fun discountedPrice(item: CartItem): Int {
        return if (item.offerPercent > 0) {
            (item.price - (item.price * item.offerPercent / 100f)).roundToInt()
        } else {
            item.price
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
        return cartItems.sumOf { item ->
            discountedPrice(item) * item.quantity   // ✅ apply discount ONLY ONCE here
        }
    }

    fun totalSavings(): Int {
        return cartItems.sumOf { item ->
            val discounted = discountedPrice(item)
            (item.price - discounted) * item.quantity
        }
    }

    val totalItemCount: State<Int> = derivedStateOf {
        cartItems.sumOf { it.quantity }
    }
}
