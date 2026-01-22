package com.sg.canteen.ui.cart

data class CartItem(
    val id: String,
    val name: String,
    val price: Int,              // final discounted price
    val imageUrl: String?,
    val quantity: Int,
    val originalPrice: Int? = null,
    val offerPercent: Int = 0    // ✅ STORE OFFER PERCENT
)
