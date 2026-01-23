package com.sg.canteen.ui.cart

data class CartItem(
    val id: String,
    val name: String,

    // ✅ Always store ORIGINAL / BASE price (MRP)
    val price: Int,

    val imageUrl: String?,
    val quantity: Int,

    // ✅ Offer percentage applied
    val offerPercent: Int = 0
)
