package com.sg.canteen.network.models

data class OrderItemDto(
    val itemId: String? = null,
    val name: String,
    val quantity: Int,

    // ✅ Final unit price (after discount)
    val unitPrice: Double,

    // ✅ Original price (MRP / strike)
    val originalPrice: Double? = null,

    // ✅ Offer percentage
    val offerPercent: Int? = 0
)
