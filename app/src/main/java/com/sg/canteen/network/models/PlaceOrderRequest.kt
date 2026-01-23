package com.sg.canteen.network.models

data class PlaceOrderRequest(
    val items: List<PlaceOrderItemDto>,
    val totalAmount: Double,
    val collectionTime: String,
    val paymentMethod: String,
    val paymentStatus: String = "PAID",
    val paymentId: String? = null,
    val deviceId: String
)

data class PlaceOrderItemDto(
    val itemId: String? = null,
    val name: String,
    val quantity: Int,

    // ✅ Final price per unit (after offer)
    val unitPrice: Double,

    // ✅ Original price (MRP / strike price)
    val originalPrice: Double? = null,

    // ✅ Offer percent
    val offerPercent: Int? = 0
)
