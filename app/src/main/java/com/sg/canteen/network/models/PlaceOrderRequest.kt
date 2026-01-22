package com.sg.canteen.network.models

data class PlaceOrderRequest(
    val items: List<OrderItemDto>,
    val totalAmount: Double,
    val collectionTime: String,
    val paymentMethod: String,
    val paymentStatus: String = "PAID",
    val paymentId: String? = null,

    // ✅ ADD THIS
    val deviceId: String
)

