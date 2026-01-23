package com.sg.canteen.network.models

data class OrderResponse(
    val _id: String,

    /* 🧾 Bill Info */
    val billNumber: String,
    val qrNumber: String,
    val qrImage: String,
    val qrVisibleAt: String? = null,

    /* 📦 Order Items */
    val items: List<OrderItemDto> = emptyList(),

    /* 📦 Order Info */
    val collectionTime: String,
    val totalAmount: Double,

    /* ✅ Kitchen Status */
    val orderStatus: String? = null,

    /* 💳 Payment */
    val paymentMethod: String,
    val paymentStatus: String,
    val paymentId: String? = null,

    /* ⏰ Meta */
    val createdAt: String
)
