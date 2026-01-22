package com.sg.canteen.network.models

data class OrderResponse(
    val _id: String,

    /* 🧾 Bill Info */
    val billNumber: String,
    val qrNumber: String,
    val qrImage: String,
    val qrVisibleAt: String,

    /* 📦 Order Info */
    val collectionTime: String,
    val totalAmount: Double,

    /* 💳 Payment */
    val paymentMethod: String,
    val paymentStatus: String,

    /* ⏰ Meta */
    val createdAt: String
)
