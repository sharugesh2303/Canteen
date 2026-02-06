package com.sg.canteen.network.models

import com.google.gson.annotations.SerializedName

/* =========================================================
    ORDER RESPONSE DTO
    Matches the Backend Order Schema including Location
========================================================= */
data class OrderResponse(
    @SerializedName("_id")
    val id: String,

    /* 🏪 Location Info (Canteen / Cafeteria) */
    // ✅ String (Not Nullable) to resolve 'Unresolved reference: location' in OrdersScreen.kt
    val location: String,

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
    // Default value avoids null checks when displaying status badges in UI
    val orderStatus: String = "PLACED",

    /* 💳 Payment */
    val paymentMethod: String,
    val paymentStatus: String,
    val paymentId: String? = null,

    /* ⏰ Meta */
    val createdAt: String
)