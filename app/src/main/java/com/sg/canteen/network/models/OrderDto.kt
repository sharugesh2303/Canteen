package com.sg.canteen.network.models

data class OrderDto(
    val _id: String,                  // MongoDB-oda unique ID
    val billNumber: String,
    val totalAmount: Double,
    val orderStatus: String,          // Backend-la 'orderStatus' nu use pannirukom
    val location: String,             // "canteen" or "cafeteria"
    val collectionTime: String,
    val paymentStatus: String,        // "PAID", "PENDING"
    val paymentMethod: String,
    val qrNumber: String,             // QR-ah open panna idhu venum
    val qrImage: String?,             // QR Image URL or Base64
    val items: List<OrderItemDto>,    // Items list (OrderItemDto separate-ah create pannaum)
    val createdAt: String             // Status date-ku idhu help aagum
)

data class OrderItemDto(
    val name: String,
    val quantity: Int,
    val unitPrice: Double,
    val delivered: Boolean
)