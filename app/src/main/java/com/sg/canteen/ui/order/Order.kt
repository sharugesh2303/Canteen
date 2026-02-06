package com.sg.canteen.ui.order

data class Order(
    val billNumber: String,       // UI-la "Bill #12345" nu kaata venum
    val items: List<OrderItem>,
    val totalAmount: Int,
    val time: String,             // Collection Time
    val date: String,             // Order potta date (CreatedAt mapping)
    val status: String,           // PLACED, READY, DELIVERED status tracking
    val location: String,         // Canteen or Cafeteria (for UI branding)
    val qrImage: String? = null   // UI-la QR-ah click panni open panna
)