package com.sg.canteen.ui.order

data class OrderItem(
    val itemName: String,
    val quantity: Int,
    val price: Int,              // Final Unit Price
    val originalPrice: Int? = 0, // MRP (to show strike-through)
    val isDelivered: Boolean = false // UI-la individual item checkmark kaata
)