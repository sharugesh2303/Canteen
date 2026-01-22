package com.sg.canteen.ui.order

data class Order(
    val items: List<OrderItem>,
    val totalAmount: Int,
    val time: String
)
