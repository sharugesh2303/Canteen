package com.sg.canteen.network.models

data class OrderDto(
    val billNumber: String,
    val totalAmount: Double,
    val status: String,
    val orderDate: String
)
