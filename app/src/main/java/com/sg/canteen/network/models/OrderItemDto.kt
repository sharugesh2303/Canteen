package com.sg.canteen.network.models

data class OrderItemDto(
    val _id: String,
    val name: String,
    val price: Double,
    val quantity: Int
)
