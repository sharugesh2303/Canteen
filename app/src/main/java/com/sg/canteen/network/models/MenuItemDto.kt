package com.sg.canteen.network.models

data class MenuItemDto(
    val _id: String,
    val name: String,
    val price: Double,                 // Active price (discounted if offer exists)
    val category: String,

    // 📍 LOCATION FIELD (REQUIRED FOR SHOP FILTERING)
    // Values will be "canteen" or "cafeteria" from the backend
    val location: String = "canteen",

    val imageUrl: String? = null,
    val stock: Int,
    val subCategory: SubCategoryDto? = null,

    // 🎁 Offer fields
    val originalPrice: Double? = null,
    val discountPercentage: Int? = null,
    val isOffer: Boolean = false,

    // 🚫 Stock availability (COMES FROM BACKEND)
    val isAvailable: Boolean = true    // 🔥 REQUIRED FOR OUT-OF-STOCK UI
)