package com.sg.canteen.network.models

data class MenuItemDto(
    val _id: String,
    val name: String,
    val price: Double, // The active price (discounted if an offer exists)
    val category: String,
    val imageUrl: String? = null,
    val stock: Int,
    val subCategory: SubCategoryDto? = null,

    // ✅ ADD THESE FIELDS TO MATCH BACKEND RESPONSE
    val originalPrice: Double? = null,
    val discountPercentage: Int? = null,
    val isOffer: Boolean = false
)