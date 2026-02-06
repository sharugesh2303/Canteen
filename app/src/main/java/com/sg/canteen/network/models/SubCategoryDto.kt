package com.sg.canteen.network.models

data class SubCategoryDto(
    val _id: String,
    val name: String,
    val imageUrl: String? = null,

    // 📍 LOCATION FIELD (REQUIRED FOR SHOP PERSISTENCE)
    // Ensures sub-categories are filtered based on the selected shop ("canteen" or "cafeteria")
    val location: String = "canteen"
)