package com.sg.canteen.network.models

// ✅ Defining this here once prevents redeclaration errors
data class AppliedOfferResult(
    val finalPrice: Int,
    val originalPrice: Int?,
    val offerPercent: Int,
    val offerName: String?
)