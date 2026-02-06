package com.sg.canteen.network.models

/* =========================================================
    PLACE ORDER REQUEST
    Main request object for creating a new order.
    Synced with Backend Schema (Location at Root Level).
========================================================= */
data class PlaceOrderRequest(
    val items: List<PlaceOrderItemDto>,
    val totalAmount: Double,
    val collectionTime: String,
    val paymentMethod: String,
    val paymentStatus: String = "PAID",
    val paymentId: String? = null,
    val deviceId: String,

    /* 🏪 Location Info (Canteen / Cafeteria) */
    // ✅ ADDED: Fixes 'No parameter with name location' in CartScreen.kt
    val location: String
)

/* =========================================================
    PLACE ORDER ITEM DTO
    Details for individual items within the order.
========================================================= */
data class PlaceOrderItemDto(
    val itemId: String? = null,
    val name: String,
    val quantity: Int,

    // ✅ Final price per unit (after offer discount)
    val unitPrice: Double,

    // ✅ Original price (MRP / strike price)
    val originalPrice: Double? = null,

    // ✅ Offer percentage applied
    val offerPercent: Int? = 0

    // ❌ REMOVED: Location is now managed at the Main Order level
)