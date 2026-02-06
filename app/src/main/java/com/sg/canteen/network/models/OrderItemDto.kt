data class OrderItemDto(
    val itemId: String? = null,
    val name: String,
    val quantity: Int,
    val unitPrice: Double,
    val originalPrice: Double? = null,
    val offerPercent: Int? = 0,

    // ✅ Add this to sync with Backend Delivery tracking
    val delivered: Boolean = false
)