package com.sg.canteen.network.models

data class OfferDto(
    val _id: String,
    val name: String,
    val discountPercentage: Int,
    val startDate: String?,
    val endDate: String?,
    val startTime: String?,
    val endTime: String?,
    val applicableCategories: List<String> = emptyList(),

    // ✅ IMPORTANT: sometimes backend returns ids, sometimes populated objects
    val applicableItems: List<Any> = emptyList(),

    val isActive: Boolean = true
) {
    // ✅ Extract IDs safely
    fun applicableItemIds(): List<String> {
        return applicableItems.mapNotNull { item ->
            when (item) {
                is String -> item
                is Map<*, *> -> item["_id"]?.toString()
                else -> null
            }
        }
    }
}
