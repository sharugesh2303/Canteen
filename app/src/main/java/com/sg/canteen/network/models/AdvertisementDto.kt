/* ======================================================
 * FILE: com/sg/canteen/network/models/AdvertisementDto.kt
 * ====================================================== */

package com.sg.canteen.network.models

import com.google.gson.annotations.SerializedName

/**
 * Data Transfer Object for Advertisements.
 * Includes a location field to differentiate between Canteen and Cafeteria banners.
 */
data class AdvertisementDto(
    @SerializedName("_id")
    val id: String,

    @SerializedName("imageUrl")
    val imageUrl: String,

    @SerializedName("isActive")
    val isActive: Boolean,

    // 📍 LOCATION FIELD
    // This value matches the backend enum: "canteen" or "cafeteria"
    // It is used to filter banners displayed in the auto-scrolling slider.
    @SerializedName("location")
    val location: String = "canteen",

    @SerializedName("uploadedAt")
    val uploadedAt: String? = null
)