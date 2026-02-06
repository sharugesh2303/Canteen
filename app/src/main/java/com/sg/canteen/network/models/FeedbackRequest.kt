package com.sg.canteen.network.models

import com.google.gson.annotations.SerializedName

/**
 * Data model for sending student feedback.
 * Includes a location field to differentiate between Canteen and Cafeteria.
 */
data class FeedbackRequest(
    @SerializedName("studentName")
    val studentName: String,

    @SerializedName("branch")
    val branch: String,

    @SerializedName("department")
    val department: String,

    @SerializedName("year")
    val year: String,

    @SerializedName("feedbackText")
    val feedbackText: String,

    // 📍 LOCATION FIELD
    // Value should be "canteen" or "cafeteria"
    // This allows the Admin Dashboard to filter feedback properly.
    @SerializedName("location")
    val location: String
)