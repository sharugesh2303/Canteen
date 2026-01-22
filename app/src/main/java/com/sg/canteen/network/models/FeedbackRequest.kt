package com.sg.canteen.network.models

data class FeedbackRequest(
    val studentName: String,
    val branch: String,
    val department: String,
    val year: String,
    val feedbackText: String
)
