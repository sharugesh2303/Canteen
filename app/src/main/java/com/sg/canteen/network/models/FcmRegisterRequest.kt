package com.sg.canteen.network.models

data class FcmRegisterRequest(
    val deviceId: String,
    val fcmToken: String
)
