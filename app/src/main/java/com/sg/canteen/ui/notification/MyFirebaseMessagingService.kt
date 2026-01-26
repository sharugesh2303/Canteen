package com.sg.canteen.notifications

import android.provider.Settings
import android.util.Log
import com.google.firebase.messaging.FirebaseMessagingService
import com.google.firebase.messaging.RemoteMessage
import com.sg.canteen.network.ApiClient
import com.sg.canteen.network.ApiService
import com.sg.canteen.network.FcmRegisterRequest
import com.sg.canteen.ui.notification.NotificationUtils
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import java.security.MessageDigest

class MyFirebaseMessagingService : FirebaseMessagingService() {

    /* 🔄 CALLED WHEN FCM TOKEN IS CREATED OR REFRESHED */
    override fun onNewToken(token: String) {
        super.onNewToken(token)

        Log.d("FCM", "🔄 New token generated: $token")

        val rawId = Settings.Secure.getString(
            applicationContext.contentResolver,
            Settings.Secure.ANDROID_ID
        )

        if (rawId.isNullOrEmpty()) {
            Log.e("FCM", "❌ Android ID is null, cannot register FCM token")
            return
        }

        val hashedDeviceId = hashDeviceId(rawId)
        Log.d("FCM", "📤 Sending refreshed token with deviceId: $hashedDeviceId")

        // Send updated token to backend
        CoroutineScope(Dispatchers.IO).launch {
            try {
                val api = ApiClient.retrofit.create(ApiService::class.java)
                api.registerFcmToken(FcmRegisterRequest(hashedDeviceId, token))
                Log.d("FCM", "✅ Refreshed token sent to server")
            } catch (e: Exception) {
                Log.e("FCM", "❌ Failed to send refreshed token", e)
            }
        }
    }

    /* 📩 CALLED WHEN PUSH NOTIFICATION ARRIVES */
    override fun onMessageReceived(remoteMessage: RemoteMessage) {
        super.onMessageReceived(remoteMessage)

        Log.d("FCM", "📩 Message received: ${remoteMessage.data}")

        // Prefer DATA payload (since backend sends data messages)
        val title = remoteMessage.data["title"]
            ?: remoteMessage.notification?.title
            ?: "Order Update"

        val body = remoteMessage.data["body"]
            ?: remoteMessage.notification?.body
            ?: "Your order is ready 🎉"

        NotificationUtils.showNotification(
            applicationContext,
            title,
            body
        )
    }

    /* 🔐 SHA-256 HASH (MUST MATCH BACKEND HASHING) */
    private fun hashDeviceId(id: String): String {
        val bytes = MessageDigest
            .getInstance("SHA-256")
            .digest(id.toByteArray())
        return bytes.joinToString("") { "%02x".format(it) }
    }
}
