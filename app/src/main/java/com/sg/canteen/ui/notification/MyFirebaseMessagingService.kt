package com.sg.canteen.notification

import android.util.Log
import com.google.firebase.messaging.FirebaseMessagingService
import com.google.firebase.messaging.RemoteMessage
import com.sg.canteen.ui.notification.NotificationHelper

class MyFirebaseMessagingService : FirebaseMessagingService() {

    companion object {
        private const val TAG = "FCM_SERVICE"
    }

    /* =========================================================
        ✅ Called when Firebase issues a new token
        This happens:
        - first install
        - app data cleared
        - token refreshed
    ========================================================= */
    override fun onNewToken(token: String) {
        super.onNewToken(token)

        Log.d(TAG, "✅ New FCM Token: $token")

        // ✅ store token locally
        NotificationHelper.saveFcmToken(applicationContext, token)

        // Later we will send token to backend API
        // (so backend can push order ready notification)
    }

    /* =========================================================
        ✅ Called when notification arrives (foreground/background)
    ========================================================= */
    override fun onMessageReceived(message: RemoteMessage) {
        super.onMessageReceived(message)

        Log.d(TAG, "📩 FCM Message Received")

        // Notification title/body from notification payload
        val title = message.notification?.title
            ?: message.data["title"]
            ?: "JJ Canteen"

        val body = message.notification?.body
            ?: message.data["body"]
            ?: "You have a new update"

        Log.d(TAG, "📌 title: $title")
        Log.d(TAG, "📌 body: $body")

        // ✅ show notification locally
        NotificationHelper.showNotification(
            context = applicationContext,
            title = title,
            body = body
        )
    }
}
