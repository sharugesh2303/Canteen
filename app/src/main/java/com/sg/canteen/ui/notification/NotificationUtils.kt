package com.sg.canteen.ui.notification

import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.os.Build

object NotificationUtils {

    // ✅ Order channel (for chef/order ready/order updates)
    const val ORDER_READY_CHANNEL_ID = "order_ready_channel"

    // ✅ Extra channels (optional)
    const val ORDER_CHANNEL_ID = "order_channel"
    const val FEEDBACK_CHANNEL_ID = "feedback_channel"

    fun createChannels(context: Context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {

            val orderReadyChannel = NotificationChannel(
                ORDER_READY_CHANNEL_ID,
                "Order Ready Notifications",
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "Notifies when order is ready"
            }

            val orderChannel = NotificationChannel(
                ORDER_CHANNEL_ID,
                "Order Notifications",
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "Order updates and status messages"
            }

            val feedbackChannel = NotificationChannel(
                FEEDBACK_CHANNEL_ID,
                "Feedback Notifications",
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "Feedback related notifications"
            }

            val manager =
                context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

            manager.createNotificationChannel(orderReadyChannel)
            manager.createNotificationChannel(orderChannel)
            manager.createNotificationChannel(feedbackChannel)
        }
    }
}
