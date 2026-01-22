package com.sg.canteen.ui.notification

import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.os.Build

object NotificationUtils {

    const val ORDER_CHANNEL_ID = "order_channel"
    const val FEEDBACK_CHANNEL_ID = "feedback_channel"

    fun createChannels(context: Context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {

            val orderChannel = NotificationChannel(
                ORDER_CHANNEL_ID,
                "Order Notifications",
                NotificationManager.IMPORTANCE_HIGH
            )

            val feedbackChannel = NotificationChannel(
                FEEDBACK_CHANNEL_ID,
                "Feedback Notifications",
                NotificationManager.IMPORTANCE_HIGH
            )

            val manager =
                context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

            manager.createNotificationChannel(orderChannel)
            manager.createNotificationChannel(feedbackChannel)
        }
    }
}
