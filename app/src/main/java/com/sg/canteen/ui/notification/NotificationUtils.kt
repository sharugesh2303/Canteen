package com.sg.canteen.ui.notification

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.media.AudioAttributes
import android.net.Uri
import android.os.Build
import androidx.core.app.NotificationCompat
import com.sg.canteen.MainActivity
import com.sg.canteen.R

object NotificationUtils {

    const val ORDER_READY_CHANNEL_ID = "order_ready_channel"
    const val ORDER_CHANNEL_ID = "order_channel"
    const val FEEDBACK_CHANNEL_ID = "feedback_channel"

    /**
     * Creates notification channels for Android O and above.
     */
    fun createChannels(context: Context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {

            val soundUri: Uri =
                Uri.parse("android.resource://${context.packageName}/raw/notification_sound")

            val audioAttributes = AudioAttributes.Builder()
                .setUsage(AudioAttributes.USAGE_NOTIFICATION)
                .build()

            /* 🔔 ORDER READY (HEADS-UP + SOUND + LOCKSCREEN) */
            val orderReadyChannel = NotificationChannel(
                ORDER_READY_CHANNEL_ID,
                "Order Ready Notifications",
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "Notifies when order is ready for pickup"
                enableVibration(true)
                vibrationPattern = longArrayOf(0, 500, 300, 500)
                setSound(soundUri, audioAttributes)
                lockscreenVisibility = Notification.VISIBILITY_PUBLIC
            }

            /* 📦 ORDER STATUS UPDATES */
            val orderChannel = NotificationChannel(
                ORDER_CHANNEL_ID,
                "Order Notifications",
                NotificationManager.IMPORTANCE_DEFAULT
            ).apply {
                description = "Order updates and status messages"
                enableVibration(true)
            }

            /* ⭐ FEEDBACK */
            val feedbackChannel = NotificationChannel(
                FEEDBACK_CHANNEL_ID,
                "Feedback Notifications",
                NotificationManager.IMPORTANCE_DEFAULT
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

    /**
     * ✅ Added this function to resolve the Unresolved reference error.
     * Builds and displays the notification.
     */
    fun showNotification(context: Context, title: String, body: String) {
        val manager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        val notificationId = System.currentTimeMillis().toInt()

        // Intent to open MainActivity when notification is clicked
        val intent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_CLEAR_TOP
        }

        val pendingIntent = PendingIntent.getActivity(
            context, 0, intent,
            PendingIntent.FLAG_ONE_SHOT or PendingIntent.FLAG_IMMUTABLE
        )

        val soundUri = Uri.parse("android.resource://${context.packageName}/raw/notification_sound")

        val notificationBuilder = NotificationCompat.Builder(context, ORDER_READY_CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_notification) // Ensure this drawable exists
            .setContentTitle(title)
            .setContentText(body)
            .setAutoCancel(true)
            .setSound(soundUri)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_MESSAGE)
            .setContentIntent(pendingIntent)

        manager.notify(notificationId, notificationBuilder.build())
    }
}