package com.sg.canteen.ui.notification

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import com.sg.canteen.MainActivity
import com.sg.canteen.R

object NotificationHelper {

    private const val PREF_NAME = "canteen_prefs"
    private const val KEY_FCM_TOKEN = "fcm_token"

    /* =========================================================
        ✅ Show Notification
    ========================================================= */
    fun showNotification(context: Context, title: String, body: String) {

        // ✅ open MainActivity when user taps notification
        val intent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }

        val pendingIntent = PendingIntent.getActivity(
            context,
            0,
            intent,
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M)
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            else
                PendingIntent.FLAG_UPDATE_CURRENT
        )

        val notification = NotificationCompat.Builder(
            context,
            NotificationUtils.ORDER_CHANNEL_ID // ✅ fixed channel id
        )
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(title)
            .setContentText(body)
            .setStyle(NotificationCompat.BigTextStyle().bigText(body))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setAutoCancel(true)
            .setContentIntent(pendingIntent)
            .build()

        NotificationManagerCompat
            .from(context)
            .notify(System.currentTimeMillis().toInt(), notification)
    }

    /* =========================================================
        ✅ Save FCM Token
    ========================================================= */
    fun saveFcmToken(context: Context, token: String) {
        val prefs = context.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE)
        prefs.edit().putString(KEY_FCM_TOKEN, token).apply()
    }

    /* =========================================================
        ✅ Get saved FCM Token
    ========================================================= */
    fun getFcmToken(context: Context): String? {
        val prefs = context.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE)
        return prefs.getString(KEY_FCM_TOKEN, null)
    }
}
