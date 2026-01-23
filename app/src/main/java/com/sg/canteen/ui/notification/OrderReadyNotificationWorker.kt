package com.sg.canteen.ui.notification

import android.content.Context
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.work.Worker
import androidx.work.WorkerParameters
import com.sg.canteen.R

class OrderReadyNotificationWorker(
    context: Context,
    params: WorkerParameters
) : Worker(context, params) {

    override fun doWork(): Result {

        val billNumber = inputData.getString("billNumber") ?: ""
        val message =
            inputData.getString("message") ?: "Your order is ready! Please collect from counter."

        val notification = NotificationCompat.Builder(
            applicationContext,
            NotificationUtils.ORDER_READY_CHANNEL_ID
        )
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle("Order Ready ✅ ${if (billNumber.isNotEmpty()) "($billNumber)" else ""}")
            .setContentText(message)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setDefaults(NotificationCompat.DEFAULT_ALL) // ✅ sound + vibration for < Oreo
            .setAutoCancel(true)
            .build()

        NotificationManagerCompat
            .from(applicationContext)
            .notify(3001, notification)

        return Result.success()
    }
}
