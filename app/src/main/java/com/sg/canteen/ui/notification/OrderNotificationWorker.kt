package com.sg.canteen.ui.notification

import android.content.Context
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.work.Worker
import androidx.work.WorkerParameters
import com.sg.canteen.R

class OrderNotificationWorker(
    context: Context,
    params: WorkerParameters
) : Worker(context, params) {

    override fun doWork(): Result {

        val notification = NotificationCompat.Builder(
            applicationContext,
            NotificationUtils.ORDER_CHANNEL_ID
        )
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle("Order Placed ✅")
            .setContentText("Your order has been sent to the kitchen")
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setAutoCancel(true)
            .build()

        NotificationManagerCompat
            .from(applicationContext)
            .notify(1001, notification)

        return Result.success()
    }
}
