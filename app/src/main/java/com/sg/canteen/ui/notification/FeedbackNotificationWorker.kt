package com.sg.canteen.ui.notification

import android.content.Context
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.work.Worker
import androidx.work.WorkerParameters
import com.sg.canteen.R

class FeedbackNotificationWorker(
    context: Context,
    params: WorkerParameters
) : Worker(context, params) {

    override fun doWork(): Result {

        val notification = NotificationCompat.Builder(
            applicationContext,
            NotificationUtils.FEEDBACK_CHANNEL_ID
        )
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle("Feedback Submitted ✅")
            .setContentText("Thank you for your valuable feedback")
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setAutoCancel(true)
            .build()

        NotificationManagerCompat
            .from(applicationContext)
            .notify(2001, notification)

        return Result.success()
    }
}
