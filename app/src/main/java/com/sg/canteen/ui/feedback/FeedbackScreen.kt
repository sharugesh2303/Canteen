package com.sg.canteen.ui.feedback

import android.widget.Toast
import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.Send
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import com.sg.canteen.network.ApiClient
import com.sg.canteen.network.ApiService
import com.sg.canteen.network.models.FeedbackRequest
import com.sg.canteen.ui.notification.FeedbackNotificationWorker
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun FeedbackScreen(
    currentLocation: String, // 📍 Added: "canteen" or "cafeteria" passed from Dashboard
    onBack: () -> Unit
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val api = remember { ApiClient.retrofit.create(ApiService::class.java) }

    var name by remember { mutableStateOf("") }
    var branch by remember { mutableStateOf("") }
    var department by remember { mutableStateOf("") }
    var year by remember { mutableStateOf("") }
    var feedback by remember { mutableStateOf("") }

    var isSubmitting by remember { mutableStateOf(false) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    // Dynamically show location in title
                    val title = if (currentLocation.equals("cafeteria", true)) "Cafeteria Feedback" else "Canteen Feedback"
                    Text(title)
                },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.Default.ArrowBack, contentDescription = "Back")
                    }
                }
            )
        }
    ) { padding ->

        Column(
            modifier = Modifier
                .padding(padding)
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {

            // Helpful text showing where the feedback is going
            Text(
                text = "Submitting feedback for: ${currentLocation.uppercase()}",
                style = MaterialTheme.typography.labelLarge,
                color = MaterialTheme.colorScheme.primary
            )

            OutlinedTextField(
                value = name,
                onValueChange = { name = it },
                label = { Text("Name") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true
            )

            OutlinedTextField(
                value = branch,
                onValueChange = { branch = it },
                label = { Text("Branch") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true
            )

            OutlinedTextField(
                value = department,
                onValueChange = { department = it },
                label = { Text("Department") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true
            )

            OutlinedTextField(
                value = year,
                onValueChange = { year = it },
                label = { Text("Year") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true
            )

            OutlinedTextField(
                value = feedback,
                onValueChange = { feedback = it },
                label = { Text("Your Feedback") },
                modifier = Modifier.fillMaxWidth(),
                minLines = 4
            )

            Button(
                onClick = {
                    scope.launch {
                        if (
                            name.isBlank() ||
                            branch.isBlank() ||
                            department.isBlank() ||
                            year.isBlank() ||
                            feedback.isBlank()
                        ) {
                            Toast.makeText(
                                context,
                                "Please fill all fields",
                                Toast.LENGTH_SHORT
                            ).show()
                            return@launch
                        }

                        isSubmitting = true

                        try {
                            api.submitFeedback(
                                FeedbackRequest(
                                    studentName = name,
                                    branch = branch,
                                    department = department,
                                    year = year,
                                    feedbackText = feedback,
                                    location = currentLocation // 📍 Added: Send the location to backend
                                )
                            )

                            // 🔔 FEEDBACK SUCCESS NOTIFICATION
                            WorkManager.getInstance(context)
                                .enqueue(
                                    OneTimeWorkRequestBuilder<FeedbackNotificationWorker>()
                                        .build()
                                )

                            Toast.makeText(
                                context,
                                "Feedback submitted successfully",
                                Toast.LENGTH_SHORT
                            ).show()

                            onBack()

                        } catch (e: Exception) {
                            e.printStackTrace()
                            Toast.makeText(
                                context,
                                "Failed to submit feedback",
                                Toast.LENGTH_SHORT
                            ).show()
                        } finally {
                            isSubmitting = false
                        }
                    }
                },
                enabled = !isSubmitting,
                modifier = Modifier.fillMaxWidth()
            ) {
                if (isSubmitting) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(20.dp),
                        strokeWidth = 2.dp,
                        color = MaterialTheme.colorScheme.onPrimary
                    )
                } else {
                    Icon(Icons.Default.Send, contentDescription = null)
                    Spacer(Modifier.width(8.dp))
                    Text("Submit Feedback")
                }
            }
        }
    }
}