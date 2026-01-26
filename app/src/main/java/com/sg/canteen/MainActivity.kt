package com.sg.canteen

import android.Manifest
import android.content.pm.PackageManager
import android.os.Bundle
import android.provider.Settings
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Modifier
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import com.google.firebase.messaging.FirebaseMessaging
import com.razorpay.Checkout
import com.razorpay.PaymentResultListener
import com.sg.canteen.network.ApiClient
import com.sg.canteen.network.ApiService
import com.sg.canteen.network.FcmRegisterRequest
import com.sg.canteen.network.SocketManager
import com.sg.canteen.network.models.AdvertisementDto
import com.sg.canteen.payment.PaymentManager
import com.sg.canteen.ui.cart.CartScreen
import com.sg.canteen.ui.cart.CartState
import com.sg.canteen.ui.dashboard.DashboardScreen
import com.sg.canteen.ui.feedback.FeedbackScreen
import com.sg.canteen.ui.notification.NotificationUtils
import com.sg.canteen.ui.order.BillWebViewScreen
import com.sg.canteen.ui.order.OrderSuccessScreen
import com.sg.canteen.ui.order.OrdersScreen
import com.sg.canteen.ui.theme.CanteenTheme
import kotlinx.coroutines.launch
import java.security.MessageDigest

class MainActivity : ComponentActivity(), PaymentResultListener {

    private val notificationPermissionLauncher =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { isGranted ->
            if (isGranted) {
                Log.d("Permission", "✅ Notification permission granted")
            }
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // 🔌 Connect Socket and Initialize Notifications
        SocketManager.connect(applicationContext)
        NotificationUtils.createChannels(this)

        // 🔐 Handle Android 13+ Notification Permissions
        checkNotificationPermission()

        // 💳 Razorpay Preload
        Checkout.preload(applicationContext)

        // 📲 Register FCM Token
        registerFcmToken()

        setContent {
            AppRoot()
        }
    }

    /**
     * ✅ STEP 1 — SHA-256 Hashing function to match backend requirements
     */
    private fun hashDeviceId(id: String): String {
        val bytes = MessageDigest
            .getInstance("SHA-256")
            .digest(id.toByteArray())
        return bytes.joinToString("") { "%02x".format(it) }
    }

    private fun checkNotificationPermission() {
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED
            ) {
                notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
            }
        }
    }

    /**
     * ✅ STEP 2 — Register token using the Hashed Device ID
     */
    private fun registerFcmToken() {
        FirebaseMessaging.getInstance().token.addOnSuccessListener { token ->
            Log.d("FCM", "Token: $token")

            // Get Raw Android ID
            val rawId = Settings.Secure.getString(
                applicationContext.contentResolver,
                Settings.Secure.ANDROID_ID
            ) ?: "unknown_device"

            // Hash it to match backend
            val deviceId = hashDeviceId(rawId)

            lifecycleScope.launch {
                try {
                    val api = ApiClient.retrofit.create(ApiService::class.java)

                    // Wrap parameters into the DTO object
                    val request = FcmRegisterRequest(
                        deviceId = deviceId,
                        fcmToken = token
                    )

                    api.registerFcmToken(request)
                    Log.d("FCM", "✅ Token registered on server with hashed ID")
                } catch (e: Exception) {
                    Log.e("FCM", "❌ Token registration failed: ${e.message}")
                }
            }
        }.addOnFailureListener {
            Log.e("FCM", "❌ Failed to fetch FCM token", it)
        }
    }

    override fun onPaymentSuccess(paymentId: String?) {
        PaymentManager.notifySuccess(paymentId)
    }

    override fun onPaymentError(code: Int, response: String?) {
        PaymentManager.notifyFailure()
    }
}

/* ================= ROOT COMPOSABLE ================= */

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AppRoot() {
    var currentScreen by rememberSaveable { mutableStateOf("dashboard") }
    var selectedQr by rememberSaveable { mutableStateOf<String?>(null) }
    var isDarkTheme by rememberSaveable { mutableStateOf(false) }
    var hasShownAd by rememberSaveable { mutableStateOf(false) }
    var ads by remember { mutableStateOf<List<AdvertisementDto>>(emptyList()) }

    LaunchedEffect(Unit) {
        ads = try {
            ApiClient.retrofit.create(ApiService::class.java).getActiveAdvertisements()
        } catch (e: Exception) {
            Log.e("API", "Failed to fetch ads", e)
            emptyList()
        }
    }

    CanteenTheme(darkTheme = isDarkTheme) {
        Scaffold(
            floatingActionButton = {
                if (currentScreen != "bill" && currentScreen != "order_success") {
                    FloatingActionButton(onClick = { currentScreen = "feedback" }) {
                        Icon(Icons.Default.Feedback, contentDescription = "Feedback")
                    }
                }
            },
            bottomBar = {
                if (currentScreen != "order_success" && currentScreen != "bill") {
                    NavigationBar {
                        val cartCount by CartState.totalItemCount

                        NavigationBarItem(
                            selected = currentScreen == "dashboard",
                            onClick = { currentScreen = "dashboard" },
                            icon = { Icon(Icons.Default.Home, null) },
                            label = { Text("Home") }
                        )
                        NavigationBarItem(
                            selected = currentScreen == "cart",
                            onClick = { currentScreen = "cart" },
                            icon = {
                                BadgedBox(
                                    badge = { if (cartCount > 0) Badge { Text(cartCount.toString()) } }
                                ) {
                                    Icon(Icons.Default.ShoppingCart, null)
                                }
                            },
                            label = { Text("Cart") }
                        )
                        NavigationBarItem(
                            selected = currentScreen == "orders",
                            onClick = { currentScreen = "orders" },
                            icon = { Icon(Icons.Default.Receipt, null) },
                            label = { Text("Orders") }
                        )
                    }
                }
            }
        ) { padding ->
            Surface(modifier = Modifier.padding(padding)) {
                when (currentScreen) {
                    "dashboard" -> DashboardScreen(
                        isDarkTheme = isDarkTheme,
                        onToggleTheme = { isDarkTheme = !isDarkTheme },
                        onGoToOrders = { currentScreen = "orders" },
                        onGoToCart = { currentScreen = "cart" },
                        showAd = !hasShownAd,
                        ads = ads,
                        onAdDismissed = { hasShownAd = true }
                    )
                    "cart" -> CartScreen(
                        onOrderPlaced = { currentScreen = "order_success" }
                    )
                    "order_success" -> OrderSuccessScreen(
                        onGoHome = { currentScreen = "dashboard" },
                        onViewOrders = { currentScreen = "orders" }
                    )
                    "orders" -> OrdersScreen(
                        onBack = { currentScreen = "dashboard" },
                        onOpenBill = { qr ->
                            selectedQr = qr
                            currentScreen = "bill"
                        }
                    )
                    "bill" -> {
                        val qr = selectedQr
                        if (qr == null) {
                            currentScreen = "orders"
                        } else {
                            BillWebViewScreen(qrNumber = qr, onBack = { currentScreen = "orders" })
                        }
                    }
                    "feedback" -> FeedbackScreen(
                        onBack = { currentScreen = "dashboard" }
                    )
                }
            }
        }
    }
}