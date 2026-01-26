package com.sg.canteen

import android.Manifest
import android.content.pm.PackageManager
import android.os.Bundle
import android.provider.Settings
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Modifier
import androidx.core.content.ContextCompat
import androidx.core.splashscreen.SplashScreen.Companion.installSplashScreen
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
            if (isGranted) Log.d("Permission", "✅ Notification permission granted")
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        // ✅ 1. Official Splash API-ai thodakkathilaeye activate pannuvom.
        // Ithu themes.xml-la irukkira windowSplashScreenBrandingImage-ai sariyaaga kaattum.
        installSplashScreen()

        super.onCreate(savedInstanceState)

        SocketManager.connect(applicationContext)
        NotificationUtils.createChannels(this)
        checkNotificationPermission()
        Checkout.preload(applicationContext)
        registerFcmToken()

        // Manual "showBranding" layer-ai remove seithu vittom.
        setContent { AppRoot() }
    }

    private fun hashDeviceId(id: String): String {
        val bytes = MessageDigest.getInstance("SHA-256").digest(id.toByteArray())
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

    private fun registerFcmToken() {
        FirebaseMessaging.getInstance().token.addOnSuccessListener { token ->
            val rawId = Settings.Secure.getString(contentResolver, Settings.Secure.ANDROID_ID)
                ?: "unknown_device"
            val deviceId = hashDeviceId(rawId)
            lifecycleScope.launch {
                try {
                    val api = ApiClient.retrofit.create(ApiService::class.java)
                    api.registerFcmToken(FcmRegisterRequest(deviceId, token))
                } catch (e: Exception) {
                    Log.e("FCM", "❌ Token registration failed: ${e.message}")
                }
            }
        }
    }

    override fun onPaymentSuccess(paymentId: String?) {
        PaymentManager.notifySuccess(paymentId)
    }

    override fun onPaymentError(code: Int, response: String?) {
        PaymentManager.notifyFailure()
    }
}

/* ================= ROOT ================= */

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AppRoot() {
    // Starting screen control-ai direct-ah dashboard-ku maatriyullom.
    var currentScreen by rememberSaveable { mutableStateOf("dashboard") }
    var selectedQr by rememberSaveable { mutableStateOf<String?>(null) }
    var isDarkTheme by rememberSaveable { mutableStateOf(false) }
    var hasShownAd by rememberSaveable { mutableStateOf(false) }
    var ads by remember { mutableStateOf<List<AdvertisementDto>>(emptyList()) }

    LaunchedEffect(Unit) {
        ads = try {
            ApiClient.retrofit.create(ApiService::class.java).getActiveAdvertisements()
        } catch (e: Exception) {
            emptyList()
        }
    }

    CanteenTheme(darkTheme = isDarkTheme) {
        Scaffold(
            floatingActionButton = {
                if (currentScreen !in listOf("bill", "order_success")) {
                    FloatingActionButton(onClick = { currentScreen = "feedback" }) {
                        Icon(Icons.Default.Feedback, contentDescription = null)
                    }
                }
            },
            bottomBar = {
                if (currentScreen !in listOf("order_success", "bill")) {
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
                                ) { Icon(Icons.Default.ShoppingCart, null) }
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
        ) { paddingValues ->
            Surface(modifier = Modifier.padding(paddingValues)) {
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
                    "cart" -> CartScreen { currentScreen = "order_success" }
                    "order_success" -> OrderSuccessScreen(
                        onGoHome = { currentScreen = "dashboard" },
                        onViewOrders = { currentScreen = "orders" }
                    )
                    "orders" -> OrdersScreen(
                        onBack = { currentScreen = "dashboard" },
                        onOpenBill = { qr -> selectedQr = qr; currentScreen = "bill" }
                    )
                    "bill" -> selectedQr?.let {
                        BillWebViewScreen(it) { currentScreen = "orders" }
                    }
                    "feedback" -> FeedbackScreen { currentScreen = "dashboard" }
                }
            }
        }
    }
}