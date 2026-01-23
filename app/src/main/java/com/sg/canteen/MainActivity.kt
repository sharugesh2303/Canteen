package com.sg.canteen

import android.Manifest
import android.content.pm.PackageManager
import android.os.Bundle
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
import com.razorpay.Checkout
import com.razorpay.PaymentResultListener
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
import com.sg.canteen.network.ApiClient
import com.sg.canteen.network.ApiService
import com.sg.canteen.network.models.AdvertisementDto

class MainActivity : ComponentActivity(), PaymentResultListener {

    private val notificationPermissionLauncher =
        registerForActivityResult(
            ActivityResultContracts.RequestPermission()
        ) { }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        NotificationUtils.createChannels(this)

        if (
            ContextCompat.checkSelfPermission(
                this,
                Manifest.permission.POST_NOTIFICATIONS
            ) != PackageManager.PERMISSION_GRANTED
        ) {
            notificationPermissionLauncher.launch(
                Manifest.permission.POST_NOTIFICATIONS
            )
        }

        Checkout.preload(applicationContext)

        setContent {
            AppRoot()   // ✅ Theme already handled inside AppRoot
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

    // ✅ Theme toggle state
    var isDarkTheme by rememberSaveable { mutableStateOf(false) }

    /* ✅ AD STATE */
    var hasShownAd by rememberSaveable { mutableStateOf(false) }
    var ads by remember { mutableStateOf<List<AdvertisementDto>>(emptyList()) }

    /* ✅ LOAD ADS ONCE */
    LaunchedEffect(Unit) {
        ads = try {
            ApiClient.retrofit
                .create(ApiService::class.java)
                .getActiveAdvertisements()
        } catch (_: Exception) {
            emptyList()
        }
    }

    // ✅ BLUE MODERN THEME APPLIED HERE
    CanteenTheme(darkTheme = isDarkTheme) {

        Scaffold(

            /* ================= FLOATING FEEDBACK BUTTON ================= */
            floatingActionButton = {
                if (currentScreen != "bill" && currentScreen != "order_success") {
                    FloatingActionButton(
                        onClick = { currentScreen = "feedback" },
                        containerColor = MaterialTheme.colorScheme.primary
                    ) {
                        Icon(
                            imageVector = Icons.Default.Feedback,
                            contentDescription = "Feedback",
                            tint = MaterialTheme.colorScheme.onPrimary
                        )
                    }
                }
            },

            floatingActionButtonPosition = FabPosition.End,

            /* ================= BOTTOM NAV BAR ================= */
            bottomBar = {
                if (currentScreen != "order_success" && currentScreen != "bill") {

                    NavigationBar(
                        containerColor = MaterialTheme.colorScheme.surface
                    ) {

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
                                    badge = {
                                        if (cartCount > 0) {
                                            Badge {
                                                Text(text = cartCount.toString())
                                            }
                                        }
                                    }
                                ) {
                                    Icon(
                                        imageVector = Icons.Default.ShoppingCart,
                                        contentDescription = "Cart"
                                    )
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

            when (currentScreen) {

                "dashboard" -> DashboardScreen(
                    modifier = Modifier.padding(padding),
                    isDarkTheme = isDarkTheme,
                    onToggleTheme = { isDarkTheme = !isDarkTheme },
                    onGoToOrders = { currentScreen = "orders" },
                    onGoToCart = { currentScreen = "cart" },

                    /* ✅ Banner Ad Control */
                    showAd = !hasShownAd,
                    ads = ads,
                    onAdDismissed = { hasShownAd = true }
                )

                "cart" -> CartScreen(
                    modifier = Modifier.padding(padding),
                    onOrderPlaced = {
                        currentScreen = "order_success"
                    }
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

                /* ✅ SAFE BILL HANDLING */
                "bill" -> {
                    val qr = selectedQr
                    if (qr == null) {
                        currentScreen = "orders"
                    } else {
                        BillWebViewScreen(
                            qrNumber = qr,
                            onBack = { currentScreen = "orders" }
                        )
                    }
                }

                "feedback" -> FeedbackScreen(
                    onBack = { currentScreen = "dashboard" }
                )
            }
        }
    }
}
