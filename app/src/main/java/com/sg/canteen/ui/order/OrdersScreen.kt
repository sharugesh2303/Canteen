package com.sg.canteen.ui.order

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.sg.canteen.network.ApiProvider
import com.sg.canteen.network.models.OrderResponse
import com.sg.canteen.ui.utils.DeviceUtils
  // ✅ ADD
import retrofit2.HttpException

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun OrdersScreen(
    onBack: () -> Unit,
    onOpenBill: (String) -> Unit
) {

    /* ---------- CONTEXT ---------- */
    val context = LocalContext.current

    /* ---------- DEVICE ID ---------- */
    val deviceId = remember {
        DeviceUtils.getDeviceId(context)
    }

    /* ---------- API ---------- */
    val api = ApiProvider.api

    /* ---------- STATE ---------- */
    var orders by remember { mutableStateOf<List<OrderResponse>>(emptyList()) }
    var loading by remember { mutableStateOf(true) }

    /* ---------- LOAD ORDERS (DEVICE BASED) ---------- */
    LaunchedEffect(deviceId) {
        try {
            orders = api.getOrders(deviceId)   // ✅ FIX
        } catch (_: HttpException) {
            orders = emptyList()
        } finally {
            loading = false
        }
    }

    /* ---------- UI ---------- */
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("My Orders") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.Default.ArrowBack, contentDescription = null)
                    }
                }
            )
        }
    ) { padding ->

        when {
            loading -> {
                Box(
                    modifier = Modifier.fillMaxSize(),
                    contentAlignment = Alignment.Center
                ) {
                    CircularProgressIndicator()
                }
            }

            orders.isEmpty() -> {
                Box(
                    modifier = Modifier.fillMaxSize(),
                    contentAlignment = Alignment.Center
                ) {
                    Text("No orders yet 🧾")
                }
            }

            else -> {
                LazyColumn(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(padding)
                        .padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    items(orders) { order ->
                        Card(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable {
                                    onOpenBill(order.qrNumber)
                                }
                        ) {
                            Column(Modifier.padding(16.dp)) {
                                Text(
                                    text = "Bill No: ${order.billNumber}",
                                    style = MaterialTheme.typography.titleMedium
                                )
                                Spacer(Modifier.height(4.dp))
                                Text("Total: ₹${order.totalAmount}")
                                Text("Collection: ${order.collectionTime}")
                                Text("Payment: ${order.paymentStatus}")
                                Spacer(Modifier.height(6.dp))
                                Text(
                                    text = "Tap to view bill",
                                    color = MaterialTheme.colorScheme.primary
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}
