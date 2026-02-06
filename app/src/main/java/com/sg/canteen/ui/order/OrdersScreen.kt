package com.sg.canteen.ui.order

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sg.canteen.network.ApiProvider
import com.sg.canteen.network.models.OrderResponse
import com.sg.canteen.ui.utils.DeviceUtils

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun OrdersScreen(
    locationFilter: String,   // ✅ NEW: "canteen" or "cafeteria"
    onBack: () -> Unit,
    onOpenBill: (String) -> Unit
) {
    val context = LocalContext.current
    val deviceId = remember { DeviceUtils.getDeviceId(context) }
    val api = ApiProvider.api

    var orders by remember { mutableStateOf<List<OrderResponse>>(emptyList()) }
    var loading by remember { mutableStateOf(true) }

    /* ---------- LOAD + FILTER ORDERS ---------- */
    LaunchedEffect(deviceId, locationFilter) {
        try {
            val allOrders = api.getOrders(deviceId)

            // ✅ FILTER ORDERS BY LOCATION
            orders = allOrders.filter {
                it.location?.equals(locationFilter, ignoreCase = true) == true
            }

        } catch (e: Exception) {
            orders = emptyList()
        } finally {
            loading = false
        }
    }

    val screenTitle =
        if (locationFilter.lowercase() == "cafeteria")
            "My Cafeteria Orders"
        else
            "My Canteen Orders"

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(screenTitle, fontWeight = FontWeight.Bold) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.Default.ArrowBack, contentDescription = "Back")
                    }
                }
            )
        }
    ) { padding ->

        when {
            loading -> {
                Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    CircularProgressIndicator()
                }
            }

            orders.isEmpty() -> {
                Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        Text("No $locationFilter orders yet 🧾")
                        Text("Order something delicious!", color = Color.Gray, fontSize = 14.sp)
                    }
                }
            }

            else -> {
                LazyColumn(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(padding)
                        .padding(horizontal = 16.dp),
                    verticalArrangement = Arrangement.spacedBy(16.dp),
                    contentPadding = PaddingValues(vertical = 16.dp)
                ) {
                    items(orders) { order ->
                        OrderCard(
                            order = order,
                            onClick = { onOpenBill(order.qrNumber) }
                        )
                    }
                }
            }
        }
    }
}

@Composable
fun OrderCard(order: OrderResponse, onClick: () -> Unit) {

    val locationColor =
        if (order.location?.lowercase() == "cafeteria")
            Color(0xFF1E88E5)
        else
            Color(0xFFF4511E)

    val statusColor = when (order.orderStatus) {
        "READY" -> Color(0xFF4CAF50)
        "DELIVERED" -> Color(0xFF757575)
        else -> Color(0xFFFB8C00)
    }

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onClick() },
        shape = RoundedCornerShape(16.dp),
        elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
    ) {
        Column(Modifier.padding(16.dp)) {

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = order.location?.uppercase() ?: "CANTEEN",
                    color = locationColor,
                    style = MaterialTheme.typography.labelLarge,
                    fontWeight = FontWeight.Black
                )

                Surface(
                    color = statusColor.copy(alpha = 0.1f),
                    shape = RoundedCornerShape(8.dp)
                ) {
                    Text(
                        text = order.orderStatus ?: "PLACED",
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
                        color = statusColor,
                        style = MaterialTheme.typography.labelMedium,
                        fontWeight = FontWeight.Bold
                    )
                }
            }

            Spacer(Modifier.height(12.dp))

            Text(
                text = "Bill No: ${order.billNumber}",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold
            )

            HorizontalDivider(Modifier.padding(vertical = 8.dp))

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Column {
                    Text("Amount", color = Color.Gray, fontSize = 12.sp)
                    Text("₹${order.totalAmount}", fontWeight = FontWeight.Bold, fontSize = 18.sp)
                }
                Column(horizontalAlignment = Alignment.End) {
                    Text("Collection Time", color = Color.Gray, fontSize = 12.sp)
                    Text(order.collectionTime, fontWeight = FontWeight.Medium)
                }
            }

            Spacer(Modifier.height(12.dp))

            Text(
                text = "View Digital Bill & QR ➔",
                color = MaterialTheme.colorScheme.primary,
                fontWeight = FontWeight.Bold,
                modifier = Modifier.align(Alignment.End)
            )
        }
    }
}
