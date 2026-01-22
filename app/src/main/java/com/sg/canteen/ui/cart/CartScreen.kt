package com.sg.canteen.ui.cart

import android.app.Activity
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Remove
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextDecoration
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import coil.compose.rememberAsyncImagePainter
import com.sg.canteen.MainActivity
import com.sg.canteen.network.ApiClient
import com.sg.canteen.network.ApiService
import com.sg.canteen.network.models.OrderItemDto
import com.sg.canteen.network.models.PlaceOrderRequest
import com.sg.canteen.payment.PaymentManager
import com.sg.canteen.ui.notification.OrderNotificationWorker
import com.sg.canteen.ui.order.OrdersState
import com.sg.canteen.ui.utils.DeviceUtils
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CartScreen(
    modifier: Modifier = Modifier,
    onOrderPlaced: () -> Unit
) {
    val context = LocalContext.current
    val activity = context as MainActivity
    val scope = rememberCoroutineScope()
    val api = remember { ApiClient.retrofit.create(ApiService::class.java) }

    val cartItems = CartState.cartItems
    val totalSavings = CartState.totalSavings()

    var showTimeDialog by remember { mutableStateOf(false) }
    var selectedTime by remember { mutableStateOf("Now") }
    val deviceId = remember { DeviceUtils.getDeviceId(context) }

    Scaffold(
        modifier = modifier,
        topBar = { TopAppBar(title = { Text("My Cart") }) }
    ) { padding ->

        if (cartItems.isEmpty()) {
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(padding),
                contentAlignment = Alignment.Center
            ) {
                Text("Your cart is empty 🛒", fontSize = 18.sp)
            }
            return@Scaffold
        }

        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp)
        ) {

            LazyColumn(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                items(cartItems, key = { it.id }) {
                    CartItemRow(it)
                }
            }

            // ✅ SAVINGS
            if (totalSavings > 0) {
                Text(
                    text = "Total Savings: ₹$totalSavings",
                    color = Color(0xFF4CAF50),
                    fontWeight = FontWeight.Bold,
                    fontSize = 16.sp,
                    modifier = Modifier.padding(vertical = 4.dp)
                )
            }

            HorizontalDivider()
            Spacer(Modifier.height(8.dp))

            Text(
                text = "Total: ₹${CartState.totalPrice()}",
                fontSize = 20.sp,
                fontWeight = FontWeight.Bold
            )

            Spacer(Modifier.height(12.dp))

            Button(
                modifier = Modifier.fillMaxWidth(),
                onClick = { showTimeDialog = true }
            ) {
                Text("Place Order")
            }
        }
    }

    if (showTimeDialog) {
        AlertDialog(
            onDismissRequest = { showTimeDialog = false },
            title = { Text("When will you collect?") },
            text = {
                Column {
                    listOf("Now", "15 minutes", "30 minutes").forEach { time ->
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            RadioButton(
                                selected = selectedTime == time,
                                onClick = { selectedTime = time }
                            )
                            Text(time)
                        }
                    }
                }
            },
            confirmButton = {
                TextButton(onClick = {
                    showTimeDialog = false
                    PaymentManager.startPayment(
                        activity = activity,
                        amount = CartState.totalPrice(),
                        onSuccess = { paymentId ->
                            scheduleOrderNotification(activity)
                            scope.launch {
                                val orderResponse = api.placeOrder(
                                    PlaceOrderRequest(
                                        items = cartItems.map {
                                            OrderItemDto(
                                                _id = it.id,
                                                name = it.name,
                                                price = it.price.toDouble(),
                                                quantity = it.quantity
                                            )
                                        },
                                        totalAmount = CartState.totalPrice().toDouble(),
                                        collectionTime = selectedTime,
                                        paymentMethod = "RAZORPAY",
                                        paymentStatus = "PAID",
                                        paymentId = paymentId,
                                        deviceId = deviceId
                                    )
                                )
                                OrdersState.lastOrder = orderResponse
                                CartState.clearCart()
                                onOrderPlaced()
                            }
                        }
                    )
                }) {
                    Text("Continue to Pay")
                }
            }
        )
    }
}

@Composable
fun CartItemRow(item: CartItem) {
    Card(modifier = Modifier.fillMaxWidth()) {

        Box(modifier = Modifier.fillMaxWidth()) {

            Row(
                modifier = Modifier.padding(12.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {

                Image(
                    painter = rememberAsyncImagePainter(item.imageUrl ?: ""),
                    contentDescription = item.name,
                    modifier = Modifier
                        .size(64.dp)
                        .clip(MaterialTheme.shapes.medium),
                    contentScale = ContentScale.Crop
                )

                Spacer(Modifier.width(12.dp))

                Column(Modifier.weight(1f)) {

                    Text(
                        item.name,
                        fontSize = 16.sp,
                        fontWeight = FontWeight.Bold
                    )

                    Row(verticalAlignment = Alignment.CenterVertically) {

                        val discountedPrice = remember(item.price, item.offerPercent) {
                            if (item.offerPercent > 0) {
                                (item.price - (item.price * item.offerPercent / 100f)).toInt()
                            } else {
                                item.price
                            }
                        }

                        Row(verticalAlignment = Alignment.CenterVertically) {

                            // ✅ DISCOUNTED PRICE
                            Text(
                                text = "₹$discountedPrice",
                                fontSize = 15.sp,
                                color = Color(0xFF4CAF50),
                                fontWeight = FontWeight.Bold
                            )

                            // ✅ ORIGINAL PRICE (STRIKE)
                            if (item.offerPercent > 0) {
                                Spacer(Modifier.width(6.dp))
                                Text(
                                    text = "₹${item.price}",
                                    fontSize = 12.sp,
                                    color = Color.Gray,
                                    textDecoration = TextDecoration.LineThrough
                                )
                            }
                        }

                    }
                }

                Row(verticalAlignment = Alignment.CenterVertically) {
                    IconButton(onClick = { CartState.decreaseQuantity(item.id) }) {
                        Icon(Icons.Default.Remove, contentDescription = null)
                    }
                    Text(item.quantity.toString(), fontWeight = FontWeight.Bold)
                    IconButton(onClick = { CartState.increaseQuantity(item.id) }) {
                        Icon(Icons.Default.Add, contentDescription = null)
                    }
                }
            }

            // ✅ FIXED OFFER BADGE
            if (item.offerPercent > 0) {
                Surface(
                    color = Color.Red,
                    shape = MaterialTheme.shapes.extraSmall,
                    modifier = Modifier
                        .align(Alignment.TopEnd)
                        .padding(4.dp)
                ) {
                    Text(
                        text = "${item.offerPercent}% OFF",
                        color = Color.White,
                        fontSize = 9.sp,
                        fontWeight = FontWeight.Bold,
                        modifier = Modifier.padding(horizontal = 4.dp, vertical = 2.dp)
                    )
                }
            }
        }
    }
}

private fun scheduleOrderNotification(activity: Activity) {
    val work = OneTimeWorkRequestBuilder<OrderNotificationWorker>().build()
    WorkManager.getInstance(activity).enqueue(work)
}

