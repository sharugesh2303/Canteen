package com.sg.canteen.ui.cart

import android.app.Activity
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
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
import com.sg.canteen.network.models.PlaceOrderItemDto
import com.sg.canteen.network.models.PlaceOrderRequest
import com.sg.canteen.payment.PaymentManager
import com.sg.canteen.ui.notification.OrderNotificationWorker
import com.sg.canteen.ui.order.OrdersState
import com.sg.canteen.ui.utils.DeviceUtils
import kotlinx.coroutines.launch
import kotlin.math.roundToInt

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
    // Total price and savings calculated based on discounted units in CartState
    val totalPrice = CartState.totalPrice()
    val totalSavings = CartState.totalSavings()

    var showTimeDialog by remember { mutableStateOf(false) }
    var selectedTime by remember { mutableStateOf("Now") }
    val deviceId = remember { DeviceUtils.getDeviceId(context) }

    Scaffold(
        modifier = modifier,
        topBar = {
            TopAppBar(title = { Text("My Cart", fontWeight = FontWeight.Bold) })
        }
    ) { padding ->

        if (cartItems.isEmpty()) {
            Box(
                modifier = Modifier.fillMaxSize().padding(padding),
                contentAlignment = Alignment.Center
            ) {
                Text("Your cart is empty 🛒", fontSize = 18.sp, color = Color.Gray)
            }
            return@Scaffold
        }

        Column(
            modifier = Modifier.fillMaxSize().padding(padding).padding(16.dp)
        ) {
            LazyColumn(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                items(cartItems, key = { it.id }) { item ->
                    CartItemRow(item)
                }
            }

            Spacer(Modifier.height(16.dp))

            // 🎉 Total Savings Banner
            if (totalSavings > 0) {
                Surface(
                    color = Color(0xFFE8F5E9),
                    shape = RoundedCornerShape(8.dp),
                    modifier = Modifier.fillMaxWidth().padding(bottom = 12.dp)
                ) {
                    Text(
                        text = "🎉 Total Savings: ₹$totalSavings",
                        color = Color(0xFF2E7D32),
                        fontWeight = FontWeight.Bold,
                        fontSize = 14.sp,
                        modifier = Modifier.padding(12.dp)
                    )
                }
            }

            // Checkout Card
            Card(
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(Modifier.padding(16.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Text("Total Payable", style = MaterialTheme.typography.titleMedium)
                        Text("₹$totalPrice", fontSize = 22.sp, fontWeight = FontWeight.Black)
                    }

                    Spacer(Modifier.height(16.dp))

                    Button(
                        modifier = Modifier.fillMaxWidth().height(50.dp),
                        shape = RoundedCornerShape(12.dp),
                        onClick = { showTimeDialog = true }
                    ) {
                        Text("Place Order", fontWeight = FontWeight.Bold)
                    }
                }
            }
        }
    }

    if (showTimeDialog) {
        AlertDialog(
            onDismissRequest = { showTimeDialog = false },
            title = { Text("Collection Details") },
            text = {
                Column {
                    listOf("Now", "15 minutes", "30 minutes").forEach { time ->
                        Row(
                            modifier = Modifier.fillMaxWidth().clickable { selectedTime = time },
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            RadioButton(selected = selectedTime == time, onClick = { selectedTime = time })
                            Text(time)
                        }
                    }
                }
            },
            confirmButton = {
                Button(onClick = {
                    showTimeDialog = false

                    PaymentManager.startPayment(
                        activity = activity,
                        amount = totalPrice,
                        onSuccess = { paymentId ->
                            scheduleOrderNotification(activity)

                            scope.launch {
                                // Standardize location string (lowercase)
                                val orderLocation = CartState.currentCartLocation?.lowercase() ?: "canteen"

                                val requestItems = cartItems.map { cartItem ->
                                    // Base unit price (MRP)
                                    val basePrice = cartItem.price
                                    val discount = cartItem.offerPercent

                                    // Final unit price after discount
                                    val finalUnitPrice = if (discount > 0)
                                        (basePrice - (basePrice * discount / 100f)).roundToInt()
                                    else basePrice

                                    PlaceOrderItemDto(
                                        itemId = cartItem.id,
                                        name = cartItem.name,
                                        quantity = cartItem.quantity,
                                        unitPrice = finalUnitPrice.toDouble(),
                                        originalPrice = basePrice.toDouble(),
                                        offerPercent = discount
                                    )
                                }

                                val orderResponse = api.placeOrder(
                                    PlaceOrderRequest(
                                        items = requestItems,
                                        totalAmount = totalPrice.toDouble(),
                                        collectionTime = selectedTime,
                                        paymentMethod = "RAZORPAY",
                                        paymentStatus = "PAID",
                                        paymentId = paymentId,
                                        deviceId = deviceId,
                                        location = orderLocation
                                    )
                                )

                                OrdersState.setOrder(orderResponse)
                                CartState.clearCart()
                                onOrderPlaced()
                            }
                        }
                    )
                }) {
                    Text("Pay ₹$totalPrice")
                }
            }
        )
    }
}

@Composable
fun CartItemRow(item: CartItem) {
    // Row-level logic for discounted price display
    val basePrice = item.price
    val offerPercent = item.offerPercent
    val discountedPrice = if (offerPercent > 0) {
        (basePrice - (basePrice * offerPercent / 100f)).roundToInt()
    } else basePrice

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
    ) {
        Row(
            modifier = Modifier.padding(12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Image(
                painter = rememberAsyncImagePainter(item.imageUrl ?: ""),
                contentDescription = item.name,
                modifier = Modifier.size(70.dp).clip(RoundedCornerShape(8.dp)),
                contentScale = ContentScale.Crop
            )

            Spacer(Modifier.width(12.dp))

            Column(Modifier.weight(1f)) {
                Text(item.name, fontSize = 16.sp, fontWeight = FontWeight.Bold)

                Row(verticalAlignment = Alignment.CenterVertically) {
                    // Current Price
                    Text("₹$discountedPrice", color = Color(0xFF2E7D32), fontWeight = FontWeight.Bold)

                    if (offerPercent > 0) {
                        Spacer(Modifier.width(8.dp))
                        // Strikethrough for Original Price
                        Text(
                            text = "₹$basePrice",
                            fontSize = 12.sp,
                            color = Color.Gray,
                            textDecoration = TextDecoration.LineThrough
                        )
                        Spacer(Modifier.width(6.dp))
                        // Offer Badge
                        Text(
                            text = "$offerPercent% OFF",
                            fontSize = 10.sp,
                            color = Color.Red,
                            fontWeight = FontWeight.Bold
                        )
                    }
                }
            }

            // Quantity Controls
            Row(verticalAlignment = Alignment.CenterVertically) {
                IconButton(onClick = { CartState.decreaseQuantity(item.id) }) {
                    Icon(Icons.Default.Remove, null, tint = Color.Red)
                }
                Text(item.quantity.toString(), fontWeight = FontWeight.Bold)
                IconButton(onClick = { CartState.increaseQuantity(item.id) }) {
                    Icon(Icons.Default.Add, null, tint = Color(0xFF2E7D32))
                }
            }
        }
    }
}

private fun scheduleOrderNotification(activity: Activity) {
    val work = OneTimeWorkRequestBuilder<OrderNotificationWorker>().build()
    WorkManager.getInstance(activity).enqueue(work)
}