package com.sg.canteen.ui.order

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.util.Base64
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

@Composable
fun OrderSuccessScreen(
    onGoHome: () -> Unit,
    onViewOrders: () -> Unit
) {
    val order = OrdersState.lastOrder

    /* ================= BASE64 → BITMAP (SAFE) ================= */
    val qrBitmap: Bitmap? = remember(order?.qrImage) {
        try {
            order?.qrImage?.let { base64 ->
                val pureBase64 = base64.substringAfter(",")
                val decodedBytes = Base64.decode(pureBase64, Base64.DEFAULT)
                BitmapFactory.decodeByteArray(
                    decodedBytes,
                    0,
                    decodedBytes.size
                )
            }
        } catch (e: Exception) {
            null
        }
    }

    Box(
        modifier = Modifier.fillMaxSize(),
        contentAlignment = Alignment.Center
    ) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            modifier = Modifier.padding(16.dp)
        ) {

            Text("✅ Order Placed!", fontSize = 26.sp)
            Spacer(Modifier.height(8.dp))
            Text("Thank you for ordering")

            Spacer(Modifier.height(20.dp))

            /* ================= QR IMAGE ================= */
            qrBitmap?.let {
                Image(
                    bitmap = it.asImageBitmap(),
                    contentDescription = "Order QR Code",
                    modifier = Modifier.size(220.dp)
                )
                Spacer(Modifier.height(12.dp))
            }

            Text("Bill No: ${order?.billNumber}")
            Spacer(Modifier.height(4.dp))
            Text("Amount Paid: ₹${order?.totalAmount}")
            Spacer(Modifier.height(4.dp))
            Text("Collection Time: ${order?.collectionTime}")

            Spacer(Modifier.height(28.dp))

            Button(
                onClick = onViewOrders,
                modifier = Modifier.fillMaxWidth(0.7f)
            ) {
                Text("View Orders")
            }

            Spacer(Modifier.height(12.dp))

            OutlinedButton(
                onClick = {
                    OrdersState.clear()
                    onGoHome()
                },
                modifier = Modifier.fillMaxWidth(0.7f)
            ) {
                Text("Back to Home")
            }
        }
    }
}
