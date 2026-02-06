package com.sg.canteen.ui.order

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import com.sg.canteen.network.models.OrderResponse

object OrdersState {

    // ✅ Compose UI auto-ah update aaga mutableStateOf use pannalam
    var lastOrder by mutableStateOf<OrderResponse?>(null)
        private set

    // ✅ Order success aagum pothu ithu vazhiya update pannunga
    fun setOrder(order: OrderResponse) {
        lastOrder = order
    }

    fun clear() {
        lastOrder = null
    }
}