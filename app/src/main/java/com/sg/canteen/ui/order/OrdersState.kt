package com.sg.canteen.ui.order

import com.sg.canteen.network.models.OrderResponse

object OrdersState {

    var lastOrder: OrderResponse? = null

    fun clear() {
        lastOrder = null
    }
}
