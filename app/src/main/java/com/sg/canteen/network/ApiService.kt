package com.sg.canteen.network

import com.sg.canteen.network.models.AdvertisementDto
import com.sg.canteen.network.models.FeedbackRequest
import com.sg.canteen.network.models.MenuItemDto
import com.sg.canteen.network.models.OfferDto
import com.sg.canteen.network.models.OrderResponse
import com.sg.canteen.network.models.PlaceOrderRequest
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Query

interface ApiService {

    /* ================= PUBLIC MENU (STUDENTS) =================
       ✅ TIME-BASED FILTER APPLIED IN BACKEND
       Backend: GET /api/menu/public
    =========================================================== */
    @GET("api/menu/public")
    suspend fun getMenu(): List<MenuItemDto>

    /* ================= ✅ PUBLIC OFFERS (STUDENTS) =================
       Backend: GET /api/offers/public
    =========================================================== */
    @GET("api/offers/public")
    suspend fun getPublicOffers(): List<OfferDto>

    /* ================= PLACE ORDER =================
       Backend: POST /api/orders
    =================================================== */
    @POST("api/orders")
    suspend fun placeOrder(
        @Body request: PlaceOrderRequest
    ): OrderResponse

    /* ================= GET ORDERS (DEVICE BASED) =================
       Backend: GET /api/orders?deviceId=XXXX
    =================================================== */
    @GET("api/orders")
    suspend fun getOrders(
        @Query("deviceId") deviceId: String
    ): List<OrderResponse>

    /* ================= PUBLIC ADVERTISEMENTS =================
       Backend: GET /advertisements/public
    =========================================================== */
    @GET("advertisements/public")
    suspend fun getActiveAdvertisements(): List<AdvertisementDto>

    /* ================= STUDENT FEEDBACK =================
       Backend: POST /api/feedback
    =========================================================== */
    @POST("api/feedback")
    suspend fun submitFeedback(
        @Body request: FeedbackRequest
    ): Map<String, String>
}
