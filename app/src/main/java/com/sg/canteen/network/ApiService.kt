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

/* ================= FCM TOKEN REQUEST MODEL ================= */
data class FcmRegisterRequest(
    val deviceId: String,
    val fcmToken: String
)

interface ApiService {

    /* ================= PUBLIC MENU (STUDENTS) ================= */
    @GET("api/menu/public")
    suspend fun getMenu(): List<MenuItemDto>

    /* ================= PUBLIC OFFERS (STUDENTS) ================= */
    @GET("api/offers/public")
    suspend fun getPublicOffers(): List<OfferDto>

    /* ================= PLACE ORDER ================= */
    @POST("api/orders")
    suspend fun placeOrder(
        @Body request: PlaceOrderRequest
    ): OrderResponse

    /* ================= GET ORDERS (DEVICE BASED) ================= */
    @GET("api/orders")
    suspend fun getOrders(
        @Query("deviceId") deviceId: String
    ): List<OrderResponse>

    /* ================= PUBLIC ADVERTISEMENTS ================= */
    @GET("advertisements/public")
    suspend fun getActiveAdvertisements(): List<AdvertisementDto>

    /* ================= STUDENT FEEDBACK ================= */
    @POST("api/feedback")
    suspend fun submitFeedback(
        @Body request: FeedbackRequest
    ): Map<String, String>

    /* ================= 🔔 REGISTER FCM TOKEN =================
       Backend: POST /api/notifications/register
       Body:
       {
         "deviceId": "...",
         "fcmToken": "..."
       }
    =========================================================== */
    @POST("api/notifications/register")
    suspend fun registerFcmToken(
        @Body request: FcmRegisterRequest
    ): Map<String, String>
}
