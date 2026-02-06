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
import retrofit2.http.PATCH
import retrofit2.http.Path
import retrofit2.http.Query

/* ================= REQUEST/RESPONSE MODELS ================= */

data class FcmRegisterRequest(
    val deviceId: String,
    val fcmToken: String
)

// Updated to match your Backend Schema exactly
data class ServiceHoursDto(
    val location: String, // ✅ Matches backend schema update
    val breakfast: TimeRange,
    val lunch: TimeRange
)

data class TimeRange(
    val start: String,
    val end: String
)

/* ================= API INTERFACE ================= */

interface ApiService {

    /* ================= PUBLIC MENU (STUDENTS) =================
       Filters between 'canteen' and 'cafeteria' items.
    =========================================================== */
    @GET("api/menu/public")
    suspend fun getPublicMenu(
        @Query("location") location: String
    ): List<MenuItemDto>

    /* ================= SERVICE HOURS =================
       ✅ Specifically fetches the hours for the selected location.
       Fixes the 8:00 AM vs 9:00 AM sync issue.
    =========================================================== */
    @GET("api/service-hours/public")
    suspend fun getServiceHours(
        @Query("location") location: String
    ): ServiceHoursDto

    /* ================= PUBLIC OFFERS (STUDENTS) =================
       ✅ FIXED: Added @Query("location") to resolve "Too many arguments" error.
       Allows splitting offers between 'canteen' and 'cafeteria'.
    =========================================================== */
    @GET("api/offers/public")
    suspend fun getPublicOffers(
        @Query("location") location: String
    ): List<OfferDto>

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

    /* ================= STUDENT FEEDBACK =================
       ✅ Updated to use the new FeedbackRequest containing 'location'.
    =========================================================== */
    @POST("api/feedback")
    suspend fun submitFeedback(
        @Body request: FeedbackRequest
    ): Map<String, String>

    /* ================= 🔔 REGISTER FCM TOKEN ================= */
    @POST("api/notifications/register")
    suspend fun registerFcmToken(
        @Body request: FcmRegisterRequest
    ): Map<String, String>
}