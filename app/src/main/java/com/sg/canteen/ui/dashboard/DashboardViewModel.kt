package com.sg.canteen.ui.dashboard

import android.util.Log
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.sg.canteen.network.ApiClient
import com.sg.canteen.network.ApiService
import com.sg.canteen.network.ServiceHoursDto
import com.sg.canteen.network.models.MenuItemDto
import com.sg.canteen.network.models.OfferDto
import kotlinx.coroutines.Job
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch

class DashboardViewModel : ViewModel() {

    private val api = ApiClient.retrofit.create(ApiService::class.java)

    // -----------------------------
    // UI STATES
    // -----------------------------
    private val _isLoading = MutableStateFlow(false)
    val isLoading: StateFlow<Boolean> = _isLoading

    private val _menuItems = MutableStateFlow<List<MenuItemDto>>(emptyList())
    val menuItems: StateFlow<List<MenuItemDto>> = _menuItems

    private val _offers = MutableStateFlow<List<OfferDto>>(emptyList())
    val offers: StateFlow<List<OfferDto>> = _offers

    private val _serviceHours = MutableStateFlow<ServiceHoursDto?>(null)
    val serviceHours: StateFlow<ServiceHoursDto?> = _serviceHours

    // 📍 Track the current active location for auto-refreshing logic
    private var currentActiveLocation: String = "canteen"
    private var refreshJob: Job? = null

    // -----------------------------
    // FETCH DATA BY LOCATION
    // -----------------------------
    /**
     * Optimized to fetch menu, hours, and offers at the same time.
     * @param location "canteen" or "cafeteria"
     */
    fun fetchDashboardData(location: String) {
        currentActiveLocation = location
        viewModelScope.launch {
            _isLoading.value = true
            try {
                // ✅ Parallel execution for faster loading of all shop data
                val menuDeferred = async { fetchMenu(location) }
                val hoursDeferred = async { fetchServiceHours(location) }
                val offersDeferred = async { fetchOffers(location) }

                menuDeferred.await()
                hoursDeferred.await()
                offersDeferred.await()

                Log.d("DashboardViewModel", "✅ Successfully synced $location Dashboard")
            } catch (e: Exception) {
                Log.e("DashboardViewModel", "❌ Sync failed for $location: ${e.message}")
            } finally {
                _isLoading.value = false
            }
        }

        // Restart the auto-refresh loop for the specific location
        startOfferAutoRefresh(location)
    }

    // -----------------------------
    // FETCH MENU
    // -----------------------------
    suspend fun fetchMenu(location: String) {
        try {
            val items = api.getPublicMenu(location)
            _menuItems.value = items
        } catch (e: Exception) {
            _menuItems.value = emptyList()
            Log.e("DashboardViewModel", "Menu API error ($location): ${e.message}")
        }
    }

    // -----------------------------
    // FETCH SERVICE HOURS
    // -----------------------------
    suspend fun fetchServiceHours(location: String) {
        try {
            val hours = api.getServiceHours(location)
            _serviceHours.value = hours
            Log.d("DashboardViewModel", "Hours for $location loaded.")
        } catch (e: Exception) {
            Log.e("DashboardViewModel", "Hours API error ($location): ${e.message}")
        }
    }

    // -----------------------------
    // 📍 FETCH OFFERS (LOCATION AWARE)
    // -----------------------------
    suspend fun fetchOffers(location: String) {
        try {
            // ✅ FIXED: Now passing location to get location-specific offers
            val freshOffers = api.getPublicOffers(location)
            _offers.value = freshOffers
            Log.d("DashboardViewModel", "Fetched ${freshOffers.size} offers for $location")
        } catch (e: Exception) {
            Log.e("DashboardViewModel", "Offer API error ($location): ${e.message}")
        }
    }

    // -----------------------------
    // AUTO REFRESH OFFERS
    // -----------------------------
    /**
     * Loops the offer fetch to keep discounts live.
     * Restarts whenever the user switches between Canteen and Cafeteria.
     */
    private fun startOfferAutoRefresh(location: String) {
        refreshJob?.cancel() // Stop previous shop's refresh loop
        refreshJob = viewModelScope.launch {
            while (true) {
                fetchOffers(location)
                delay(15_000) // Refresh every 15 seconds
            }
        }
    }
}