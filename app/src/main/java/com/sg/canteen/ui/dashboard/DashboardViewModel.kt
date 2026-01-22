package com.sg.canteen.ui.dashboard

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.sg.canteen.network.ApiClient
import com.sg.canteen.network.ApiService
import com.sg.canteen.network.models.MenuItemDto
import com.sg.canteen.network.models.OfferDto
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

    init {
        loadMenu()
        startOfferAutoRefresh()   // ✅ auto sync offers
    }

    // -----------------------------
    // LOAD MENU
    // -----------------------------
    private fun loadMenu() {
        viewModelScope.launch {
            _isLoading.value = true
            try {
                _menuItems.value = api.getMenu()
            } catch (e: Exception) {
                _menuItems.value = emptyList()
            } finally {
                _isLoading.value = false
            }
        }
    }

    // -----------------------------
    // AUTO REFRESH OFFERS
    // -----------------------------
    private fun startOfferAutoRefresh() {
        viewModelScope.launch {
            while (true) {
                try {
                    val freshOffers = api.getPublicOffers()
                    _offers.value = freshOffers
                } catch (e: Exception) {
                    e.printStackTrace()
                }
                delay(10_000)   // 🔁 refresh every 10 seconds
            }
        }
    }
}
