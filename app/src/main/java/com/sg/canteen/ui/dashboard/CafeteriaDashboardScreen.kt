package com.sg.canteen.ui.dashboard

// ---------- Compose Foundation ----------
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.items
import androidx.compose.foundation.pager.HorizontalPager
import androidx.compose.foundation.pager.rememberPagerState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.lazy.grid.GridItemSpan

// ---------- Material Icons ----------
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.*
import androidx.compose.material.icons.outlined.FavoriteBorder

// ---------- Material3 ----------
import androidx.compose.material3.*

// ---------- Runtime ----------
import androidx.compose.runtime.*

// ---------- UI ----------
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.*
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

// ---------- DataStore ----------
import androidx.datastore.preferences.core.edit

// ---------- Coil ----------
import coil.compose.rememberAsyncImagePainter

// ---------- App specific ----------
import com.sg.canteen.R
import com.sg.canteen.network.models.* import com.sg.canteen.ui.cart.CartState
import com.sg.canteen.ui.utils.FAVORITES_KEY
import com.sg.canteen.ui.utils.SEARCH_HISTORY_KEY
import com.sg.canteen.ui.utils.appDataStore

// ---------- Coroutines ----------
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch

// ---------- Utils ----------
import kotlin.math.roundToInt

/**
 * Helper to calculate discounts for menu items
 */
private fun applyOfferToItem(item: MenuItemDto, offers: List<OfferDto>): AppliedOfferResult {
    val basePrice = (item.originalPrice ?: item.price).roundToInt()
    if (offers.isEmpty()) return AppliedOfferResult(basePrice, null, 0, null)

    val itemId = item._id.trim()
    var bestDiscount = 0
    var bestOfferName: String? = null

    offers.forEach { offer ->
        if (offer.isActive && offer.applicableItemIds().map { it.trim() }.contains(itemId)) {
            if (offer.discountPercentage > bestDiscount) {
                bestDiscount = offer.discountPercentage
                bestOfferName = offer.name
            }
        }
    }

    if (bestDiscount <= 0) return AppliedOfferResult(basePrice, null, 0, null)
    val discounted = (basePrice - (basePrice * bestDiscount / 100f)).roundToInt()
    return AppliedOfferResult(discounted, basePrice, bestDiscount, bestOfferName)
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CafeteriaDashboardScreen(
    modifier: Modifier = Modifier,
    isDarkTheme: Boolean,
    onToggleTheme: () -> Unit,
    onGoToOrders: () -> Unit,
    onGoToCart: () -> Unit,
    onBack: () -> Unit,
    onSwitchToCanteen: () -> Unit,
    ads: List<AdvertisementDto>,
    viewModel: DashboardViewModel = androidx.lifecycle.viewmodel.compose.viewModel()
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    val isLoading by viewModel.isLoading.collectAsState()
    val menuItems by viewModel.menuItems.collectAsState()
    val offers by viewModel.offers.collectAsState()

    var selectedCategory by remember { mutableStateOf("Breakfast") }
    var showSearchScreen by remember { mutableStateOf(false) }
    var searchQuery by remember { mutableStateOf("") }
    var showLocationMenu by remember { mutableStateOf(false) }

    val searchHistory = remember { mutableStateListOf<String>() }
    val favorites = remember { mutableStateListOf<String>() }

    val cafeteriaAds = remember(ads) {
        ads.filter { it.location.equals("cafeteria", ignoreCase = true) && it.isActive }
    }

    LaunchedEffect(Unit) {
        viewModel.fetchDashboardData(location = "cafeteria")
        val prefs = context.appDataStore.data.first()
        favorites.clear()
        favorites.addAll(prefs[FAVORITES_KEY] ?: emptySet())
        searchHistory.clear()
        searchHistory.addAll(prefs[SEARCH_HISTORY_KEY] ?: emptySet())
    }

    val allPossibleCategories = listOf("Breakfast", "Lunch", "Snacks", "Stationery", "Essentials", "Favorites")
    val visibleCategories = remember(menuItems) {
        allPossibleCategories.filter { cat ->
            cat == "Favorites" || menuItems.any { it.category.equals(cat, ignoreCase = true) }
        }
    }

    val filteredItems = remember(selectedCategory, menuItems, favorites.size) {
        menuItems.filter { item ->
            when (selectedCategory) {
                "Favorites" -> favorites.contains(item._id)
                else -> item.category.equals(selectedCategory, ignoreCase = true)
            }
        }
    }

    Box(modifier = Modifier.fillMaxSize()) {
        Scaffold(
            topBar = {
                Column(modifier = Modifier.background(MaterialTheme.colorScheme.surface)) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 16.dp, vertical = 8.dp)
                            .statusBarsPadding(),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(Icons.Default.LocationOn, contentDescription = null, tint = Color.Red)
                        Spacer(modifier = Modifier.width(8.dp))

                        Box {
                            Row(
                                modifier = Modifier.clickable { showLocationMenu = true },
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text(
                                    text = "Cafeteria",
                                    fontWeight = FontWeight.Bold,
                                    fontSize = 18.sp
                                )
                                Icon(Icons.Default.KeyboardArrowDown, contentDescription = null)
                            }

                            DropdownMenu(
                                expanded = showLocationMenu,
                                onDismissRequest = { showLocationMenu = false }
                            ) {
                                DropdownMenuItem(
                                    text = { Text("Canteen") },
                                    leadingIcon = { Icon(Icons.Default.Storefront, null) },
                                    onClick = {
                                        showLocationMenu = false
                                        CartState.clearCart()
                                        onSwitchToCanteen()
                                    }
                                )
                                DropdownMenuItem(
                                    text = { Text("Cafeteria") },
                                    leadingIcon = { Icon(Icons.Default.Coffee, null) },
                                    onClick = { showLocationMenu = false }
                                )
                            }
                        }

                        Spacer(modifier = Modifier.weight(1f))

                        IconButton(onClick = onToggleTheme) {
                            Icon(if (isDarkTheme) Icons.Default.LightMode else Icons.Default.DarkMode, null)
                        }
                    }

                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(60.dp)
                            .padding(horizontal = 16.dp),
                        contentAlignment = Alignment.CenterStart
                    ) {
                        Image(
                            painter = painterResource(id = R.drawable.college_logo),
                            contentDescription = "Logo",
                            modifier = Modifier.fillMaxHeight(),
                            contentScale = ContentScale.Fit
                        )
                    }
                }
            }
        ) { padding ->
            if (isLoading) {
                Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) { CircularProgressIndicator() }
            } else {
                LazyVerticalGrid(
                    modifier = Modifier.padding(padding).fillMaxSize(),
                    columns = GridCells.Fixed(2),
                    verticalArrangement = Arrangement.spacedBy(10.dp),
                    horizontalArrangement = Arrangement.spacedBy(10.dp),
                    contentPadding = PaddingValues(12.dp)
                ) {
                    item(span = { GridItemSpan(2) }) {
                        SearchBar(query = searchQuery, onQueryChange = {}, onClick = { showSearchScreen = true })
                    }

                    if (cafeteriaAds.isNotEmpty()) {
                        item(span = { GridItemSpan(2) }) {
                            val virtualCount = Int.MAX_VALUE
                            val initialPage = virtualCount / 2 - (virtualCount / 2 % cafeteriaAds.size)
                            val pagerState = rememberPagerState(initialPage = initialPage, pageCount = { virtualCount })

                            LaunchedEffect(cafeteriaAds) {
                                while(true) {
                                    delay(3000)
                                    pagerState.animateScrollToPage(pagerState.currentPage + 1)
                                }
                            }

                            Box(modifier = Modifier.fillMaxWidth().height(180.dp).clip(RoundedCornerShape(16.dp))) {
                                HorizontalPager(state = pagerState, modifier = Modifier.fillMaxSize()) { virtualPage ->
                                    val actualPage = virtualPage % cafeteriaAds.size
                                    Image(
                                        painter = rememberAsyncImagePainter(cafeteriaAds[actualPage].imageUrl),
                                        contentDescription = null,
                                        modifier = Modifier.fillMaxSize(),
                                        contentScale = ContentScale.Crop
                                    )
                                }
                            }
                        }
                    }

                    item(span = { GridItemSpan(2) }) {
                        LazyRow(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            items(visibleCategories) { cat ->
                                FilterChip(
                                    selected = cat == selectedCategory,
                                    onClick = { selectedCategory = cat },
                                    label = { Text(cat) }
                                )
                            }
                        }
                    }

                    items(filteredItems, key = { it._id }) { item ->
                        val offer = remember(item._id, offers) { applyOfferToItem(item, offers) }
                        DashboardGridCard(
                            item = item,
                            isFavorite = favorites.contains(item._id),
                            finalPrice = offer.finalPrice,
                            originalPrice = offer.originalPrice,
                            offerPercent = offer.offerPercent,
                            onToggleFavorite = {
                                if (favorites.contains(item._id)) favorites.remove(item._id)
                                else favorites.add(item._id)
                                scope.launch { context.appDataStore.edit { it[FAVORITES_KEY] = favorites.toSet() } }
                            },
                            onAddClicked = {
                                val basePrice = (item.originalPrice ?: item.price).toInt()
                                CartState.addItem(
                                    id = item._id, name = item.name, actualPrice = basePrice,
                                    imageUrl = item.imageUrl, offerPercent = offer.offerPercent,
                                    location = "cafeteria"
                                )
                            }
                        )
                    }
                }
            }
        }
    }

    if (showSearchScreen) {
        SearchOverlay(
            query = searchQuery,
            onQueryChange = { searchQuery = it },
            history = searchHistory,
            results = if (searchQuery.isNotBlank()) menuItems.filter { it.name.contains(searchQuery, ignoreCase = true) } else emptyList(),
            favorites = favorites,
            offers = offers,
            onClose = { showSearchScreen = false; searchQuery = "" },
            onToggleFavorite = { item ->
                if (favorites.contains(item._id)) favorites.remove(item._id) else favorites.add(item._id)
                scope.launch { context.appDataStore.edit { it[FAVORITES_KEY] = favorites.toSet() } }
            },
            onHistoryRemove = { h ->
                searchHistory.remove(h)
                scope.launch { context.appDataStore.edit { it[SEARCH_HISTORY_KEY] = searchHistory.toSet() } }
            },
            onItemAdd = { item ->
                val offer = applyOfferToItem(item, offers)
                CartState.addItem(item._id, item.name, (item.originalPrice ?: item.price).toInt(), item.imageUrl, offer.offerPercent, "cafeteria")
            }
        )
    }
}