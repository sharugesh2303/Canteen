package com.sg.canteen.ui.dashboard

// ---------- Compose Foundation ----------
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.items
import androidx.compose.foundation.pager.HorizontalPager
import androidx.compose.foundation.pager.PagerState // ✅ Added PagerState
import androidx.compose.foundation.pager.rememberPagerState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.lazy.grid.GridItemSpan
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.runtime.collectAsState

// ---------- Material Icons ----------
import androidx.compose.material.icons.Icons
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
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.*
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextDecoration
import androidx.compose.ui.unit.Density
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

// ---------- DataStore ----------
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringSetPreferencesKey

// ---------- Coil ----------
import coil.compose.rememberAsyncImagePainter

// ---------- App specific ----------
import com.sg.canteen.R // ✅ Ensure this matches your project's package name
import com.sg.canteen.network.models.AdvertisementDto
import com.sg.canteen.network.models.MenuItemDto
import com.sg.canteen.network.models.OfferDto
import com.sg.canteen.ui.cart.CartState
import com.sg.canteen.ui.utils.FAVORITES_KEY
import com.sg.canteen.ui.utils.appDataStore

// ---------- Coroutines ----------
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch

// ---------- Utils ----------
import kotlin.math.roundToInt

// -----------------------------
// DATASTORE KEY
// -----------------------------
val SEARCH_HISTORY_KEY = stringSetPreferencesKey("search_history")

// -----------------------------
// OFFER RESULT MODEL
// -----------------------------
data class AppliedOfferResult(
    val finalPrice: Int,
    val originalPrice: Int?,
    val offerPercent: Int,
    val offerName: String?
)

// -----------------------------
// ✅ APPLY OFFER (FIXED - PROPER BASE PRICE)
// -----------------------------
private fun applyOfferToItem(
    item: MenuItemDto,
    offers: List<OfferDto>
): AppliedOfferResult {

    // ✅ base price should be originalPrice first (MRP)
    val basePrice = (item.originalPrice ?: item.price).roundToInt()

    if (offers.isEmpty()) {
        return AppliedOfferResult(
            finalPrice = basePrice,
            originalPrice = null,
            offerPercent = 0,
            offerName = null
        )
    }

    val itemId = item._id.trim()

    var bestDiscount = 0
    var bestOfferName: String? = null

    offers.forEach { offer ->
        val offerItemIds = offer.applicableItemIds().map { it.trim() }

        if (offer.isActive && offerItemIds.contains(itemId)) {
            if (offer.discountPercentage > bestDiscount) {
                bestDiscount = offer.discountPercentage
                bestOfferName = offer.name
            }
        }
    }

    if (bestDiscount <= 0) {
        return AppliedOfferResult(
            finalPrice = basePrice,
            originalPrice = null,
            offerPercent = 0,
            offerName = null
        )
    }

    val discounted =
        (basePrice - (basePrice * bestDiscount / 100f)).roundToInt()

    return AppliedOfferResult(
        finalPrice = discounted,
        originalPrice = basePrice,
        offerPercent = bestDiscount,
        offerName = bestOfferName
    )
}

// -----------------------------
// WAVY BANNER SHAPE
// -----------------------------
class WavyBannerShape(
    private val waveCount: Int = 12,
    private val waveHeight: Float = 25f
) : Shape {
    override fun createOutline(
        size: Size,
        layoutDirection: LayoutDirection,
        density: Density
    ): Outline {
        val path = Path().apply {
            val waveWidth = size.width / waveCount
            moveTo(0f, waveHeight)
            for (i in 0 until waveCount) {
                relativeQuadraticBezierTo(
                    waveWidth / 4f,
                    -waveHeight,
                    waveWidth / 2f,
                    0f
                )
                relativeQuadraticBezierTo(
                    waveWidth / 4f,
                    waveHeight,
                    waveWidth / 2f,
                    0f
                )
            }
            close()
        }
        return Outline.Generic(path)
    }
}

// -----------------------------
// DEFAULT CATEGORY
// -----------------------------


// -----------------------------
// DASHBOARD SCREEN
// -----------------------------
@OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)
@Composable
fun DashboardScreen(
    modifier: Modifier = Modifier,
    isDarkTheme: Boolean,
    onToggleTheme: () -> Unit,
    onGoToOrders: () -> Unit,
    onGoToCart: () -> Unit,
    showAd: Boolean,
    ads: List<AdvertisementDto>,
    onAdDismissed: () -> Unit,
    onBack: () -> Unit, // ✅ Add this line
    onSwitchToCafeteria: () -> Unit, // ✅ Add this line
    viewModel: DashboardViewModel =
        androidx.lifecycle.viewmodel.compose.viewModel()

) {

    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    val isLoading by viewModel.isLoading.collectAsState()
    val menuItems by viewModel.menuItems.collectAsState()
    val offers by viewModel.offers.collectAsState()


    // ✅ IMPORTANT: Directly observe offers

    var showLocationMenu by remember { mutableStateOf(false) }
    var selectedCategory by remember { mutableStateOf("Snacks") }

    var selectedSnackSubId by remember { mutableStateOf<String?>(null) }
    var showSearchScreen by remember { mutableStateOf(false) }
    var searchQuery by remember { mutableStateOf("") }

    val searchHistory = remember { mutableStateListOf<String>() }
    val favorites = remember { mutableStateListOf<String>() }

    // -----------------------------
    // LOAD FAVORITES + SEARCH
    // -----------------------------
    // -----------------------------
    // LOAD FAVORITES + REFRESH FOR CANTEEN
    // -----------------------------
    LaunchedEffect(Unit) {
        // ViewModel-il neenga unified fetch function vechu irukkureenga, athaan crt
        viewModel.fetchDashboardData("canteen")

        val prefs = context.appDataStore.data.first()
        favorites.clear()
        favorites.addAll(prefs[FAVORITES_KEY] ?: emptySet())

        searchHistory.clear()
        searchHistory.addAll(prefs[SEARCH_HISTORY_KEY] ?: emptySet())
    }
    // 1. Create the filtered list (Place this above the if check)
    val canteenAds = remember(ads) {
        ads.filter { it.location.equals("canteen", ignoreCase = true) && it.isActive }
    }

    // -----------------------------
    // CATEGORIES
    // -----------------------------
    val allCategories =
        listOf("Breakfast", "Lunch", "Snacks", "Stationery", "Essentials", "Favorites")

    // ✅ Dependency list-la 'menuItems' matrum 'isAvailableNow' nichayam irukkanum
    val visibleCategories = remember(menuItems) {
        allCategories.filter { cat ->
            cat == "Favorites" || menuItems.any { it.category.equals(cat, ignoreCase = true) }
        }
    }

    // 🧊 SNACK SUB-CATEGORIES
    val snackSubCategories = remember(menuItems) {
        menuItems
            .filter { it.category == "Snacks" && it.subCategory != null }
            .map { it.subCategory!! }
            .distinctBy { it._id }
    }

    // -----------------------------
    // FILTER ITEMS
    // -----------------------------
    val filteredItems = remember(selectedCategory, selectedSnackSubId, menuItems, favorites.size) {
        menuItems.filter { item ->
            when (selectedCategory) {
                "Favorites" -> favorites.contains(item._id)
                "Snacks" -> selectedSnackSubId == null || item.subCategory?._id == selectedSnackSubId
                else -> item.category.equals(selectedCategory, ignoreCase = true)
            }
        }
    }


    // -----------------------------
    // SEARCH RESULT
    // -----------------------------
    val searchResults =
        if (searchQuery.isNotBlank()) {
            menuItems.filter {
                it.name.contains(searchQuery, ignoreCase = true)
            }
        } else emptyList()

    /// -----------------------------
// UI
// -----------------------------
    Box(modifier = Modifier.fillMaxSize()) {

        Scaffold(
            modifier = modifier,
            topBar = {
                Column(modifier = Modifier.background(MaterialTheme.colorScheme.surface)) {
                    // --- Row 1: Location Switcher & Theme ---
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
                                Text(text = "Canteen", fontWeight = FontWeight.Bold, fontSize = 18.sp)
                                Icon(Icons.Default.KeyboardArrowDown, contentDescription = null)
                            }

                            DropdownMenu(
                                expanded = showLocationMenu,
                                onDismissRequest = { showLocationMenu = false }
                            ) {
                                DropdownMenuItem(
                                    text = { Text("Canteen") },
                                    leadingIcon = { Icon(Icons.Default.Storefront, null) },
                                    onClick = { showLocationMenu = false }
                                )
                                DropdownMenuItem(
                                    text = { Text("Cafeteria") },
                                    leadingIcon = { Icon(Icons.Default.Coffee, null) },
                                    onClick = {
                                        showLocationMenu = false
                                        CartState.clearCart() // ✅ Important: Clear cart before switching
                                        onSwitchToCafeteria()
                                    }
                                )
                            }
                        }

                        Spacer(modifier = Modifier.weight(1f))

                        IconButton(onClick = onToggleTheme) {
                            Icon(if (isDarkTheme) Icons.Default.LightMode else Icons.Default.DarkMode, null)
                        }
                    }

                    // --- Row 2: Back Button & Logo ---
                    Row(
                        modifier = Modifier.fillMaxWidth().height(60.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        IconButton(onClick = {
                            CartState.clearCart()
                            onBack()
                        }) {
                            Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                        }
                        Image(
                            painter = painterResource(id = R.drawable.college_logo),
                            contentDescription = "Logo",
                            modifier = Modifier.fillMaxHeight().padding(end = 16.dp),
                            contentScale = ContentScale.Fit
                        )
                    }
                }
            }
        ) { padding ->

            if (isLoading) {

                Box(
                    modifier = Modifier.fillMaxSize(),
                    contentAlignment = Alignment.Center
                ) {
                    CircularProgressIndicator()
                }

            } else {

                // ✅ SINGLE SCROLL CONTAINER (NO CRASH)
                LazyVerticalGrid(
                    modifier = Modifier
                        .padding(padding)
                        .fillMaxSize(),
                    columns = GridCells.Fixed(2),          // ✅ 2 items per row
                    verticalArrangement = Arrangement.spacedBy(10.dp),
                    horizontalArrangement = Arrangement.spacedBy(10.dp),
                    contentPadding = PaddingValues(12.dp)
                ) {

                    // 🔍 SEARCH BAR (FULL WIDTH) + THEME BUTTON
                    item(span = { GridItemSpan(2) }) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Box(modifier = Modifier.weight(1f)) {
                                SearchBar(
                                    query = searchQuery,
                                    onQueryChange = { searchQuery = it },
                                    onClick = { showSearchScreen = true }
                                )
                            }
                            IconButton(onClick = onToggleTheme) {
                                Icon(
                                    if (isDarkTheme)
                                        Icons.Default.LightMode
                                    else
                                        Icons.Default.DarkMode,
                                    contentDescription = "Toggle Theme"
                                )
                            }
                        }
                    }

                    // 🔥 AD BANNER (FULL WIDTH)

// 2. Use the filtered list for the UI (Loop logic improved)
                    if (canteenAds.isNotEmpty()) {
                        item(span = { GridItemSpan(2) }) {
                            // Infinite scrolling-க்கு மிக அதிகமான பக்கங்கள் இருப்பது போன்ற ஒரு மாயையை (Illusion) உருவாக்குகிறோம்
                            val virtualCount = Int.MAX_VALUE
                            val initialPage = virtualCount / 2 - (virtualCount / 2 % canteenAds.size)

                            val pagerState = rememberPagerState(
                                initialPage = initialPage,
                                pageCount = { virtualCount }
                            )

                            // 🔁 Continuous Auto-slide logic (Forward Only)
                            LaunchedEffect(canteenAds) {
                                while (true) {
                                    delay(3000) // 3 வினாடிகள் இடைவெளி
                                    if (canteenAds.size > 1) {
                                        // இது எப்போதும் அடுத்த பக்கத்திற்கு (Forward) மட்டுமே நகர்த்தும்
                                        pagerState.animateScrollToPage(pagerState.currentPage + 1)
                                    }
                                }
                            }

                            Box(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .height(180.dp)
                                    .padding(vertical = 8.dp)
                                    .clip(RoundedCornerShape(16.dp))
                            ) {
                                HorizontalPager(
                                    state = pagerState,
                                    modifier = Modifier.fillMaxSize(),
                                    // பக்கங்களை முன்கூட்டியே தயார் நிலையில் வைக்க (Smoothness)
                                    beyondViewportPageCount = 1
                                ) { virtualPage ->
                                    // அசல் அட்வர்டைஸ்மெண்ட் இன்டெக்ஸை கணக்கிடுதல்
                                    val actualPage = virtualPage % canteenAds.size

                                    Image(
                                        painter = rememberAsyncImagePainter(
                                            canteenAds[actualPage].imageUrl
                                        ),
                                        contentDescription = "Canteen Promotion",
                                        modifier = Modifier.fillMaxSize(),
                                        contentScale = ContentScale.Crop
                                    )
                                }
                            }
                        }
                    }

                    // ✅ CATEGORY CHIPS (FULL WIDTH)
                    item(span = { GridItemSpan(2) }) {
                        LazyRow(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            items(visibleCategories) { cat ->
                                CategoryChip(
                                    name = cat,
                                    selected = cat == selectedCategory,
                                    onClick = {
                                        selectedCategory = cat
                                        selectedSnackSubId = null
                                    }
                                )
                            }
                        }
                    }

                    // 🧊 SNACK SUB CATEGORY GRID
                    if (selectedCategory == "Snacks" && selectedSnackSubId == null) {

                        items(snackSubCategories, key = { it._id }) { sub ->
                            SnackSubCategoryCard(
                                name = sub.name ?: "Unknown",
                                imageUrl = sub.imageUrl,
                                onClick = { selectedSnackSubId = sub._id }
                            )
                        }

                    } else {

                        // 🧱 MAIN PRODUCT GRID (2 ITEMS PER ROW ✅)
                        items(filteredItems, key = { it._id }) { item ->

                            val offerApplied =
                                remember(item._id, offers) {
                                    applyOfferToItem(item, offers)
                                }

                            DashboardGridCard(
                                item = item,
                                isFavorite = favorites.contains(item._id),
                                finalPrice = offerApplied.finalPrice,
                                originalPrice = offerApplied.originalPrice,
                                offerPercent = offerApplied.offerPercent,
                                onToggleFavorite = {
                                    if (favorites.contains(item._id))
                                        favorites.remove(item._id)
                                    else
                                        favorites.add(item._id)

                                    scope.launch {
                                        context.appDataStore.edit {
                                            it[FAVORITES_KEY] = favorites.toSet()
                                        }
                                    }
                                },
                                onAddClicked = {
                                    val basePrice = (item.originalPrice ?: item.price).toInt()
                                    CartState.addItem(
                                        id = item._id,
                                        name = item.name,
                                        actualPrice = basePrice,
                                        imageUrl = item.imageUrl,
                                        offerPercent = offerApplied.offerPercent, // 🔥 FIX: Pass calculated offer
                                        location = "canteen"
                                    )
                                }
                            )
                        }
                    }
                }
            }
        }
    }


    // 🔍 SEARCH OVERLAY
    if (showSearchScreen) {
        SearchOverlay(
            query = searchQuery,
            onQueryChange = { searchQuery = it },
            history = searchHistory,
            results = searchResults,
            offers = offers,   // ✅ ADD THIS LINE
            favorites = favorites,
            onClose = {
                showSearchScreen = false
                searchQuery = ""
            },
            onToggleFavorite = { item ->
                if (favorites.contains(item._id))
                    favorites.remove(item._id)
                else
                    favorites.add(item._id)

                scope.launch {
                    context.appDataStore.edit {
                        it[FAVORITES_KEY] = favorites.toSet()
                    }
                }
            },
            onHistoryRemove = { h ->
                searchHistory.remove(h)
                scope.launch {
                    context.appDataStore.edit {
                        it[SEARCH_HISTORY_KEY] = searchHistory.toSet()
                    }
                }
            },
            onItemAdd = { item ->
                // 🔥 FIX: Calculate offer for searched item so Cart sees discounted price
                val offer = applyOfferToItem(item, offers)

                if (!searchHistory.contains(item.name)) {
                    searchHistory.add(item.name)
                    if (searchHistory.size > 8) searchHistory.removeAt(0)
                    scope.launch { context.appDataStore.edit { it[SEARCH_HISTORY_KEY] = searchHistory.toSet() } }
                }

                CartState.addItem(
                    id = item._id,
                    name = item.name,
                    actualPrice = (item.originalPrice ?: item.price).toInt(),
                    imageUrl = item.imageUrl,
                    offerPercent = offer.offerPercent, // 🔥 FIX: Pass calculated offer
                    location = "canteen"
                )
            }
        )
    }
}


// -----------------------------
// SEARCH OVERLAY
// -----------------------------
@Composable
fun SearchOverlay(
    query: String,
    onQueryChange: (String) -> Unit,
    history: List<String>,
    results: List<MenuItemDto>,
    favorites: List<String>,
    offers: List<OfferDto>,
    onClose: () -> Unit,
    onToggleFavorite: (MenuItemDto) -> Unit,
    onHistoryRemove: (String) -> Unit,
    onItemAdd: (MenuItemDto) -> Unit
) {
    Surface(
        modifier = Modifier.fillMaxSize(),
        color = MaterialTheme.colorScheme.surface
    ) {
        Column {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .statusBarsPadding()
                    .padding(8.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                IconButton(onClick = onClose) {
                    Icon(Icons.Default.ArrowBack, null)
                }
                TextField(
                    value = query,
                    onValueChange = onQueryChange,
                    modifier = Modifier.weight(1f),
                    placeholder = { Text("Search items...") },
                    singleLine = true,
                    trailingIcon = {
                        if (query.isNotEmpty()) {
                            IconButton(onClick = { onQueryChange("") }) {
                                Icon(Icons.Default.Close, null)
                            }
                        }
                    }
                )
            }

            HorizontalDivider()

            // ================= ITEMS VIEW =================

            if (query.isBlank()) {

                // 🔍 SEARCH HISTORY LIST (keep as list)
                LazyColumn {
                    items(history.asReversed()) { h ->
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable { onQueryChange(h) }
                                .padding(16.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Icon(Icons.Default.History, null, tint = Color.Gray)
                            Spacer(Modifier.width(12.dp))
                            Text(h, Modifier.weight(1f))
                            IconButton(onClick = { onHistoryRemove(h) }) {
                                Icon(Icons.Default.Clear, null, tint = Color.LightGray)
                            }
                        }
                    }
                }

            } else {

                // 🧱 PRODUCT GRID VIEW (MODERN UI)
                LazyVerticalGrid(
                    columns = GridCells.Fixed(2),
                    contentPadding = PaddingValues(12.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    items(results, key = { it._id }) { item ->

                        val offerApplied =
                            remember(item._id, offers) {
                                applyOfferToItem(item, offers)
                            }

                        DashboardGridCard(
                            item = item,
                            isFavorite = favorites.contains(item._id),
                            finalPrice = offerApplied.finalPrice,
                            originalPrice = offerApplied.originalPrice,
                            offerPercent = offerApplied.offerPercent,
                            onToggleFavorite = { onToggleFavorite(item) },
                            onAddClicked = { onItemAdd(item) }
                        )
                    }
                }
            }

        }
    }
}

// -----------------------------
// MENU ITEM ROW
// -----------------------------
@Composable
fun MenuItemRow(
    item: MenuItemDto,
    offers: List<OfferDto>,
    isFavorite: Boolean,
    onToggleFavorite: () -> Unit,
    onAddClicked: () -> Unit = {},
    finalPrice: Int = item.price.roundToInt(),
    appliedOriginalPrice: Int? = null,
    offerPercent: Int = 0
) {
    val isOutOfStock = (item.stock ?: 0) <= 0
    val hasOffer =
        offerPercent > 0 &&
                appliedOriginalPrice != null &&
                appliedOriginalPrice > finalPrice

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 8.dp, vertical = 6.dp),
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(
            containerColor =
                if (isOutOfStock)
                    MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f)
                else
                    MaterialTheme.colorScheme.surface
        )
    ) {
        Row(
            modifier = Modifier.padding(10.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {

            // IMAGE + BADGES
            Box(contentAlignment = Alignment.Center) {
                Image(
                    painter = rememberAsyncImagePainter(item.imageUrl),
                    contentDescription = null,
                    modifier = Modifier
                        .size(85.dp)
                        .clip(RoundedCornerShape(10.dp)),
                    contentScale = ContentScale.Crop,
                    colorFilter =
                        if (isOutOfStock)
                            ColorFilter.colorMatrix(
                                ColorMatrix().apply { setToSaturation(0f) }
                            )
                        else null
                )

                // OUT OF STOCK OVERLAY
                if (isOutOfStock) {
                    Box(
                        modifier = Modifier
                            .matchParentSize()
                            .background(Color.Black.copy(alpha = 0.5f))
                            .clip(RoundedCornerShape(10.dp)),
                        contentAlignment = Alignment.Center
                    ) {
                        Text(
                            "OUT OF\nSTOCK",
                            color = Color.White,
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Black,
                            textAlign = TextAlign.Center
                        )
                    }
                }

                // OFFER BADGE
                if (hasOffer && !isOutOfStock) {
                    Box(
                        modifier = Modifier
                            .align(Alignment.TopStart)
                            .padding(4.dp)
                            .size(38.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(
                            Icons.Default.LocalOffer,
                            null,
                            tint = Color.Red,
                            modifier = Modifier.fillMaxSize()
                        )
                        Text(
                            text = "$offerPercent%",
                            color = Color.White,
                            fontSize = 9.sp,
                            fontWeight = FontWeight.Bold
                        )
                    }
                }

                // FAVORITE BUTTON
                IconButton(
                    onClick = onToggleFavorite,
                    modifier = Modifier
                        .align(Alignment.TopEnd)
                        .size(32.dp)
                        .padding(4.dp)
                ) {
                    Icon(
                        imageVector =
                            if (isFavorite)
                                Icons.Default.Favorite
                            else
                                Icons.Outlined.FavoriteBorder,
                        contentDescription = null,
                        tint =
                            if (isFavorite) Color.Red
                            else if (isOutOfStock) Color.LightGray
                            else Color.Black,
                        modifier = Modifier.size(22.dp)
                    )
                }
            }

            Spacer(Modifier.width(12.dp))

            // TEXT AREA
            Column(Modifier.weight(1f)) {
                Text(
                    item.name,
                    fontWeight = FontWeight.SemiBold,
                    fontSize = 16.sp,
                    color = if (isOutOfStock) Color.Gray else Color.Unspecified
                )

                if (hasOffer) {
                    Text(
                        "₹$appliedOriginalPrice",
                        style = TextStyle(
                            textDecoration = TextDecoration.LineThrough,
                            color = Color.Gray,
                            fontSize = 12.sp
                        )
                    )
                }

                Text(
                    "₹$finalPrice",
                    fontWeight = FontWeight.Bold,
                    color =
                        if (isOutOfStock) Color.Gray
                        else MaterialTheme.colorScheme.primary,
                    fontSize = 15.sp
                )
            }

            // ACTION BUTTON
            if (isOutOfStock) {
                Text(
                    "Unavailable",
                    color = Color.Red,
                    fontSize = 12.sp,
                    fontWeight = FontWeight.Bold
                )
            } else {
                Button(
                    onClick = {
                        onAddClicked()

                        val basePrice = (item.originalPrice ?: item.price).toInt()

                        CartState.addItem(
                            id = item._id,
                            name = item.name,
                            actualPrice = basePrice,
                            imageUrl = item.imageUrl,
                            offerPercent = offerPercent, // 🔥 FIX: Use the percentage passed to the row
                            location = "canteen"
                        )
                    }
                ) {
                    Text("+ Add", fontWeight = FontWeight.Bold)
                }
            }
        }
    }
}

// -----------------------------
// SNACK SUBCATEGORY CARD
// -----------------------------
@Composable
fun SnackSubCategoryCard(
    name: String,
    imageUrl: String?,
    onClick: () -> Unit
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .aspectRatio(1f)
            .clickable { onClick() },
        shape = RoundedCornerShape(16.dp),
        elevation = CardDefaults.cardElevation(6.dp)
    ) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Image(
                painter = rememberAsyncImagePainter(imageUrl),
                contentDescription = null,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(120.dp),
                contentScale = ContentScale.Crop
            )

            Spacer(Modifier.height(8.dp))

            Text(
                text = name,
                fontWeight = FontWeight.Bold,
                fontSize = 16.sp,
                modifier = Modifier.padding(8.dp)
            )
        }
    }
}

// -----------------------------
// SEARCH BAR
// -----------------------------
@Composable
fun SearchBar(
    query: String,
    onQueryChange: (String) -> Unit,
    onClick: () -> Unit
) {
    OutlinedTextField(
        value = query,
        onValueChange = onQueryChange,
        modifier = Modifier
            .fillMaxWidth()
            .padding(12.dp)
            .clickable { onClick() },
        placeholder = { Text("Search for snacks, drinks...") },
        leadingIcon = {
            Icon(Icons.Default.Search, contentDescription = null)
        },
        shape = RoundedCornerShape(14.dp),
        singleLine = true,
        enabled = false, // Prevents typing directly to force overlay on click
        colors = OutlinedTextFieldDefaults.colors(
            disabledTextColor = MaterialTheme.colorScheme.onSurface,
            disabledBorderColor = MaterialTheme.colorScheme.outline,
            disabledLeadingIconColor = MaterialTheme.colorScheme.onSurfaceVariant,
            disabledTrailingIconColor = MaterialTheme.colorScheme.onSurfaceVariant,
            disabledPlaceholderColor = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    )
}

@Composable
fun DashboardGridCard(

    item: MenuItemDto,
    isFavorite: Boolean,
    finalPrice: Int,
    originalPrice: Int?,
    offerPercent: Int,
    onToggleFavorite: () -> Unit,
    onAddClicked: () -> Unit
) {

    val isOutOfStock = !item.isAvailable || item.stock <= 0

    Card(
        shape = RoundedCornerShape(12.dp),
        elevation = CardDefaults.cardElevation(3.dp),
        modifier = Modifier
            .fillMaxWidth()
            .aspectRatio(0.78f)
    ) {
        Box {

            Column {

                Image(
                    painter = rememberAsyncImagePainter(item.imageUrl),
                    contentDescription = item.name,
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(120.dp)
                        .clip(RoundedCornerShape(10.dp)),
                    contentScale = ContentScale.Fit,
                    colorFilter = if (isOutOfStock)
                        ColorFilter.colorMatrix(ColorMatrix().apply { setToSaturation(0f) })
                    else null
                )

                Column(modifier = Modifier.padding(5.dp)) {

                    Text(
                        text = item.name,
                        fontWeight = FontWeight.SemiBold,
                        fontSize = 12.sp,
                        maxLines = 1,
                        color = if (isOutOfStock) Color.Gray else Color.Unspecified
                    )

                    Spacer(Modifier.height(4.dp))

                    Row(verticalAlignment = Alignment.CenterVertically) {

                        Text(
                            text = "₹$finalPrice",
                            color = if (isOutOfStock) Color.Gray else MaterialTheme.colorScheme.primary,
                            fontWeight = FontWeight.Bold
                        )

                        if (offerPercent > 0 && originalPrice != null) {
                            Spacer(Modifier.width(6.dp))
                            Text(
                                text = "₹$originalPrice",
                                fontSize = 12.sp,
                                color = Color.Gray,
                                textDecoration = TextDecoration.LineThrough
                            )
                        }
                    }

                    Spacer(Modifier.height(6.dp))

                    if (isOutOfStock) {

                        Text(
                            text = "Out of Stock",
                            color = Color.Red,
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Bold
                        )

                        Spacer(Modifier.height(4.dp))

                        Button(
                            onClick = {},
                            enabled = false,
                            modifier = Modifier
                                .fillMaxWidth()
                                .height(30.dp),
                            shape = RoundedCornerShape(50),
                            colors = ButtonDefaults.buttonColors(
                                containerColor = Color.LightGray
                            ),
                            contentPadding = PaddingValues(0.dp)
                        ) {
                            Text("Unavailable", fontSize = 11.sp)
                        }

                    } else {

                        Button(
                            onClick = onAddClicked,
                            modifier = Modifier
                                .fillMaxWidth()
                                .height(30.dp),
                            shape = RoundedCornerShape(50),
                            contentPadding = PaddingValues(0.dp)
                        ) {
                            Text("+ Add", fontSize = 11.sp)
                        }
                    }
                }
            }

            IconButton(
                onClick = onToggleFavorite,
                modifier = Modifier.align(Alignment.TopEnd)
            ) {
                Icon(
                    imageVector = if (isFavorite)
                        Icons.Default.Favorite
                    else
                        Icons.Default.FavoriteBorder,
                    contentDescription = null,
                    tint = if (isFavorite) Color.Red else Color.White
                )
            }

            if (offerPercent > 0 && !isOutOfStock) {
                Surface(
                    color = Color.Red,
                    shape = RoundedCornerShape(6.dp),
                    modifier = Modifier
                        .align(Alignment.TopStart)
                        .padding(6.dp)
                ) {
                    Text(
                        text = "$offerPercent% OFF",
                        color = Color.White,
                        fontSize = 10.sp,
                        fontWeight = FontWeight.Bold,
                        modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                    )
                }
            }
        }
    }
}
