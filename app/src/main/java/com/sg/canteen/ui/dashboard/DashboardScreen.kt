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
import androidx.compose.foundation.pager.rememberPagerState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.lazy.grid.GridItemSpan


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
import java.util.Calendar
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
private fun determineDefaultCategory(): String {
    val hour = Calendar.getInstance().get(Calendar.HOUR_OF_DAY)
    return when {
        hour < 12 -> "Breakfast"
        hour < 16 -> "Lunch"
        else -> "Snacks"
    }
}

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
    viewModel: DashboardViewModel =
        androidx.lifecycle.viewmodel.compose.viewModel()
) {

    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    val isLoading by viewModel.isLoading.collectAsState()
    val menuItems by viewModel.menuItems.collectAsState()

    // ✅ IMPORTANT: Directly observe offers
    val offers by viewModel.offers.collectAsState()

    var selectedCategory by remember { mutableStateOf("Snacks") }

    var selectedSnackSubId by remember { mutableStateOf<String?>(null) }
    var showSearchScreen by remember { mutableStateOf(false) }
    var searchQuery by remember { mutableStateOf("") }

    val searchHistory = remember { mutableStateListOf<String>() }
    val favorites = remember { mutableStateListOf<String>() }

    // -----------------------------
    // LOAD FAVORITES + SEARCH
    // -----------------------------
    LaunchedEffect(Unit) {
        val prefs = context.appDataStore.data.first()

        favorites.clear()
        favorites.addAll(prefs[FAVORITES_KEY] ?: emptySet())

        searchHistory.clear()
        searchHistory.addAll(prefs[SEARCH_HISTORY_KEY] ?: emptySet())
    }

    // -----------------------------
    // CATEGORIES
    // -----------------------------
    val allCategories =
        listOf("Breakfast", "Lunch", "Snacks", "Stationery", "Essentials", "Favorites")

    val visibleCategories = allCategories.filter { cat ->
        cat == "Favorites" || menuItems.any { it.category == cat }
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
    val filteredItems = remember(
        selectedCategory,
        selectedSnackSubId,
        menuItems,
        favorites.size
    ) {
        menuItems.filter { item ->
            when (selectedCategory) {
                "Favorites" -> favorites.contains(item._id)

                "Snacks" -> {
                    selectedSnackSubId != null &&
                            item.category == "Snacks" &&
                            item.subCategory?._id == selectedSnackSubId
                }

                else -> item.category == selectedCategory
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
                TopAppBar(
                    title = { Text("JJ Canteen", fontWeight = FontWeight.Bold) },
                    actions = {
                        IconButton(onClick = { showSearchScreen = true }) {
                            Icon(Icons.Default.Search, null)
                        }
                        IconButton(onClick = onToggleTheme) {
                            Icon(
                                if (isDarkTheme)
                                    Icons.Default.LightMode
                                else
                                    Icons.Default.DarkMode,
                                null
                            )
                        }
                    }
                )
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

                    // 🔍 SEARCH BAR (FULL WIDTH)
                    item(span = { GridItemSpan(2) }) {
                        SearchBar(
                            query = searchQuery,
                            onQueryChange = { searchQuery = it },
                            onClick = { showSearchScreen = true }
                        )
                    }

                    // 🔥 AD BANNER (FULL WIDTH)
                    if (ads.isNotEmpty()) {
                        item(span = { GridItemSpan(2) }) {

                            val pagerState = rememberPagerState { ads.size }

                            LaunchedEffect(pagerState.currentPage) {
                                delay(3000)
                                if (ads.isNotEmpty()) {
                                    val next =
                                        (pagerState.currentPage + 1) % ads.size
                                    pagerState.animateScrollToPage(next)
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
                                    modifier = Modifier.fillMaxSize()
                                ) { page ->
                                    Image(
                                        painter = rememberAsyncImagePainter(
                                            ads[page].imageUrl
                                        ),
                                        contentDescription = null,
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
                                    CartState.addItem(
                                        id = item._id,
                                        name = item.name,
                                        imageUrl = item.imageUrl ?: "",
                                        actualPrice = offerApplied.finalPrice
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
                favorites = favorites,
                offers = offers,
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
                    if (!searchHistory.contains(item.name)) {
                        searchHistory.add(item.name)
                        if (searchHistory.size > 8) searchHistory.removeAt(0)

                        scope.launch {
                            context.appDataStore.edit {
                                it[SEARCH_HISTORY_KEY] = searchHistory.toSet()
                            }
                        }
                    }
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

                        // ✅ MATCH OFFER SAFELY
                        val matchedOffer = offers.firstOrNull { offer ->
                            offer.isActive &&
                                    offer.applicableItemIds()
                                        .any { it.trim() == item._id.trim() }
                        }

                        val discountPercent = matchedOffer?.discountPercentage ?: 0

                        // ✅ BASE PRICE = originalPrice first
                        val basePrice = (item.originalPrice ?: item.price).toInt()

                        CartState.addItem(
                            id = item._id,
                            name = item.name,
                            actualPrice = basePrice,
                            imageUrl = item.imageUrl,
                            offerPercent = discountPercent
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
            .padding(12.dp),
        placeholder = { Text("Search for snacks, drinks...") },
        leadingIcon = {
            Icon(Icons.Default.Search, contentDescription = null)
        },
        shape = RoundedCornerShape(14.dp),
        singleLine = true
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
    Card(
        shape = RoundedCornerShape(12.dp),
        elevation = CardDefaults.cardElevation(3.dp),
        modifier = Modifier
            .fillMaxWidth()
            .aspectRatio(0.78f)  // 🔥 fixed compact card height

    ) {
        Box {

            Column {

                Image(
                    painter = rememberAsyncImagePainter(item.imageUrl),
                    contentDescription = item.name,
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(120.dp)   // ✅ fixed height works correctly in grid
                        .clip(RoundedCornerShape(10.dp)),
                    contentScale = ContentScale.Fit   // ✅ PNG safe scaling
                )




                Column(modifier = Modifier.padding(5.dp)) {

                    Text(
                        text = item.name,
                        fontWeight = FontWeight.SemiBold,
                        fontSize = 12.sp,
                        maxLines = 1
                    )



                    Spacer(Modifier.height(4.dp))

                    Row(verticalAlignment = Alignment.CenterVertically) {

                        Text(
                            text = "₹$finalPrice",
                            color = MaterialTheme.colorScheme.primary,
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

                    Spacer(Modifier.height(8.dp))

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

            if (offerPercent > 0) {
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
