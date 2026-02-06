/* ======================================================
 * FILE: com/sg/canteen/ui/components/AdvertisementDialog.kt
 * ====================================================== */

package com.sg.canteen.ui.components

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.pager.HorizontalPager
import androidx.compose.foundation.pager.rememberPagerState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import coil.compose.rememberAsyncImagePainter
import com.sg.canteen.network.models.AdvertisementDto
import kotlinx.coroutines.delay

/**
 * A dialog that displays location-specific advertisements.
 * * @param ads The full list of advertisements fetched from the backend.
 * @param currentLocation The active shop location ("canteen" or "cafeteria").
 * @param onDismiss Callback to close the dialog.
 */
@Composable
fun AdvertisementDialog(
    ads: List<AdvertisementDto>,
    currentLocation: String,
    onDismiss: () -> Unit
) {
    // 📍 FILTER LOGIC: Strict location matching
    // This ensures Canteen ads play only in Canteen side and vice versa.
    val filteredAds = remember(ads, currentLocation) {
        ads.filter { ad ->
            ad.location.equals(currentLocation, ignoreCase = true) && ad.isActive
        }
    }

    // If no ads match the current location, do not show the dialog
    if (filteredAds.isEmpty()) return

    val pagerState = rememberPagerState { filteredAds.size }

    // 🔁 Auto-slide logic specific to the filtered list
    LaunchedEffect(filteredAds) {
        while (true) {
            delay(3500)
            if (filteredAds.size > 1) {
                val next = (pagerState.currentPage + 1) % filteredAds.size
                pagerState.animateScrollToPage(next)
            }
        }
    }

    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(usePlatformDefaultWidth = false)
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {

            /* ===== AD BANNER CONTAINER ===== */
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(240.dp)
                    .clip(RoundedCornerShape(24.dp))
                    .background(Color.Black)
            ) {

                HorizontalPager(
                    state = pagerState,
                    modifier = Modifier.fillMaxSize()
                ) { page ->
                    Image(
                        painter = rememberAsyncImagePainter(filteredAds[page].imageUrl),
                        contentDescription = "Promotion for $currentLocation",
                        modifier = Modifier.fillMaxSize(),
                        contentScale = ContentScale.Crop
                    )
                }

                /* ===== CLOSE BUTTON ===== */
                IconButton(
                    onClick = onDismiss,
                    modifier = Modifier
                        .align(Alignment.TopEnd)
                        .padding(12.dp)
                        .size(32.dp)
                        .background(Color.Black.copy(alpha = 0.5f), CircleShape)
                ) {
                    Icon(
                        imageVector = Icons.Default.Close,
                        contentDescription = "Dismiss",
                        tint = Color.White,
                        modifier = Modifier.size(20.dp)
                    )
                }
            }

            Spacer(modifier = Modifier.height(12.dp))

            /* ===== PAGER DOT INDICATORS ===== */
            if (filteredAds.size > 1) {
                Row(
                    horizontalArrangement = Arrangement.Center,
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier
                        .background(Color.Black.copy(alpha = 0.3f), RoundedCornerShape(10.dp))
                        .padding(horizontal = 8.dp, vertical = 4.dp)
                ) {
                    repeat(filteredAds.size) { index ->
                        val isSelected = pagerState.currentPage == index
                        Box(
                            modifier = Modifier
                                .padding(horizontal = 3.dp)
                                .size(if (isSelected) 8.dp else 6.dp)
                                .clip(CircleShape)
                                .background(
                                    if (isSelected) Color.White else Color.White.copy(alpha = 0.4f)
                                )
                        )
                    }
                }
            }
        }
    }
}