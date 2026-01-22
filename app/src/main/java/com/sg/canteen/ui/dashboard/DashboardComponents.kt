package com.sg.canteen.ui.dashboard

import androidx.compose.foundation.Image
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextDecoration
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import coil.compose.rememberAsyncImagePainter
import com.sg.canteen.network.models.MenuItemDto
import com.sg.canteen.network.models.SubCategoryDto

@Composable
fun CategoryChip(
    name: String,
    selected: Boolean,
    onClick: () -> Unit
) {
    Surface(
        shape = MaterialTheme.shapes.large,
        color = if (selected) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surfaceVariant,
        modifier = Modifier
            .height(40.dp)
            .clickable(onClick = onClick)
    ) {
        Box(modifier = Modifier.padding(horizontal = 16.dp), contentAlignment = Alignment.Center) {
            Text(
                text = name,
                fontSize = 13.sp,
                color = if (selected) MaterialTheme.colorScheme.onPrimaryContainer else MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

@Composable
fun SnackSubCategory(
    sub: SubCategoryDto,
    onClick: () -> Unit
) {
    Card(modifier = Modifier.height(110.dp).fillMaxWidth().clickable(onClick = onClick)) {
        Column(modifier = Modifier.fillMaxSize(), verticalArrangement = Arrangement.Center, horizontalAlignment = Alignment.CenterHorizontally) {
            Image(
                painter = rememberAsyncImagePainter(sub.imageUrl ?: ""),
                contentDescription = sub.name,
                modifier = Modifier.size(48.dp),
                contentScale = ContentScale.Crop
            )
            Spacer(modifier = Modifier.height(6.dp))
            Text(text = sub.name, fontSize = 12.sp)
        }
    }
}

@Composable
fun MenuItemCard(
    item: MenuItemDto,
    onAddToCart: () -> Unit
) {
    Card(modifier = Modifier.fillMaxWidth(), elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)) {
        Box(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(8.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                Image(
                    painter = rememberAsyncImagePainter(item.imageUrl ?: ""),
                    contentDescription = item.name,
                    modifier = Modifier.height(90.dp).fillMaxWidth().clip(MaterialTheme.shapes.medium),
                    contentScale = ContentScale.Crop
                )
                Spacer(modifier = Modifier.height(6.dp))
                Text(text = item.name, fontSize = 13.sp, fontWeight = FontWeight.Bold, maxLines = 1, overflow = TextOverflow.Ellipsis)

                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.Center) {
                    // Current active price in Green if it's an offer
                    Text(
                        text = "₹${item.price.toInt()}",
                        fontSize = 14.sp,
                        fontWeight = FontWeight.Black,
                        color = if (item.isOffer) Color(0xFF4CAF50) else MaterialTheme.colorScheme.onSurface
                    )
                    // Strikethrough for original price
                    if (item.isOffer && item.originalPrice != null) {
                        Spacer(modifier = Modifier.width(4.dp))
                        Text(
                            text = "₹${item.originalPrice.toInt()}",
                            fontSize = 11.sp,
                            color = Color.Gray,
                            textDecoration = TextDecoration.LineThrough
                        )
                    }
                }
                Spacer(modifier = Modifier.height(6.dp))
                Button(onClick = onAddToCart, modifier = Modifier.fillMaxWidth(), contentPadding = PaddingValues(0.dp), enabled = item.stock > 0) {
                    Text(text = if (item.stock > 0) "Add" else "Out", fontSize = 11.sp)
                }
            }
            // Percentage Badge in top right
            if (item.isOffer && item.discountPercentage != null) {
                Surface(color = Color.Red, shape = MaterialTheme.shapes.extraSmall, modifier = Modifier.align(Alignment.TopEnd).padding(4.dp)) {
                    Text(text = "${item.discountPercentage}% OFF", color = Color.White, fontSize = 9.sp, fontWeight = FontWeight.Bold, modifier = Modifier.padding(horizontal = 4.dp, vertical = 2.dp))
                }
            }
        }
    }
}