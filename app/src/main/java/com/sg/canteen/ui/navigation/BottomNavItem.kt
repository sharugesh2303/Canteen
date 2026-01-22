package com.sg.canteen.ui.navigation

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.ShoppingCart
import androidx.compose.material.icons.filled.List
import androidx.compose.ui.graphics.vector.ImageVector


sealed class BottomNavItem(val icon: ImageVector) {
    object Home : BottomNavItem(Icons.Filled.Home)
    object Cart : BottomNavItem(Icons.Filled.ShoppingCart)
    object Orders : BottomNavItem(Icons.Filled.List)
}
