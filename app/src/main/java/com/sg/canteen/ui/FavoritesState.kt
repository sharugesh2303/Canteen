package com.sg.canteen.ui.favorites

import androidx.compose.runtime.mutableStateListOf
import com.sg.canteen.network.models.MenuItemDto

object FavoritesState {

    private val favorites = mutableStateListOf<MenuItemDto>()

    fun toggle(item: MenuItemDto) {
        if (favorites.any { it._id == item._id }) {
            favorites.removeAll { it._id == item._id }
        } else {
            favorites.add(item)
        }
    }

    fun isFavorite(id: String): Boolean {
        return favorites.any { it._id == id }
    }

    fun getAll(): List<MenuItemDto> = favorites
}
