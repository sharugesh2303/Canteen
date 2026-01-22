package com.sg.canteen.ui.utils

import android.content.Context
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.stringSetPreferencesKey
import androidx.datastore.preferences.preferencesDataStore

/* ---------- SINGLE DATASTORE ---------- */
val Context.appDataStore by preferencesDataStore(name = "app_prefs")

/* ---------- KEYS ---------- */
val DARK_MODE_KEY = booleanPreferencesKey("dark_mode")
val FAVORITES_KEY = stringSetPreferencesKey("favorites")
