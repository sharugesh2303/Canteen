package com.sg.canteen.ui.utils

import android.content.Context

object SessionManager {

    private const val PREF = "canteen_prefs"
    private const val TOKEN = "jwt_token"

    fun saveToken(context: Context, token: String) {
        context.getSharedPreferences(PREF, Context.MODE_PRIVATE)
            .edit()
            .putString(TOKEN, token)
            .apply()
    }

    fun getToken(context: Context): String {
        return context.getSharedPreferences(PREF, Context.MODE_PRIVATE)
            .getString(TOKEN, "") ?: ""
    }
}
