package com.sg.canteen.network

import android.util.Log
import io.socket.client.IO
import io.socket.client.Socket

object SocketManager {

    private const val TAG = "SocketManager"
    private const val SOCKET_URL = "http://10.0.2.2:10000"

    private var socket: Socket? = null

    /* ================= CONNECT ================= */
    fun connect() {
        if (socket != null && socket!!.connected()) return

        try {
            val options = IO.Options().apply {
                transports = arrayOf("websocket") // 🔥 IMPORTANT (fix xhr poll error)
                reconnection = true
                reconnectionAttempts = Int.MAX_VALUE
                reconnectionDelay = 2000
                timeout = 10000
            }

            socket = IO.socket(SOCKET_URL, options)

            socket?.on(Socket.EVENT_CONNECT) {
                Log.d(TAG, "✅ Socket connected")
            }

            socket?.on(Socket.EVENT_DISCONNECT) {
                Log.d(TAG, "❌ Socket disconnected")
            }

            socket?.on(Socket.EVENT_CONNECT_ERROR) { args ->
                Log.e(TAG, "❌ Socket error: ${args.joinToString()}")
            }

            socket?.connect()

        } catch (e: Exception) {
            Log.e(TAG, "❌ Socket init failed", e)
        }
    }

    /* ================= DISCONNECT ================= */
    fun disconnect() {
        socket?.off()
        socket?.disconnect()
        socket = null
    }

    /* ================= MENU UPDATE ================= */
    fun onMenuUpdate(callback: () -> Unit) {
        socket?.off("menuUpdate")
        socket?.on("menuUpdate") {
            Log.d(TAG, "📢 Menu updated")
            callback()
        }
    }

    /* ================= ORDER UPDATE (THIS WAS MISSING) ================= */
    fun onOrderUpdate(callback: () -> Unit) {
        socket?.off("orderUpdate")
        socket?.on("orderUpdate") {
            Log.d(TAG, "📦 Order updated")
            callback()
        }
    }
}
