package com.sg.canteen.network

import android.content.Context
import android.provider.Settings
import android.util.Log
import io.socket.client.IO
import io.socket.client.Socket
import io.socket.client.Manager
import io.socket.engineio.client.transports.WebSocket
import org.json.JSONObject
import java.security.MessageDigest

object SocketManager {

    private const val TAG = "SocketManager"
    private const val SOCKET_URL = "http://10.162.152.133:10000"

    private var socket: Socket? = null
    private var cachedHashedDeviceId: String? = null

    /* ================= CONNECT ================= */
    fun connect(context: Context) {
        if (socket != null && socket!!.connected()) return

        try {
            val options = IO.Options().apply {
                // ✅ Force WebSocket (fixes xhr poll error)
                transports = arrayOf(WebSocket.NAME, "polling") // ✅ important for cloud

                reconnection = true
                reconnectionAttempts = Int.MAX_VALUE
                reconnectionDelay = 2000
                timeout = 20000
                forceNew = true

                upgrade = true
                rememberUpgrade = true
            }

            socket = IO.socket(SOCKET_URL, options)

            val rawDeviceId = getDeviceId(context)
            cachedHashedDeviceId = hashDeviceId(rawDeviceId)

            /* 🔌 CONNECT */
            socket?.on(Socket.EVENT_CONNECT) {
                Log.d(TAG, "✅ Socket connected")
                registerStudent()
            }

            /* 🔁 RECONNECT (FIXED) */
            socket?.io()?.on(Manager.EVENT_RECONNECT) {
                Log.d(TAG, "🔄 Socket reconnected")
                registerStudent()
            }

            /* ❌ DISCONNECT */
            socket?.on(Socket.EVENT_DISCONNECT) {
                Log.d(TAG, "❌ Socket disconnected")
            }

            /* ⚠️ ERROR */
            socket?.on(Socket.EVENT_CONNECT_ERROR) { args ->
                Log.e(TAG, "❌ Socket error: ${args.joinToString()}")
            }

            socket?.connect()

        } catch (e: Exception) {
            Log.e(TAG, "❌ Socket init failed", e)
        }
    }

    /* ================= REGISTER STUDENT ================= */
    private fun registerStudent() {
        cachedHashedDeviceId?.let {
            socket?.emit("register_student", it)
            Log.d(TAG, "📲 register_student emitted with: $it")
        }
    }

    /* ================= DEVICE ID ================= */
    private fun getDeviceId(context: Context): String {
        val prefs = context.getSharedPreferences("canteen_prefs", Context.MODE_PRIVATE)
        var deviceId = prefs.getString("device_id", null)

        if (deviceId.isNullOrEmpty()) {
            deviceId = Settings.Secure.getString(context.contentResolver, Settings.Secure.ANDROID_ID)
            prefs.edit().putString("device_id", deviceId).apply()
            Log.d(TAG, "📱 New deviceId saved: $deviceId")
        }

        return deviceId ?: "unknown_device"
    }

    /* ================= HASH FUNCTION ================= */
    private fun hashDeviceId(deviceId: String): String {
        val bytes = MessageDigest.getInstance("SHA-256").digest(deviceId.toByteArray())
        return bytes.joinToString("") { "%02x".format(it) }
    }

    /* ================= DISCONNECT ================= */
    fun disconnect() {
        socket?.off()
        socket?.disconnect()
        socket = null
        cachedHashedDeviceId = null
    }

    /* ================= MENU UPDATE ================= */
    fun onMenuUpdate(callback: () -> Unit) {
        socket?.off("menuUpdate")
        socket?.on("menuUpdate") {
            Log.d(TAG, "📢 Menu updated")
            callback()
        }
    }

    /* ================= ORDER UPDATE ================= */
    fun onOrderUpdate(callback: () -> Unit) {
        socket?.off("orderUpdate")
        socket?.on("orderUpdate") {
            Log.d(TAG, "📦 Order updated")
            callback()
        }
    }

    /* ================= ORDER READY ================= */
    fun onOrderReady(callback: (billNumber: String, message: String) -> Unit) {
        socket?.off("orderReady")
        socket?.on("orderReady") { args ->
            try {
                val data = args[0] as JSONObject
                val billNumber = data.optString("billNumber", "")
                val message = data.optString(
                    "message",
                    "Your order is ready! Please collect from counter."
                )

                Log.d(TAG, "🔔 Order Ready received for bill: $billNumber")
                callback(billNumber, message)

            } catch (e: Exception) {
                Log.e(TAG, "❌ orderReady parse error", e)
            }
        }
    }
}
