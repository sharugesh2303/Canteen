package com.sg.canteen.ui.order

import android.annotation.SuppressLint
import android.view.ViewGroup
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.viewinterop.AndroidView

@OptIn(ExperimentalMaterial3Api::class)
@SuppressLint("SetJavaScriptEnabled")
@Composable
fun BillWebViewScreen(
    qrNumber: String,
    onBack: () -> Unit
) {
    // 🌍 LIVE BACKEND URL (Koyeb)
    val baseUrl = "https://evil-gypsy-sharugesh-06d0c56b.koyeb.app"
    val billUrl = "$baseUrl/api/orders/bill/$qrNumber"

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Order Bill") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.Default.ArrowBack, contentDescription = "Back")
                    }
                }
            )
        }
    ) { padding ->

        AndroidView(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),

            factory = { context ->
                WebView(context).apply {

                    layoutParams = ViewGroup.LayoutParams(
                        ViewGroup.LayoutParams.MATCH_PARENT,
                        ViewGroup.LayoutParams.MATCH_PARENT
                    )

                    // Keep navigation inside WebView
                    webViewClient = WebViewClient()

                    settings.apply {
                        javaScriptEnabled = true
                        domStorageEnabled = true
                        loadWithOverviewMode = true
                        useWideViewPort = true
                        builtInZoomControls = true
                        displayZoomControls = false

                        // HTTPS so mixed content not required, but safe fallback
                        mixedContentMode = WebSettings.MIXED_CONTENT_COMPATIBILITY_MODE
                    }

                    loadUrl(billUrl)
                }
            },

            update = { webView ->
                webView.loadUrl(billUrl)
            }
        )
    }
}
