package com.sg.canteen.ui.order

import android.view.ViewGroup
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
@Composable
fun BillWebViewScreen(
    qrNumber: String,
    onBack: () -> Unit
) {
    // 🔥 FIXED: Use the IP address confirmed in your logs
    val baseUrl = "http://10.224.254.133:10000"
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
                    // Ensure links stay inside the app
                    webViewClient = WebViewClient()

                    // Enable JS for the CSS styling in your backend send() block
                    settings.javaScriptEnabled = true

                    // Allow mixed content if your backend is HTTP while testing
                    settings.mixedContentMode = android.webkit.WebSettings.MIXED_CONTENT_ALWAYS_ALLOW

                    loadUrl(billUrl)
                }
            },
            update = { webView ->
                webView.loadUrl(billUrl)
            }
        )
    }
}