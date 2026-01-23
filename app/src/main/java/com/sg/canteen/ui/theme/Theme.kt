package com.sg.canteen.ui.theme

import androidx.compose.material3.*
import androidx.compose.runtime.Composable

private val LightColors = lightColorScheme(
    primary = BluePrimary,
    secondary = BlueSecondary,
    background = BlueContainer,
    surface = White,
    onPrimary = White,
    onSurface = DarkBlue
)

@Composable
fun CanteenTheme(
    darkTheme: Boolean = false,
    content: @Composable () -> Unit
) {

    val colors = if (darkTheme) {
        darkColorScheme(
            primary = BluePrimary,
            secondary = BlueSecondary,
            background = DarkBlue,
            surface = DarkBlue,
            onPrimary = White,
            onSurface = White
        )
    } else {
        lightColorScheme(
            primary = BluePrimary,
            secondary = BlueSecondary,
            background = BlueContainer,
            surface = White,
            onPrimary = White,
            onSurface = DarkBlue
        )
    }

    MaterialTheme(
        colorScheme = colors,
        typography = Typography(),
        content = content
    )
}

