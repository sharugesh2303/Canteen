plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
}

android {
    namespace = "com.sg.canteen"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.sg.canteen"
        minSdk = 24
        targetSdk = 36
        versionCode = 1
        versionName = "1.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }

    kotlinOptions {
        jvmTarget = "11"
    }

    buildFeatures {
        compose = true
    }
}

dependencies {

    /* ---------- ANDROID CORE ---------- */
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.activity.compose)

    /* ---------- 🔴 REQUIRED FOR VIEWMODEL + COMPOSE ---------- */
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.6")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.6")

    /* ---------- COMPOSE ---------- */
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.graphics)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.compose.material3)

    /* ---------- MATERIAL ICONS ---------- */
    implementation("androidx.compose.material:material-icons-extended")

    /* ---------- IMAGE LOADING ---------- */
    implementation("io.coil-kt:coil-compose:2.6.0")

    /* ---------- WEBVIEW ---------- */
    implementation("androidx.webkit:webkit:1.10.0")

    /* ---------- DATASTORE ---------- */
    implementation("androidx.datastore:datastore-preferences:1.1.1")

    /* ---------- WORK MANAGER ---------- */
    implementation("androidx.work:work-runtime-ktx:2.9.0")

    /* ---------- RETROFIT ---------- */
    implementation("com.squareup.retrofit2:retrofit:2.9.0")
    implementation("com.squareup.retrofit2:converter-gson:2.9.0")

    /* ---------- OKHTTP ---------- */
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    implementation("com.squareup.okhttp3:logging-interceptor:4.12.0")

    /* ---------- SOCKET.IO ---------- */
    implementation("io.socket:socket.io-client:2.1.0") {
        exclude(group = "org.json", module = "json")
    }

    /* ---------- RAZORPAY ---------- */
    implementation("com.razorpay:checkout:1.6.38")

    /* ---------- TESTING ---------- */
    testImplementation(libs.junit)

    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
    androidTestImplementation(platform(libs.androidx.compose.bom))
    androidTestImplementation(libs.androidx.compose.ui.test.junit4)

    debugImplementation(libs.androidx.compose.ui.tooling)
    debugImplementation(libs.androidx.compose.ui.test.manifest)
}
