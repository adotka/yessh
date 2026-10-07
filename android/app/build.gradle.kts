plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
    id("org.jetbrains.kotlin.plugin.serialization")
}

// Release signing comes from the environment (CI secrets or your shell); never from the repo.
// The CA key lives in Android Keystore under this app's identity, so every update must be
// signed with the same key or the CA is lost.
val signingStore = System.getenv("YESSH_SIGNING_STORE_FILE")

android {
    namespace = "io.github.adotka.yessh"
    compileSdk = 35

    defaultConfig {
        applicationId = "io.github.adotka.yessh"
        minSdk = 30
        targetSdk = 35
        versionCode = (System.getenv("YESSH_VERSION_CODE") ?: "1").toInt()
        versionName = System.getenv("YESSH_VERSION_NAME") ?: "0.1.0-dev"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    signingConfigs {
        if (signingStore != null) {
            create("release") {
                storeFile = file(signingStore)
                storePassword = System.getenv("YESSH_SIGNING_STORE_PASSWORD")
                keyAlias = System.getenv("YESSH_SIGNING_KEY_ALIAS")
                keyPassword = System.getenv("YESSH_SIGNING_KEY_PASSWORD")
            }
        }
    }

    buildTypes {
        debug {
            // Debug builds install next to release builds and have their own CA.
            applicationIdSuffix = ".debug"
            versionNameSuffix = "-debug"
        }
        release {
            isMinifyEnabled = false
            signingConfig = signingConfigs.findByName("release")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions { jvmTarget = "17" }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    packaging {
        resources.excludes += "/META-INF/{AL2.0,LGPL2.1}"
    }

    lint {
        abortOnError = true
        warningsAsErrors = false
    }
}

dependencies {
    implementation(project(":core"))

    implementation(platform("androidx.compose:compose-bom:2024.12.01"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-core")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.7")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")
    implementation("com.google.zxing:core:3.5.3")

    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation("org.jetbrains.kotlin:kotlin-test-junit:2.0.21")
}
