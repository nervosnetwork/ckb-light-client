plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.nervosnetwork.ckblightclient"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.nervosnetwork.ckblightclient"
        minSdk = 21
        targetSdk = 34
        versionCode = 1
        versionName = "0.5.3"

        ndk {
            abiFilters += listOf("arm64-v8a")
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"))
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }

    kotlinOptions {
        jvmTarget = "1.8"
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.12.0")
    implementation("androidx.appcompat:appcompat:1.6.1")
    implementation("com.google.android.material:material:1.10.0")
    implementation("androidx.constraintlayout:constraintlayout:2.1.4")

    // Fragments
    implementation("androidx.fragment:fragment-ktx:1.6.2")

    // Lifecycle & Coroutines
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.7.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.7.3")

    // JSON Parsing
    implementation("com.google.code.gson:gson:2.10.1")

    // SwipeRefreshLayout
    implementation("androidx.swiperefreshlayout:swiperefreshlayout:1.1.0")
    
    // OkHttp for HTTP requests
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
}

// Copy Rust JNI libraries from target directory to jniLibs
tasks.register<Copy>("copyNativeLibrary") {
    from("../../target/aarch64-linux-android/release/libckb_light_client_lib.so") {
        into("arm64-v8a")
    }
    into("src/main/jniLibs")
}

tasks.named("preBuild") {
    dependsOn("copyNativeLibrary")
}
