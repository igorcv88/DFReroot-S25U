plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
}

/* Same resolution as :app - see the comment there. Both APKs must share one key. */
val dfrKeystore: File = System.getenv("KEYSTORE_FILE")
    ?.takeIf { it.isNotBlank() }
    ?.let { File(it) }
    ?: rootProject.file("app/keystore.jks")
val dfrStorePassword: String = System.getenv("KEYSTORE_PASSWORD") ?: "dfreroot"
val dfrKeyAlias: String = System.getenv("KEY_ALIAS") ?: "dfreroot"
val dfrKeyPassword: String = System.getenv("KEY_PASSWORD") ?: "dfreroot"

android {
    namespace = "com.polygraphene.df.installer"
    compileSdk = 36

    buildFeatures {
        buildConfig = true
    }

    defaultConfig {
        applicationId = "com.polygraphene.df.installer"
        minSdk = 32
        targetSdk = 36
        versionCode = 8
        versionName = "2.0.5-zzic"
    }
    signingConfigs {
        // Must use the same signing key as DFReroot: the key inserted into
        // packages.xml has to match the DFReroot APK signature.
        create("keystore") {
            storeFile = dfrKeystore
            storePassword = dfrStorePassword
            keyAlias = dfrKeyAlias
            keyPassword = dfrKeyPassword
        }
    }
    buildTypes {
        debug {
            signingConfig = signingConfigs.getByName("keystore")
        }
        release {
            signingConfig = signingConfigs.getByName("keystore")
            isMinifyEnabled = false
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
    kotlinOptions {
        jvmTarget = "11"
    }
}

dependencies {
    implementation(libs.androidx.core.ktx)
}
