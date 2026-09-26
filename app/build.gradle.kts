plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
}

/*
 * Release signing material. DFReroot and DFInstaller MUST be signed with the
 * same key (the installer writes DFReroot's certificate into packages.xml), so
 * both modules resolve it the same way:
 *
 *   KEYSTORE_FILE / KEYSTORE_PASSWORD / KEY_ALIAS / KEY_PASSWORD  (environment)
 *
 * CI decodes the KEYSTORE_BASE64 secret to a file outside the working tree and
 * points KEYSTORE_FILE at it, so no key or password is ever committed. With no
 * environment set, the create-keystore.sh development defaults are used, which
 * keeps `./build.sh` working locally exactly as before.
 */
val dfrKeystore: File = System.getenv("KEYSTORE_FILE")
    ?.takeIf { it.isNotBlank() }
    ?.let { File(it) }
    ?: rootProject.file("app/keystore.jks")
val dfrStorePassword: String = System.getenv("KEYSTORE_PASSWORD") ?: "dfreroot"
val dfrKeyAlias: String = System.getenv("KEY_ALIAS") ?: "dfreroot"
val dfrKeyPassword: String = System.getenv("KEY_PASSWORD") ?: "dfreroot"

android {
    namespace = "com.polygraphene.df.reroot"
    compileSdk = 36

    buildFeatures {
        buildConfig = true
    }

    defaultConfig {
        applicationId = "com.polygraphene.df.reroot"
        minSdk = 32
        targetSdk = 36
        versionCode = 8
        versionName = "2.0.5-zzic"

        // DirtyFrag native payload (stage1.S) is AArch64-only; the rest of the
        // chain (system_server hosting, network_stack hop) is arch-independent
        // and testable on the x86_64 emulator (native load fails gracefully).
        ndk {
            abiFilters += listOf("arm64-v8a")
        }
    }
    signingConfigs {
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
    externalNativeBuild {
        cmake {
            path("src/main/jni/CMakeLists.txt")
        }
    }
}

dependencies {
    implementation(libs.androidx.core.ktx)
}
