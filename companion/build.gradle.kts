plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
}

/*
 * Same key as :app and :installer.
 *
 * Not for the packages.xml reason - this module injects nothing - but because
 * the caller check at the other end of the Binder compares the caller's signing
 * certificate against this one. A companion signed with a different key would
 * refuse every request from DFReroot, which is the gate working and is not what
 * anyone wants to debug on a device.
 */
val dfrKeystore: File = System.getenv("KEYSTORE_FILE")
    ?.takeIf { it.isNotBlank() }
    ?.let { File(it) }
    ?: rootProject.file("app/keystore.jks")
val dfrStorePassword: String = System.getenv("KEYSTORE_PASSWORD") ?: "dfreroot"
val dfrKeyAlias: String = System.getenv("KEY_ALIAS") ?: "dfreroot"
val dfrKeyPassword: String = System.getenv("KEY_PASSWORD") ?: "dfreroot"

android {
    namespace = "com.polygraphene.df.companion"
    compileSdk = 36

    defaultConfig {
        /*
         * Its OWN application id, and deliberately no sharedUserId.
         *
         * The RMG managerless grant contract refuses shared-UID peers outright
         * and requires an appId in 10000..19999, so a companion that shared
         * android.uid.system could never be granted - which is also why
         * DFReroot itself cannot be the grant holder and this module exists.
         */
        applicationId = "com.polygraphene.df.companion"
        minSdk = 32
        targetSdk = 36
        // One derived version for every module; never a literal. See the root
        // build.gradle.kts.
        versionCode = rootProject.extra["dfrVersionCode"] as Int
        versionName = rootProject.extra["dfrVersionName"] as String
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
}
