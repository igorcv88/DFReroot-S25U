// Top-level build file.
plugins {
    alias(libs.plugins.android.application) apply false
}

/*
 * ONE definition of the release version, for both modules.
 *
 * versionCode/versionName used to be literals in app/build.gradle.kts and
 * installer/build.gradle.kts. That meant four hand-edited numbers in two files
 * per release, and every way of getting it wrong was tried at least once: the
 * installer left a version behind while the app moved, a tag naming a version the
 * tree did not carry, a tag naming a version the tree already carried. The guards
 * caught each of them - after a runner had been spent, on the one workflow the
 * owner is allowed to run.
 *
 * So nothing in the tree names a version any more. tools/resolve_release_version.sh
 * derives it once per release run (from the dispatched tag, or by bumping the
 * greatest existing tag) and .github/workflows/release.yml exports the pair below.
 * The tag, both APKs, both asset filenames and the release title therefore cannot
 * disagree: there is one value and nothing to type.
 *
 * Absence is a REFUSAL, not a default. A silent fallback here would compile
 * 0.0.0-dev into an APK published as df_reroot_2.0.6-zzic.apk - exactly the drift
 * the derivation removes, reintroduced where no gate would see it. AutoRootPolicy
 * binds a qualification to versionCode AND versionName, so a wrong pair does not
 * merely mislabel the build: it decides whether an unattended root attempt is
 * allowed to believe a previous run's evidence.
 *
 * ./build.sh sets an explicit development pair, so a local build still works
 * without arguments and is plainly identifiable as not a release.
 */
val dfrVersionName: String = (System.getenv("DFR_VERSION_NAME") ?: "").trim().also {
    require(it.isNotEmpty()) {
        "DFR_VERSION_NAME is not set. The version is derived by " +
            "tools/resolve_release_version.sh and exported by the release " +
            "workflow; ./build.sh sets a development pair for local builds. " +
            "Refusing to invent one - a guessed versionName is compiled into " +
            "both APKs and into the Auto Root qualification record."
    }
}
val dfrVersionCode: Int = (System.getenv("DFR_VERSION_CODE") ?: "").trim().let {
    require(it.isNotEmpty()) {
        "DFR_VERSION_CODE is not set (DFR_VERSION_NAME is $dfrVersionName). " +
            "Both move together or neither does."
    }
    requireNotNull(it.toIntOrNull()) { "DFR_VERSION_CODE=$it is not an integer" }
}
require(dfrVersionCode > 0) { "DFR_VERSION_CODE=$dfrVersionCode must be positive" }

extra["dfrVersionName"] = dfrVersionName
extra["dfrVersionCode"] = dfrVersionCode
