# DFReroot

Persistent root via the Dirty Frag on Android.
A stable second-stage root: get temporary root once with another exploit (e.g. ghostlock),
persist a system-UID app, then use Dirty Frag from it for all subsequent roots.

## Supported devices

Tested only on Galaxy S26 OneUI 8.5 (samsung/m1qjpnx/m1q:16/BP4A.251205.006/S942QOPU1AZDE_SJP1AZDE:user/release-keys), but might work on other versions.

## Background

Exploits of `ghostlock` vulnerability are somewhat unstable on Android. It's frustrating to get temporary root for each reboots while scared of kernel crashes. This exploit achives comfortable second-stage root by Dirty Frag.

## Pipeline

```
temp root (ghostlock) -> DFInstaller injects key -> soft reboot
  -> install DFReroot as android.uid.system -> Run DirtyFrag -> root (ksud)
```

1. **DFInstaller** (`com.polygraphene.df.installer`, normal app) edits
   `/data/system/packages.xml` as root, inserting signing key into the
   `android.uid.system` shared-user `pastSigs`.
2. After a soft reboot PMS re-reads `packages.xml`.
3. **DFReroot** (`com.polygraphene.df.reroot`, `sharedUserId="android.uid.system"`)
   installs as system UID and survives reboots.
4. DFReroot hops `system_server -> network_stack` (which can `dlopen` and holds
   `CAP_NET_ADMIN`), patches vendor/libc/libc++ via Dirty Frag, loads a tiny LKM
   that sets SELinux permissive, and late-loads **ksud**.

## Prerequisites

1. A vulnerability to get temporary root access
2. A kernel vulnerable to Dirty Frag

## Usage

1. Obtain temporary root with another explot (e.g. ghostlock).
2. Install `df_installer_(version).apk` from [Release](https://github.com/polygraphene/DFReroot/releases), and grant root on it from root managers.
3. **Inject** -> **Soft reboot** (restarts the framework; PMS re-reads `packages.xml`).
4. **Install DFReroot** (via `pm install`, needs `su` again after the reboot).
5. Open DFReroot, press **Run DirtyFrag**.

`df_reroot.apk` is bundled in `df_installer.apk`. No need to download/install it manually.

## Uninstall

1. Run **Uninstall key** to revert modifications to `packages.xml`.
2. Uninstall DFReroot and DFInstaller.

## Build

```sh
# Generate app/keystore.jks 
$ ./create-keystore.sh
# Generate df_reroot.apk + df_installer.apk
$ ANDROID_NDK_HOME=(ndk path) ANDROID_HOME=(sdk path) ./build.sh
```

Signing is resolved from the environment when set, so CI never needs a committed
key. Both APKs **must** use the same key — DFInstaller injects DFReroot's
certificate into `packages.xml`:

```sh
$ KEYSTORE_FILE=/path/to/keystore.jks KEYSTORE_PASSWORD=... \
  KEY_ALIAS=... KEY_PASSWORD=... ./build.sh
```

With none of those set, the `create-keystore.sh` development defaults are used.
`.github/workflows/release.yml` builds and publishes signed APKs to GitHub
Releases from the `KEYSTORE_BASE64` / `KEYSTORE_PASSWORD` / `KEY_ALIAS` /
`KEY_PASSWORD` repository secrets; push a `v*` tag or run it manually.

The LKM rebuild needs Docker (GKI DDK), see `dirtyfrag-lkm/build.sh`.
Build ksud from kdp-612-3.3.0 branch of [my fork](https://github.com/polygraphene/KernelSU/tree/kdp-612-3.3.0) of KernelSU.

## Layout

- `installer/` — DFInstaller app: `PackagesXml`/`Abx` (packages.xml read/write,
  ABX-aware), `InjectMain` (root `app_process` entry: `--check/--dry-run/--dump/--uninstall`/inject),
  `SysKey`/`SigKey` (cert via PackageManager, v1/v2/v3 agnostic), GUI.
- `app/` — DFReroot app: `StageHop` (system_server -> network_stack),
  `DirtyFrag` (JNI bridge, package name must stay `org.lsposed.lspromise`),
  `KsudStage`, native `exp.c` + `stage1.S` (arm64), `dirtyfrag.ko`.
- `dirtyfrag-lkm/` — LKM source (resolves `kallsyms_lookup_name`, clears
  `selinux_state.enforcing`).
- `logtestexe/` — standalone logcat-socket test binary.

## Caveats

- `packages.xml` is backed up once to `packages.xml.bak-df-installer`.

## Acknowledgments

- [Dirty Frag by @V4bel](https://github.com/V4bel/dirtyfrag) - Discovering and exploiting Dirty Frag
- [LSPromise by @LSPosed](https://github.com/LSPosed/LSPromise) - Exploiting Dirty Frag on android
- [AbxOverflow by @michalbednarski](https://github.com/michalbednarski/AbxOverflow) - Idea for persistent `system_server` privilege
