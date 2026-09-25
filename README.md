# DFReroot

Persistent root via the Dirty Frag on Android.
A stable second-stage root: get temporary root once with another exploit (e.g. ghostlock),
persist a system-UID app, then use Dirty Frag from it for all subsequent roots.

## Supported devices

The upstream project is verified end to end on Galaxy S26 OneUI 8.5
(`samsung/m1qjpnx/m1q:16/BP4A.251205.006/S942QOPU1AZDE_SJP1AZDE:user/release-keys`).

This fork also carries a **fail-closed exact-firmware profile** for:

```text
Galaxy S25 Ultra, SM-S938B / pa3q
Android 17 / One UI 9 Beta 3
firmware S938BXXUCZZIC
kernel 6.6.127-android15-8-p33f4ffe-abogkiS938BXXUCZZIC-4k
```

On that exact S25 Ultra firmware, `v2.0.4-zzic` has now been physically
validated through the complete root chain:

- exact target / kernel / userspace gates passed;
- the exact ZZIC DirtyFrag helper was selected and hash-bound;
- all six page-cache write stages completed;
- the transient helper successfully drove SELinux to `Permissive`;
- the DFR-specific ksud late-loaded KernelSU;
- `su` returned `uid=0(root)` in `u:r:ksu:s0`;
- manual `setenforce 1` restored `Enforcing`, and KernelSU root continued to
  work afterwards in the same boot.

That proves the root path. It does **not yet** make `v2.0.4-zzic` the final safe
automation: the current app can report success at the stage2 bind marker while
SELinux is still globally `Permissive`. The next implementation is to make
KernelSU control-channel verification + SELinux restoration + read-back part of
the automatic post-root completion state.

Until that lands, treat `v2.0.4-zzic` as the hardware-validation release for
this firmware. If it is run, do not run it twice in the same boot; verify the
final SELinux state and hard reboot if the post-root closeout is uncertain.

The profile remains exact and fail-closed. A device asserting `SM-S938B` or
`pa3q` but differing in any pinned identity field is `MISMATCH` and refuses
rather than falling through to generic behavior. An unrelated device takes the
unchanged upstream family path.

`docs/S25U_ZZIC_COMPATIBILITY.md` is the authoritative evidence record and
`docs/HANDOFF.md` is the current implementation plan. Contributors and agents
must read **`AGENTS.md`** first (also exposed as `CLAUDE.md`).

## Background

Exploits of `ghostlock` vulnerability are somewhat unstable on Android. It's frustrating to get temporary root for each reboots while scared of kernel crashes. This exploit achives comfortable second-stage root by Dirty Frag.

## Pipeline

```
temp root (ghostlock) -> DFInstaller injects key -> soft reboot
  -> install DFReroot as android.uid.system -> Run DirtyFrag
    -> transient helper sets SELinux permissive -> late-load KernelSU/ksud
      -> verify KernelSU -> restore SELinux enforcing -> post-root complete
```

1. **DFInstaller** (`com.polygraphene.df.installer`, normal app) edits
   `/data/system/packages.xml` as root, inserting signing key into the
   `android.uid.system` shared-user `pastSigs`.
2. After a soft reboot PMS re-reads `packages.xml`.
3. **DFReroot** (`com.polygraphene.df.reroot`, `sharedUserId="android.uid.system"`)
   installs as system UID and survives reboots.
4. DFReroot hops `system_server -> network_stack` (which can `dlopen` and holds
   `CAP_NET_ADMIN`), patches vendor/libc/libc++ via Dirty Frag, loads a transient
   LKM that sets SELinux permissive, and late-loads the pinned **ksud**.
5. On the ZZIC path, automatic post-root closeout is the current remaining work:
   prove the KernelSU control channel, restore SELinux to enforcing, verify the
   read-back, and only then report final success.

## Prerequisites

1. A vulnerability to get temporary root access
2. A kernel vulnerable to Dirty Frag

## Usage

1. Obtain temporary root with another explot (e.g. ghostlock).
2. Install `df_installer_(version).apk` from this fork's [Releases](https://github.com/igorcv88/DFReroot-S25U/releases), and grant root on it from the temporary-root environment/root manager.
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

- **ZZIC v2.0.4 post-root state:** the root chain is physically proven, including
  successful KernelSU root and a manual return from Permissive to Enforcing.
  The current release does not yet automate that final restoration, so a green
  native result is not equivalent to `POST_ROOT_COMPLETE`. See
  `docs/HANDOFF.md` before changing or retesting this path.
- `/dev/df` is a same-boot armed-hook guard. If it exists, do not run DirtyFrag
  a second time; a hard reboot is the recovery boundary.
- `packages.xml` is backed up once to `packages.xml.bak-df-installer`. The backup
  is written transactionally and verified by size and SHA-256 before the original
  is touched; an existing backup is never overwritten, but one that is empty,
  truncated or unparsable makes the injection refuse rather than proceed without
  a working rollback. The original file's uid/gid/mode/SELinux label are captured
  before any write and re-verified afterwards; a divergence rolls back.

## Acknowledgments

- [Dirty Frag by @V4bel](https://github.com/V4bel/dirtyfrag) - Discovering and exploiting Dirty Frag
- [LSPromise by @LSPosed](https://github.com/LSPosed/LSPromise) - Exploiting Dirty Frag on android
- [AbxOverflow by @michalbednarski](https://github.com/michalbednarski/AbxOverflow) - Idea for persistent `system_server` privilege
