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

That proves the root path. It does **not** make `v2.0.4-zzic` the final safe
automation: that release can report success at the stage2 bind marker while
SELinux is still globally `Permissive`. Treat it as the hardware-validation
release for this firmware — and if it is run, do not run it twice in the same
boot; verify the final SELinux state and hard reboot if the closeout is
uncertain.

### Current state

The automatic closeout now exists in source and is the content of the next
candidate, `v2.0.5-zzic` (versionCode 8), which **has not been built or run on
hardware yet**:

- the UI cannot go green on a native result alone. Final success requires a live
  KernelSU control proof, automatic restoration to `Enforcing`, a sysfs
  read-back, a second live proof, a same-boot `POST_ROOT_COMPLETE` record, and a
  final independent `/sys/fs/selinux/enforce == 1` read;
- `dfm3` (the stage2 bind marker) is explicitly never final success, and stage2
  accepts only the helper's intentional `finit_module() == -E2BIG`;
- one shared execution path (`DfrRootCoordinator`) serves both the button and the
  new boot service, so neither can be the entry point that forgets a gate;
- **Auto Root after full boot** exists and ships **disabled**. It cannot be
  enabled until a manual run on that exact build, ksud digest and firmware ends
  in a verified same-boot `POST_ROOT_COMPLETE`, and the owner then opts in. Armed,
  it makes one attempt per full boot (`boot_id`), never after a soft reboot, and
  any failure after the native run locks that boot until a hard reboot.

| Gate | State |
|---|---|
| A–H (identity, kernel, AMS/NetworkStack, module ABI, ELF, installer) | physically proven on `S938BXXUCZZIC` |
| I — automatic safe end state | **pending physical acceptance** |
| `AUTO_ROOT_FULL_BOOT` | **unverified, ships disabled** |
| `POST_ROOT_LSPOSED_COMPAT` | proven on `ZZI4`, not yet on `ZZIC` |

Everything above is checked offline with no device and no SDK; the one property
that is not is compilation, since the environment that produced the code has no
Android SDK, NDK or Gradle. Read `docs/PHYSICAL_TESTING.md` before testing on the
device — it is the operator protocol, including what to capture, when to stop, and
how to recover.

The profile remains exact and fail-closed. A device asserting `SM-S938B` or
`pa3q` but differing in any pinned identity field is `MISMATCH` and refuses
rather than falling through to generic behavior. An unrelated device takes the
unchanged upstream family path.

Documentation map — each of these owns exactly one question:

| File | Question it answers |
|---|---|
| `AGENTS.md` (= `CLAUDE.md`) | the rules that must not be broken. **Read first** |
| `docs/S25U_ZZIC_COMPATIBILITY.md` | which gates are proven, and by what evidence |
| `docs/HANDOFF.md` | what is left to do, and what closes it |
| `docs/PHYSICAL_TESTING.md` | how to test on the device, and what each line means |
| `docs/AUTO_ROOT.md` | the unattended boot path and its acceptance |
| `docs/GATE_G_LKM_BUILD.md` | how the exact ZZIC module and its CRC evidence were produced |

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
5. On the ZZIC path the closeout is automatic and fail-closed: prove the KernelSU
   control channel, restore SELinux to enforcing, read it back, prove control
   again, publish a same-boot record — and only then report final success. Any
   step missing is a failure, never an "unknown". Implemented, not yet accepted on
   hardware.
6. Optionally, and only after a verified manual run plus an explicit opt-in, the
   same path can run once per full boot from `BOOT_COMPLETED`. See
   `docs/AUTO_ROOT.md`.

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
`KEY_PASSWORD` repository secrets; push a `v*` tag or run it manually. The tag
must spell this tree's `versionName` exactly (`v` + `versionName`): the assets,
their `versionCode` and the release title all come from the gradle file while the
release is published under the tag, so a disagreement is refused offline, before
the build is spent. It runs the whole offline gate set first for the same reason —
a logic regression costs seconds, not a signed build.

The LKM rebuild needs Docker (GKI DDK), see `dirtyfrag-lkm/build.sh`.
Build ksud from kdp-612-3.3.0 branch of [my fork](https://github.com/polygraphene/KernelSU/tree/kdp-612-3.3.0) of KernelSU.

## Layout

- `installer/` — DFInstaller app: `PackagesXml`/`Abx` (packages.xml read/write,
  ABX-aware), `InjectMain` (root `app_process` entry: `--check/--dry-run/--dump/--uninstall`/inject),
  `SysKey`/`SigKey` (cert via PackageManager, v1/v2/v3 agnostic), GUI.
- `app/` — DFReroot app: `StageHop` (system_server -> network_stack),
  `DirtyFrag` (JNI bridge, package name must stay `org.lsposed.lspromise`),
  `KsudStage`, `DfrRootCoordinator` (the single execution path),
  `PostRootStatus` / `AutoRootPolicy` / `RunGuard` / `AwaitBox` (pure,
  host-tested decisions), `DfrBootReceiver` + `DfrAutoRootService` (Auto Root),
  native `exp.c` + `stage1.S` (arm64), `dirtyfrag.ko`.
- `dirtyfrag-lkm/` — LKM source (resolves `kallsyms_lookup_name`, clears
  `selinux_state.enforcing`).
- `logtestexe/` — standalone logcat-socket test binary.

## Caveats

- **The published release (`v2.0.4-zzic`) does not automate the closeout.** Its
  root chain is physically proven, including KernelSU root and a manual return
  from Permissive to Enforcing, but a green native result there is not equivalent
  to `POST_ROOT_COMPLETE`. The automatic version is `v2.0.5-zzic`, which is not
  built yet.
- **Auto Root is off, and refuses to be talked into being on.** No preference,
  intent or marker file is authority: the qualification requires a verified manual
  completion on the same versionCode, ksud digest and firmware, and the chain
  re-proves every gate on its own evidence anyway. An app update, a repinned ksud
  or a firmware update voids it.
- **A refusal is the tool working.** A run that stops at a gate and writes nothing
  is the designed outcome for anything unproven. Do not weaken a gate to get past
  it; report which evidence would unblock it.
- `/dev/df` is a same-boot armed-hook guard. If it exists, do not run DirtyFrag
  a second time; a hard reboot is the recovery boundary.
- `packages.xml` is backed up once to `packages.xml.bak-df-installer`. The backup
  is written transactionally and verified by size and SHA-256 before the original
  is touched; an existing backup is never overwritten, but one that is empty,
  truncated or unparsable makes the injection refuse rather than proceed without
  a working rollback. The original file's uid/gid/mode/SELinux label are captured
  before any write and re-verified afterwards; a divergence rolls back.

## What could come next

Owed on hardware, in order: the Gate-I acceptance, then `AUTO_ROOT_FULL_BOOT`,
then `POST_ROOT_LSPOSED_COMPAT` as its own separate result.

Cheap and useful without hardware: compiling the tree once with an SDK/NDK before
the next signed dispatch (the one property no offline audit covers), taking Gate F
to `PASS` by pointing `tools/elf_audit.py --root` at a dump of the device's
libraries, and teaching `tools/zzic_collect.sh` to print a post-root evidence
bundle with `boot_id` beside every value, so one boot's evidence cannot be mixed
with another's.

Structural, only if the project wants it: a second exact-firmware profile — the
identity, the module family table and the derived CRC evidence are already
separate, so another firmware is additive, at the cost of its own witness modules,
AVB chain and hashes, with nothing reused across firmwares. Also possible:
moving the Auto Root trigger into a companion app (the local policy would not
change, only who asks), and surfacing the last unattended outcome in the UI from
the per-boot journal. `docs/HANDOFF.md` carries the detail and the constraints.

## Acknowledgments

- [Dirty Frag by @V4bel](https://github.com/V4bel/dirtyfrag) - Discovering and exploiting Dirty Frag
- [LSPromise by @LSPosed](https://github.com/LSPosed/LSPromise) - Exploiting Dirty Frag on android
- [AbxOverflow by @michalbednarski](https://github.com/michalbednarski/AbxOverflow) - Idea for persistent `system_server` privilege
