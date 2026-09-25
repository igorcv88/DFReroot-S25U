# AGENTS.md — standing directives for this repository

Read this before changing anything. It holds only what stays true across
versions: what this repository is, the rules that must not be broken, and how to
verify work without a device.

It deliberately contains **no gate states, no version numbers and no "current
status"**. Those live in:

- `docs/S25U_ZZIC_COMPATIBILITY.md` — the authoritative gate matrix and evidence
  record. When this file and that one disagree about what is *proven*, that one
  wins.
- `docs/HANDOFF.md` — where to pick up: current state, the remaining blockers,
  and the exact command that closes each.

`CLAUDE.md` is a symlink to this file. Edit `AGENTS.md`; never replace the
symlink with a copy, or the two will drift.

---

## 1. What this repository is

A fork of `polygraphene/DFReroot`, which is a **second-stage root** tool: you
obtain temporary root once with some other exploit, use it to persist a
system-UID app, and thereafter re-root from that app via the Dirty Frag
page-cache write primitive. It is offensive security tooling for hardware its
owner controls.

Two Android apps, one signing key:

| Module | Package | Role |
|---|---|---|
| `installer/` | `com.polygraphene.df.installer` | Normal app. As root via `app_process`, writes our signing certificate into the `android.uid.system` shared-user `pastSigs` in `/data/system/packages.xml`. |
| `app/` | `com.polygraphene.df.reroot` | `sharedUserId="android.uid.system"`. After a soft reboot it installs as system UID, hops `system_server → com.android.networkstack.process`, and runs the native Dirty Frag chain from there. |

**Both APKs must be signed with the same key.** DFInstaller injects DFReroot's
certificate, so a mismatch makes the injected key useless. The release workflow
compares the two certificate digests and fails if they differ.

What this fork adds on top of upstream: a **fail-closed target profile** for one
exact Samsung firmware, runtime gates that enforce it, boundary-tagged
`[DFR][*]` diagnostics, and offline audit tools under `tools/`.

An **unrelated** device — one that asserts neither the pinned model nor the
pinned codename — takes the unchanged upstream path. A device that asserts
either of them and deviates in any pinned field is `MISMATCH` and refuses
everything; it does **not** fall through to the generic path. See §3.1.

### The chain, end to end

```
temp root -> DFInstaller edits packages.xml -> soft reboot (PMS re-reads it)
  -> DFReroot installs as android.uid.system -> runs inside system_server
    -> AMS -> ProcessRecord -> IApplicationThread -> scheduleReceiver
      -> StageReceiver inside network_stack (can dlopen, holds CAP_NET_ADMIN)
        -> libexp.so -> Dirty Frag page-cache writes
           (crash_dump64, the vendor ELF, libc.so, libc++.so)
          -> LKM sets SELinux permissive -> ksud
```

---

## 2. The governing principle: fail-closed

This is the whole point of the fork. Every gate answers "may this proceed?" and
the answer is **no** unless positive evidence says otherwise.

- **Missing evidence is a refusal, never a pass.** "We never captured the hash"
  is not evidence of a match. "No `avc: denied` appeared" is not evidence of
  permission — the policy may `dontaudit`.
- **A verdict with no evidence behind it is a refusal.** A NULL profile, a NULL
  observation, an unrecognised enum value: all refuse.
- **An unreadable artefact changes which proof is required, never whether one
  is required.** See rule 3.3.
- **Nothing is validated after a write.** All identity checks, module selection
  and policy decisions run before the first page-cache write, so a refusal never
  leaves a corrupted file behind.

If you find yourself writing code that turns an absence, an error or an
uncertainty into permission to proceed, stop. That is the one thing this
repository exists to prevent.

---

## 3. Hard rules

### 3.1 Identity comparison is exact and case-sensitive

`ro.product.manufacturer` is lowercase `samsung` on Samsung firmware. Pinning
`Samsung` makes the real device classify `MISMATCH` and refuse everything. Host
tests assert both directions; `tools/profile_binding_audit.py` re-checks it.

A device that asserts the pinned model or codename but deviates in any field is
`MISMATCH` (a hard refusal), **not** a fall-through to the generic path.

### 3.2 A gate is only as strong as its weakest entry point

`patch_ko()`, `patch_libc()` and `patch_cxx()` are each independently reachable
(JNI natives, plus `StageReceiver` transactions 1–3). Both the identity gate
(`gate_target`) and the module policy (`gate_module_policy`) run in **all
three**. Enforcing either in one stage is the same as not enforcing it.
`tools/profile_binding_audit.py` fails CI if a stage drops the policy call.

### 3.3 Proof may change form; it may not be skipped

`/vendor/lib64/libstagefrighthw.so` cannot be `open`ed from
`u:r:system_server:s0` or `u:r:network_stack:s0` on this firmware (`EACCES`) —
which is exactly why `patch_ko()` writes it through the `crash_dump64` helper
(`use_helper = 1`) instead of opening it. A gate that demands a direct read of
it is unsatisfiable by construction.

So its identity is established through `dfr_vendor_provenance_eval()`: the AVB
chain the pinned digest was captured under (vbmeta digest, `avb_version`,
`hash_alg`, `verifiedbootstate`, `device_state`, `flash.locked`, `veritymode`,
`/vendor` filesystem type and read-only flag). Every element is compared, and
any divergence refuses.

**Do not "simplify" this back into a direct `gate_hash()` of the vendor ELF.**
`tools/profile_binding_audit.py` fails CI if that call shape reappears.

Corollaries that hold for any future artefact in this position:

- A file that **is** readable and hashes wrong is always a hard refusal. No
  provenance excuses it.
- Unreadable for an errno other than the one documented for the policy denial is
  a fault, not a policy — refuse.
- Anchors that may or may not be observable (`stat` size, SELinux label when
  `getattr` may also be denied) are compared **when available** and recorded
  `SKIP` when not. Absence is never counted as agreement.

### 3.4 Artefact hashes are scoped to the stage that writes them

The chain rewrites the vendor file, `libc` and `libc++` in the page cache. A
stage that re-hashes an artefact an earlier stage already patched would compare
against the pristine pinned digest and abort the chain **on its own writes**.

`patch_ko()` owns `DFR_ART_CRASHDUMP | DFR_ART_VENDOR` (it writes both),
`patch_libc()` owns `DFR_ART_LIBC`, `patch_cxx()` owns `DFR_ART_LIBCXX`.
Artefacts a stage does not own log `SKIP`.

**Never widen a stage's mask to "check everything."** That is self-blocking.
Each artefact is still validated exactly once, while pristine, immediately
before it is written.

### 3.5 A boolean is not evidence — bind claims to bytes

`ko_zzic_verified == 1` IMPLIES `ko_sha256` is pinned AND `ko_filename` names a
bundled module AND `SHA-256(the bytes actually selected) == ko_sha256`.

All three fields move together or none do. Enforced at run time in `patch_ko()`
and offline in `tools/profile_binding_audit.py`, which also rejects a stale
digest left pinned while the flag is 0.

`MODULE_VS_ZZIC_KERNEL = COMPATIBLE` from `tools/ko_audit.py`, against the exact
kernel's `Module.symvers`, is the **only** result that justifies setting them.
Matching the GKI base version and the page size is **not sufficient** when the
kernel has `CONFIG_MODVERSIONS=y`, and must never be treated as if it were.

Nor is agreement among the `__versions` entries that happen to exist. Under
`CONFIG_MODVERSIONS` the kernel refuses a load when the table exists but names no
version for a symbol it is resolving, and `CONFIG_MODULE_FORCE_LOAD` is not set
on this kernel — so a table covering three of four imports is unloadable while an
entries-only diff reads `COMPATIBLE`. `ko_audit.py` therefore requires
`imports_requiring_modversion - __versions entries == {}`, reports a hole as a
hole (never as a CRC mismatch), reports an import absent from `Module.symvers`
separately again, and exempts weak undefined symbols, which the loader is allowed
to leave unresolved. The acceptance run for a newly built module must pass
`--require-modversion-coverage`.

`Module.symvers` is a kernel *build* artefact. It does not exist on a running
Android filesystem, so "search the device for it" is not a valid plan.

### 3.6 No execution override, under any name

The marker that once let the owner accept the kernel-crash risk was removed, not
kept. `tools/profile_binding_audit.py` rejects its reintroduction by
**mechanism**, not just by spelling: no source that ships inside DFReroot may
reference a world-writable `/data/local/tmp` path at all, because a marker read
from one is the only shape such an override can take.

The consequence is deliberate and worth stating plainly: while the module is
unverified, the chain cannot be exercised end to end on this firmware — not even
on purpose. Restoring an at-own-risk opt-in is a policy decision for the
repository owner, made in the open. **It is not a patch an agent applies because
a run is inconvenient.**

Equally out of bounds as "fixes": setting SELinux permissive to get past a gate,
editing the device's SELinux policy, making the chain depend on KernelSU,
requiring the user to disable a root manager's namespace features, or removing a
validation because it fails.

### 3.7 Signals are never collapsed

Separate facts get separate values:

| These are different facts |
|---|
| `NETWORKSTACK_PROCESS_FOUND` (a process with that uid was observed) vs `REMOTE_COMPONENT_REACHED` (our code executed inside it) |
| `NATIVE_LIBRARY_DISCOVERABLE` (the `.so` exists on disk) vs `LIBEXP_LOADED` (`dlopen` succeeded in that domain) |
| a primary lookup being unavailable vs the lookup as a whole failing |

A boundary that falls back successfully must end on an explicit `PASS`, not on a
bare `UNKNOWN` from the step that was skipped. A reader of the log must never
have to guess whether an `UNKNOWN` was fatal.

No single `/dev/df*` marker means end-to-end compatibility.

### 3.8 Evidence is per-boot

`boot_id` is logged at every boundary. States captured across different boots
must never be combined into one apparently successful chain.

### 3.9 The DFInstaller write path

`/data/system/packages.xml` is the file whose corruption bricks the device's
package database. Rules:

- **The source of truth for metadata is the ORIGINAL file, `stat`'d before any
  write.** Never the backup (a file created by a root `app_process` is
  `root:root 0644`), never a hardcoded mode. Capture uid, gid, mode, SELinux
  label and a digest up front; re-verify after the write; roll back and refuse
  on any divergence.
- **Backups are transactional**: stage under a temporary name, read back and
  compare size **and** SHA-256, apply the original's metadata, `fsync`, then
  atomic `rename(2)`.
- **An existing backup is never overwritten** — it is the pristine
  pre-injection image, and a second run must not replace it with an injected
  one. But it *is* validated, and one that is empty, truncated or unparsable is
  a **hard failure**, not a reassuring log line. A backup that restores nothing
  is worse than no backup: it looks like a safety net.
- The logic lives in `installer/.../SafeWrite.java`, deliberately free of
  Android imports, behind a `FileOps` interface. **Keep it there.** Inlining it
  back into `PackagesXml.kt` is how the metadata source of truth drifts onto the
  backup file again, and it makes the EPERM-then-`rename` branch — the one that
  actually runs on the device — untestable.

### 3.10 The C profile and the JSON profile must agree

`app/src/main/jni/target_profile.c` (runtime) and `tools/zzic_profile.json`
(offline tools) are two copies of one definition of "the target". Any pinned
value goes in **both**. Inside the JSON, an artefact hash appears twice — as a
top-level field and under `targets[<path>]` — and those two must agree as well.
`tools/profile_binding_audit.py` fails on any of these drifts.

---

## 4. Where authority lives

| Question | Authoritative source |
|---|---|
| What is the target, and what is pinned about it? | `app/src/main/jni/target_profile.{h,c}` |
| Same, for the offline Python tools | `tools/zzic_profile.json` |
| Which gates are actually proven, and by what evidence? | `docs/S25U_ZZIC_COMPATIBILITY.md` |
| What is left to do and what closes it? | `docs/HANDOFF.md` |
| Do the profile's internal invariants hold? | `tools/profile_binding_audit.py` |
| What does the release advertise? | generated by `tools/release_notes.py` — never hand-written prose |

**If the device disagrees with the profile, the profile is wrong.** Correct it
from observed values, never the reverse — and never "adjust" a comparison to
make a real device pass.

---

## 5. Verification — all of it runs with no device and no SDK

Run these before proposing any change. They are fast and they are the gate.

```sh
git diff --check
sh    tools/tests/run_tests.sh            # target profile + gates, a host syntax
                                          # pass over exp.c, and the Gate-G
                                          # modversion rules
sh    tools/tests/run_installer_tests.sh  # SafeWrite against an in-memory fs
sh    tools/tests/test_resolve_release_tag.sh
python3 tools/profile_binding_audit.py    # profile invariants + drift + no override
python3 tools/elf_audit.py                # Gate F
python3 tools/ko_audit.py app/src/main/jni/dirtyfrag-android15-6.6.ko   # Gate G
python3 tools/release_notes.py            # the notes still generate
python3 -m compileall -q tools
```

With an SDK and NDK, additionally:

```sh
./build.sh
./tools/ci_build_audit.sh                 # Gate E + bundled-asset byte identity
./tools/repro_report.sh
```

Every audit tool exits non-zero on a failed gate. `UNVERIFIED` and `N/A` are
successful on purpose — evidence absent, or not a candidate; neither is a
defect. **Never ignore a non-zero exit from a release audit.**

### Testing rules

- Logic that decides anything belongs in a **pure, host-testable** unit —
  `target_profile.c` for the native side, `SafeWrite.java` for the installer —
  with the platform behind a thin interface. That is what makes the paths that
  only occur on hardware (a denied `open`, an `EPERM` overwrite) reachable from
  a test.
- Every new gate needs its **negative** cases, one per element. A gate that
  cannot fail is not a gate.
- Kotlin that needs an Android runtime cannot be unit-tested here. Guard it with
  a static check in `tools/profile_binding_audit.py` asserting the signal or the
  invoked shape is still present.

---

## 6. Build, release and GitHub conventions

Toolchain known to work: JDK 21, Gradle wrapper, AGP 8.7.3, Kotlin 2.0.21, SDK
platform 36, build-tools 36.0.0, NDK 27.0.12077973, CMake 3.22.1.

```sh
ANDROID_HOME=<sdk> ANDROID_NDK_HOME=<ndk> ./build.sh
# signing from the environment when set; create-keystore.sh defaults otherwise
KEYSTORE_FILE=... KEYSTORE_PASSWORD=... KEY_ALIAS=... KEY_PASSWORD=... ./build.sh
```

**Both APKs must be signed with the same key.** DFInstaller injects DFReroot's
certificate, so a mismatch makes the injected key useless. The release workflow
compares the two certificate digests and fails if they differ.

The release must contain both APKs, `SHA256SUMS.txt` and `build-provenance.txt`,
and the `assets/df_reroot.apk` bundled inside the installer must be
**byte-identical** to the published `df_reroot.apk` — `tools/ci_build_audit.sh`
proves this.

### 6.1 GitHub Actions minutes are a real, billed cost

**Do not dispatch a workflow that is not absolutely necessary.** Runner minutes
come out of the owner's account, and almost nothing in this repository needs a
runner to be checked.

- **Every validation runs locally, with no device and no SDK.** The list is §5.
  Run it on your own machine. A push that only wants "CI to check it" is a
  workflow dispatch that buys nothing the commands in §5 did not already prove.
- **`release.yml` is the validation run.** It executes the whole offline gate
  set *before* it spends a signed build, so a logic regression fails there in
  seconds. That is by design: it means there is no separate CI run to schedule.
- **`ci.yml` is manual-dispatch only and is disabled at the repository level.**
  That is deliberate — it used to run a full SDK + NDK + Gradle build on every
  push to every branch, re-proving what `release.yml` already gates. **Never
  re-enable it**, never add push/PR triggers to any workflow, and never enable
  a workflow the owner disabled.
- **The only routinely justified dispatch is `release.yml`**, when a release is
  actually wanted, because producing signed APKs needs the repository secrets
  and cannot be done anywhere else. One dispatch, not one per attempt: get the
  build right locally first.
- If you genuinely believe a runner is needed for something else, **ask before
  dispatching.** Do not spend the minutes and explain afterwards.

### 6.2 Every change goes through a pull request

**Never commit or push directly to `main`** unless the owner explicitly says to
in that request. Work on a branch, open a PR, and let the owner decide when it
lands. This holds for documentation and one-line fixes as much as for code —
"it was trivial" is not an exemption, because the PR is also the record of what
changed and why.

A standing instruction to develop on a named branch is not permission to bypass
the PR; it is where the PR comes from. Rewriting history on a branch you did not
create is separately out of bounds.

### 6.3 Releases are published as stable, not pre-release

**Publish releases as the stable/latest release.** `release.yml` defaults
`prerelease` to `false`, and that default stands; marking one as a pre-release
is an explicit choice the owner makes, not something an agent does because a
gate is unverified.

This is not a softening of anything. The pre-release flag is a GitHub label on a
download page; it never gated anything. What actually protects the device is the
fail-closed chain inside the APK, which refuses on its own evidence and is
unaffected by how the release is labelled. The compatibility state is
communicated where it can be precise — the release notes, generated by
`tools/release_notes.py` from the compiled profile, which state every gate and
say plainly when and why the build will refuse.

So: keep the notes generated and truthful, and do not hand-write release prose.
The one failure this pair must never produce is a release whose notes claim a
gate state the shipped profile does not have.

## 7. Things that look like defects and are not

- **`libexp.so` is arm64-only.** A load failure on an x86_64 emulator is
  expected and non-fatal, so the Java hop stays testable there.
- **The JNI package name `org.lsposed.lspromise.DirtyFrag` is load-bearing.**
  `exp.c` registers `Java_org_lsposed_lspromise_DirtyFrag_*` and `JNI_OnLoad`
  looks the class up by that name. Renaming either side breaks linkage.
- **`REFERENCE_DIRTYFRAG_FIX_ABSENT=CONFIRMED`** is an independent static fact.
  It is not proof of exploitability and must not be used to promote any gate.
- **The kernel release string parsing to `android15`** is kernel-*family* module
  selection. It is not identity, and it never substitutes for the identity gate.
- **A run that refuses at a gate and writes nothing is the tool working.** Do not
  "fix" it by weakening the gate.

---

## 8. Working conventions

- **Write the reason, not the change.** Comments in this repository explain why
  a boundary exists and what breaks without it, because the next agent's failure
  mode is deleting something that looks redundant. Match that density.
- **Never promote a gate without independent evidence for every boundary it
  covers**, and record the evidence in `docs/S25U_ZZIC_COMPATIBILITY.md`.
- **Keep documentation behind the code, not ahead of it.** Release notes are
  generated from the profile precisely because hand-written prose once
  advertised blockers the build had already cleared. When a doc states a fact
  that can change, either generate it or say where the authoritative copy is.
- **Report refusals as refusals.** If a gate blocks the work you were asked to
  do, say so and say which evidence would unblock it. Do not route around it.
