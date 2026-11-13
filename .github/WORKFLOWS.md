# Active GitHub Actions workflows

This repository deliberately keeps **five** workflows. They are not interchangeable.

| Workflow | Trigger | Why it remains |
| --- | --- | --- |
| `ci.yml` | Pull request, manual | Offline policy tests, profile and payload binding, Android build/package checks. Required before merging code that ships in the APK. |
| `release.yml` | Manual, version tag | Produces the release-signed DFReroot/DFInstaller APKs and publishes the GitHub Release. This is the release path; never replace with a review build. |
| `companion-review-build.yml` | Manual on the default branch | Produces the separately signed DFR Companion used for RMG-provider identity and live `su` attestation. It is not in the main APK release. |
| `build-dzif-dirtyfrag.yml` | Manual | Rebuilds and audits the exact DZIF DirtyFrag kernel module if its native source or pinned kernel changes. |
| `build-zzic-dirtyfrag.yml` | Manual | Rebuilds and audits the distinct ZZIC DirtyFrag kernel module; an old target remains intentionally buildable. |

## Archived one-off workflows

The October 2026 `dzif-defex-apk-review.yml` and `postflash-apk-review.yml` signed-review workflows were tied to historical review branches and duplicated the tests and signed-build functionality now provided by `ci.yml` and `release.yml`. They were removed from the active workflow directory, along with the unused postflash marker. Their implementation and logs remain recoverable from Git history and GitHub Actions history.

**Do not auto-publish signed APKs on pull requests.** Use `ci.yml` on PRs and manually invoke `release.yml` after the audited change is on `main`.

## DFR Companion

The Companion remains useful, even after DirtyFrag's POST_ROOT success. The current interactive provider-detection / RMG-reuse path uses it. It is **not** the native exploit or the POST_ROOT completion mechanism. Avoid uninstalling it while the existing RMG provider remains in use until the next cold-boot behavior has been verified without relying on it.

Deleting a workflow YAML does not erase its historical runs from GitHub's Actions UI; the historical items may remain visible under the workflow history.
