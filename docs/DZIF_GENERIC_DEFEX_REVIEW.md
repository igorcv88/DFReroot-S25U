# DZIF generic DEFEX review pair (not deployed)

Source: RMGLabs-Payloads PR #13, commit 1744867bcbce530ac6f84d5e91ce88b2345dc3b1.
GitHub Actions nonpublishing run: 39075657763.

- KernelSU .ko SHA-256: 54f3ac938683227ff35f9c27b7316f8948d65df8f8174e860c6d24d76105f5ec.
- KernelSU .ko GNU build-id: aac86c92710e0f92b39c8a6ea777143908764174.
- ksud SHA-256: a885a4d7643d9c282c1f8f2d89837f00163bf13b9674a90992efc6608a7168f7.
- ksud GNU build-id: 944b0e2f0d353a68e76ab0f010799c138ceec27b.

The `ksud` asset embeds this KernelSU `.ko`. Do not substitute the separate
DirtyFrag `.ko`. No Early Root allowlist modification, merge, release or
on-device load is authorized by this PR. Offline tests are not physical validation.
The importer must be called with `--from-file` until producer artifact promotion.
