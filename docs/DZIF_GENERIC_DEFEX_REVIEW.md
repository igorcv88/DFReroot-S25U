# DZIF DEFEX v2 — proveniencia de main

Fonte: `igorcv88/RMGLabs-Payloads`, commit `7f03e0a72653e84b472d7f8ec8c71c502c2e9822` (main antes do build).

O workflow `build-dzif-exact-port.yml` com perfil `dfreroot` realizou build ARM64, auditoria ABI e publicacao do ksud correspondente no repositorio produtor.

- `ksud` SHA-256: `89eb37bd8a3b9c5e9f7e7391ccacf634bf6391cf3c8f6a305a7e7eb54e8a4a9e`.
- `ksud` tamanho: `6678728` bytes.
- KernelSU `.ko` SHA-256 incorporado: `ca08bc0adf102b4da920aac714a30a99043ae00eefa473128e32932a8e056f03`.
- KernelSU `.ko` GNU build-id: `3a682471778910778f2c4c718fd90b56a4d7ab13`.
- KernelSU `.ko` tamanho: `3630896` bytes.
- Politica: `samsung-kdp-rkp-defex,staged-daemon-hotfix,generic-zygisk-defex-v2,throne-tracker-serialise,dfr-kdp-cred-fix,dfr-marker-binds-module`.

O `.ko` KernelSU citado acima esta embutido no `ksud` DFR; **nao** substituir o DirtyFrag `.ko` independente em `app/src/main/jni/`.

Verificacao no aparelho (LSPosed, PIFork e estabilidade): ainda pendente ate teste fisico.
