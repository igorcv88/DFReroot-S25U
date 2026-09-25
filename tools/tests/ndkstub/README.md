# Minimal NDK header stubs

Just enough of `jni.h`, `sys/system_properties.h` and `android/log.h` for a host
`cc -fsyntax-only` pass over `app/src/main/jni/exp.c` (see
`tools/tests/exp_syntax_check.sh`). Everything else exp.c includes
(`linux/xfrm.h`, `sys/xattr.h`, `linux/netlink.h`, ...) exists on a normal Linux
host already.

These stubs are **only** for the syntax pass. They are never compiled into the
app: the real NDK headers are used for the ARM64 build. Their job is to catch a
typo in a gate in seconds, on a runner with no SDK, instead of at the signed
build several minutes later.
