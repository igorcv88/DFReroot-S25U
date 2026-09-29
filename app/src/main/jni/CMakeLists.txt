cmake_minimum_required(VERSION 3.22)
project(exp)

enable_language(ASM)

set(CMAKE_ASM_FLAGS "${CMAKE_ASM_FLAGS} -I${CMAKE_SOURCE_DIR}")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${C_FLAGS} -I${CMAKE_SOURCE_DIR}  -Wall -Wextra -Wmost -fno-stack-protector -fomit-frame-pointer")

add_library(exp SHARED exp.c stage1.S elf_parser.c target_profile.c sha256.c)

set_source_files_properties(exp.c PROPERTIES
    OBJECT_DEPENDS "${CMAKE_SOURCE_DIR}/dirtyfrag-android12-5.10.ko;${CMAKE_SOURCE_DIR}/dirtyfrag-android13-5.10.ko;${CMAKE_SOURCE_DIR}/dirtyfrag-android13-5.15.ko;${CMAKE_SOURCE_DIR}/dirtyfrag-android14-5.15.ko;${CMAKE_SOURCE_DIR}/dirtyfrag-android14-6.1.ko;${CMAKE_SOURCE_DIR}/dirtyfrag-android15-6.6.ko;${CMAKE_SOURCE_DIR}/dirtyfrag-android15-6.6-S938BXXUCZZIC.ko;${CMAKE_SOURCE_DIR}/dirtyfrag-android16-6.12.ko;${CMAKE_SOURCE_DIR}/dirtyfrag-android17-6.18.ko;${CMAKE_SOURCE_DIR}/splicehelper")

# The soft-reboot root transport. Separate from libexp.so on purpose: libexp is
# the payload dlopen'd inside network_stack, while this is loaded by the app's
# own process - which on this firmware is system_server - and must carry none of
# the exploit. See app/src/main/jni/dfr_su_core.h for why it forks at all.
add_library(dfrsu SHARED dfr_su_jni.c dfr_su_core.c dfr_verified_exec_core.c sha256.c)

target_link_libraries(exp log)
target_link_libraries(dfrsu log)
