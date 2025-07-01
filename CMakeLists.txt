cmake_minimum_required(VERSION 3.26.0 FATAL_ERROR)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

include(CCache OPTIONAL)
include(NoInSourceBuilds OPTIONAL)

option(USE_VCPKG_TOOLCHAIN "Use vcpkg toolchain file" ON)

if(USE_VCPKG_TOOLCHAIN)
  set(VCPKG_OVERLAY_PORTS "${CMAKE_SOURCE_DIR}/vcpkg_ports")

  if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    set(CMAKE_TOOLCHAIN_FILE "${CMAKE_SOURCE_DIR}/vcpkg/scripts/buildsystems/vcpkg.cmake" CACHE FILEPATH "Vcpkg toolchain file")
  endif()
endif()

# project setup
project(ProcessMonitor VERSION 1.0.0 LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(BUILD_SHARED_LIBS OFF CACHE BOOL "Build only static libraries" FORCE)

# dependencies
find_package(PkgConfig REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)

pkg_check_modules(LIBBPF REQUIRED IMPORTED_TARGET libbpf)
pkg_check_modules(ZLIB REQUIRED IMPORTED_TARGET zlib)

# tools
set(CLANG_EXECUTABLE "" CACHE FILEPATH "Path to clang executable")
set(BPFTOOL_EXECUTABLE "" CACHE FILEPATH "Path to bpftool executable")
set(SHELL_EXECUTABLE "" CACHE FILEPATH "Path to shell executable")

if(CLANG_EXECUTABLE)
  set(CLANG ${CLANG_EXECUTABLE})
else()
  find_program(CLANG clang REQUIRED)
endif()

if(BPFTOOL_EXECUTABLE)
  set(BPFTOOL ${BPFTOOL_EXECUTABLE})
else()
  find_program(BPFTOOL bpftool REQUIRED)
endif()

if(SHELL_EXECUTABLE)
  set(SHELL ${SHELL_EXECUTABLE})
else()
  find_program(SHELL sh REQUIRED)
endif()

execute_process(
  COMMAND ${BPFTOOL} --version
  OUTPUT_VARIABLE BPFTOOL_VERSION
  ERROR_QUIET
  OUTPUT_STRIP_TRAILING_WHITESPACE
)

# if(NOT BPFTOOL_VERSION VERSION_GREATER_EQUAL "5.7")
#   message(WARNING "bpftool version (${BPFTOOL_VERSION}) is older than recommended 5.7+, may cause incompatibilities")
# endif()

# eBPF resources
set(BPF_NAME "procmon")
set(BPF_SRC_PATH "${CMAKE_SOURCE_DIR}/src/${BPF_NAME}.bpf.c")
set(BPF_OBJ_PATH "${CMAKE_CURRENT_BINARY_DIR}/${BPF_NAME}.bpf.o")
set(BPF_SKEL ${BPF_NAME}.skel.h)
set(BPF_SKEL_PATH "${CMAKE_CURRENT_BINARY_DIR}/${BPF_SKEL}")
set(VMLINUX_HEADER_PATH "${CMAKE_CURRENT_BINARY_DIR}/vmlinux.h")

# generate vmlinux.h
add_custom_command(
    OUTPUT ${VMLINUX_HEADER_PATH}
    COMMAND ${SHELL} -c "${BPFTOOL} btf dump file /sys/kernel/btf/vmlinux format c > ${VMLINUX_HEADER_PATH}"
    COMMENT "Generating vmlinux.h from system BTF"
    VERBATIM
)

# compile eBPF C file to .o
add_custom_command(
    OUTPUT ${BPF_OBJ_PATH}
    COMMAND ${SHELL} -c "${CLANG} -g -O2 -Wall -Wextra -Werror -target bpf -I${CMAKE_CURRENT_BINARY_DIR} -I${libbpf_SOURCE_DIR}/src -D__BPF__ -c ${BPF_SRC_PATH} -o ${BPF_OBJ_PATH}"
    DEPENDS ${VMLINUX_HEADER_PATH}
    COMMENT "Compiling BPF C code"
    VERBATIM
)

# generate eBPF skeleton header
add_custom_command(
    OUTPUT ${BPF_SKEL_PATH}
    COMMAND ${SHELL} -c "${BPFTOOL} gen skeleton ${BPF_OBJ_PATH} > ${BPF_SKEL_PATH}"
    DEPENDS ${BPF_OBJ_PATH}
    COMMENT "Generating BPF skeleton header"
    VERBATIM
)

add_custom_target(generate_and_compile_bpf ALL DEPENDS ${BPF_SKEL_PATH})

# main executable
add_executable(${PROJECT_NAME} src/main.cpp)

target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_SOURCE_DIR}/src/include
)

target_compile_definitions(${PROJECT_NAME} PRIVATE BPF_SKEL_HEADER="${BPF_SKEL}")

target_link_options(${PROJECT_NAME} PRIVATE -static-libgcc -static-libstdc++ -static)

target_link_libraries(${PROJECT_NAME} PRIVATE
    nlohmann_json::nlohmann_json
    PkgConfig::LIBBPF
    PkgConfig::ZLIB
)

add_dependencies(${PROJECT_NAME} generate_and_compile_bpf)
