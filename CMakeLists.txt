cmake_minimum_required(VERSION 3.18.0 FATAL_ERROR)

cmake_policy(VERSION 3.18.0..3.31.10)

if (${CMAKE_VERSION} VERSION_GREATER_EQUAL "3.19.0")
   # allows spaces in ctest names
   cmake_policy(SET CMP0110 NEW)
endif()

if (${CMAKE_VERSION} VERSION_GREATER_EQUAL "3.20.0")
   # enable RTTI on MSVC
   cmake_policy(SET CMP0117 OLD)
endif()

if (${CMAKE_VERSION} VERSION_GREATER_EQUAL "3.31.0")
   # normalized path
   cmake_policy(SET CMP0177 NEW)
endif()

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/modules")

project(CsCrypto)

set(BUILD_MAJOR "1")
set(BUILD_MINOR "1")
set(BUILD_MICRO "1")

option(BUILD_EXAMPLES "Build the CsCrypto examples" OFF)
option(BUILD_TESTS    "Enables building the Catch2 Unit Tests" OFF)

option(ENABLE_BOTAN   "Enable Botan if Found" ON)
option(ENABLE_OPENSSL "Enable OpenSSL 1.1 if Found" ON)

include(FeatureSummary)

# location for install or package
if (CMAKE_SYSTEM_NAME MATCHES "Darwin")
   include(GNUInstallDirs)

   file(RELATIVE_PATH CS_BIN_RPATH "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_BINDIR}"
                                   "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}")

   set(CMAKE_INSTALL_RPATH "@executable_path/${CS_BIN_RPATH}")

elseif (CMAKE_SYSTEM_NAME MATCHES "(Linux|OpenBSD|FreeBSD|NetBSD|DragonFly)")
   include(GNUInstallDirs)

   file(RELATIVE_PATH CS_BIN_RPATH "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_BINDIR}"
                                   "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}")

   set(CMAKE_INSTALL_RPATH "$ORIGIN/${CS_BIN_RPATH}")

elseif (CMAKE_SYSTEM_NAME MATCHES "Windows")
   set(CMAKE_INSTALL_BINDIR bin)
   set(CMAKE_INSTALL_LIBDIR lib)
   set(CMAKE_INSTALL_INCLUDEDIR include)

endif()

if(APPLE)
    set(CMAKE_EXE_LINKER_FLAGS    "${CMAKE_EXE_LINKER_FLAGS}    -Wl,-undefined,error")
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,-undefined,error")
    set(CMAKE_MODULE_LINKER_FLAGS "${CMAKE_MODULE_LINKER_FLAGS} -Wl,-undefined,error")
else()
    set(CMAKE_EXE_LINKER_FLAGS    "${CMAKE_EXE_LINKER_FLAGS}    -Wl,--no-undefined")
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,--no-undefined")
    set(CMAKE_MODULE_LINKER_FLAGS "${CMAKE_MODULE_LINKER_FLAGS} -Wl,--no-undefined")
endif()

if (CMAKE_SYSTEM_NAME MATCHES "Darwin")
   set(PKG_PREFIX "CsCrypto.framework/Resources")

elseif (CMAKE_SYSTEM_NAME MATCHES "Windows")
   set(PKG_PREFIX "cmake/CsCrypto")

else()
   set(PKG_PREFIX "${CMAKE_INSTALL_LIBDIR}/cmake/CsCrypto")

endif()

# location for building binary files
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

add_subdirectory(src/core)
add_subdirectory(src/drivers)
add_subdirectory(src/util)

if (BUILD_EXAMPLES)
   message("CsCrypto examples enabled")

   add_subdirectory(examples)
endif()

if (BUILD_TESTS)
   message("CsCrypto tests enabled")
   enable_testing()

   add_subdirectory(test/core)
   add_subdirectory(test/util)
endif()

message("")
message("CsCrypto will be built in:      ${CMAKE_BINARY_DIR}")
message("CsCrypto will be installed in:  ${CMAKE_INSTALL_PREFIX}")
message("\n")
