add_library(Util INTERFACE)
add_library(CsCrypto::Util ALIAS Util)

target_include_directories(
   Util
   INTERFACE
   $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
   $<INSTALL_INTERFACE:include/CsCrypto>
)

target_compile_features(
   Util
   INTERFACE
   cxx_std_20
)

list(APPEND CS_CRYPTO_UTIL_INCLUDES
   ${CMAKE_CURRENT_SOURCE_DIR}/conversions/byte.h
   ${CMAKE_CURRENT_SOURCE_DIR}/conversions/hex.h
   ${CMAKE_CURRENT_SOURCE_DIR}/tools/crypto_traits.h
   ${CMAKE_CURRENT_SOURCE_DIR}/tools/is_detected_traits.h
   ${CMAKE_CURRENT_SOURCE_DIR}/tools/result.h
   ${CMAKE_CURRENT_SOURCE_DIR}/tools/span.h
)

install(
   FILES ${CS_CRYPTO_UTIL_INCLUDES}
   DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/CsCrypto/util
   COMPONENT Util
)

install(
   TARGETS Util
   EXPORT Util-export
   DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
   COMPONENT Util
)

install(
   EXPORT Util-export
   FILE Util.cmake
   DESTINATION ${PKG_PREFIX}
)
