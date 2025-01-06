add_library(Drivers INTERFACE)
add_library(CsCrypto::Drivers ALIAS Drivers)

target_include_directories(
   Drivers
   INTERFACE
   $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/..>
   $<INSTALL_INTERFACE:include/CsCrypto>
)

target_compile_features(
   Drivers
   INTERFACE
   cxx_std_20
)

target_link_libraries(
   Drivers
   INTERFACE
   CsCrypto::Core
   CsCrypto::Util
)

message("-- Searching for required packages\n")

if (ENABLE_OPENSSL)
   # look for OpenSSL
   find_package(OpenSSL 1.1)

   if (TARGET OpenSSL::Crypto)

      if (OpenSSL_FOUND)
         message(STATUS "OpenSSL was found \n"
            " * Version: ${OPENSSL_VERSION}\n"
            " * Path: ${OPENSSL_CRYPTO_LIBRARY}\n")
      endif()

      target_compile_definitions(
         Drivers
         INTERFACE
         CSCRYPTO_HAVE_OPENSSL=1
      )

      target_link_libraries(
         Drivers
         INTERFACE
         OpenSSL::Crypto
      )
   endif()
endif()


if (ENABLE_BOTAN)
   # look for Botan
   find_package(Botan)

   if (TARGET Botan::Botan)

      if (Botan_FOUND)
         message(STATUS "Botan was found \n"
            " * Path: ${BOTAN_LIBRARY}\n")
      endif()

      target_compile_definitions(
         Drivers
         INTERFACE
         CSCRYPTO_HAVE_BOTAN=1
      )

      target_link_libraries(
         Drivers
         INTERFACE
         Botan::Botan
      )
   endif()
endif()

list(APPEND CS_CRYPTO_DRIVERS_INCLUDES
   ${CMAKE_CURRENT_SOURCE_DIR}/backend/botan/aes.h
   ${CMAKE_CURRENT_SOURCE_DIR}/backend/botan/config.h
   ${CMAKE_CURRENT_SOURCE_DIR}/backend/botan/hash.h
   ${CMAKE_CURRENT_SOURCE_DIR}/backend/openssl/aes.h
   ${CMAKE_CURRENT_SOURCE_DIR}/backend/openssl/config.h
   ${CMAKE_CURRENT_SOURCE_DIR}/backend/openssl/hash.h
   ${CMAKE_CURRENT_SOURCE_DIR}/base/aes.h
   ${CMAKE_CURRENT_SOURCE_DIR}/base/config.h
   ${CMAKE_CURRENT_SOURCE_DIR}/base/drivers.h
   ${CMAKE_CURRENT_SOURCE_DIR}/base/hash.h
   ${CMAKE_CURRENT_SOURCE_DIR}/base/traits.h
)

install(
   FILES ${CS_CRYPTO_DRIVERS_INCLUDES}
   DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/CsCrypto/drivers
   COMPONENT Drivers
)

install(
   TARGETS Drivers
   EXPORT Drivers-export
   DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
   COMPONENT Drivers
)

install(
   EXPORT Drivers-export
   FILE Drivers.cmake
   DESTINATION ${PKG_PREFIX}
)
