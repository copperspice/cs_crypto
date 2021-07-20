add_library(Core INTERFACE)
add_library(CsCrypto::Core ALIAS Core)

target_include_directories(
   Core
   INTERFACE
   $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/..>
   $<INSTALL_INTERFACE:include/CsCrypto>
)

target_compile_features(
   Core
   INTERFACE
   cxx_std_17
)

target_link_libraries(
   Core
   INTERFACE
   CsCrypto::Util
)

list(APPEND CS_CRYPTO_CORE_INCLUDES
   ${CMAKE_CURRENT_SOURCE_DIR}/cipher/sym_encrypt_decrypt.h
   ${CMAKE_CURRENT_SOURCE_DIR}/cipher/sym_process_msg.h
   ${CMAKE_CURRENT_SOURCE_DIR}/cipher/sym_secret_key.h
   ${CMAKE_CURRENT_SOURCE_DIR}/cipher/sym_init_vector.h
   ${CMAKE_CURRENT_SOURCE_DIR}/cipher/sym_traits.h
   ${CMAKE_CURRENT_SOURCE_DIR}/cipher/block/aes.h
   ${CMAKE_CURRENT_SOURCE_DIR}/cipher/block/mode.h

   ${CMAKE_CURRENT_SOURCE_DIR}/hash/hash_append.h
   ${CMAKE_CURRENT_SOURCE_DIR}/hash/hash_digest.h
   ${CMAKE_CURRENT_SOURCE_DIR}/hash/hash_traits.h
   ${CMAKE_CURRENT_SOURCE_DIR}/hash/md4.h
   ${CMAKE_CURRENT_SOURCE_DIR}/hash/md5.h
   ${CMAKE_CURRENT_SOURCE_DIR}/hash/sha1.h
   ${CMAKE_CURRENT_SOURCE_DIR}/hash/sha2.h
   ${CMAKE_CURRENT_SOURCE_DIR}/hash/sha3.h
)

install(
   FILES ${CS_CRYPTO_CORE_INCLUDES}
   DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/CsCrypto/core
   COMPONENT Core
)

install(
   TARGETS Core
   EXPORT Core-export
   DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
   COMPONENT Core
)

install(
   EXPORT Core-export
   FILE Core.cmake
   DESTINATION ${PKG_PREFIX}
)

