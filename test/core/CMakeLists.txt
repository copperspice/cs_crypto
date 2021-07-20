include(Load_Catch2)
include(CTest)

add_executable(core_tests "")

target_link_libraries(
   core_tests
   CsCrypto::Core
   CsCrypto::Drivers
   Catch2::Catch2
)

target_sources(
   core_tests
   PRIVATE
   ${CMAKE_CURRENT_SOURCE_DIR}/test_main.cpp

   ${CMAKE_CURRENT_SOURCE_DIR}/cipher/test_sym_encrypt_decrypt.cpp
   ${CMAKE_CURRENT_SOURCE_DIR}/cipher/test_sym_process_msg.cpp
   ${CMAKE_CURRENT_SOURCE_DIR}/cipher/test_sym_secret_key.cpp
   ${CMAKE_CURRENT_SOURCE_DIR}/cipher/test_sym_init_vector.cpp

   ${CMAKE_CURRENT_SOURCE_DIR}/hash/test_copy_context.cpp
   ${CMAKE_CURRENT_SOURCE_DIR}/hash/test_hash_append.cpp
   ${CMAKE_CURRENT_SOURCE_DIR}/hash/test_hash_digest.cpp
   ${CMAKE_CURRENT_SOURCE_DIR}/hash/test_md4.cpp
   ${CMAKE_CURRENT_SOURCE_DIR}/hash/test_md5.cpp
   ${CMAKE_CURRENT_SOURCE_DIR}/hash/test_sha1.cpp
   ${CMAKE_CURRENT_SOURCE_DIR}/hash/test_sha2.cpp
   ${CMAKE_CURRENT_SOURCE_DIR}/hash/test_sha3.cpp
)

include(ParseAndAddCatchTests)
ParseAndAddCatchTests(core_tests)
