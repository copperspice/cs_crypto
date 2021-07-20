add_executable(
   hash_file
   hash_file.cpp
)

target_link_libraries(
   hash_file
   CsCrypto::Core
   CsCrypto::Drivers
)

add_executable(
   encrypt_string
   encrypt_string.cpp
)

target_link_libraries(
   encrypt_string
   CsCrypto::Core
   CsCrypto::Drivers
)
