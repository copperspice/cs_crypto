include(Load_Catch2)
include(CTest)

add_executable(util_tests "")

target_link_libraries(
   util_tests
   CsCrypto::Core
   CsCrypto::Drivers
   Catch2::Catch2
)

target_sources(util_tests
   PRIVATE
   ${CMAKE_CURRENT_SOURCE_DIR}/test_main.cpp
   ${CMAKE_CURRENT_SOURCE_DIR}/tools/test_span.cpp
   ${CMAKE_CURRENT_SOURCE_DIR}/tools/test_result.cpp
)

include(ParseAndAddCatchTests)
ParseAndAddCatchTests(util_tests)
