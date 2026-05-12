include(FetchContent)
FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG v1.15.2
)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

include(GoogleTest)

add_executable(sniffer_tests
    test_bitreader.cpp
    test_nas.cpp
    test_framing.cpp
    test_s1ap.cpp
)
target_link_libraries(sniffer_tests
    PRIVATE
        sniffer_lib
        GTest::gtest_main
)
gtest_discover_tests(sniffer_tests)
