cmake_minimum_required(VERSION 3.20)
project(sniffer CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()

add_compile_options(-Wall -Wextra -Wpedantic -Werror)

find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED IMPORTED_TARGET libpcap)
find_package(SQLite3 REQUIRED)

add_library(sniffer_lib STATIC
    src/ingest.cpp
    src/framing.cpp
    src/s1ap.cpp
    src/nas.cpp
    src/nas_ies.cpp
    src/bitreader.cpp
    src/db.cpp
)
target_include_directories(sniffer_lib PUBLIC src)
target_link_libraries(sniffer_lib
    PUBLIC
        PkgConfig::PCAP
        SQLite::SQLite3
)

add_executable(sniffer src/main.cpp)
target_link_libraries(sniffer PRIVATE sniffer_lib)

enable_testing()
add_subdirectory(tests)
