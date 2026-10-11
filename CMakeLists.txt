cmake_minimum_required(VERSION 3.16)
project(AESCipher VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(MSVC)
    add_compile_options(/W4)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

include(FetchContent)
FetchContent_Declare(
    cli11
    GIT_REPOSITORY https://github.com/CLIUtils/CLI11.git
    GIT_TAG        v2.4.2
)
FetchContent_MakeAvailable(cli11)

add_library(aes_core
    src/aes.cpp
    src/padding.cpp
)

target_include_directories(aes_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

add_executable(aes_app
    src/main.cpp
)

target_link_libraries(aes_app PRIVATE aes_core CLI11::CLI11)