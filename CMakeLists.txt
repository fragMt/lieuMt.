cmake_minimum_required(VERSION 3.24)

project(lieuMt
    VERSION 0.1.0
    LANGUAGES CXX)

add_executable(lieuMt
    src/main.cpp)

set_target_properties(lieuMt PROPERTIES
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS OFF)

target_compile_options(lieuMt PRIVATE -Wall -Wextra -Wpedantic)
