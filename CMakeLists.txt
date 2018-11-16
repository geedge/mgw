cmake_minimum_required(VERSION 3.5)
project(mgw)

set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)
#include(Version)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_C_STANDARD 11)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set (CMAKE_CXX_FLAGS "-Werror")

add_definitions(-D_GNU_SOURCE)

add_subdirectory(vendor)
add_subdirectory(common)
add_subdirectory(access)

# cmake -DCMAKE_BUILD_TYPE=Debug