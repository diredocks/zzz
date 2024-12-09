# Minimum CMake version
cmake_minimum_required(VERSION 3.10)

# Project name and version
project(d3x LANGUAGES C)

# Set the C standard to C11
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED True)

# Enable debugging and sanitization if the build type is Debug
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    message(STATUS "Enabling debug options")
    add_compile_options(-g -fsanitize=address,undefined)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=address,undefined")
endif()

# Find all source files recursively in the subdirectories
file(GLOB_RECURSE SRC_FILES
    ${CMAKE_SOURCE_DIR}/src/*.c
)

# Include directories (add subdirectories if you have headers in them)
include_directories(${CMAKE_SOURCE_DIR}/src)

# Define the executable target
add_executable(d3x ${SRC_FILES})

# Link the required libraries
target_link_libraries(d3x pcap)

# Optionally set default build type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type" FORCE)
endif()
