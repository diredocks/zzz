# Minimum required CMake version
cmake_minimum_required(VERSION 3.10)

# Project name and version
project(d3x LANGUAGES C)

# Set the C standard to C11
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED TRUE)

# Default build type (Release if not specified)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# Enable Debugging and Sanitizers for Debug build type
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  message(STATUS "Enabling Debug options (sanitizers and debug symbols)")
  add_compile_options(-g -fsanitize=address,undefined)
  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=address,undefined")
endif()

# --- 1. Find Source Files ---
# Recursively find all source files in src directory
file(GLOB_RECURSE SRC_FILES ${CMAKE_SOURCE_DIR}/src/*.c)

# --- 2. Set Up Cross-Compilation for Windows (MinGW) ---
if(MSYS)
  message(STATUS "Using MSYS toolchain for cross-compilation to Windows (MinGW)")
  set(CMAKE_SYSTEM_NAME Windows)
  set(CMAKE_SYSTEM_PROCESSOR x86_64)
  set(CMAKE_C_COMPILER "x86_64-w64-mingw32-gcc")
  message(STATUS "Compiling for Windows with MinGW")
endif()

# --- 3. Include Directories ---
# Include directories for source and headers
include_directories(
  ${CMAKE_SOURCE_DIR}/src
  ${CMAKE_SOURCE_DIR}/npcap_sdk/Include
)

# --- 4. Library Directories (MinGW for Windows) ---
if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  link_directories(${CMAKE_SOURCE_DIR}/npcap_sdk/Lib/x64)
endif()

# --- 5. Define Executable Target ---
# Define the executable target with source files
add_executable(d3x ${SRC_FILES})

# --- 6. Link Libraries ---
# Link platform-specific libraries
if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  target_link_libraries(d3x
    wpcap          # Windows Packet Capture library
    ws2_32         # Windows Sockets library
    iphlpapi       # Windows IP Helper API
  )
else()
  target_link_libraries(d3x pcap)  # Link libpcap for non-Windows platforms
endif()
