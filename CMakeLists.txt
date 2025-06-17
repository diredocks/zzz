cmake_minimum_required(VERSION 3.24)

project(zzz LANGUAGES C)
set(CMAKE_C_STANDARD 23)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

file(GLOB_RECURSE SRC_FILES 
    src/*.c
)

add_executable(${PROJECT_NAME} ${SRC_FILES})
target_include_directories(${PROJECT_NAME} 
    PRIVATE 
        src
    PUBLIC 
        include
)

if(CMAKE_BUILD_TYPE MATCHES "Debug")
  set(
    CMAKE_C_FLAGS
    "${CMAKE_C_FLAGS} -Werror -fsanitize=address -g"
  )
  target_link_options(zzz
    BEFORE PUBLIC -fsanitize=address
  )
endif()

target_link_libraries(${PROJECT_NAME}
  pcap
)
