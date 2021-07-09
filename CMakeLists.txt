cmake_minimum_required(VERSION 3.10)
set(TARGET_NAME dll_injector)
project(${TARGET_NAME} LANGUAGES C CXX)
set(CMAKE_CXX_STANDARD 17)

add_subdirectory(./examples)
add_subdirectory(./dll_injector)



