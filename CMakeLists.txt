cmake_minimum_required(VERSION 3.10)
set(TARGET_NAME dll_injector)
project(${TARGET_NAME} LANGUAGES C CXX)
set(CMAKE_CXX_STANDARD 17)

file(GLOB LIB_INJECTOR_SRCS ${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp ${CMAKE_CURRENT_SOURCE_DIR}/include/*.h)

include_directories(./include)

add_library(${TARGET_NAME} STATIC ${LIB_INJECTOR_SRCS})
