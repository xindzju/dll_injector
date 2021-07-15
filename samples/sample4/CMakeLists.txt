cmake_minimum_required(VERSION 3.10)
set(TARGET_NAME sample4)

file(GLOB EXAMPLE_SRCS ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp ${CMAKE_CURRENT_SOURCE_DIR}/*.h)

include_directories(../dll_injector/include)

add_executable(${TARGET_NAME} ${EXAMPLE_SRCS})
target_link_libraries(${TARGET_NAME} dll_injector)
set_target_properties(${TARGET_NAME} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/$<CONFIG> FOLDER "samples")