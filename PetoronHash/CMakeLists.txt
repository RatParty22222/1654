cmake_minimum_required(VERSION 3.16)
project(petoron_hash LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

add_library(petoron_hash
    src/hash.cpp
    src/util.cpp
    src/phash.cpp
)
target_include_directories(petoron_hash PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

add_executable(demo examples/demo.cpp)
target_link_libraries(demo PRIVATE petoron_hash)
target_include_directories(demo PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

add_executable(kat tests/kat.cpp)
target_link_libraries(kat PRIVATE petoron_hash)
target_include_directories(kat PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

option(PETORON_WARN "Enable warnings" ON)
option(PETORON_LTO  "Enable interprocedural optimization (LTO)" ON)

if (PETORON_WARN)
  if (MSVC)
    target_compile_options(petoron_hash PRIVATE /W4)
    target_compile_options(demo          PRIVATE /W4)
    target_compile_options(kat           PRIVATE /W4)
  else()
    target_compile_options(petoron_hash PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion)
    target_compile_options(demo          PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion)
    target_compile_options(kat           PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion)
  endif()
endif()

if (PETORON_LTO)
  include(CheckIPOSupported)
  check_ipo_supported(RESULT lto_ok OUTPUT lto_msg)
  if (lto_ok)
    set_property(TARGET petoron_hash PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)
    set_property(TARGET demo          PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)
    set_property(TARGET kat           PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)
  endif()
endif()

include(GNUInstallDirs)
install(TARGETS petoron_hash demo kat
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)


