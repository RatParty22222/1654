cmake_minimum_required(VERSION 3.16)
project(1654 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

add_subdirectory(PetoronHash)

add_executable(1654
  main.cpp

  core/index.cpp
  core/vault_reader.cpp
  core/vault_writer.cpp
  core/vault_update.cpp
  core/vault_transfer.cpp
  core/object_crypto.cpp
  core/pass.cpp

  modes/encrypt.cpp
  modes/decrypt.cpp
  modes/view.cpp
  modes/extract.cpp
  modes/add.cpp
  modes/delete.cpp
  modes/edit.cpp
  modes/stealth_plus.cpp
  modes/stealth_minus.cpp
  modes/transfer.cpp
)

target_include_directories(1654 PRIVATE
  .
  core
  modes
  PetoronHash/include
)

if (TARGET petoron_hash)
  target_link_libraries(1654 PRIVATE petoron_hash)
elseif (TARGET PetoronHash)
  target_link_libraries(1654 PRIVATE PetoronHash)
elseif (TARGET PetoronHash::PetoronHash)
  target_link_libraries(1654 PRIVATE PetoronHash::PetoronHash)
elseif (TARGET petoronhash)
  target_link_libraries(1654 PRIVATE petoronhash)
elseif (TARGET petoron::hash)
  target_link_libraries(1654 PRIVATE petoron::hash)
else()
  message(FATAL_ERROR "PetoronHash library target not found in PetoronHash/CMakeLists.txt")
endif()

if (MSVC)
  target_compile_options(1654 PRIVATE /W4)
else()
  target_compile_options(1654 PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_executable(1654_selftest
  selftest.cpp
  core/index.cpp
  core/vault_reader.cpp
)

target_include_directories(1654_selftest PRIVATE
  .
  core
  modes
  PetoronHash/include
)

target_link_libraries(1654_selftest PRIVATE petoron_hash)

