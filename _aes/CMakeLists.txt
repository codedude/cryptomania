cmake_minimum_required(VERSION 3.4)

# set the project name and version
project(Crypto LANGUAGES CXX VERSION 0.1)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()


set(Boost_INCLUDE_DIR /usr/include/boost)
set(Boost_LIBRARY_DIR /usr/lib/x86_64-linux-gnu)
find_package(Boost COMPONENTS system filesystem regex program_options REQUIRED)
include_directories(${Boost_INCLUDE_DIR})
link_directories(${Boost_LIBRARY_DIR})

add_executable(crypto 
src/main.cpp 
src/loadData.cpp
src/types.cpp

src/aes_core.cpp
src/aes_lookups.cpp
src/aes_cipher.cpp
src/aes_mode.cpp
)

target_include_directories(crypto PRIVATE inc)

# specify the C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

target_link_libraries(crypto ${Boost_LIBRARIES})

target_compile_options(crypto PRIVATE
  "-Wall" "-Wextra" "-Wpedantic" "-march=native" "-g"
  "-O2"
  "-Wno-unused" "-Wno-unused-result"
  "-Wshadow"
  "-Wnon-virtual-dtor"
  "-Wcast-qual"
  "-Wconversion-null"
  "-Woverlength-strings"
  "-Wpointer-arith"
  "-Wunused-local-typedefs"
  "-Wvarargs"
  "-Wvla"
  "-Wwrite-strings"
)

target_link_options(crypto PRIVATE
  "-g"
  "-O2"
)

target_compile_definitions(crypto PRIVATE
  "-DDLOG"
)
