cmake_minimum_required(VERSION 3.20)

project(BMTX LANGUAGES CXX RC)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(BMTX WIN32
    src/main.cpp
    src/app.rc
)

target_compile_definitions(BMTX PRIVATE
    UNICODE
    _UNICODE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)

target_link_libraries(BMTX PRIVATE
    user32
    shell32
    gdi32
)

if(MSVC)
    target_compile_options(BMTX PRIVATE /W4 /permissive- /utf-8)
endif()

install(TARGETS BMTX RUNTIME DESTINATION .)
