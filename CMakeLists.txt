cmake_minimum_required(VERSION 3.20)

if(POLICY CMP0091)
    cmake_policy(SET CMP0091 NEW)
endif()

project(BMTX LANGUAGES C CXX RC)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Link the MSVC runtime statically so the installer does not need to deploy
# a separate Visual C++ Redistributable package on the target machine.
if(MSVC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

find_program(MIDL_EXECUTABLE midl REQUIRED)

set(RPC_IDL ${CMAKE_CURRENT_SOURCE_DIR}/rpc/bmtx_rpc.idl)
set(RPC_GENERATED_DIR ${CMAKE_CURRENT_BINARY_DIR}/generated)
set(RPC_HEADER ${RPC_GENERATED_DIR}/bmtx_rpc.h)
set(RPC_CLIENT_STUB ${RPC_GENERATED_DIR}/bmtx_rpc_c.c)
set(RPC_SERVER_STUB ${RPC_GENERATED_DIR}/bmtx_rpc_s.c)

file(MAKE_DIRECTORY ${RPC_GENERATED_DIR})
execute_process(
    COMMAND ${MIDL_EXECUTABLE}
            /nologo
            /env x64
            /char signed
            /target NT60
            /h bmtx_rpc.h
            /client stub
            /server stub
            /out ${RPC_GENERATED_DIR}
            ${RPC_IDL}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    RESULT_VARIABLE MIDL_RESULT
    OUTPUT_VARIABLE MIDL_OUTPUT
    ERROR_VARIABLE MIDL_ERROR
)

if(NOT MIDL_RESULT EQUAL 0)
    message(FATAL_ERROR "MIDL failed with code ${MIDL_RESULT}\n${MIDL_OUTPUT}\n${MIDL_ERROR}")
endif()

add_executable(BMTX WIN32
    src/main.cpp
    src/rpc_memory.cpp
    ${RPC_CLIENT_STUB}
    src/app.rc
)

target_include_directories(BMTX PRIVATE
    ${RPC_GENERATED_DIR}
    src
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
    advapi32
    rpcrt4
    comdlg32
    ole32
)

add_executable(BMTXService WIN32
    src/service.cpp
    src/rpc_memory.cpp
    ${RPC_SERVER_STUB}
)

target_include_directories(BMTXService PRIVATE
    ${RPC_GENERATED_DIR}
    src
)

target_compile_definitions(BMTXService PRIVATE
    UNICODE
    _UNICODE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)

target_link_libraries(BMTXService PRIVATE
    advapi32
    rpcrt4
    wtsapi32
    userenv
    winhttp
    shlwapi
    bcrypt
)

if(MSVC)
    target_compile_options(BMTX PRIVATE /W4 /permissive- /utf-8 /EHa)
    target_compile_options(BMTXService PRIVATE /W4 /permissive- /utf-8 /EHa)
endif()

install(TARGETS BMTX BMTXService RUNTIME DESTINATION .)
install(FILES assets/bmtx.ico DESTINATION assets)
install(FILES README_AVDB_TASK.txt README_INSTALLER_TASK.txt DESTINATION .)

install(FILES avdb/bmtx_avdb.bin avdb/bmtx_avdb.bak DESTINATION avdb)


add_custom_target(copy_avdb_to_runtime ALL
    COMMAND ${CMAKE_COMMAND} -E make_directory "$<TARGET_FILE_DIR:BMTXService>/avdb"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different "${CMAKE_CURRENT_SOURCE_DIR}/avdb/bmtx_avdb.bin" "$<TARGET_FILE_DIR:BMTXService>/avdb/bmtx_avdb.bin"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different "${CMAKE_CURRENT_SOURCE_DIR}/avdb/bmtx_avdb.bak" "$<TARGET_FILE_DIR:BMTXService>/avdb/bmtx_avdb.bak"
    DEPENDS BMTXService
)


# Installer support. The GitHub Actions workflow installs NSIS and invokes this
# target after building Release binaries. It creates a single Windows installer
# that installs the client, service, resources, default AV databases, and
# registers the Windows service for automatic startup.
find_program(MAKENSIS_EXECUTABLE makensis)
if(MAKENSIS_EXECUTABLE)
    add_custom_target(BMTXInstaller
        COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_CURRENT_BINARY_DIR}/installer"
        COMMAND "${MAKENSIS_EXECUTABLE}"
            /DAPP_BUILD_DIR="$<TARGET_FILE_DIR:BMTX>"
            /DPROJECT_DIR="${CMAKE_CURRENT_SOURCE_DIR}"
            /DOUT_DIR="${CMAKE_CURRENT_BINARY_DIR}/installer"
            "${CMAKE_CURRENT_SOURCE_DIR}/installer/BMTXInstaller.nsi"
        DEPENDS BMTX BMTXService copy_avdb_to_runtime
        BYPRODUCTS "${CMAKE_CURRENT_BINARY_DIR}/installer/BMTXSetup.exe"
        COMMENT "Building BMTX NSIS installer"
    )
endif()
