cmake_minimum_required(VERSION 3.10)
project(ZeroMQProject)

# Используем find_package для поиска ZeroMQ
find_package(PkgConfig REQUIRED)
pkg_check_modules(ZeroMQ IMPORTED_TARGET libzmq)

if(ZeroMQ_FOUND)
    include_directories(${ZeroMQ_INCLUDE_DIRS})
    set(SOURCE_DIR ${CMAKE_SOURCE_DIR}/tests)
    set(EXECUTABLE_OUTPUT_PATH ${CMAKE_SOURCE_DIR}/src)

    # Компиляция server.c и client.c
    add_executable(server ${SOURCE_DIR}/server.c)
    target_link_libraries(server PkgConfig::ZeroMQ)

    add_executable(client ${SOURCE_DIR}/client.c)
    target_link_libraries(client PkgConfig::ZeroMQ)

    # Запуск server и client
    add_custom_target(run_server
        COMMAND ./server
        DEPENDS server
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src
    )

    add_custom_target(run_client
        COMMAND ./client
        DEPENDS client
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src
    )

    add_custom_target(run_all
        COMMAND ./server &
        COMMAND ./client
        DEPENDS server client
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src
    )
else()
    message(FATAL_ERROR "ZeroMQ not found. Please install it.")
endif()
