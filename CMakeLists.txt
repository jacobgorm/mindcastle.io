cmake_minimum_required(VERSION 3.4)

set(CMAKE_C_FLAGS "-Wall -Werror -Ofast -Wfatal-errors -Wno-unused-result -g")

#set (SANITIZE 1)
if (SANITIZE)
set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address -fno-omit-frame-pointer")
endif()

include_directories(
    "${CMAKE_SOURCE_DIR}"
)

add_executable(oneroot
    block-swap.c
    nbd.c
    aio.c
    ioh.c
    block-swap/dubtree.c
    block-swap/hashtable.c
    block-swap/simpletree.c
    block-swap/cbf.c
    )

target_link_libraries(oneroot -lb2 -lpthread -llz4 -luuid -lcurl)
