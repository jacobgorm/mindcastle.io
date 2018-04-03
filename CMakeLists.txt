cmake_minimum_required(VERSION 3.4)

set(CMAKE_C_FLAGS "-Wall -Werror -Ofast -Wfatal-errors -Wno-unused-result -g")

#set (SANITIZE 1)
if (SANITIZE)
set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address -fno-omit-frame-pointer")
endif()

include_directories(
    "${CMAKE_SOURCE_DIR}"
)

add_library(swap SHARED
    block-swap.c
    aio.c
    ioh.c
    block-swap/dubtree.c
    block-swap/hashtable.c
    block-swap/simpletree.c
    block-swap/cbf.c
    )

install(TARGETS swap
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib)

add_executable(oneroot nbd.c)
target_link_libraries(oneroot swap -lb2 -lpthread -llz4 -luuid -lcurl)
install(TARGETS oneroot DESTINATION bin)
