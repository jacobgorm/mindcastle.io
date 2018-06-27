cmake_minimum_required(VERSION 3.4)

project("oneroot" C)

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
    block-swap/crypto.c
    block-swap/dubtree.c
    block-swap/hashtable.c
    block-swap/simpletree.c
    block-swap/cbf.c
    )

install(TARGETS swap
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib)

add_executable(oneroot nbd.c)
target_link_libraries(oneroot swap -lpthread -llz4 -luuid -lssl -lcurl)

add_executable(img-test img-test.c mt19937-64.c)
target_link_libraries(img-test swap -lpthread -llz4 -luuid -lssl -lcurl)

install(TARGETS oneroot DESTINATION bin)
