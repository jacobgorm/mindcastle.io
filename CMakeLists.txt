cmake_minimum_required(VERSION 3.4)

project("oneroot" C)
find_package(CURL)
find_package(OpenSSL)

set(CMAKE_C_FLAGS "-Wall -Werror -Ofast -Wfatal-errors -Wno-unused-result -g")

#set (SANITIZE 1)
if (SANITIZE)
set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address -fno-omit-frame-pointer")
endif()

include_directories(
    "${CMAKE_SOURCE_DIR}"
)

add_library(swap
    block-swap.c
    aio.c
    ioh.c
    block-swap/crypto.c
    block-swap/dubtree.c
    block-swap/hashtable.c
    block-swap/simpletree.c
    )

install(TARGETS swap
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib)

add_executable(oneroot nbd.c)
target_link_libraries(oneroot swap -lpthread -llz4 -luuid ${OPENSSL_LIBRARIES} ${CURL_LIBRARIES})

add_executable(img-test img-test.c mt19937-64.c)
target_link_libraries(img-test swap -lpthread -llz4 -luuid ${OPENSSL_LIBRARIES} ${CURL_LIBRARIES})

add_executable(img-fsck img-fsck.c)
target_link_libraries(img-fsck swap -lpthread -llz4 -luuid ${OPENSSL_LIBRARIES} ${CURL_LIBRARIES})

install(TARGETS oneroot img-fsck img-test DESTINATION bin)
