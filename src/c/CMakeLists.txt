cmake_minimum_required(VERSION 3.28)
project(autonomous_trust C)

set(CMAKE_C_STANDARD 11)

add_library(autonomous_trust STATIC autonomous_trust.c
        config/configuration.c
        config/configuration.h
        structures/redblack.c
        structures/redblack.h
        structures/merkle.c
        structures/merkle.h
        structures/array.c
        structures/array.h
        )

add_executable(rb_test test/rb_test.c)
target_link_libraries(rb_test PRIVATE autonomous_trust)
add_executable(array_test test/array_test.c)
target_link_libraries(array_test PRIVATE autonomous_trust)

# enable testing functionality
enable_testing()

# define tests
add_test(NAME rb_test COMMAND $<TARGET_FILE:rb_test>)
add_test(NAME array_test COMMAND $<TARGET_FILE:array_test>)
