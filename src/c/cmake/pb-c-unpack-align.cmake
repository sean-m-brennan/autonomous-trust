# Rewrite protoc-c's generated <message>__unpack() casts to go through void *.
#
# Usage: cmake -DPB_C_SRC=<file.pb-c.c> -P pb-c-unpack-align.cmake
#
# protobuf_c_message_unpack() returns a ProtobufCMessage *, which is 4-byte
# aligned on 32-bit SPARC, and the generated code casts it straight to the
# message struct. A message with an int64/double field needs 8, so
# -Wcast-align (an error under -Werror) rejects the cast. The pointer is
# allocated by the ProtobufCAllocator (malloc), so it is always suitably
# aligned and the cast is sound; going through void * says so to the
# compiler. Every unpack is rewritten, not just the warning ones, so a field
# added later cannot reintroduce the error.

if(NOT PB_C_SRC)
    message(FATAL_ERROR "pb-c-unpack-align.cmake: PB_C_SRC not set")
endif()

file(READ ${PB_C_SRC} _src)
string(REGEX REPLACE
    "return \\(([A-Za-z0-9_]+) \\*\\)\n( +)protobuf_c_message_unpack"
    "return (\\1 *)(void *)\n\\2protobuf_c_message_unpack"
    _out "${_src}")
if(NOT _out STREQUAL _src)
    file(WRITE ${PB_C_SRC} "${_out}")
endif()
