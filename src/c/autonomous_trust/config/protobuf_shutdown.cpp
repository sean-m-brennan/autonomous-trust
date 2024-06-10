#include "google/protobuf/message_lite.h"
#include "protobuf_shutdown.h"

void shutdown_protobuf_library() {
    google::protobuf::ShutdownProtobufLibrary();
}
