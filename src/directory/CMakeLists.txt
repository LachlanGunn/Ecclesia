ADD_GO_EXECUTABLE(directory main.go) # "${PROJECT_PROTOBUF_PATH}/commitreveal.pb.go")
ADD_DEPENDENCIES(directory protobufs protocol_common)
