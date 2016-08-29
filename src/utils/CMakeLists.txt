ADD_GO_EXECUTABLE(generate_key   generate_key.go)

ADD_GO_EXECUTABLE(read_directory read_directory.go)
ADD_DEPENDENCIES(read_directory protocol_common)
