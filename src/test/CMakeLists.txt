ADD_GO_EXECUTABLE(write_structure write_structure.go)
ADD_DEPENDENCIES(write_structure protobufs)

ADD_GO_EXECUTABLE(generate_commitment generate_commitment.go)
ADD_DEPENDENCIES(write_structure protobufs)

ADD_GO_EXECUTABLE(tls_test_server tls_test_server.go)

ADD_CUSTOM_COMMAND(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/test.sh
  COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/test.sh  ${CMAKE_CURRENT_BINARY_DIR}/test.sh
  DEPENDS test.sh
  VERBATIM
)

ADD_CUSTOM_TARGET(test_scripts ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/test.sh)
