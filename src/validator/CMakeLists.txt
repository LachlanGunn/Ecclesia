ADD_GO_EXECUTABLE(validate main.go)
ADD_DEPENDENCIES(validate directory_library verifier_library)
