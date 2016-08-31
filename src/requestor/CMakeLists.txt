ADD_GO_LIBRARY(directory_library directory/directory.go)

ADD_GO_EXECUTABLE(requestor main.go)
ADD_DEPENDENCIES(requestor directory_library protobufs)
