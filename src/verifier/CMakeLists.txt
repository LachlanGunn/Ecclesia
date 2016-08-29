ADD_GO_LIBRARY(verifier_library registration/register.go)

ADD_GO_EXECUTABLE(verifier verifier.go)
ADD_DEPENDENCIES(verifier verifier_library)
