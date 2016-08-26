PROTOBUF_GENERATE_GO(commitreveal_SRCS
  OUTDIR ${PROJECT_PROTOBUF_PATH}
  SOURCES commitreveal.proto generic.proto)

ADD_CUSTOM_TARGET(protobufs ALL DEPENDS ${commitreveal_SRCS})
