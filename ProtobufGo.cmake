# Modified from FindProtobuf.cmake.
#
#=============================================================================
# Copyright 2009 Kitware, Inc.
# Copyright 2009-2011 Philip Lowman <philip@yhbt.com>
# Copyright 2008 Esben Mose Hansen, Ange Optimization ApS
#
# Distributed under the OSI-approved BSD License (the "License");
# see accompanying file Copyright.txt for details.
#
# This software is distributed WITHOUT ANY WARRANTY; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See the License for more information.
#=============================================================================

function(PROTOBUF_GENERATE_GO SRCS)
  if(NOT ARGN)
    message(SEND_ERROR "Error: PROTOBUF_GENERATE_GO() called without any proto files")
    return()
  endif()

  SET(options)
  SET(args_single OUTDIR)
  SET(args_multi  SOURCES)
  CMAKE_PARSE_ARGUMENTS(PBGG "${options}" "${args_single}" "${args_multi}" ${ARGN})

  #if(PROTOBUF_GENERATE_CPP_APPEND_PATH)
  #  # Create an include path for each file specified
  #  foreach(FIL ${PBGG_SOURCES})
  #    get_filename_component(ABS_FIL ${FIL} ABSOLUTE)
  #    get_filename_component(ABS_PATH ${ABS_FIL} PATH)
  #    list(FIND _protobuf_include_path ${ABS_PATH} _contains_already)
  #    if(${_contains_already} EQUAL -1)
  #        list(APPEND _protobuf_include_path -I ${ABS_PATH})
  #    endif()
  #  endforeach()
  #else()
  #  set(_protobuf_include_path -I ${CMAKE_CURRENT_SOURCE_DIR})
  #endif()

  if(DEFINED Protobuf_IMPORT_DIRS)
    foreach(DIR ${Protobuf_IMPORT_DIRS})
      get_filename_component(ABS_PATH ${DIR} ABSOLUTE)
      list(FIND _protobuf_include_path ${ABS_PATH} _contains_already)
      if(${_contains_already} EQUAL -1)
          list(APPEND _protobuf_include_path -I ${ABS_PATH})
      endif()
    endforeach()
  endif()

  FILE(MAKE_DIRECTORY ${PBGG_OUTDIR})

  set(${SRCS})
  set(protos)
  foreach(FIL ${PBGG_SOURCES})
    get_filename_component(ABS_FIL ${FIL} ABSOLUTE)
    get_filename_component(FIL_WE ${FIL} NAME_WE)
    get_filename_component(ABS_DIR ${ABS_FIL} PATH)

    list(APPEND ${SRCS} "${PBGG_OUTDIR}/${FIL_WE}.pb.go")
    list(APPEND protos "${ABS_FIL}")
  endforeach()

    add_custom_command(
      OUTPUT ${${SRCS}}
      COMMAND  ${Protobuf_PROTOC_EXECUTABLE}
      ARGS --go_out ${PBGG_OUTDIR} --proto_path ${CMAKE_CURRENT_SOURCE_DIR} ${_protobuf_include_path} ${protos}
      DEPENDS ${protos} ${Protobuf_PROTOC_EXECUTABLE}
      WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
      COMMENT "Running Go protocol buffer compiler on ${FIL}"
      VERBATIM )

  set_source_files_properties(${${SRCS}} PROPERTIES GENERATED TRUE)
  set(${SRCS} ${${SRCS}} PARENT_SCOPE)
endfunction()

