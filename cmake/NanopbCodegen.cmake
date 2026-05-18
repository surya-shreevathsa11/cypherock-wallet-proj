# Pre-generated nanopb sources live in ${CMAKE_SOURCE_DIR}/generated/.
# Regenerate with:
#   python3 -m venv .venv && .venv/bin/pip install grpcio-tools
#   .venv/bin/python third_party/nanopb/generator/nanopb_generator.py \
#     -I proto -fproto/mta.options -D generated proto/mta.proto

function(nanopb_add_library TARGET_NAME)
  set(NANOPB_DIR "${CMAKE_SOURCE_DIR}/third_party/nanopb")
  add_library(${TARGET_NAME} STATIC
    "${CMAKE_SOURCE_DIR}/generated/mta.pb.c"
    "${NANOPB_DIR}/pb_common.c"
    "${NANOPB_DIR}/pb_encode.c"
    "${NANOPB_DIR}/pb_decode.c"
  )
  target_include_directories(${TARGET_NAME} PUBLIC
    "${CMAKE_SOURCE_DIR}/generated"
    "${NANOPB_DIR}"
  )
endfunction()
