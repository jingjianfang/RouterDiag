set(ROOT "${CMAKE_CURRENT_LIST_DIR}/..")
file(READ "${ROOT}/diagnostic/FieldDiagnosticController.h" FDH)

function(req text needle msg)
  string(FIND "${text}" "${needle}" pos)
  if(pos EQUAL -1)
    message(FATAL_ERROR "${msg}: missing [${needle}]")
  endif()
endfunction()

# FieldDiagnosticConfig stores EndpointRole and uses EndpointRole enumerators in
# default member initializers. The defining header must therefore be included
# directly rather than relying on an unrelated transitive include.
req("${FDH}" "#include \"DiagnosticTypes.h\"" "FieldDiagnosticController.h must directly include EndpointRole definition")
req("${FDH}" "EndpointRole masterRole = EndpointRole::Client;" "master role default must remain client")
req("${FDH}" "EndpointRole terminalRole = EndpointRole::Server;" "terminal role default must remain server")

message(STATUS "Batch28 compile header dependency contract passed")
