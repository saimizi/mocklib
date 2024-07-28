set(MOCK_LIB_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/libc_mock.c)

add_library(mock_lib SHARED ${MOCK_LIB_SOURCES})
target_include_directories(mock_lib PUBLIC ${PROJECT_SOURCE_DIR}/lib
                                           ${PROJECT_SOURCE_DIR}/driver)
target_link_libraries(mock_lib cmocka)

# Reconfigure to set WRAP_SYMBOLES if mock library sources are changed.
set_property(
  DIRECTORY
  APPEND
  PROPERTY CMAKE_CONFIGURE_DEPENDS ${MOCK_LIB_SOURCES})

execute_process(COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/scripts/get_mocks.sh
                        ${MOCK_LIB_SOURCES} OUTPUT_VARIABLE WRAP_SYMBOLES)

# Create interface library for linking mock_lib
add_library(wrap_symbols INTERFACE)
target_link_libraries(wrap_symbols INTERFACE mock_lib)
target_link_options(wrap_symbols INTERFACE "-Wl,${WRAP_SYMBOLES}")

