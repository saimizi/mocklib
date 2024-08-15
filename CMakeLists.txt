set(MOCK_LIB_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/libc_mock.c)

if(ENABLE_NL_MOCK)
  include(FindPkgConfig)
  pkg_check_modules(LIBNL_GENL REQUIRED libnl-genl-3.0)

  set(MOCK_LIB_SOURCES ${MOCK_LIB_SOURCES}
                       ${CMAKE_CURRENT_SOURCE_DIR}/nl_mock.c)
endif()

add_library(mock STATIC ${MOCK_LIB_SOURCES})
target_include_directories(
  mock PUBLIC ${PROJECT_SOURCE_DIR}/lib ${PROJECT_SOURCE_DIR}/driver
              ${LIBNL_GENL_INCLUDE_DIRS})
target_link_libraries(mock cmocka)

# Reconfigure to set WRAP_SYMBOLES if mock library sources are changed.
set_property(
  DIRECTORY
  APPEND
  PROPERTY CMAKE_CONFIGURE_DEPENDS ${MOCK_LIB_SOURCES})

execute_process(COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/scripts/get_mocks.sh
                        ${MOCK_LIB_SOURCES} OUTPUT_VARIABLE WRAP_SYMBOLES)

# Create interface library for linking mock_lib
add_library(wrap_symbols INTERFACE)
target_link_libraries(wrap_symbols INTERFACE mock ${LIBNL_GENL_LIBRARIES})
target_link_options(wrap_symbols INTERFACE "-Wl,${WRAP_SYMBOLES}")
