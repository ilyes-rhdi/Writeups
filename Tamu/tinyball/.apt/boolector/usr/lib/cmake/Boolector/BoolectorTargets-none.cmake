#----------------------------------------------------------------
# Generated CMake target import file for configuration "None".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "Boolector::boolector" for configuration "None"
set_property(TARGET Boolector::boolector APPEND PROPERTY IMPORTED_CONFIGURATIONS NONE)
set_target_properties(Boolector::boolector PROPERTIES
  IMPORTED_LOCATION_NONE "${_IMPORT_PREFIX}/lib/libboolector.so"
  IMPORTED_SONAME_NONE "libboolector.so"
  )

list(APPEND _cmake_import_check_targets Boolector::boolector )
list(APPEND _cmake_import_check_files_for_Boolector::boolector "${_IMPORT_PREFIX}/lib/libboolector.so" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
