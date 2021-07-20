# - Try to find the Botan library
#
# Once done this will define
#
#  BOTAN_FOUND - System has Botan
#  BOTAN_INCLUDE_DIR - The Botan include directory
#  BOTAN_LIBRARIES - The libraries needed to use Botan
#  BOTAN_DEFINITIONS - Compiler switches required for using Botan
#
#  Creates an imported target Botan::Botan
#

if (BOTAN_INCLUDE_DIR AND BOTAN_LIBRARY)
   # in cache already
   set(Botan_FIND_QUIETLY TRUE)
endif (BOTAN_INCLUDE_DIR AND BOTAN_LIBRARY)

if (NOT WIN32)
   # try using pkg-config to get the directories and then use these values
   # in the FIND_PATH() and FIND_LIBRARY() calls
   # also fills in BOTAN_DEFINITIONS, although that isn't normally useful
   find_package(PkgConfig)
   pkg_check_modules(BOTAN QUIET IMPORTED_TARGET botan>=2.0 botan-2>=2.0)
endif (NOT WIN32)

find_path(BOTAN_INCLUDE_DIR botan/botan.h
   HINTS
   "/usr/include/botan"
   ${PC_BOTAN_INCLUDEDIR}
   ${PC_BOTAN_INCLUDE_DIRS}
   PATH_SUFFIXES
   botan-2
   )

find_library(BOTAN_LIBRARY NAMES ${PC_BOTAN_LIBRARIES} botan botan-2
   HINTS
   ${PC_BOTAN_LIBDIR}
   ${PC_BOTAN_LIBRARY_DIRS}
   )

mark_as_advanced(BOTAN_INCLUDE_DIR BOTAN_LIBRARY)

# handle the QUIETLY and REQUIRED arguments and set BOTAN_FOUND to TRUE if
# all listed variables are TRUE
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Botan DEFAULT_MSG BOTAN_LIBRARY BOTAN_INCLUDE_DIR)

if(BOTAN_FOUND)
   set(BOTAN_LIBRARIES    ${BOTAN_LIBRARY})
   set(BOTAN_INCLUDE_DIRS ${BOTAN_INCLUDE_DIR})

   if (NOT TARGET Botan::Botan)
      add_library(Botan::Botan INTERFACE IMPORTED)
      set_target_properties(Botan::Botan PROPERTIES
         INTERFACE_INCLUDE_DIRECTORIES "${BOTAN_INCLUDE_DIRS}"
         INTERFACE_LINK_LIBRARIES "${BOTAN_LIBRARIES}"
         )
   endif()
endif()
