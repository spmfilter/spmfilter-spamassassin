cmake_minimum_required(VERSION 2.6)

project(spmfilter-spamassassin)

# check for build.properties
include("${CMAKE_SOURCE_DIR}/build.properties" OPTIONAL)

# check prefix
if(PREFIX)
    SET(CMAKE_INSTALL_PREFIX ${PREFIX})
endif(PREFIX)

# check libdir
if(NOT LIBDIR)
        set(LIBDIR "lib")
endif(NOT LIBDIR)

include(FindPkgConfig)

pkg_search_module(SPMFILTER REQUIRED spmfilter >= 0.4)
if(SPMFILTER_FOUND)
    include_directories(${SPMFILTER_INCLUDE_DIRS})
    link_directories(${SPMFILTER_LIBRARY_DIRS})
	set(VERSION_REGEX "0\\.4\\.[0-9]+")
	if(${SPMFILTER_VERSION} MATCHES ${VERSION_REGEX})
		set(HAVE_SPMFILTER04 TRUE)
	endif(${SPMFILTER_VERSION} MATCHES ${VERSION_REGEX})
endif(SPMFILTER_FOUND)

# check for enabled debugging
if(ENABLE_DEBUG)
    set(CMAKE_VERBOSE_MAKEFILE TRUE)
    add_definitions(-DDEBUG -g -O0 -Wall)
endif(ENABLE_DEBUG)

# check for glib2
pkg_search_module(GLIB2 REQUIRED glib-2.0)
if(GLIB2_FOUND)
    include_directories(${GLIB2_INCLUDE_DIRS})
    link_directories(${GLIB2_LIBRARY_DIRS})
endif(GLIB2_FOUND)

# check out current version
file(READ ${CMAKE_CURRENT_SOURCE_DIR}/VERSION PLUGIN_VERSION)

# write config.h
CONFIGURE_FILE(
	${CMAKE_CURRENT_SOURCE_DIR}/src/config.h.cmake
    ${CMAKE_CURRENT_SOURCE_DIR}/src/config.h
)

add_subdirectory(src)

set(CPACK_PACKAGE_NAME "spmfilter-spamassassin")
set(CPACK_PACKAGE_VENDOR "spmfilter.org")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "plugin to spam-check mails with spamassassin (SPAMD)")
set(CPACK_PACKAGE_DESCRIPTION_FILE ${CMAKE_CURRENT_SOURCE_DIR}/README)
set(CPACK_PACKAGE_VERSION ${PLUGIN_VERSION})
set(CPACK_COMPONENTS_ALL applications libraries headers)

set(CPACK_SOURCE_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${PLUGIN_VERSION}")
set(CPACK_SOURCE_GENERATOR TGZ)
set(CPACK_SOURCE_IGNORE_FILES
"\\\\.hg"
"nbproject"
"cmake_build"
"build\\\\.properties"
"spmfilter-spamassassin-Makefile\\\\.mk"
"\\\\.dep\\\\.inc"
)

include(CPack)