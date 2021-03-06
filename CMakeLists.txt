# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 IBM Corp.
cmake_minimum_required( VERSION 3.12 )
project( secvarctl C )

set( CMAKE_C_COMPILER gcc )
#sources/dependencies for secvarctl
set( DEPEN secvarctl.h prlog.h err.h generic.h )
set( DEPDIR include/ )
list( TRANSFORM DEPEN PREPEND ${DEPDIR} )
set( SRC secvarctl.c generic.c )

# for generic edk2-inspired secvar operations
# - things that don't touch the in-firmware variables themselves
set( SECVARDEPEN edk2-svc.h )
set( SECVARDEPDIR backends/powernv/include/ )
list( TRANSFORM SECVARDEPEN PREPEND ${SECVARDEPDIR} )
set ( SECVARSRC edk2-svc-validate.c edk2-svc-generate.c util.c )
set ( SECVARSRCDIR secvar/ )
list( TRANSFORM SECVARSRC PREPEND ${SECVARSRCDIR} )
list( APPEND DEPEN ${SECVARDEPEN} )
list( APPEND SRC ${SECVARSRC} )


#sources/dependencies for edk2 backend
set( EDK2DEPEN edk2-svc.h )
set( EDK2DEPDIR backends/powernv/include/ )
list( TRANSFORM EDK2DEPEN PREPEND ${EDK2DEPDIR} )
set ( EDK2SRC edk2-svc-read.c edk2-svc-write.c edk2-svc-verify.c )
set ( EDK2SRCDIR backends/powernv/ )
list( TRANSFORM EDK2SRC PREPEND ${EDK2SRCDIR} )
list( APPEND DEPEN ${EDK2DEPEN} )
list( APPEND SRC ${EDK2SRC} )

#sources/dependencies for efivarfs backend
set( EVFSDEPEN efivarfs.h )
set( EVFSDEPDIR backends/efivarfs/include/ )
list( TRANSFORM EVFSDEPEN PREPEND ${EVFSDEPDIR} )
set ( EVFSSRC efivarfs-read.c )
set ( EVFSSRCDIR backends/efivarfs/ )
list( TRANSFORM EVFSSRC PREPEND ${EVFSSRCDIR} )
list( APPEND DEPEN ${EVFSDEPEN} )
list( APPEND SRC ${EVFSSRC} )


#sources/dependencies for borrowed skiboot code
set( SKIBOOTDEPEN list.h config.h container_of.h check_type.h secvar.h opal-api.h endian.h short_types.h edk2.h edk2-compat-process.h )
set( SKIBOOTDEPDIR external/skiboot/include/ )
list( TRANSFORM SKIBOOTDEPEN PREPEND ${SKIBOOTDEPDIR} )
set ( SKIBOOTSRC secvar_util.c edk2-compat.c edk2-compat-process.c )
set ( SKIBOOTSRCDIR external/skiboot/ )
list( TRANSFORM SKIBOOTSRC PREPEND ${SKIBOOTSRCDIR} )
list( APPEND DEPEN ${SKIBOOTDEPEN} )
list( APPEND SRC ${SKIBOOTSRC} )

#sources/dependencies for extra mbedtls functions
set( EXTRAMBEDTLSDEP generate-pkcs7.h pkcs7.h )
set( EXTRAMBEDTLSDEPDIR external/extraMbedtls/include/ )
list( TRANSFORM EXTRAMBEDTLSDEP PREPEND ${EXTRAMBEDTLSDEPDIR} )
set ( EXTRAMBEDTLSSRC generate-pkcs7.c pkcs7.c )
set ( EXTRAMBEDTLSSRCDIR  external/extraMbedtls/ )
list( TRANSFORM EXTRAMBEDTLSSRC PREPEND ${EXTRAMBEDTLSSRCDIR} )
list( APPEND DEPEN ${EXTRAMBEDTLSDEP} )
list( APPEND SRC ${EXTRAMBEDTLSSRC} )

# include paths:
#  - include/
#  - the root directory so that we can e.g. #include "{external,backends}/..."
include_directories(include .)

add_executable( secvarctl ${SRC} )


#User specified options 
option( STATIC "Create statically linked executable" OFF )
if ( STATIC )
  set( BUILD_SHARED_LIBRARIES OFF )
  set( CMAKE_EXE_LINKER_FLAGS "-static" )
  set( PTHREAD "pthread" )
endif(  )

#Strip resulting executable for minimal size
option( STRIP "Strip executable of extra data for minimal size" OFF )
if ( STRIP )
  set( BUILD_SHARED_LIBRARIES OFF )
  string( APPEND CMAKE_C_FLAGS "-s" )
endif(  )

#no crypto means don't compile the generate command = smaller executable
option( NO_CRYPTO "Build without crypto functions for smaller executable, some functionality lost" OFF )
if ( NO_CRYPTO )
  target_compile_definitions( secvarctl PRIVATE  NO_CRYPTO )
endif(  )

#append possible extensions for library
LIST( APPEND CMAKE_FIND_LIBRARY_SUFFIXES ".so.0" ".a" ".so" )

#get mbedtls if custom path defined
if ( DEFINED CUSTOM_MBEDTLS )
    find_library( MBEDX509 mbedx509 PATHS ${CUSTOM_MBEDTLS}/library NO_DEFAULT_PATH REQUIRED )
    find_library( MBEDCRYPTO mbedcrypto PATHS ${CUSTOM_MBEDTLS}/library NO_DEFAULT_PATH REQUIRED )
    find_library( MBEDTLS mbedtls PATHS ${CUSTOM_MBEDTLS}/library NO_DEFAULT_PATH REQUIRED )
    include_directories( ${CUSTOM_MBEDTLS}/include )
 
else(  )
    find_library( MBEDX509 mbedx509 HINTS ENV PATH REQUIRED )
    find_library( MBEDCRYPTO mbedcrypto HINTS ENV PATH REQUIRED )
    find_library( MBEDTLS mbedtls HINTS ENV PATH REQUIRED )
endif (  )
target_link_libraries( secvarctl ${MBEDTLS} ${MBEDX509} ${MBEDCRYPTO} ${PTHREAD} ) 

#set default build type to release
set( DEFAULT_BUILD_TYPE "Release" )
if ( NOT CMAKE_BUILD_TYPE )
  set( CMAKE_BUILD_TYPE ${DEFAULT_BUILD_TYPE} )
    message( "Setting build type to default: " ${CMAKE_BUILD_TYPE} )
endif(  )
#allow for different optimizations here
set( CMAKE_C_FLAGS_RELEASE     "-O2 -g" )
set( CMAKE_C_FLAGS_DEBUG       "-O0 -g3" )
set( CMAKE_C_FLAGS_COVERAGE    "-O0 -g3 -fprofile-arcs -ftest-coverage" )


target_compile_options( secvarctl PRIVATE -Wall -Werror )



#set c standard
set( CMAKE_C_STANDARD 99 )
set( CMAKE_C_STANDARD_REQUIRED ON )

install( FILES ${CMAKE_CURRENT_SOURCE_DIR}/secvarctl.1 DESTINATION ${CMAKE_INSTALL_PREFIX}/share/man/man1 )
install( TARGETS secvarctl DESTINATION bin )
