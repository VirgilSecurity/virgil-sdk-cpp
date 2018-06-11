#
# Copyright (C) 2015-2018 Virgil Security Inc.
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#     (1) Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#
#     (2) Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#
#     (3) Neither the name of the copyright holder nor the names of its
#     contributors may be used to endorse or promote products derived from
#     this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
# Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
#

#
# Make possible to create and install restless cmake configuration files
#

cmake_minimum_required (VERSION 3.2 FATAL_ERROR)

# Redefine project name to be equal to the target name
project (${RESTLESS_LIBRARIES} VERSION 0.3.0 LANGUAGES CXX)

# Define install directoies names
set (INSTALL_LIB_DIR_NAME "lib" CACHE STRING "Name of the directory where libraries will be installed")
set (INSTALL_BIN_DIR_NAME "bin" CACHE STRING "Name of the directory where binaries will be installed")
set (INSTALL_CFG_DIR_NAME
    "${INSTALL_LIB_DIR_NAME}/cmake/${PROJECT_NAME}" CACHE STRING
    "Path to the CMake configuration files be installed"
)

# Build shared library if defined
set (BUILD_SHARED_LIBS OFF CACHE BOOL "Force to create shared libraries")

# Build target
aux_source_directory ("${CMAKE_CURRENT_SOURCE_DIR}" SRC_FILES)

add_library (${RESTLESS_LIBRARIES} ${SRC_FILES})
target_include_directories (${RESTLESS_LIBRARIES}
    PUBLIC "$<BUILD_INTERFACE:${RESTLESS_INCLUDE_DIRS}>"
    PRIVATE "$<BUILD_INTERFACE:${CURL_INCLUDE_DIRS}>"
)
target_link_libraries(${RESTLESS_LIBRARIES} ${CURL_LIBRARIES})
if (BUILD_SHARED_LIBS)
    set_target_properties (${RESTLESS_LIBRARIES} PROPERTIES
        VERSION ${${PROJECT_NAME}_VERSION} SOVERSION ${${PROJECT_NAME}_VERSION_MAJOR}
    )
endif ()

# Define configuration paths
set (generated_dir "${CMAKE_CURRENT_BINARY_DIR}/generated")
set (version_config "${generated_dir}/${PROJECT_NAME}-config-version.cmake")
set (project_config "${generated_dir}/${PROJECT_NAME}-config.cmake")
set (targets_export_name "${PROJECT_NAME}-targets")
set (namespace "asoni::")

# Create configuration files
include (CMakePackageConfigHelpers)

# Write Version Config
write_basic_package_version_file (
    "${version_config}" COMPATIBILITY SameMajorVersion
)

# Write  Project Config
configure_package_config_file (
    "cmake/config.cmake.in"
    "${project_config}"
    INSTALL_DESTINATION "${INSTALL_CFG_DIR_NAME}"
)

# Install targets
install (TARGETS ${PROJECT_NAME}
    EXPORT "${targets_export_name}"
    LIBRARY DESTINATION "${INSTALL_LIB_DIR_NAME}"
    ARCHIVE DESTINATION "${INSTALL_LIB_DIR_NAME}"
    RUNTIME DESTINATION "${INSTALL_BIN_DIR_NAME}"
)

# Install headers
install (DIRECTORY "${RESTLESS_INCLUDE_DIRS}/" DESTINATION "include/${PROJECT_NAME}")

# Install configurations
install (
    FILES "${project_config}" "${version_config}"
    DESTINATION "${INSTALL_CFG_DIR_NAME}"
)

install (
    EXPORT "${targets_export_name}"
    NAMESPACE "${namespace}"
    DESTINATION "${INSTALL_CFG_DIR_NAME}"
)
