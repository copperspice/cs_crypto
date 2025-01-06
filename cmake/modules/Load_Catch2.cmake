# ***********************************************************************
#
# Copyright (c) 2021-2025 Barbara Geller
# Copyright (c) 2021-2025 Ansel Sermersheim
#
# This file is part of CsCrypto.
#
# CsCrypto is free software which is released under the BSD 2-Clause license.
# For license details refer to the LICENSE provided with this project.
#
# CsCrypto is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#
# https://opensource.org/licenses/BSD-2-Clause
#
# ***********************************************************************

find_package(Catch2 QUIET)

set_package_properties(Catch2 PROPERTIES
   PURPOSE "Required for Catch Unit Tests"
   DESCRIPTION "Unit test framework"
   URL "https://github.com/catchorg/Catch2"
   TYPE RECOMMENDED
)

if (NOT TARGET Catch2::Catch2)
   message(STATUS "Catch2 was not found, CsCrypto unit tests will not be built\n")
   return()
endif()
