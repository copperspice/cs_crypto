/***********************************************************************
*
* Copyright (c) 2021-2024 Tim van Deurzen
* Copyright (c) 2021-2024 Barbara Geller
* Copyright (c) 2021-2024 Ansel Sermersheim
*
* This file is part of CsCrypto.
*
* CsCrypto is free software, released under the BSD 2-Clause license.
* For license details refer to LICENSE provided with this project.
*
* CsCrypto is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
*
* https://opensource.org/licenses/BSD-2-Clause
*
***********************************************************************/

#include <catch2/catch.hpp>

#include <util/tools/result.h>

enum class error_values {
   Bad      = 0,
   Worse    = 1,
   Terrible = 2
};

using test_result = cs_crypto::util::result<int, error_values>;

TEST_CASE("A result value can be constructed and queried.", "[result]")
{
   auto value = cs_crypto::util::result<int, error_values>(1);
   REQUIRE(value.is_ok());
   REQUIRE(! value.is_error());
}

TEST_CASE("A result can be created with the different constructors.", "[result]")
{
   auto value = test_result(42);

   REQUIRE(value.is_ok());
   REQUIRE(! value.is_error());
   REQUIRE(value.value() == 42);

   auto value2 = test_result(error_values::Bad);

   REQUIRE(! value2.is_ok());
   REQUIRE(value2.is_error());
   REQUIRE(value2.err() == error_values::Bad);
}
