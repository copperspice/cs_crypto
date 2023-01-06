/***********************************************************************
*
* Copyright (c) 2021-2023 Tim van Deurzen
* Copyright (c) 2021-2023 Barbara Geller
* Copyright (c) 2021-2023 Ansel Sermersheim
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

#include <core/cipher/sym_init_vector.h>

#include <cstddef>
#include <type_traits>

using namespace std::string_literals;

TEMPLATE_TEST_CASE("init_vector construct_a", "[init_vector]", char, unsigned char, std::byte)
{
   TestType key_data[16];
   cs_crypto::cipher::init_vector<16> key = cs_crypto::cipher::init_vector<16>(key_data);

   REQUIRE(key.size() == 16);
}

TEST_CASE("init_vector construct_b", "[init_vector]")
{
   SECTION("valid input init_vector data")
   {
      std::optional<cs_crypto::cipher::init_vector<16>> key = cs_crypto::cipher::init_vector<16>::from_string("xxxxxxxxxxxxxxxx"s);
      REQUIRE(key.has_value());
   }

   SECTION("invalid input nonce data")
   {
      std::optional<cs_crypto::cipher::init_vector<16>> key = cs_crypto::cipher::init_vector<16>::from_string(""s);
      REQUIRE(! key.has_value());
   }
}

TEST_CASE("init_vector move-only", "[init_vector]")
{
   using test_type = typename cs_crypto::cipher::init_vector<16>;

   STATIC_REQUIRE(std::is_move_assignable_v<test_type>);
   STATIC_REQUIRE(std::is_move_constructible_v<test_type>);
   STATIC_REQUIRE(std::is_nothrow_move_assignable_v<test_type>);
   STATIC_REQUIRE(std::is_nothrow_move_constructible_v<test_type>);

   STATIC_REQUIRE_FALSE(std::is_copy_assignable_v<test_type>);
   STATIC_REQUIRE_FALSE(std::is_copy_constructible_v<test_type>);
   STATIC_REQUIRE_FALSE(std::is_nothrow_copy_assignable_v<test_type>);
   STATIC_REQUIRE_FALSE(std::is_nothrow_copy_constructible_v<test_type>);
}
