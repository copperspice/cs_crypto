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

#include <core/hash/md4.h>
#include <drivers/base/traits.h>
#include <drivers/backend/botan/config.h>
#include <drivers/backend/openssl/config.h>
#include <util/conversions/hex.h>
#include <util/tools/crypto_traits.h>

using namespace std::string_literals;
using namespace cs_crypto::traits;
using namespace cs_crypto::drivers;
using namespace cs_crypto::drivers::traits;

TEMPLATE_TEST_CASE("Hash MD4", "[md4]",
            enum_to_type<implementation::openssl>, enum_to_type<implementation::botan>)
{
   using TestDriver = typename driver_for<TestType::value>::hash;

   if constexpr (have_driver_v<TestType::value>) {
      using cs_crypto::hash::md4;

      // Testcases from RFC 1321:
      auto test_data = GENERATE(table<std::string, std::string>(
        {
            { "31d6cfe0d16ae931b73c59d7e0c089c0"s, ""s },
            { "bde52cb31de33e46245e05fbdbd6fb24"s, "a"s },
            { "a448017aaf21d8525fc10ae87aa6729d"s, "abc"s },
            { "d9130a8164549fe818874806e1c7014b"s, "message digest"s },
            { "d79e1c308aa5bbcdeea8ed63df412da9"s, "abcdefghijklmnopqrstuvwxyz"s },
            { "043f8582f241db351ce627e153e7f0e4"s, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"s },
            { "e33b4ddc9c38f2199c3e7b164fcc0536"s, "12345678901234567890123456789012345678901234567890123456789012345678901234567890"s }
        }));

      auto [expected_output, input] = test_data;
      auto output                   = cs_crypto::util::hex(md4<TestDriver>(input).value());

      REQUIRE(output == expected_output);
   }
}
