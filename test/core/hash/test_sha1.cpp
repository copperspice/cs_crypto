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

#include <core/hash/sha1.h>
#include <drivers/base/traits.h>
#include <drivers/backend/botan/config.h>
#include <drivers/backend/openssl/config.h>
#include <util/conversions/hex.h>
#include <util/tools/crypto_traits.h>

using namespace std::string_literals;
using namespace cs_crypto::traits;
using namespace cs_crypto::drivers;
using namespace cs_crypto::drivers::traits;

TEMPLATE_TEST_CASE("Hash SHA1", "[sha1]",
            enum_to_type<implementation::openssl>, enum_to_type<implementation::botan>)
{
   using TestDriver = typename driver_for<TestType::value>::hash;

   if constexpr (have_driver_v<TestType::value>) {
      using cs_crypto::hash::sha1;

      // Testcases from RFC 3174:
      auto test_data = GENERATE(table<std::string, std::string>(
         {
            { "a9993e364706816aba3e25717850c26c9cd0d89d"s, "abc"s },
            { "84983e441c3bd26ebaae4aa1f95129e5e54670f1"s, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"s },
            { "34aa973cd4c4daa4f61eeb2bdbad27316534016f"s, std::string(1000000, 'a') },
            { "dea356a2cddd90c7a7ecedc5ebb563934f460452"s, "0123456701234567012345670123456701234567012345670123456701234567"
                                                           "0123456701234567012345670123456701234567012345670123456701234567"
                                                           "0123456701234567012345670123456701234567012345670123456701234567"
                                                           "0123456701234567012345670123456701234567012345670123456701234567"
                                                           "0123456701234567012345670123456701234567012345670123456701234567"
                                                           "0123456701234567012345670123456701234567012345670123456701234567"
                                                           "0123456701234567012345670123456701234567012345670123456701234567"
                                                           "0123456701234567012345670123456701234567012345670123456701234567"
                                                           "0123456701234567012345670123456701234567012345670123456701234567"
                                                           "0123456701234567012345670123456701234567012345670123456701234567"s },
         }));

      auto [expected_output, input] = test_data;
      auto output                   = cs_crypto::util::hex(sha1<TestDriver>(input).value());

      REQUIRE(output == expected_output);
   }
}
