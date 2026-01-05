/***********************************************************************
*
* Copyright (c) 2021-2026 Tim van Deurzen
* Copyright (c) 2021-2026 Barbara Geller
* Copyright (c) 2021-2026 Ansel Sermersheim
*
* This file is part of CsCrypto.
*
* CsCrypto is free software which is released under the BSD 2-Clause license.
* For license details refer to the LICENSE provided with this project.
*
* CsCrypto is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
*
* https://opensource.org/licenses/BSD-2-Clause
*
***********************************************************************/

#include <catch2/catch.hpp>

#include <core/hash/md5.h>
#include <drivers/base/traits.h>
#include <drivers/backend/botan/config.h>
#include <drivers/backend/openssl/config.h>
#include <util/conversions/hex.h>
#include <util/tools/crypto_traits.h>

using namespace std::string_literals;
using namespace cs_crypto::traits;
using namespace cs_crypto::drivers;
using namespace cs_crypto::drivers::traits;

TEMPLATE_TEST_CASE("Hash MD5", "[md5]",
            enum_to_type<implementation::openssl>, enum_to_type<implementation::botan>)
{
   using TestDriver = typename driver_for<TestType::value>::hash;

   if constexpr (have_driver_v<TestType::value>) {
      using cs_crypto::hash::md5;

      // Testcases from RFC 1321:
      auto test_data = GENERATE(table<std::string, std::string>(
           {
               { "d41d8cd98f00b204e9800998ecf8427e"s, ""s },
               { "0cc175b9c0f1b6a831c399e269772661"s, "a"s },
               { "900150983cd24fb0d6963f7d28e17f72"s, "abc"s },
               { "f96b697d7cb7938d525a2f31aaf161d0"s, "message digest"s },
               { "c3fcd3d76192e4007dfb496cca67e13b"s, "abcdefghijklmnopqrstuvwxyz"s },
               { "d174ab98d277d9f5a5611c2c9f419d9f"s, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"s },
               { "57edf4a22be3c955ac49da2e2107b67a"s, "12345678901234567890123456789012345678901234567890123456789012345678901234567890"s }
           }));

      auto [expected_output, input] = test_data;
      auto output                   = cs_crypto::util::hex(md5<TestDriver>(input).value());

      REQUIRE(output == expected_output);
   }
}
