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

#ifndef CS_CRYPTO_UTIL_HEX_H
#define CS_CRYPTO_UTIL_HEX_H

#include <util/conversions/byte.h>
#include <util/tools/crypto_traits.h>

#include <cstddef>
#include <iterator>
#include <string>

namespace cs_crypto::util {

struct hex_byte {
   char high;
   char low;
};

constexpr hex_byte to_hex_char(const unsigned char value) noexcept
{
   constexpr char const chars[] = "0123456789abcdef";
   return {chars[value >> 4], chars[value & 0x0f]};
}

constexpr hex_byte to_hex_char(const std::byte value) noexcept
{
   return to_hex_char(std::to_integer<unsigned char>(value));
}

template <typename Iter, typename Sentinel>
std::string hex(Iter iter, const Sentinel last)
{
   std::string result;

   const auto distance = std::distance(iter, last);
   result.reserve(distance * 2);

   while (iter != last) {
      auto [high, low] = to_hex_char(*iter);
      result.push_back(high);
      result.push_back(low);
      iter = std::next(iter);
   }

   return result;
}

template <typename Range, typename = std::enable_if_t<cs_crypto::traits::is_iterable_v<Range>>>
std::string hex(Range &&input)
{
   return hex(std::begin(input), std::end(input));
}

}  // namespace cs_crypto::util

#endif