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

#ifndef CS_CRYPTO_UTIL_BYTE_H
#define CS_CRYPTO_UTIL_BYTE_H

#include <util/tools/crypto_traits.h>

#include <cstddef>
#include <type_traits>

namespace cs_crypto::util {

inline const unsigned char *from_byte_ptr(const std::byte *value)
{
   return reinterpret_cast<const unsigned char *>(value);
}

inline unsigned char *from_byte_ptr(std::byte *value)
{
   return reinterpret_cast<unsigned char *>(value);
}

template <typename T>
inline const std::byte *to_byte_ptr(const T *value)
{
   static_assert(cs_crypto::traits::is_uniquely_represented_byte_v<T>, "Unable to convert const T * to const std::byte *");
   return reinterpret_cast<const std::byte *>(value);
}

}  // namespace cs_crypto::util

#endif
