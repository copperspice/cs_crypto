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

#ifndef CS_CRYPTO_SHA3_H
#define CS_CRYPTO_SHA3_H

#include <core/hash/hash_digest.h>
#include <core/hash/hash_traits.h>

namespace cs_crypto::hash {

template <typename Driver, typename... Ts>
auto sha3_224(Ts &&... args)
{
   return hash_digest<Driver, traits::sha3_224_ctx>(std::forward<Ts>(args)...);
}

template <typename Driver, typename... Ts>
auto sha3_256(Ts &&... args)
{
   return hash_digest<Driver, traits::sha3_256_ctx>(std::forward<Ts>(args)...);
}

template <typename Driver, typename... Ts>
auto sha3_384(Ts &&... args)
{
   return hash_digest<Driver, traits::sha3_384_ctx>(std::forward<Ts>(args)...);
}

template <typename Driver, typename... Ts>
auto sha3_512(Ts &&... args)
{
   return hash_digest<Driver, traits::sha3_512_ctx>(std::forward<Ts>(args)...);
}

}   // namespace cs_crypto::hash

#endif