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

#ifndef CS_CRYPTO_SHA2_H
#define CS_CRYPTO_SHA2_H

#include <core/hash/hash_digest.h>
#include <core/hash/hash_traits.h>

namespace cs_crypto::hash {

template <typename Driver, typename... Ts>
auto sha2_224(Ts &&... args)
{
   return hash_digest<Driver, traits::sha2_224_ctx>(std::forward<Ts>(args)...);
}

template <typename Driver, typename... Ts>
auto sha2_256(Ts &&... args)
{
   return hash_digest<Driver, traits::sha2_256_ctx>(std::forward<Ts>(args)...);
}

template <typename Driver, typename... Ts>
auto sha2_384(Ts &&... args)
{
   return hash_digest<Driver, traits::sha2_384_ctx>(std::forward<Ts>(args)...);
}

template <typename Driver, typename... Ts>
auto sha2_512(Ts &&... args)
{
   return hash_digest<Driver, traits::sha2_512_ctx>(std::forward<Ts>(args)...);
}

} // namespace cs_crypto::hash

#endif
