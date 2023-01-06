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

#ifndef CS_CRYPTO_TRAITS_H
#define CS_CRYPTO_TRAITS_H

namespace cs_crypto::hash::traits {

template <typename Driver>
using md4_ctx = typename Driver::md4;

template <typename Driver>
using md5_ctx = typename Driver::md5;

template <typename Driver>
using sha1_ctx = typename Driver::sha1;

template <typename Driver>
using sha2_224_ctx = typename Driver::sha2_224;

template <typename Driver>
using sha2_256_ctx = typename Driver::sha2_256;

template <typename Driver>
using sha2_384_ctx = typename Driver::sha2_384;

template <typename Driver>
using sha2_512_ctx = typename Driver::sha2_512;

template <typename Driver>
using sha3_224_ctx = typename Driver::sha3_224;

template <typename Driver>
using sha3_256_ctx = typename Driver::sha3_256;

template <typename Driver>
using sha3_384_ctx = typename Driver::sha3_384;

template <typename Driver>
using sha3_512_ctx = typename Driver::sha3_512;

}   // namespace cs_crypto::hash

#endif
