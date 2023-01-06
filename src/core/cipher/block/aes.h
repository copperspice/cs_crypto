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

#ifndef CS_CRYPTO_CORE_AES_H
#define CS_CRYPTO_CORE_AES_H

#include <cstddef>

namespace cs_crypto::block_cipher {

// all AES variations have the same block size, i.e. 16 bytes.
struct aes_base {
   constexpr static const std::size_t block_size = 16;
};

// AES 128 has a 16 byte block and a 16 byte key.
struct aes128 : public aes_base {
   constexpr static const std::size_t key_size = 16;
};

// AES 192 has a 16 byte block and a 24 byte key.

struct aes192 : public aes_base {
   constexpr static const std::size_t key_size = 24;
};

// AES 256 has a 16 byte block and a 32 byte key.
struct aes256 : public aes_base {
   constexpr static const std::size_t key_size = 32;
};

}  // namespace cs_crypto::block_cipher

#endif
