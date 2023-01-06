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

#ifndef CS_CRYPTO_CORE_MODE_H
#define CS_CRYPTO_CORE_MODE_H

#include <cstddef>

namespace cs_crypto::block_cipher::mode {

// cipher block chaining mode
struct CBC {
   constexpr static const std::size_t iv_size = 16;
};

} // namespace cs_crypto::block_cipher

#endif
