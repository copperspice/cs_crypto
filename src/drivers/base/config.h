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

#ifndef CS_CRYPTO_DRIVERS_CONFIG_H
#define CS_CRYPTO_DRIVERS_CONFIG_H

#include <drivers/base/aes.h>
#include <drivers/base/hash.h>
#include <drivers/base/traits.h>

namespace cs_crypto::drivers::traits {

template <>
struct driver_for<implementation::base> {
   using hash                 = basic_hash;
   using symmetric_encryption = basic_cipher_mode;
};

}  // namespace cs_crypto::drivers::traits

#endif
