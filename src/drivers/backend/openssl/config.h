/***********************************************************************
*
* Copyright (c) 2021-2022 Tim van Deurzen
* Copyright (c) 2021-2022 Ansel Sermersheim
* Copyright (c) 2021-2022 Barbara Geller
*
* This file is part of CsCrypto.
*
* CsCrypto is free software, released under the BSD 2-Clause license.
* For license details refer to LICENSE provided with this project.
*
* CopperSpice is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
*
* https://opensource.org/licenses/BSD-2-Clause
*
***********************************************************************/

#ifndef CS_CRYPTO_DRIVERS_OPENSSL_CONFIG_H
#define CS_CRYPTO_DRIVERS_OPENSSL_CONFIG_H

#if CSCRYPTO_HAVE_OPENSSL

#include <drivers/base/traits.h>
#include <drivers/base/drivers.h>
#include <drivers/backend/openssl/hash.h>
#include <drivers/backend/openssl/aes.h>

namespace cs_crypto::drivers::traits {

template <>
struct driver_for<implementation::openssl> {
   using hash                 = cs_crypto::drivers::openssl::hash;
   using symmetric_encryption = cs_crypto::drivers::openssl::cipher_mode;
};

} // namespace cs_crypto::drivers::traits

#endif

#endif
