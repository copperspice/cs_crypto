/***********************************************************************
*
* Copyright (c) 2021 Tim van Deurzen
* Copyright (c) 2021 Ansel Sermersheim
* Copyright (c) 2021 Barbara Geller
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

#ifndef CS_CRYPTO_DRIVERS_BOTAN_HASH_H
#define CS_CRYPTO_DRIVERS_BOTAN_HASH_H

#ifdef CSCRYPTO_HAVE_BOTAN

#include <drivers/base/hash.h>
#include <util/conversions/byte.h>
#include <util/tools/span.h>

#include <array>
#include <optional>
#include <cstddef>
#include <type_traits>

#include <botan/md4.h>
#include <botan/md5.h>
#include <botan/sha160.h>
#include <botan/sha2_32.h>
#include <botan/sha2_64.h>
#include <botan/sha3.h>

namespace cs_crypto::drivers::botan {

template <typename BotanContext, std::size_t SIZE>
struct hasher_interface {
 public:
   constexpr static const std::size_t digest_size = SIZE;

   hasher_interface(const hasher_interface & other)
   {
      if (this == &other) {
         return;
      }

      this->m_context = other.m_context->copy_state();
   };

   hasher_interface &operator=(const hasher_interface & other) &
   {
      if (this == &other) {
         return *this;
      }

      hasher_interface tmp = other;
      std::swap(*this, tmp);

      return *this;
   }

   hasher_interface(hasher_interface &&) = default;
   hasher_interface &operator=(hasher_interface &&) & = default;

   static std::optional<hasher_interface> make_context()
   {
      auto retval = hasher_interface();

      if (retval.m_context == nullptr) {
         return std::nullopt;
      }

      return retval;
   }

   void update(cs_crypto::util::span<std::byte> bytes) &
   {
      m_context->update(cs_crypto::util::from_byte_ptr(bytes.data()), bytes.size());
   }

   auto finalize() &&
   {
      std::array<std::byte, digest_size> md = {};
      m_context->final(cs_crypto::util::from_byte_ptr(md.data()));

      return md;
   }

 private:
   std::unique_ptr<Botan::HashFunction> m_context;

   hasher_interface()
      : m_context(std::make_unique<BotanContext>())
   {
   }
};

struct hash : cs_crypto::drivers::basic_hash {
   using md4 = hasher_interface<Botan::MD4, 16>;

   using md5 = hasher_interface<Botan::MD5, 16>;

   using sha1 = hasher_interface<Botan::SHA_160, 20>;

   using sha2_224 = hasher_interface<Botan::SHA_224, 28>;
   using sha2_256 = hasher_interface<Botan::SHA_256, 32>;
   using sha2_384 = hasher_interface<Botan::SHA_384, 48>;
   using sha2_512 = hasher_interface<Botan::SHA_512, 64>;

   using sha3_224 = hasher_interface<Botan::SHA_3_224, 28>;
   using sha3_256 = hasher_interface<Botan::SHA_3_256, 32>;
   using sha3_384 = hasher_interface<Botan::SHA_3_384, 48>;
   using sha3_512 = hasher_interface<Botan::SHA_3_512, 64>;
};

}  // namespace cs_crypto::drivers::botan

#endif   // CSCRYPTO_HAVE_BOTAN

#endif
