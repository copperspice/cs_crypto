/***********************************************************************
*
* Copyright (c) 2021-2026 Tim van Deurzen
* Copyright (c) 2021-2026 Barbara Geller
* Copyright (c) 2021-2026 Ansel Sermersheim
*
* This file is part of CsCrypto.
*
* CsCrypto is free software which is released under the BSD 2-Clause license.
* For license details refer to the LICENSE provided with this project.
*
* CsCrypto is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
*
* https://opensource.org/licenses/BSD-2-Clause
*
***********************************************************************/

#ifndef CS_CRYPTO_DRIVERS_OPENSSL_HASH_H
#define CS_CRYPTO_DRIVERS_OPENSSL_HASH_H

#ifdef CSCRYPTO_HAVE_OPENSSL

#include <drivers/base/hash.h>
#include <util/conversions/byte.h>
#include <util/tools/crypto_traits.h>
#include <util/tools/span.h>

#include <array>
#include <memory>
#include <cstddef>
#include <optional>
#include <iostream>

#include <openssl/evp.h>
#include <openssl/md4.h>
#include <openssl/md5.h>
#include <openssl/sha.h>

namespace cs_crypto::drivers::openssl {

template <typename OpenSSLContext, std::size_t SIZE, auto doHash_Init, auto doHash_Update, auto doHash_Finalize>
struct hasher_interface {
 public:
   constexpr static const std::size_t digest_size = SIZE;

   ~hasher_interface() = default;

   hasher_interface(const hasher_interface &other) = default;
   hasher_interface &operator=(const hasher_interface &other) = default;

   hasher_interface(hasher_interface &&other) = default;
   hasher_interface &operator=(hasher_interface &&other) = default;

   static std::optional<hasher_interface> make_context()
   {
      OpenSSLContext ctx;

      // doHash_Init refers to an init function in OpenSSL (SHA1_Init, MD5_Init, etc)
      if (doHash_Init(&ctx) != 1) {
         return std::nullopt;
      }

      return hasher_interface(std::move(ctx));
   }

   void update(cs_crypto::util::span<std::byte> bytes) &
   {
      // doHash_Update refers to an update function in OpenSSL (SHA1_Update, MD5_Update, etc)
      doHash_Update(&m_context, bytes.data(), bytes.size());
   }

   auto finalize() &&
   {
      std::array<std::byte, digest_size> md{};

      // doHash_Finalize refers to a finalize function in OpenSSL (SHA1_Final, MD5_Final, etc)
      doHash_Finalize(util::from_byte_ptr(md.data()), &m_context);

      return md;
   }

 private:
   OpenSSLContext m_context;

   explicit hasher_interface(OpenSSLContext &&context)
      : m_context(std::move(context))
   {
   }
};

template <auto DigestInitFn, std::size_t SIZE>
struct keccak_interface {
 public:
   constexpr static const std::size_t digest_size = SIZE;

   keccak_interface(keccak_interface const &other)
      : keccak_interface()
   {
      if (this == &other) {
         return;
      }

      EVP_MD_CTX_copy_ex(this->m_context.get(), other.m_context.get());
   }

   ~keccak_interface() = default;

   keccak_interface &operator=(keccak_interface const & other)
   {
      auto tmp = other;
      std::swap(this->m_context, tmp.m_context);

      return *this;
   }

   keccak_interface(keccak_interface &&) = default;
   keccak_interface &operator=(keccak_interface &&) = default;

   static std::optional<keccak_interface> make_context()
   {
      keccak_interface retval = {};

      if (retval.m_context == nullptr) {
         return std::nullopt;
      }

      return retval;
   }

   void update(cs_crypto::util::span<std::byte> bytes) &
   {
      EVP_DigestUpdate(m_context.get(), bytes.data(), bytes.size());
   }

   auto finalize() &&
   {
      std::array<std::byte, digest_size> result = {};
      unsigned int sz = 0;

      EVP_DigestFinal_ex(m_context.get(), util::from_byte_ptr(result.data()), &sz);

      return result;
   }

 private:
   std::unique_ptr<EVP_MD_CTX, decltype(&::EVP_MD_CTX_free)> m_context;

   keccak_interface()
      : m_context{EVP_MD_CTX_new(), ::EVP_MD_CTX_free}
   {
      if (m_context != nullptr && EVP_DigestInit_ex(m_context.get(), DigestInitFn(), nullptr) != 1) {
         EVP_MD_CTX_free(m_context.get());
         m_context = nullptr;
      }
   }
};

struct hash : cs_crypto::drivers::basic_hash {
   using md4 = hasher_interface<MD4_CTX, MD4_DIGEST_LENGTH, MD4_Init, MD4_Update, MD4_Final>;
   using md5 = hasher_interface<MD5_CTX, MD5_DIGEST_LENGTH, MD5_Init, MD5_Update, MD5_Final>;

   using sha1 = hasher_interface<SHA_CTX, SHA_DIGEST_LENGTH, SHA1_Init, SHA1_Update, SHA1_Final>;

   using sha2_224 = hasher_interface<SHA256_CTX, SHA224_DIGEST_LENGTH, SHA224_Init, SHA224_Update, SHA224_Final>;
   using sha2_256 = hasher_interface<SHA256_CTX, SHA256_DIGEST_LENGTH, SHA256_Init, SHA256_Update, SHA256_Final>;
   using sha2_384 = hasher_interface<SHA512_CTX, SHA384_DIGEST_LENGTH, SHA384_Init, SHA384_Update, SHA384_Final>;
   using sha2_512 = hasher_interface<SHA512_CTX, SHA512_DIGEST_LENGTH, SHA512_Init, SHA512_Update, SHA512_Final>;

   using sha3_224 = keccak_interface<EVP_sha3_224, 28>;
   using sha3_256 = keccak_interface<EVP_sha3_256, 32>;
   using sha3_384 = keccak_interface<EVP_sha3_384, 48>;
   using sha3_512 = keccak_interface<EVP_sha3_512, 64>;
};

}  // namespace cs_crypto::drivers::openssl

#endif   // CSCRYPTO_HAVE_OPENSSL

#endif
