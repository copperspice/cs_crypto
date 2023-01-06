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

#ifndef CS_CRYPTO_DRIVERS_BOTAN_AES_H
#define CS_CRYPTO_DRIVERS_BOTAN_AES_H

#ifdef CSCRYPTO_HAVE_BOTAN

#include <core/cipher/block/aes.h>
#include <core/cipher/block/mode.h>
#include <core/cipher/sym_secret_key.h>
#include <core/cipher/sym_init_vector.h>
#include <core/cipher/sym_traits.h>
#include <drivers/base/aes.h>
#include <util/conversions/byte.h>
#include <util/tools/crypto_traits.h>
#include <util/tools/span.h>

#include <cstddef>
#include <optional>

#include <botan/aes.h>
#include <botan/cipher_mode.h>
#include <botan/cbc.h>
#include <botan/cfb.h>

namespace cs_crypto::drivers::botan {

template <typename Botan_T>
class aes_interface : public Botan_T
{
 public:
   using cipher_type = typename Botan_T::cipher_type;
   using mode_type   = typename Botan_T::mode_type;

   using key_type    = typename Botan_T::key_type;
   using iv_type     = typename Botan_T::iv_type;

   aes_interface(const aes_interface &) = delete;

   ~aes_interface() = default;

   aes_interface &operator=(const aes_interface &) & = delete;

   aes_interface(aes_interface&&) = default;
   aes_interface &operator=(aes_interface&&) & = default;

   static std::optional<aes_interface> make_context(key_type &&secret_key, iv_type &&iv)
   {
      auto context = Botan_T::make_context();

      if (context == nullptr) {
         return std::nullopt;
      }

      // The key and nonce are copied into the context by Botan, no need to
      // store the key and nonce after this point.

      context->set_key(util::from_byte_ptr(secret_key.data()), secret_key.size());
      context->start(util::from_byte_ptr(iv.data()), iv.size());

      return aes_interface(std::move(context));
   }

   void update(cs_crypto::util::span<std::byte> plaintext_block) &
   {
      cs_crypto::util::span<uint8_t> uint_view = {util::from_byte_ptr(plaintext_block.data()), plaintext_block.size()};
      m_plaintext.insert(m_plaintext.end(), uint_view.begin(), uint_view.end());
   }

   std::vector<std::byte> finalize() &&
   {
      std::vector<std::byte> result;
      m_context->finish(m_plaintext);

      result.resize(m_plaintext.size());
      cs_crypto::util::span<std::byte> byte_view = {util::to_byte_ptr(m_plaintext.data()), m_plaintext.size()};
      std::copy(byte_view.begin(), byte_view.end(), result.begin());

      return result;
   }

 private:
   Botan::secure_vector<uint8_t> m_plaintext;
   std::unique_ptr<typename Botan_T::botan_context> m_context;

   explicit aes_interface(std::unique_ptr<typename Botan_T::botan_context> &&context)
      : m_plaintext(), m_context(std::move(context))
   {
   }
};

template <typename Cipher, typename Mode, bool Encryption>
struct aes_internal {
   static_assert(cs_crypto::traits::always_false<Cipher>{}, "Cipher and Mode combination is not available");
};

template <typename Cipher, bool Encryption>
struct aes_internal<Cipher, block_cipher::mode::CBC, Encryption> {
   using cipher_type   = Cipher;
   using mode_type     = block_cipher::mode::CBC;

   using key_type      = cipher::secret_key<cipher::traits::key_size_v<cipher_type>>;
   using iv_type       = cipher::init_vector<cipher::traits::iv_size_v<mode_type>>;

   using botan_context = std::conditional_t<Encryption, Botan::CBC_Encryption, Botan::CBC_Decryption>;

   ~aes_internal() = default;

   static std::unique_ptr<botan_context> make_context() noexcept
   {
      std::unique_ptr<botan_context> context;

      if constexpr (std::is_same_v<Cipher, block_cipher::aes128>) {
         return std::make_unique<botan_context>(new Botan::AES_128, new Botan::PKCS7_Padding);

      } else if constexpr (std::is_same_v<Cipher, block_cipher::aes192>) {
         return std::make_unique<botan_context>(new Botan::AES_192, new Botan::PKCS7_Padding);

      } else if constexpr (std::is_same_v<Cipher, block_cipher::aes256>) {
         return std::make_unique<botan_context>(new Botan::AES_256, new Botan::PKCS7_Padding);
      }

      return nullptr;
   }
};

struct cipher_mode : public basic_cipher_mode {
   template <typename Cipher, typename Mode>
   using encrypt = aes_interface<aes_internal<Cipher, Mode, true>>;

   template <typename Cipher, typename Mode>
   using decrypt = aes_interface<aes_internal<Cipher, Mode, false>>;
};

}  // namespace cs_crypto::drivers::botan

#endif // CSCRYPTO_HAVE_BOTAN

#endif
