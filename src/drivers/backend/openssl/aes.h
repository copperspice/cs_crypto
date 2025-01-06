/***********************************************************************
*
* Copyright (c) 2021-2025 Tim van Deurzen
* Copyright (c) 2021-2025 Barbara Geller
* Copyright (c) 2021-2025 Ansel Sermersheim
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

#ifndef CS_CRYPTO_DRIVERS_OPENSSL_AES_H
#define CS_CRYPTO_DRIVERS_OPENSSL_AES_H

#ifdef CSCRYPTO_HAVE_OPENSSL

#include <core/cipher/block/aes.h>
#include <core/cipher/block/mode.h>
#include <core/cipher/sym_secret_key.h>
#include <core/cipher/sym_init_vector.h>
#include <core/cipher/sym_traits.h>
#include <drivers/base/aes.h>
#include <util/conversions/byte.h>
#include <util/tools/crypto_traits.h>
#include <util/tools/span.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <iterator>
#include <memory>
#include <vector>
#include <optional>

#include <openssl/evp.h>

namespace cs_crypto::drivers::openssl {

template <typename Cipher, typename Mode>
struct initialization_fn {
   static_assert(cs_crypto::traits::always_false<Cipher>{}, "Cipher and Mode combination is not available");
};

template <typename Cipher, typename Mode, bool Encryption = true>
class aes_interface
{
 public:
   using cipher_type = Cipher;
   using mode_type   = Mode;

   using key_type    = cipher::secret_key<cipher::traits::key_size_v<Cipher>>;
   using iv_type     = cipher::init_vector<cipher::traits::iv_size_v<Mode>>;

   ~aes_interface() = default;

   aes_interface(const aes_interface &) = delete;
   aes_interface(aes_interface &&) = default;

   aes_interface &operator=(const aes_interface &) & = delete;
   aes_interface &operator=(aes_interface &&) & = default;

   static std::optional<aes_interface> make_context(key_type &&secret_key, iv_type &&iv)
   {
      // initialization of the cipher context copies the key and context,
      // no need to store them after this point

      context_type context(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);

      int result;

      if constexpr (Encryption) {
         result = EVP_EncryptInit_ex(context.get(), initializer(), nullptr,
                  util::from_byte_ptr(secret_key.data()), util::from_byte_ptr(iv.data()));

      } else {
         result = EVP_DecryptInit_ex(context.get(), initializer(), nullptr,
                  util::from_byte_ptr(secret_key.data()), util::from_byte_ptr(iv.data()));
      }

      if (result != 1) {
         return std::nullopt;
      }

      return aes_interface(std::move(context));
   }

   void update(util::span<std::byte> plaintext_block) &
   {
      int len = m_ciphertext.size();
      m_ciphertext.resize(len + plaintext_block.size() + Cipher::block_size);

      if constexpr (Encryption) {
         EVP_EncryptUpdate(m_context.get(), util::from_byte_ptr(m_ciphertext.data() + m_last_byte_written),
                  &len, util::from_byte_ptr(plaintext_block.data()), plaintext_block.size());

      } else {
         EVP_DecryptUpdate(m_context.get(), util::from_byte_ptr(m_ciphertext.data() + m_last_byte_written),
                  &len, util::from_byte_ptr(plaintext_block.data()), plaintext_block.size());
      }

      m_last_byte_written += len;
   }

   std::vector<std::byte> finalize() &&
   {
      std::vector<std::byte> result;
      int len;
      m_ciphertext.resize(m_ciphertext.size() + Cipher::block_size);

      if constexpr (Encryption) {
         EVP_EncryptFinal_ex(m_context.get(),
                  util::from_byte_ptr(m_ciphertext.data()) + m_last_byte_written, &len);
      } else {
        EVP_DecryptFinal_ex(m_context.get(),
                  util::from_byte_ptr(m_ciphertext.data()) + m_last_byte_written, &len);
      }

      result.resize(m_last_byte_written + len);
      std::copy_n(m_ciphertext.begin(), m_last_byte_written + len, result.begin());
      return result;
   }

 private:
   using context_type = std::unique_ptr<EVP_CIPHER_CTX, decltype(&::EVP_CIPHER_CTX_free)>;
   context_type m_context;

   std::vector<std::byte> m_ciphertext = {};
   std::size_t m_last_byte_written = 0;

   constexpr static const auto initializer = initialization_fn<Cipher, Mode>::init_function;

   aes_interface(context_type &&context)
      : m_context(std::move(context))
   {
   }
};

template <>
struct initialization_fn<block_cipher::aes128, block_cipher::mode::CBC> {
   constexpr static const auto init_function = EVP_aes_128_cbc;
};

template <>
struct initialization_fn<block_cipher::aes192, block_cipher::mode::CBC> {
   constexpr static const auto init_function = EVP_aes_192_cbc;
};

template <>
struct initialization_fn<block_cipher::aes256, block_cipher::mode::CBC> {
   constexpr static const auto init_function = EVP_aes_256_cbc;
};

struct cipher_mode : public basic_cipher_mode {
   template <typename Cipher, typename Mode>
   using encrypt = aes_interface<Cipher, Mode, true>;

   template <typename Cipher, typename Mode>
   using decrypt = aes_interface<Cipher, Mode, false>;
};

}  // namespace cs_crypto::drivers::openssl

#endif   // CSCRYPTO_HAVE_OPENSSL

#endif
