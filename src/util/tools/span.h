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

#ifndef CS_CRYPTO_UTIL_SPAN_H
#define CS_CRYPTO_UTIL_SPAN_H

#include <util/tools/crypto_traits.h>

#include <array>
#include <iterator>
#include <limits>
#include <type_traits>

namespace cs_crypto::util {

template <typename T>
class span
{
 public:
   using element_type    = T;
   using value_type      = std::remove_cv_t<T>;
   using size_type       = std::size_t;
   using difference_type = std::ptrdiff_t;
   using reference       = element_type &;
   using const_reference = const element_type &;
   using pointer         = element_type *;
   using const_pointer   = const element_type *;
   using iterator        = pointer;
   using const_iterator  = const_pointer;

   constexpr span() = default;

   template <typename Iter, typename = std::enable_if_t<std::is_same_v<typename std::iterator_traits<Iter>::iterator_category,
                  std::random_access_iterator_tag>>>
   constexpr span(Iter iter, size_type size) noexcept
      : m_data(std::addressof(*iter)), m_size(size)
   {
   }

   template <std::size_t N>
   constexpr explicit span(const cs_crypto::traits::identity_t<element_type> (&arr)[N]) noexcept
      : m_data(std::data(arr)), m_size(N)
   {
   }

   template <std::size_t N>
   constexpr explicit span(std::array<T, N> &arr) noexcept
      : m_data(std::data(arr)), m_size(N)
   {
   }

   template <std::size_t N>
   constexpr explicit span(const std::array<T, N> &arr) noexcept
      : m_data(std::data(arr)), m_size(N)
   {
   }

   constexpr span(const span &) = default;
   constexpr span &operator=(const span &) & = default;

   constexpr span(span &&) = default;
   constexpr span &operator=(span &&) & = default;

   constexpr const_iterator begin() const noexcept
   {
      return m_data;
   }

   constexpr const_iterator end() const noexcept
   {
      return m_data + m_size;
   }

   constexpr const_pointer data() const noexcept
   {
      return m_data;
   }

   constexpr size_type size() const noexcept
   {
      return m_size;
   }

   constexpr bool empty() const noexcept
   {
      return m_size == 0;
   }

 private:
   const_pointer m_data   = nullptr;
   const size_type m_size = 0;
};

template <class It>
span(It, std::size_t) -> span<std::remove_reference_t<typename std::iterator_traits<It>::reference>>;

}  // namespace cs_crypto::util

#endif
