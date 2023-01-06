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

#ifndef CS_CRYPTO_UTIL_RESULT_H
#define CS_CRYPTO_UTIL_RESULT_H

#include <variant>
#include <type_traits>

namespace cs_crypto::util {

template <typename E>
class error
{
   static_assert(! std::is_same_v<E, void>, "Error type can not be void");

 public:
   error() = delete;

   constexpr explicit error(const E &err) noexcept
      : m_error(err)
   {
   }

   constexpr explicit error(E &&err) noexcept
      : m_error(std::move(err))
   {
   }

   ~error() noexcept = default;

   constexpr error(const error &) noexcept = default;
   constexpr error &operator=(const error &) & noexcept = default;

   constexpr error(error &&) noexcept = default;
   constexpr error &operator=(error &&) & noexcept = default;

   constexpr const E &value() & noexcept
   {
      return m_error;
   }

   constexpr const E &value() const & noexcept
   {
      return m_error;
   }

   constexpr E &&value() && noexcept
   {
      return std::move(m_error);
   }

 private:
   E m_error;
};

template <typename Value, typename Error>
class result
{
 public:
   constexpr explicit result(Value &&value) noexcept
      : m_content(std::forward<Value>(value))
   {
   }

   constexpr explicit result(Error &&err) noexcept
      : m_content(error(std::move(err)))
   {
   }

   ~result() noexcept = default;

   constexpr result(const result &) noexcept = default;
   constexpr result &operator=(const result &) &noexcept = default;

   constexpr result(result &&) noexcept = default;
   constexpr result &operator=(result &&) & noexcept = default;

   constexpr const Value &value() const & noexcept
   {
      return std::get<Value>(m_content);
   }

   constexpr const Value &value() & noexcept
   {
      return std::get<Value>(m_content);
   }

   constexpr Value &&value() && noexcept
   {
      return std::get<Value>(std::move(m_content));
   }

   constexpr const Error &err() const & noexcept
   {
      return std::get<error_t>(m_content).value();
   }

   constexpr const Error &err() & noexcept
   {
      return std::get<error_t>(m_content).value();
   }

   constexpr Error &&err() && noexcept
   {
      return std::get<error_t>(std::move(m_content)).value();
   }

   constexpr bool is_error() const noexcept
   {
      return std::holds_alternative<error_t>(m_content);
   }

   constexpr bool is_ok() const noexcept
   {
      return std::holds_alternative<Value>(m_content);
   }

 private:
   using error_t = error<Error>;

   // using std::variant means std::terminate can be called if the content is an error
   const std::variant<Value, error_t> m_content;
};

}   // namespace cs_crypto::util

#endif