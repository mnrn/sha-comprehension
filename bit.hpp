/**
 * @brief 基本となるビット演算メモ
 * @date  2016/01/30 ~ 2016/07/09
 */

#ifndef BIT_HPP
#define BIT_HPP

#include <climits>
#include <cstdint>
#include <limits>
#include <type_traits>

/**
 * @brief ビットの左ローテーション
 * @param Integer x   ローテーション対象の値(符号なし整数)
 * @param uint32_t n  シフトする値
 */
template <class Integer> constexpr Integer rotl(Integer x, std::uint32_t n) {
  static_assert(std::is_unsigned_v<Integer>,
                "only makes sence for unsigned types");
  return (x << n) | (x >> ((sizeof(Integer) * CHAR_BIT - 1) & (-n)));
}

/**
 * @brief ビットの右ローテーション
 * @param Integer x   ローテーション対象の値(符号なし整数)
 * @param uint32_t n  シフトする値
 */
template <class Integer> constexpr Integer rotr(Integer x, std::uint32_t n) {
  static_assert(std::is_unsigned_v<Integer>,
                "only makes sence for unsigned types");
  return (x >> n) | (x << ((sizeof(Integer) * CHAR_BIT - 1) & (-n)));
}

/**
 * @brief パリティの計算を行う
 */
template <class Integer>
constexpr Integer parity(Integer x, Integer y, Integer z) {
  static_assert(std::is_unsigned_v<Integer>,
                "only makes sence for unsigned types");
  return (x ^ y ^ z);
}

/**
 * @brief 選択関数Ch(choice function)
 * @note  SHAの計算に使われます
 */
template <class Integer> constexpr Integer ch(Integer x, Integer y, Integer z) {
  static_assert(std::is_unsigned_v<Integer>,
                "only makes sence for unsigned types");
  return (x & y) ^ (~x & z);
}

/**
 * @brief 多数決関数Maj(majority function)
 * @note  SHAの計算に使われます
 */
template <class Integer>
constexpr Integer maj(Integer x, Integer y, Integer z) {
  static_assert(std::is_unsigned_v<Integer>,
                "only makes sence for unsigned types");
  return (x & y) ^ (y & z) ^ (z & x);
}

#endif // end of BIT_HPP
