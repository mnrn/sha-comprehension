/**
 * @brief SHA256の実装
 * @date  2016/07/10
 */

#ifndef SHA256_HPP
#define SHA256_HPP

#include "../bit.hpp"
#include <array>
#include <string>
#include <vector>

//#define DEBUG
#ifdef DEBUG
#define FMT_HEADER_ONLY
#include <../fmt/printf.h>
#include <iostream>
#endif

class SHA256 {
public:
  /**
   * @brief  SHA256の計算を行う
   * @param  const std::string& msg ハッシュ化対象のascii文字列
   * @return ハッシュ化されたbyte列(digest message)
   */
  std::vector<std::uint8_t> hash(const std::string &msg) const {
    std::vector<std::uint8_t> bytes(msg.size(), 0x00);
    std::copy(msg.cbegin(), msg.cend(), bytes.begin());
    return hash(bytes);
  }

public:
  /**
   * @brief  SHA256の計算を行う
   * @param  const std::vector<std::uint8_t>& msg ハッシュ化対象のbyte列
   * @return ハッシュ化されたbyte列(digest message)
   */
  std::vector<std::uint8_t> hash(const std::vector<std::uint8_t> &msg) const {
    // ハッシュ値を用意
    std::vector<std::uint32_t> H{
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    };

    // プリプロセス: メッセージにパディングを施す
    const std::vector<std::uint8_t> padded_msg = padding(msg);

    // メッセージを512-bitのチャンクに分割する
    const std::size_t chunks_num =
        padded_msg.size() / 64; // チャンクの大きさは512(8 * 64)-bit * n
    for (std::size_t i = 0; i < chunks_num; i++) {

      // message schedule: W0, W1, ..., W63
      std::uint32_t W[64];

      // 0 <= t <= 15 : メッセージを16つの32-bit wordsに分割する
      for (std::uint32_t t = 0; t < 16; t++) {

        const std::uint32_t base = i * 64 + t * 4;
        W[t] = (padded_msg[base + 0] << 24) | (padded_msg[base + 1] << 16) |
               (padded_msg[base + 2] << 8) | (padded_msg[base + 3]);
#ifdef DEBUG
        fmt::printf("W[%2d] = %08x\n", t, W[t]);
#endif
      }

      // 16 <= t <= 63 : 16つの32-bits wordsを64つの32-bit wordsに分割する
      for (std::uint32_t t = 16; t < 64; t++) {
        W[t] = small_sigma1(W[t - 2]) + W[t - 7] + small_sigma0(W[t - 15]) +
               W[t - 16];
      }

      // 8つの変数a, b, c, d, e, f, g, hを(i - 1)st hash valueで初期化する
      std::uint32_t a = H[0];
      std::uint32_t b = H[1];
      std::uint32_t c = H[2];
      std::uint32_t d = H[3];
      std::uint32_t e = H[4];
      std::uint32_t f = H[5];
      std::uint32_t g = H[6];
      std::uint32_t h = H[7];

      // Main Loop
      for (std::uint32_t t = 0; t < 64; t++) {

        const std::uint32_t T1 = h + big_sigma1(e) + ch(e, f, g) + K[t] + W[t];
        const std::uint32_t T2 = big_sigma0(a) + maj(a, b, c);

        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;

#ifdef DEBUG
        fmt::printf("t = %2d ", t);
        fmt::printf("a = %08x ", a);
        fmt::printf("b = %08x ", b);
        fmt::printf("c = %08x ", c);
        fmt::printf("d = %08x ", d);
        fmt::printf("e = %08x ", e);
        fmt::printf("f = %08x ", f);
        fmt::printf("g = %08x ", g);
        fmt::printf("h = %08x\n", h);
#endif
      }

      // ハッシュ値の更新
      H[0] = a + H[0];
      H[1] = b + H[1];
      H[2] = c + H[2];
      H[3] = d + H[3];
      H[4] = e + H[4];
      H[5] = f + H[5];
      H[6] = g + H[6];
      H[7] = h + H[7];

#ifdef __DEBUG__
      for (auto &&h : H) {
        fmt::printf("%08x ", h);
      }
      std::cout << std::endl;
#endif
    }

    // 最終的なハッシュ値を返す
    std::vector<std::uint8_t> M(32); // 8 * 32 = 256-bits
    for (std::size_t i = 0; i < 8; i++) {

      const std::size_t base = i * 4;
      M[base + 0] = static_cast<std::uint8_t>(H[i] >> 24);
      M[base + 1] = static_cast<std::uint8_t>(H[i] >> 16);
      M[base + 2] = static_cast<std::uint8_t>(H[i] >> 8);
      M[base + 3] = static_cast<std::uint8_t>(H[i]);
    }

    return M;
  }

private:
  /**
   * @brief
   * 入力メッセージMに対し、メッセージ長が512-bitの倍数になるように、Mの末尾に以下のようなパディングを施す
   *          M || 1 || 0k || l
   *        ただし、lはMのメッセージ長の2進数表現(64-bit)であり、kはl * 1 + k ≡
   * 448 (mod 512)を満たす最小の正数である
   *
   * @note  例えば、message "abs"は8 * 3 = 24の長さを持つ
   *        したがって、メッセージは1つの1と、448 - (24 + 1) = 423つの0、
   *        そしてメッセージ長をパディングされ、以下のようになる
   *
   *                                         ~ 423 ~  ~   64   ~
   *        01100001  01100010  01100011  1  00...00  00...011000
   *        a         b         c                          l = 24
   */
  std::vector<std::uint8_t>
  padding(const std::vector<std::uint8_t> &msg) const {
    // パディングすべき大きさを計算する
    const std::size_t msglen = msg.size();
    std::size_t padlen = 64 - (msglen % 64);

    // 余裕がなければ拡張
    if (padlen < 9) {
      padlen += 64;
    }

    // パディングされたメッセージを格納するための変数を用意
    const std::size_t padded_len = msglen + padlen;
    std::vector<std::uint8_t> padded_msg(padded_len,
                                         0x00); // まずここで0で埋めてしまう
    std::copy(msg.cbegin(), msg.cend(), padded_msg.begin());

    // 0b10000000を付加
    padded_msg[msglen] = 0x80;

    // メッセージ長を付加
    padded_msg[padded_len - 4] = static_cast<std::uint8_t>((msglen * 8) >> 24);
    padded_msg[padded_len - 3] = static_cast<std::uint8_t>((msglen * 8) >> 16);
    padded_msg[padded_len - 2] = static_cast<std::uint8_t>((msglen * 8) >> 8);
    padded_msg[padded_len - 1] = static_cast<std::uint8_t>((msglen * 8));

    return padded_msg;
  }

  /**
   * @brief SHA256で使用する関数Σ{256}0(x)
   * @note  仕様書の式(4.4)に相当
   */
  constexpr std::uint32_t big_sigma0(std::uint32_t x) const {
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
  }

  /**
   * @brief SHA256で使用する関数Σ{256}1(x)
   * @note  仕様書の式(4.5)に相当
   */
  constexpr std::uint32_t big_sigma1(std::uint32_t x) const {
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
  }

  /**
   * @brief SHA256で使用する関数σ{256}0(x)
   * @note  仕様書の式(4.6)に相当
   */
  constexpr std::uint32_t small_sigma0(std::uint32_t x) const {
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
  }

  /**
   * @brief SHA256で使用する関数σ{256}1(x)
   * @note  仕様書の式(4.7)に相当
   */
  constexpr std::uint32_t small_sigma1(std::uint32_t x) const {
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
  }

  /** @brief SHA256で使用する64つの32-bit words: 定数K{256}0, K{256}1,
   * ...K{256}63 <*/
  inline static constexpr std::array<std::uint32_t, 64> K{
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b,
      0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
      0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7,
      0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
      0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152,

      0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
      0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
      0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
      0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,

      0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
      0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
      0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  };
};

#endif // end of SHA256_H
