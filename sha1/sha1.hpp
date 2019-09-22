/**
 * @brief SHA1の実装
 * @date  2016/07/09
 */

#ifndef SHA1_HPP
#define SHA1_HPP

#include "../bit.hpp"
#include <string>
#include <vector>

//#define DEBUG
#ifdef DEBUG
#define FMT_HEADER_ONLY
#include <../fmt/printf.h>
#include <iostream>
#endif

class SHA1 {
public:
  /**
   * @brief  SHA1(Secure Hash Algorithm 1)の計算を行う
   * @param  const std::string& msg ハッシュ化対象のascii文字列
   * @return ハッシュ化されたbyte列
   */
  std::vector<std::uint8_t> hash(const std::string &msg) const {
    std::vector<std::uint8_t> bytes(msg.size(), 0x00);
    std::copy(msg.cbegin(), msg.cend(), bytes.begin());
    return hash(bytes);
  }

public:
  /**
   * @brief  SHA1(Secure Hash Algorithm 1)の計算を行う
   * @param  const std::vector<std::uint8_t>& msg ハッシュ化対象のbyte列
   * @return ハッシュ化されたbyte列
   */
  std::vector<std::uint8_t> hash(const std::vector<std::uint8_t> &msg) const {
    // ハッシュ値を用意
    std::vector<std::uint32_t> H{
        0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0,
    };

    // プリプロセス: メッセージにパディングを施す
    const std::vector<std::uint8_t> padded_msg = padding(msg);

    // メッセージを512-bitのチャンクに分割する
    const std::size_t chunks_num =
        padded_msg.size() / 64; // チャンクの大きさは512(8 * 64)-bit * n
    for (std::size_t i = 0; i < chunks_num; i++) {
      std::vector<std::uint32_t> W(80);

      // 0 <= t <= 15 : メッセージを16つの32-bit wordsに分割する
      for (std::uint32_t t = 0; t < 16; t++) {
        std::uint32_t base = i * 64 + t * 4;
        W[t] = (padded_msg[base + 0] << 24) | (padded_msg[base + 1] << 16) |
               (padded_msg[base + 2] << 8) | (padded_msg[base + 3]);
#ifdef DEBUG
        fmt::printf("W[%2d] = %08x", t, W[t]);
#endif
      }

      // 16 <= t <= 79 : 16つの32-bit wordsを80つの32-bits wordsに拡張する
      for (std::uint32_t t = 16; t < 80; t++) {
        W[t] = rotl(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16], 1);
      }

      // 5つのword...a, b, c, d, eの値を初期化する
      std::uint32_t a = H[0];
      std::uint32_t b = H[1];
      std::uint32_t c = H[2];
      std::uint32_t d = H[3];
      std::uint32_t e = H[4];

      // Main Loop: US Secure Hash Algorithm 1 (SHA-1)
      for (std::uint32_t t = 0; t < 80; t++) {
        const std::uint32_t T = rotl(a, 5) + f(t, b, c, d) + e + K(t) + W[t];
        e = d;
        d = c;
        c = rotl(b, 30);
        b = a;
        a = T;

#ifdef DEBUG
        fmt::printf("t = %2d ", t);
        fmt::printf("a = %08x ", a);
        fmt::printf("b = %08x ", b);
        fmt::printf("c = %08x ", c);
        fmt::printf("d = %08x ", d);
        fmt::printf("e = %08x\n", e);
#endif
      }

      // ハッシュ値の更新
      H[0] = a + H[0];
      H[1] = b + H[1];
      H[2] = c + H[2];
      H[3] = d + H[3];
      H[4] = e + H[4];

#ifdef DEBUG
      for (auto &&h : H) {
        fmt::printf("%08x ", h);
      }
      std::cout << std::endl;
#endif
    }

    // 最終的なハッシュ値を返す
    std::vector<std::uint8_t> M(20); // 8 * 20 = 160-bits
    for (std::size_t i = 0; i < 5; i++) {
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
    padded_msg[msglen] = 0b10000000;

    // メッセージ長を付加
    padded_msg[padded_len - 4] = static_cast<std::uint8_t>((msglen * 8) >> 24);
    padded_msg[padded_len - 3] = static_cast<std::uint8_t>((msglen * 8) >> 16);
    padded_msg[padded_len - 2] = static_cast<std::uint8_t>((msglen * 8) >> 8);
    padded_msg[padded_len - 1] = static_cast<std::uint8_t>((msglen * 8));

    return padded_msg;
  }

  /**
   * @brief 論理関数ft(x, y, z)を定義する
   * @param t  0 <= t <= 79を満たすような整数(パラメタ)
   */
  constexpr std::uint32_t f(std::uint32_t t, std::uint32_t x, std::uint32_t y,
                            std::uint32_t z) const {
    // if      (/*0<=t&&*/ t <= 19) { return ch(x, y, z);     }
    // else if (20 <= t && t <= 39) { return parity(x, y, z); }
    // else if (40 <= t && t <= 59) { return maj(x, y, z);    }
    // return parity(x, y, z);  // 60 <= t <= 79

    return (/*0<=t&&*/ t <= 19)
               ? ch(x, y, z)
               : (20 <= t && t <= 39)
                     ? parity(x, y, z)
                     : (40 <= t && t <= 59) ? maj(x, y, z)
                                            : parity(x, y, z); // 60 <= t <= 79
  }

  /**
   * @brief SHA-1で使用する32-bit定数(関数)Ktの定義
   */
  constexpr std::uint32_t K(std::uint32_t t) const {
    // if      (/*0<=t&&*/ t <= 19) { return 0x5a827999; }
    // else if (20 <= t && t <= 39) { return 0x6ed9eba1; }
    // else if (40 <= t && t <= 59) { return 0x8f1bbcdc; }
    // return 0xca62c1d6;  // 60 <= t <= 79

    return (/*0<=t&&*/ t <= 19)
               ? 0x5a827999
               : (20 <= t && t <= 39)
                     ? 0x6ed9eba1
                     : (40 <= t && t <= 59) ? 0x8f1bbcdc
                                            : 0xca62c1d6; // 60 <= t <= 79
  }
};

#endif // SHA1_HPP
