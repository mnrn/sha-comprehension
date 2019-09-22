/**
 * @brief SHA-512の実装
 * @date  2016/07/10
 */

#ifndef SHA512_HPP
#define SHA512_HPP

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

class SHA512 {
public:
  /**
   * @brief  SHA-512の計算を行う
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
   * @brief  SHA-512の計算を行う
   * @param  const std::vector<std::uint8_t>& msg ハッシュ化対象のbyte列
   * @return ハッシュ化されたbyte列(digest message)
   */
  std::vector<std::uint8_t> hash(const std::vector<std::uint8_t> &msg) const {
    // ハッシュ値を用意
    std::vector<std::uint64_t> H{
        0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b,
        0xa54ff53a5f1d36f1, 0x510e527fade682d1, 0x9b05688c2b3e6c1f,
        0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
    };

    // プリプロセス: メッセージにパディングを施す
    const std::vector<std::uint8_t> padded_msg = padding(msg);

    // メッセージを1024-bitのチャンクに分割する
    const std::size_t chunks_num =
        padded_msg.size() / 128; // チャンクの大きさは1024(8 * 128)bit
    for (std::size_t i = 0; i < chunks_num; i++) {

      // message schedule: W{i}
      std::vector<std::uint64_t> W(80);

      // 0 <= t <= 15 : メッセージを16つの64-bit wordsに分割
      for (std::uint64_t t = 0; t < 16; t++) {

        std::size_t base = 128 * i + t * 8;
        W[t] = ((padded_msg[base] & 0xffULL) << 56) |
               ((padded_msg[base + 1] & 0xffULL) << 48) |
               ((padded_msg[base + 2] & 0xffULL) << 40) |
               ((padded_msg[base + 3] & 0xffULL) << 32) |
               ((padded_msg[base + 4] & 0xffULL) << 24) |
               ((padded_msg[base + 5] & 0xffULL) << 16) |
               ((padded_msg[base + 6] & 0xffULL) << 8) |
               ((padded_msg[base + 7] & 0xffULL));

#ifdef DEBUG
        fmt::printf("W[%2d] = %16x\n", t, W[t]);
#endif
      }

      // 16 <= t <= 79 : 16つの64-bit wordsを80つの64-bit wordsに分割
      for (std::uint64_t t = 16; t < 80; t++) {
        W[t] = small_sigma512_1(W[t - 2]) + W[t - 7] +
               small_sigma512_0(W[t - 15]) + W[t - 16];
      }

      // 8つの変数a, b, c, d, e, f, g, hを(i - 1)st hash valueで初期化する
      std::uint64_t a = H[0];
      std::uint64_t b = H[1];
      std::uint64_t c = H[2];
      std::uint64_t d = H[3];
      std::uint64_t e = H[4];
      std::uint64_t f = H[5];
      std::uint64_t g = H[6];
      std::uint64_t h = H[7];

      for (std::uint64_t t = 0; t < 80; t++) {

        const std::uint64_t T1 =
            h + big_sigma512_1(e) + ch(e, f, g) + K[t] + W[t];
        const std::uint64_t T2 = big_sigma512_0(a) + maj(a, b, c);

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
        fmt::printf("a = %16x ", a);
        fmt::printf("b = %16x ", b);
        fmt::printf("c = %16x ", c);
        fmt::printf("d = %16x ", d);
        fmt::printf("e = %16x ", e);
        fmt::printf("f = %16x ", f);
        fmt::printf("g = %16x ", g);
        fmt::printf("h = %16x\n", h)
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

#ifdef DEBUG
      for (auto &&h : H) {
        fmt::printf("%16x ", h);
      }
      std::cout << std::endl;
#endif
    }

    // 最終的なハッシュ値を返す
    std::vector<std::uint8_t> M(64); // 8 * 64 = 512-bits
    for (std::size_t i = 0; i < 8; i++) {

      const std::size_t base = i * 8;
      M[base] = static_cast<std::uint8_t>(H[i] >> 56);
      M[base + 1] = static_cast<std::uint8_t>(H[i] >> 48);
      M[base + 2] = static_cast<std::uint8_t>(H[i] >> 40);
      M[base + 3] = static_cast<std::uint8_t>(H[i] >> 32);
      M[base + 4] = static_cast<std::uint8_t>(H[i] >> 24);
      M[base + 5] = static_cast<std::uint8_t>(H[i] >> 16);
      M[base + 6] = static_cast<std::uint8_t>(H[i] >> 8);
      M[base + 7] = static_cast<std::uint8_t>(H[i]);
    }

    return M;
  }

private:
  /**
   * @brief
   *入力メッセージMに対し、メッセージ長が1024-bitの倍数になるように、Mの末尾に以下のようなパディングを施す
   *          M || 1 || 0k || l
   *        ただし、lはMのメッセージ長の2進数表現(128-bit)であり、 kは l + 1 + k
   *≡ 896 mod 1024を満たす最小の正数である
   *
   *　@note  例えば、message "abc"は8 * 3 = 24の長さを持つ
   *         したがって、メッセージは1つの1と、896 - (24 + 1) = 871つの0、
   *         そして、メッセージ長をパディングされ、以下のような1024-bit長のメッセージとなる
   *
   *                                          ~ 871 ~  ~   128   ~
   *         01100001  01100010  01100011  1  00...00  00...011000
   *         a         b         c                          l = 24
   */
  std::vector<std::uint8_t>
  padding(const std::vector<std::uint8_t> &msg) const {
    // パディングすべき大きさを決定する
    const std::size_t msglen = msg.size();
    std::size_t padlen = 128 - (msglen % 128);

    // 余裕がなければ拡張
    if (padlen < 17) {
      padlen += 128;
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
   * @brief SHA-384およびSHA-512で使用する関数Σ{512}0(x)
   * @note  仕様書の式(4.10)に相当する
   */
  constexpr std::uint64_t big_sigma512_0(std::uint64_t x) const {
    return rotr(x, 28) ^ rotr(x, 34) ^ rotr(x, 39);
  }

  /**
   * @brief SHA-384およびSHA-512で使用する関数Σ{512}1(x)
   * @note  仕様書の式(4.11)相当する
   */
  constexpr std::uint64_t big_sigma512_1(std::uint64_t x) const {
    return rotr(x, 14) ^ rotr(x, 18) ^ rotr(x, 41);
  }

  /**
   * @brief SHA-384およびSHA-512で使用する関数σ{512}0(x)
   * @note  仕様書の式(4.12)に相当する
   */
  constexpr std::uint64_t small_sigma512_0(std::uint64_t x) const {
    return rotr(x, 1) ^ rotr(x, 8) ^ (x >> 7);
  }

  /**
   * @brief SHA-384およびSHA-512で使用する関数σ{512}1(x)
   * @note  仕様書の式(4.13)に相当する
   */
  constexpr std::uint64_t small_sigma512_1(std::uint64_t x) const {
    return rotr(x, 19) ^ rotr(x, 61) ^ (x >> 6);
  }

  /**< @brief SHA-384およびSHA-512で使用される80つの64-bit words: 定数 K{512}0,
   * K{512}1, ..., K{512}79 */
  inline static constexpr std::array<std::uint64_t, 80> K{
      0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f,
      0xe9b5dba58189dbbc, 0x3956c25bf348b538, 0x59f111f1b605d019,
      0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242,
      0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
      0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
      0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3,
      0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 0x2de92c6f592b0275,
      0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
      0x983e5152ee66dfab,

      0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
      0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f,
      0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926,
      0x4d2c6dfc5ac42aed, 0x53380d139d95b3df, 0x650a73548baf63de,
      0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
      0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791,
      0xc76c51a30654be30, 0xd192e819d6ef5218, 0xd69906245565a910,
      0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8,
      0x1e376c085141ab53,

      0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63,
      0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
      0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72,
      0x8cc702081a6439ec, 0x90befffa23631e28, 0xa4506cebde82bde9,
      0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c,
      0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
      0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae,
      0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493,
      0x3c9ebe0a15c9bebc,

      0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a,
      0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
  };
};

#endif
