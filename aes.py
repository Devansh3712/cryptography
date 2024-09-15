# Reference:
# https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf

# The block ciphers AES-128, AES-192 and AES-256 differ in 3 aspects
# 1) Length of key
# 2) Number of rounds -> determines the size of required key schedule
# 3) Specification of recursion in KeyExpansion()
#
# Number of rounds is denoted by nr and the number of words of the key
# is denoted by nk
#
# AES-128 -> nk = 4, nr = 10
# AES-192 -> nk = 6, nr = 12
# AES-256 -> nk = 8, nr = 14

# fmt: off
# Let 'b' denote an input byte to SBox(), and let 'c' denote the constant
# byte 01100011. The output byte b' = SBox(b) is constructed by 2
# transformations:
# 1) An intermediate value b˜
#    b˜ = { {00} if b = {00} else b^−1 }
#    Where b^-1 is the multiplicative inverse of b in GF(2^8)
#
# 2) Apply affine transformation to the bits of b˜ to produce b'
#    bi' = bi˜⊕ b˜(i + 4) mod 8 ⊕ b˜(i + 5) mod 8 ⊕ b˜(i + 6) mod 8 ⊕ b˜(i + 7) mod 8 ⊕ ci
s_box = (
    (0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76),
    (0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0),
    (0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15),
    (0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75),
    (0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84),
    (0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf),
    (0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8),
    (0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2),
    (0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73),
    (0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb),
    (0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79),
    (0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08),
    (0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a),
    (0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e),
    (0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf),
    (0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16),
)
# fmt: on

r_con = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)


def sub_word(word: list[int]) -> list[int]:
    return [s_box[byte >> 4][byte & 0xF] for byte in word]


# KeyExpansion() is a routine that is applied to the key to generateround
# 4 * (rounds + 1) words. 4 words are generated for each (round + 1) applications
# of AddRoundKey() in Cipher(). The output consists of a linear array of words,
# denoted by w[i] where 0 <= i < 4 * (rounds + 1)
#
# It invokes 10 fixed words denoted by Rcon[j] for 1 <= j <= 10, known as round
# constants. For AES-128, a distinct round constant is called in generation of
# each of the 10 round keys.
#
# 2 transformations on words are called
# 1) RotWord([a0, a1, a2, a3]) = [a1, a2, a3, a0]
# 2) SubWord([a0, a1, a2, a3]) = [SBox(a0), SBox(a1), SBox(s2), SBox(a3)]
def key_expansion(key: list[int], nk: int, nr: int) -> list[list[int]]:
    # Each word is of 4 bytes, output is of size 4 * (nr + 1)
    w = [[0 for _ in range(4)] for _ in range(4 * (nr + 1))]
    for i in range(nk):
        w[i] = key[4 * i : 4 * (i + 1)]

    for i in range(nk, 4 * (nr + 1)):
        temp = w[i - 1].copy()
        if i % nk == 0:
            temp = sub_word(temp[1:] + temp[:1])
            temp[0] ^= r_con[i // nk - 1]
        elif nk > 6 and i % nk == 4:
            temp = sub_word(temp)
        for j in range(4):
            w[i][j] = w[i - nk][j] ^ temp[j]
    return w


# AddRoundKey() is a transformation of the state in which a round key is
# combined with the state by applying XOR operation.
#
# [s'[0,c], s'[1,c], s'[2,c], s'[3,c]] = [s[0, c], s[1, c], s[2, c], s[3, c]] ⊕ w[4 * round + c]
def add_round_key(
    state: list[list[int]], round_key: list[list[int]]
) -> list[list[int]]:
    for r in range(4):
        for c in range(4):
            # Round key is stored row-wise and has to be used
            # column-wise, so it is indexed using round_key[c][r]
            state[r][c] ^= round_key[c][r]
    return state


# SubBytes() is an invertible, non-linear transformation of the state in
# which a S-box is applied independently to each byte in the state.
def sub_bytes(state: list[list[int]]) -> list[list[int]]:
    for r in range(4):
        for c in range(4):
            b = state[r][c]
            state[r][c] = s_box[b >> 4][b & 0xF]
    return state


# ShiftRows() is a transformation of the state in which the bytes in the
# last 3 rows of the state are cyclically shifted. The number of positions
# by which the bytes are shifted depends on the row index r.
#
# s'[r, c] = s[r, (c + r) mod 4]
# for 0 <= r < 4 and 0 <= c < 4
def shift_rows(state: list[list[int]]) -> list[list[int]]:
    for r in range(1, 4):
        state[r] = state[r][r:] + state[r][:r]
    return state


# Multiplication in GF(2^8) is defined on 2 bytes in two steps:
# 1) 2 polynomials that represent the bytes are multiplied as polynomials
# 2) Resulting polynomial is reduced module the following fixed polynomial
#    m(x) = x^8 + x^4 + x^3 + x + 1
#
# Product b•2 can be expressed as:
# x_times(b) = { b6b5b4b3b2b10 if b7 == 0
#                b6b5b4b3b2b10 ⊕ 00011011 if b7 = 1}
def gf_mul(m: int, n: int) -> int:
    result = 0
    for _ in range(8):
        if n & 1:
            result ^= m
        carry = m & 0x80
        m <<= 1
        if carry:
            # Irreducible polynomial
            m ^= 0x1B
        n >>= 1
    return result & 0xFF


# MixColumns() is a transformation of the state that multiplies each of the
# 4 columns of the state by a single fixed matrix
#
# [a0, a1, a2, a3] = [{02}, {01}, {01}, {03}]
def mix_columns(state: list[list[int]]) -> list[list[int]]:
    matrix = (
        (2, 3, 1, 1),
        (1, 2, 3, 1),
        (1, 1, 2, 3),
        (3, 1, 1, 2),
    )
    for c in range(4):
        cols = [state[r][c] for r in range(4)]
        for r in range(4):
            result = 0
            for col, a in zip(cols, matrix[r]):
                result ^= gf_mul(col, a)
            state[r][c] = result
    return state


# Arguments for Cipher are:
# 1) Data input 'in' -> block represented as linear array of 16 bytes
# 2) Number of rounds for the instance
# 3) The round keys
#
# AES-128(in, key) = Cipher(in, 10, KeyExpansion(key))
# AES-192(in, key) = Cipher(in, 12, KeyExpansion(key))
# AES-256(in, key) = Cipher(in, 14, KeyExpansion(key))
def cipher(input: list[int], nr: int, w: list[list[int]]):
    # Internally, the algorithms for AES block ciphers are performed on a
    # 2D array of bytes called state.
    #
    # s[r, c] = in[r + 4c]
    # out[r + 4c] = s[r, c]
    state = [[input[r + 4 * c] for c in range(4)] for r in range(4)]
    state = add_round_key(state, w[0:4])
    for round in range(1, nr):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, w[4 * round : 4 * (round + 1)])
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, w[4 * nr : 4 * (nr + 1)])
    return state


# fmt: off
key = [
    0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
]
input = [
    0x32, 0x43, 0xF6, 0xA8, 0x88, 0x5A, 0x30, 0x8D, 0x31, 0x31, 0x98, 0xA2, 0xE0, 0x37, 0x07, 0x34
]
# fmt: on
got = cipher(input, 10, key_expansion(key, 4, 10))
want = [
    [0x39, 0x02, 0xDC, 0x19],
    [0x25, 0xDC, 0x11, 0x6A],
    [0x84, 0x09, 0x85, 0x0B],
    [0x1D, 0xFB, 0x97, 0x32],
]
assert got == want
