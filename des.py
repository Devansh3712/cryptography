# Reference:
# https://page.math.tu-berlin.de/~kant/teaching/hess/krypto-ws2006/des.htm
from typing import Tuple

# DES is a block cipher - operates on plaintext blocks of 64 bits
# and returns a ciphertext of the same size. Thus DES results in
# permutation among 2^64 possible arrangements, each of which may
# be a 0 or 1.
BLOCK_SIZE = 64
BoxType = Tuple[Tuple[int, ...], ...]

# 64-bit key is permuted according to the following permutation
# table, PC-1. The 56th bit (0 based indexing) of the original
# key becomes the first bit of the permuted key K+ and so on
pc1 = (
    (57, 49, 41, 33, 25, 17, 9),
    (1, 58, 50, 42, 34, 26, 18),
    (10, 2, 59, 51, 43, 35, 27),
    (19, 11, 3, 60, 52, 44, 36),
    (63, 55, 47, 39, 31, 23, 15),
    (7, 62, 54, 46, 38, 30, 22),
    (14, 6, 61, 53, 45, 37, 29),
    (21, 13, 5, 28, 20, 12, 4),
)

# Now form the keys Kn, for 1 <= n <= 16, by applying the PC-2
# permutation table to each of the concatenated pairs CnDn. Each
# pair has 56 bits, but PC-2 only uses 48 of these
pc2 = (
    (14, 17, 11, 24, 1, 5),
    (3, 28, 15, 6, 21, 10),
    (23, 19, 12, 4, 26, 8),
    (16, 7, 27, 20, 13, 2),
    (41, 52, 31, 37, 47, 55),
    (30, 40, 51, 45, 33, 48),
    (44, 49, 39, 56, 34, 53),
    (46, 42, 50, 36, 29, 32),
)

# There is an initial permutation IP of 64 bits of the message data
# M. This rearranges the bits according to the following table, where
# the entries in the table show the new arrangement of the bits from
# their initial order
ip = (
    (58, 50, 42, 34, 26, 18, 10, 2),
    (60, 52, 44, 36, 28, 20, 12, 4),
    (62, 54, 46, 38, 30, 22, 14, 6),
    (64, 56, 48, 40, 32, 24, 16, 8),
    (57, 49, 41, 33, 25, 17, 9, 1),
    (59, 51, 43, 35, 27, 19, 11, 3),
    (61, 53, 45, 37, 29, 21, 13, 5),
    (63, 55, 47, 39, 31, 23, 15, 7),
)

# E-bit selection table is used to expand each block Rn-1. This is done
# by repeating some of the bits of Rn-1
e_table = (
    (32, 1, 2, 3, 4, 5),
    (4, 5, 6, 7, 8, 9),
    (8, 9, 10, 11, 12, 13),
    (12, 13, 14, 15, 16, 17),
    (16, 17, 18, 19, 20, 21),
    (20, 21, 22, 23, 24, 25),
    (24, 25, 26, 27, 28, 29),
    (28, 29, 30, 31, 32, 1),
)

s1 = (
    (14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7),
    (0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8),
    (4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0),
    (15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13),
)

s2 = (
    (15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10),
    (3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5),
    (0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15),
    (13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9),
)

s3 = (
    (10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8),
    (13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1),
    (13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7),
    (1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12),
)

s4 = (
    (7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15),
    (13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9),
    (10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4),
    (3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14),
)

s5 = (
    (2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9),
    (14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6),
    (4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14),
    (11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3),
)

s6 = (
    (12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11),
    (10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8),
    (9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6),
    (4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13),
)

s7 = (
    (4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1),
    (13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6),
    (1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2),
    (6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12),
)

s8 = (
    (13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7),
    (1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2),
    (7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8),
    (2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11),
)

# P yields a 32-bit output from a 32-bit input by permuting the bits
# of the input block
p = (
    (16, 7, 20, 21),
    (29, 12, 28, 17),
    (1, 15, 23, 26),
    (5, 18, 31, 10),
    (2, 8, 24, 14),
    (32, 27, 3, 9),
    (19, 13, 30, 6),
    (22, 11, 4, 25),
)

ip_inverse = (
    (40, 8, 48, 16, 56, 24, 64, 32),
    (39, 7, 47, 15, 55, 23, 63, 31),
    (38, 6, 46, 14, 54, 22, 62, 30),
    (37, 5, 45, 13, 53, 21, 61, 29),
    (36, 4, 44, 12, 52, 20, 60, 28),
    (35, 3, 43, 11, 51, 19, 59, 27),
    (34, 2, 42, 10, 50, 18, 58, 26),
    (33, 1, 41, 9, 49, 17, 57, 25),
)


def hex_to_bin(x: int) -> list[int]:
    x_bits = [0] * BLOCK_SIZE
    for i in range(BLOCK_SIZE):
        x_bits[BLOCK_SIZE - 1 - i] = (x >> i) & 1
    return x_bits


def bin_to_dec(x: list[int]) -> int:
    decimal = 0
    for digit in x:
        decimal = decimal * 2 + digit
    return decimal


def permute(block: list[int], table: BoxType):
    return [block[index - 1] for row in table for index in row]


def generate_subkeys(key_bits: list[int]) -> list[list[int]]:
    # DES operates on 64 bit blocks using key sizes of 56 bits. The
    # keys are actually stored as being 64 bits long, but every 8th
    # bit in the key is not used
    key_plus = permute(key_bits, pc1)
    # Split key into left and right halves, C0 and D0, where each
    # half has 28 bits
    c = [key_plus[:28]]
    d = [key_plus[28:]]
    # Now create blocks Cn and Dn, 1 <= n <= 16. Each pair of blocks
    # Cn and Dn is formed from the previous pair Cn-1 and Dn-1 using
    # the following left shifts of the previous block
    #
    # To do a left shift, move each bit one place to the left, except
    # for the first bit, which is cycled to the end of the block
    shifts = (1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1)
    for i in range(16):
        # Obtain Cn and Dn from Cn-1 and Dn-1 by left shifting
        # c[i] and d[i] represent Cn-1 and Dn-1 respectively
        c_i = c[i][shifts[i] :] + c[i][: shifts[i]]
        d_i = d[i][shifts[i] :] + d[i][: shifts[i]]
        c.append(c_i)
        d.append(d_i)
    # First element in c and d are C0 and D0 which are not to be used
    # for creating the subkeys
    subkeys = [permute(ci + di, pc2) for (ci, di) in zip(c[1:], d[1:])]
    return subkeys


def substitute(block: list[int], table: BoxType):
    # First and last bits of block represent in base 2 a number in the
    # decimal range [0, 3] (binary 0 to 11), representing a row
    row = bin_to_dec(block[0::5])
    # The middle 4 bits of block represent in base 2 a number in the
    # decimal range 0 to 15 (binary 0000 to 1111), representing a
    # column
    col = bin_to_dec(block[1:5])
    # Look up in the S box table the number in at the above row and
    # column, which is a number in the range 0 to 15 and is uniquely
    # represented by a 4 bit block
    return hex_to_bin(table[row][col])[-4:]


def feistel(block: list[int], subkey: list[int]):
    # To calculate f, we first expand each block Rn-1 from 32 bits to
    # 48 bits
    e = permute(block, e_table)
    # XOR the output E(Rn-1) with key K(n)
    f_x = [e_i ^ k_i for (e_i, k_i) in zip(e, subkey)]
    # The expanded 48 bits are divided into 8 groups of 6 bits, and use
    # them as addresses in S-box tables. Each group of 6 bits will give
    # us an address in a different S-box
    #
    # Kn + E(Rn-1) = B1B2B3B4B5B6B7B8
    # Where each Bi is a group of 6 bits
    #
    # Now calculate
    # S1(B1)S2(B2)S3(B3)S4(B4)S5(B5)S6(B6)S7(B7)S8(B8)
    #
    # Where Si(Bi) referres to the output of the ith S-box, which takes
    # a 6-bit block as input and yields a 4-bit block as output
    f_s = []
    curr = 0
    s_tables = (s1, s2, s3, s4, s5, s6, s7, s8)
    for s in s_tables:
        block = f_x[curr : curr + 6]
        f_s += substitute(block, s)
        curr += 6
    # Final stage in the calculation of f is to do a permutation P
    # of the S-box output to obtain the final value of f
    #
    # f = P(S1(B1)S2(B2)...S8(B8))
    f = permute(f_s, p)
    return f


def des_rounds(initial_permutation: list[int], subkeys: list[list[int]]):
    l = initial_permutation[:32]
    r = initial_permutation[32:]
    for i in range(16):
        # Now proceed through 16 iterations, 1 <= n <= 16, using a function f
        # which operates on 2 blocks: a data block of 32 bits and a key Kn of
        # 48 bits - to produce a block of 32 bits
        #
        # Ln = Rn-1
        # Rn = Ln-1 + f(Rn-1, Kn)
        # Where + denote XOR addition (bit-by-bit addition modulo 2)
        l_i = r
        f = feistel(r, subkeys[i])
        r_i = [l_bit ^ f_bit for l_bit, f_bit in zip(l, f)]
        # Update Ln and Rn
        l, r = l_i, r_i
    return r + l


def des_encrypt(message: int, key: int):
    key_bits = hex_to_bin(key)
    message_bits = hex_to_bin(message)
    subkeys = generate_subkeys(key_bits)
    initial_permutation = permute(message_bits, ip)
    ciphertext = des_rounds(initial_permutation, subkeys)
    # Apply a final permutation IP^-1
    return permute(ciphertext, ip_inverse)


# Key should be of 64 bits
key = 0x133457799BBCDFF1
# Message should be in blocks of 64 bit, if less than that it should
# be padded with zeores
message = 0x74616E7573687269
ciphertext = des_encrypt(message, key)

assert 0x1C43A6059EAD0F58 == bin_to_dec(ciphertext)
