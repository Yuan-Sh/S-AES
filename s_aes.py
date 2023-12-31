import random
import re
import threading
import time

s_box = [0x9, 0x4, 0xA, 0xB,
         0xD, 0x1, 0x8, 0x5,
         0x6, 0x2, 0x0, 0x3,
         0xC, 0xE, 0xF, 0x7]

add = [[0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF],
       [0x1, 0x0, 0x3, 0x2, 0x5, 0x4, 0x7, 0x6, 0x9, 0x8, 0xB, 0xA, 0xD, 0xC, 0xF, 0xE],
       [0x2, 0x3, 0x0, 0x1, 0x6, 0x7, 0x4, 0x5, 0xA, 0xB, 0x8, 0x9, 0xE, 0xF, 0xC, 0xD],
       [0x3, 0x2, 0x1, 0x0, 0x7, 0x6, 0x5, 0x4, 0xB, 0xA, 0x9, 0x8, 0xF, 0xE, 0xD, 0xC],
       [0x4, 0x5, 0x6, 0x7, 0x0, 0x1, 0x2, 0x3, 0xC, 0xD, 0xE, 0xF, 0x8, 0x9, 0xA, 0xB],
       [0x5, 0x4, 0x7, 0x6, 0x1, 0x0, 0x3, 0x2, 0xD, 0xC, 0xF, 0xE, 0x9, 0x8, 0xB, 0xA],
       [0x6, 0x7, 0x4, 0x5, 0x2, 0x3, 0x0, 0x1, 0xE, 0xF, 0xC, 0xD, 0xA, 0xB, 0x8, 0x9],
       [0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1, 0x0, 0xF, 0xE, 0xD, 0xC, 0xB, 0xA, 0x9, 0x8],
       [0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7],
       [0x9, 0x8, 0xB, 0xA, 0xD, 0xC, 0xF, 0xE, 0x1, 0x0, 0x3, 0x2, 0x5, 0x4, 0x7, 0x6],
       [0xA, 0xB, 0x8, 0x9, 0xE, 0xF, 0xC, 0xD, 0x2, 0x3, 0x0, 0x1, 0x6, 0x7, 0x4, 0x5],
       [0xB, 0xA, 0x9, 0x8, 0xF, 0xE, 0xD, 0xC, 0x3, 0x2, 0x1, 0x0, 0x7, 0x6, 0x5, 0x4],
       [0xC, 0xD, 0xE, 0xF, 0x8, 0x9, 0xA, 0xB, 0x4, 0x5, 0x6, 0x7, 0x0, 0x1, 0x2, 0x3],
       [0xD, 0xC, 0xF, 0xE, 0x9, 0x8, 0xB, 0xA, 0x5, 0x4, 0x7, 0x6, 0x1, 0x0, 0x3, 0x2],
       [0xE, 0xF, 0xC, 0xD, 0xA, 0xB, 0x8, 0x9, 0x6, 0x7, 0x4, 0x5, 0x2, 0x3, 0x0, 0x1],
       [0xF, 0xE, 0xD, 0xC, 0xB, 0xA, 0x9, 0x8, 0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1, 0x0]]

multiply = [0x0, 0x4, 0x8, 0xC, 0x3, 0x7, 0xB, 0xF, 0x6, 0x2, 0xE, 0xA, 0x5, 0x1, 0xD, 0x9]
contrary_multiply = [[0x0, 0x9, 0x1, 0x8, 0x2, 0xB, 0x3, 0xA, 0x4, 0xD, 0x5, 0xC, 0x6, 0xF, 0x7, 0xE],  # 9 2
           [0x0, 0x2, 0x4, 0x6, 0x8, 0xA, 0xC, 0xE, 0x3, 0x1, 0x7, 0x5, 0xB, 0x9, 0xF, 0xD]]


# 轮密钥加
def add_round_key(state_matrix, kw):
    ls = [[hex(int(state_matrix[:4], 2) ^ (int(kw[:4], 2))), hex(int(state_matrix[8:12], 2) ^ (int(kw[8:12], 2)))],
          [hex(int(state_matrix[4:8], 2) ^ (int(kw[4:8], 2))), hex(int(state_matrix[12:16], 2) ^ (int(kw[12:16], 2)))]]
    # print("轮密钥加后:" + str(ls))
    return ls


# 半字节替代
def byte_substitution(s_box, state_matrix):
    ls_r = [[hex(state_matrix[int(s_box[0][0], 16)]),
             hex(state_matrix[int(s_box[0][1], 16)])],
            [hex(state_matrix[int(s_box[1][0], 16)]),
             hex(state_matrix[int(s_box[1][1], 16)])]]
    # print("半字节替代后:" + str(ls_r))
    return ls_r


# 行移位
def shiftRow(state_matrix):
    return [[state_matrix[0][0], state_matrix[0][1]],
            [state_matrix[1][1], state_matrix[1][0]]]


# 列混淆
def mixColumns(state_matrix):
    ls = [[add[int(state_matrix[0][0], 16)][multiply[int(state_matrix[1][0], 16)]],
           add[int(state_matrix[0][1], 16)][multiply[int(state_matrix[1][1], 16)]]],
          [add[multiply[int(state_matrix[0][0], 16)]][int(state_matrix[1][0], 16)],
           add[multiply[int(state_matrix[0][1], 16)]][int(state_matrix[1][1], 16)]]]
    # print("列混淆后:" + str(ls))
    return bin(ls[0][0])[2:].rjust(4, '0') + \
        bin(ls[1][0])[2:].rjust(4, '0') + \
        bin(ls[0][1])[2:].rjust(4, '0') + \
        bin(ls[1][1])[2:].rjust(4, '0')


# 逆列混淆
def invMixColumns(state_matrix):
    return [[hex(add[contrary_multiply[0][int(state_matrix[0][0], 16)]][contrary_multiply[1][int(state_matrix[1][0], 16)]]),
             hex(add[contrary_multiply[0][int(state_matrix[0][1], 16)]][contrary_multiply[1][int(state_matrix[1][1], 16)]])],
            [hex(add[contrary_multiply[1][int(state_matrix[0][0], 16)]][contrary_multiply[0][int(state_matrix[1][0], 16)]]),
             hex(add[contrary_multiply[1][int(state_matrix[0][1], 16)]][contrary_multiply[0][int(state_matrix[1][1], 16)]])]]


# 密钥扩展
def key_expansion(key, rcon):
    # print("RCON:" + rcon)
    w_left = bin(int(key[:8], 2) ^ int(rcon, 2))[2:].rjust(8, '0')
    # print("密钥左半(异或):" + w_left)
    w_right = bin(int(key[8:16], 2) ^ int(rcon, 2))[2:].rjust(8, '0')
    # print("密钥右半(异或):" + w_right)
    w_right_l = bin(int(key, 2))[2:].rjust(16, '0')[12:16]
    w_right_r = bin(int(key, 2))[2:].rjust(16, '0')[8:12]
    new_w_l = bin(s_box[int(w_right_l, 2)])[2:].rjust(4, '0')
    new_w_r = bin(s_box[int(w_right_r, 2)])[2:].rjust(4, '0')
    new_w_right = new_w_l + new_w_r
    new_L = bin(int(w_left, 2) ^ int(new_w_right, 2))[2:].rjust(8, '0')
    # print("密钥新左半:" + new_L)
    new_R = bin(int(new_L, 2) ^ int(key[8:16], 2))[2:].rjust(8, '0')
    # print("密钥新右半:" + new_L)
    # print("新密钥:" + new_L + new_R)
    return new_L + new_R
