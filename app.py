import random
import time

from flask import Flask, render_template, request, jsonify
import sympy

app = Flask(__name__)

# 全局变量标识
IS_BINARY = True

# S-Box，使用Edward Schaefer教授提供的S盒数据
s_box = [
    ['1001', '0100', '1010', '1011'],
    ['1101', '0001', '1000', '0101'],
    ['0110', '0010', '0000', '0011'],
    ['1100', '1110', '1111', '0111']
]
s_reverse_box = [
    ['1010', '0101', '1001', '1011'],
    ['0001', '0111', '1000', '1111'],
    ['0110', '0000', '0010', '0011'],
    ['1100', '0100', '1101', '1110']
]

plus_field = [
    [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F],
    [0x01, 0x00, 0x03, 0x02, 0x05, 0x04, 0x07, 0x06, 0x09, 0x08, 0x0B, 0x0A, 0x0D, 0x0C, 0x0F, 0x0E],
    [0x02, 0x03, 0x00, 0x01, 0x06, 0x07, 0x04, 0x05, 0x0A, 0x0B, 0x08, 0x09, 0x0E, 0x0F, 0x0C, 0x0D],
    [0x03, 0x02, 0x01, 0x00, 0x07, 0x06, 0x05, 0x04, 0x0B, 0x0A, 0x09, 0x08, 0x0F, 0x0E, 0x0D, 0x0C],
    [0x04, 0x05, 0x06, 0x07, 0x00, 0x01, 0x02, 0x03, 0x0C, 0x0D, 0x0E, 0x0F, 0x08, 0x09, 0x0A, 0x0B],
    [0x05, 0x04, 0x07, 0x06, 0x01, 0x00, 0x03, 0x02, 0x0D, 0x0C, 0x0F, 0x0E, 0x09, 0x08, 0x0B, 0x0A],
    [0x06, 0x07, 0x04, 0x05, 0x02, 0x03, 0x00, 0x01, 0x0E, 0x0F, 0x0C, 0x0D, 0x0A, 0x0B, 0x08, 0x09],
    [0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00, 0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08],
    [0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07],
    [0x09, 0x08, 0x0B, 0x0A, 0x0D, 0x0C, 0x0F, 0x0E, 0x01, 0x00, 0x03, 0x02, 0x05, 0x04, 0x07, 0x06],
    [0x0A, 0x0B, 0x08, 0x09, 0x0E, 0x0F, 0x0C, 0x0D, 0x02, 0x03, 0x00, 0x01, 0x06, 0x07, 0x04, 0x05],
    [0x0B, 0x0A, 0x09, 0x08, 0x0F, 0x0E, 0x0D, 0x0C, 0x03, 0x02, 0x01, 0x00, 0x07, 0x06, 0x05, 0x04],
    [0x0C, 0x0D, 0x0E, 0x0F, 0x08, 0x09, 0x0A, 0x0B, 0x04, 0x05, 0x06, 0x07, 0x00, 0x01, 0x02, 0x03],
    [0x0D, 0x0C, 0x0F, 0x0E, 0x09, 0x08, 0x0B, 0x0A, 0x05, 0x04, 0x07, 0x06, 0x01, 0x00, 0x03, 0x02],
    [0x0E, 0x0F, 0x0C, 0x0D, 0x0A, 0x0B, 0x08, 0x09, 0x06, 0x07, 0x04, 0x05, 0x02, 0x03, 0x00, 0x01],
    [0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00]
]
multi_field = [
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F],
    [0x00, 0x02, 0x04, 0x06, 0x08, 0x0A, 0x0C, 0x0E, 0x03, 0x01, 0x07, 0x05, 0x0B, 0x09, 0x0F, 0x0D],
    [0x00, 0x03, 0x06, 0x05, 0x0C, 0x0F, 0x0A, 0x09, 0x0B, 0x08, 0x0D, 0x0E, 0x07, 0x04, 0x01, 0x02],
    [0x00, 0x04, 0x08, 0x0C, 0x03, 0x07, 0x0B, 0x0F, 0x06, 0x02, 0x0E, 0x0A, 0x05, 0x01, 0x0D, 0x09],
    [0x00, 0x05, 0x0A, 0x0F, 0x07, 0x02, 0x0D, 0x08, 0x0E, 0x0B, 0x04, 0x01, 0x09, 0x0C, 0x03, 0x06],
    [0x00, 0x06, 0x0C, 0x0A, 0x0B, 0x0D, 0x07, 0x01, 0x05, 0x03, 0x09, 0x0F, 0x0E, 0x08, 0x02, 0x04],
    [0x00, 0x07, 0x0E, 0x09, 0x0F, 0x08, 0x01, 0x06, 0x0D, 0x0A, 0x03, 0x04, 0x02, 0x05, 0x0C, 0x0B],
    [0x00, 0x08, 0x03, 0x0B, 0x06, 0x0E, 0x05, 0x0D, 0x0C, 0x04, 0x0F, 0x07, 0x0A, 0x02, 0x09, 0x01],
    [0x00, 0x09, 0x01, 0x08, 0x02, 0x0B, 0x03, 0x0A, 0x04, 0x0D, 0x05, 0x0C, 0x06, 0x0F, 0x07, 0x0E],
    [0x00, 0x0A, 0x07, 0x0D, 0x0E, 0x04, 0x09, 0x03, 0x0F, 0x05, 0x08, 0x02, 0x01, 0x0B, 0x06, 0x0C],
    [0x00, 0x0B, 0x05, 0x0E, 0x0A, 0x01, 0x0F, 0x04, 0x07, 0x0C, 0x02, 0x09, 0x0D, 0x06, 0x08, 0x03],
    [0x00, 0x0C, 0x0B, 0x07, 0x05, 0x09, 0x0E, 0x02, 0x0A, 0x06, 0x01, 0x0D, 0x0F, 0x03, 0x04, 0x08],
    [0x00, 0x0D, 0x09, 0x04, 0x01, 0x0C, 0x08, 0x05, 0x02, 0x0F, 0x0B, 0x06, 0x03, 0x0E, 0x0A, 0x07],
    [0x00, 0x0E, 0x0F, 0x01, 0x0D, 0x03, 0x02, 0x0C, 0x09, 0x07, 0x06, 0x08, 0x04, 0x0A, 0x0B, 0x05],
    [0x00, 0x0F, 0x0D, 0x02, 0x09, 0x06, 0x04, 0x0B, 0x01, 0x0E, 0x0C, 0x03, 0x08, 0x07, 0x05, 0x0A]
]

x = sympy.symbols('x')

m0 = ''
m1 = ''
m2 = ''
m3 = ''
m4 = ''
m5 = ''


def column_reverse_confusion(result4):
    # 直接在矩阵里找index
    # 分割输入字符串成4个部分，每部分包含4位二进制
    part1 = result4[:4]
    part2 = result4[4:8]
    part3 = result4[8:12]
    part4 = result4[12:]

    # 将每部分从二进制转换为10进制整数
    a = int(part1, 2)
    b = int(part2, 2)
    c = int(part3, 2)
    d = int(part4, 2)

    # 前两位不需要
    s00 = bin(plus_field[multi_field[9][a]][multi_field[2][c]])[2:]
    s00 = s00.zfill(4)
    print(s00)

    s01 = bin(plus_field[multi_field[9][b]][multi_field[2][d]])[2:]
    s01 = s01.zfill(4)
    print(s01)

    s10 = bin(plus_field[multi_field[2][a]][multi_field[9][c]])[2:]
    s10 = s10.zfill(4)
    print(s10)

    s11 = bin(plus_field[multi_field[2][b]][multi_field[9][d]])[2:]
    s11 = s11.zfill(4)
    print(s11)

    return s00 + s01 + s10 + s11


def column_confusion(result2):
    # 直接在矩阵里找index
    # 分割输入字符串成4个部分，每部分包含4位二进制
    part1 = result2[:4]
    part2 = result2[4:8]
    part3 = result2[8:12]
    part4 = result2[12:]

    # 将每部分从二进制转换为10进制整数
    a = int(part1, 2)
    b = int(part2, 2)
    c = int(part3, 2)
    d = int(part4, 2)

    # 前两位不需要
    s00 = bin(plus_field[a][multi_field[4][c]])[2:]
    s00 = s00.zfill(4)
    print(s00)

    s01 = bin(plus_field[b][multi_field[4][d]])[2:]
    s01 = s01.zfill(4)
    print(s01)

    s10 = bin(plus_field[multi_field[4][a]][c])[2:]
    s10 = s10.zfill(4)
    print(s10)

    s11 = bin(plus_field[multi_field[4][b]][d])[2:]
    s11 = s11.zfill(4)
    print(s11)

    return s00 + s01 + s10 + s11


def generate_m2(m0, m1):
    m1_part1 = m1[4:]
    m1_part0 = m1[:4]

    # 我直接计算交换后的部分的两位
    m1_part1_0 = m1_part1[:2]
    m1_part1_1 = m1_part1[2:]

    m1_part0_0 = m1_part0[:2]
    m1_part0_1 = m1_part0[2:]

    # 变成S—box的索引才可以
    m1_part1_0_decimal = int(m1_part1_0, 2)
    m1_part1_1_decimal = int(m1_part1_1, 2)

    m1_part0_0_decimal = int(m1_part0_0, 2)
    m1_part0_1_decimal = int(m1_part0_1, 2)

    n1 = s_box[m1_part1_0_decimal][m1_part1_1_decimal]
    n2 = s_box[m1_part0_0_decimal][m1_part0_1_decimal]

    # 准备拿来和x的三次方进行异或的结果
    s_box_result = n1 + n2
    print('s_box_result', s_box_result)

    # 使用转义字符执行按位异或操作
    g_result = ''
    for i in range(len(s_box_result)):
        g_result += '1' if s_box_result[i] != '10000000'[i] else '0'
    print(type(g_result))
    # 将二进制字符串转换为整数，然后执行异或运算
    # g_result = bin(int('10000000', 2) ^ int(s_box_result, 2))[2:]
    print('g_result', g_result)
    # 继续执行与m0的异或结果

    num1 = ''
    for i in range(len(g_result)):
        num1 += '1' if g_result[i] != m0[i] else '0'
    return num1
    # 索引已经齐全了


def generate_m4(m2, m3):
    m3_part1 = m3[4:]
    m3_part0 = m3[:4]

    # 我直接计算交换后的部分的两位
    m3_part1_0 = m3_part1[:2]
    m3_part1_1 = m3_part1[2:]

    m3_part0_0 = m3_part0[:2]
    m3_part0_1 = m3_part0[2:]

    # 变成S—box的索引才可以
    m3_part1_0_decimal = int(m3_part1_0, 2)
    m3_part1_1_decimal = int(m3_part1_1, 2)

    m3_part0_0_decimal = int(m3_part0_0, 2)
    m3_part0_1_decimal = int(m3_part0_1, 2)

    n1 = s_box[m3_part1_0_decimal][m3_part1_1_decimal]
    n2 = s_box[m3_part0_0_decimal][m3_part0_1_decimal]

    # 准备拿来和x的三次方进行异或的结果
    s_box_result = n1 + n2
    # 将二进制字符串转换为整数，然后执行异或运算
    g_result = ''
    for i in range(len(s_box_result)):
        g_result += '1' if s_box_result[i] != '00110000'[i] else '0'
    # 继续执行与m0的异或结果
    num2 = ''
    for i in range(len(g_result)):
        num2 += '1' if g_result[i] != m2[i] else '0'
    return num2


def generate_normal_m(mth1, mth2):
    num3 = ''
    for i in range(len(mth1)):
        num3 += '1' if mth2[i] != mth1[i] else '0'
    return num3


def key_genrerate(key):
    global m0, m1, m2, m3, m4, m5  # 使用global关键字声明这些变量为全局变量
    if len(key) != 16:
        raise ValueError("Key must be 16 characters long")

    m0 = key[:8]
    m1 = key[8:]
    m2 = generate_m2(m0, m1)
    m3 = generate_normal_m(m1, m2)
    m4 = generate_m4(m2, m3)
    m5 = generate_normal_m(m3, m4)


def code_round_1(plaintext, key):
    key_genrerate(key)
    # 第一次计算所需要的轮密钥
    key_round1 = m0 + m1
    num4 = ''

    for i in range(len(plaintext)):
        num4 += '1' if plaintext[i] != key_round1[i] else '0'
    return num4


def code_round_2(plain_round1, key):
    # 先进行半字节代替
    result1 = ''
    print(plain_round1)
    print(m0)
    print(m1)
    print(m2)
    print(m3)

    for i in range(0, len(plain_round1), 4):
        half_byte = plain_round1[i:i + 4]
        row = int(half_byte[:2], 2)
        col = int(half_byte[2:], 2)
        s_box_value = s_box[row][col]
        result1 += s_box_value

    # 再进行行移位操作,把第san段和第四段位置互换
    result2 = result1[:4] + result1[4:8] + result1[12:] + result1[8:12]

    # 再进行列混淆
    result3 = column_confusion(result2)

    # 最后进行轮密钥加
    key_genrerate(key)
    key_round2 = m2 + m3
    result4 = ''
    for i in range(len(result3)):
        result4 += '1' if result3[i] != key_round2[i] else '0'
    return result4


def code_round_3(plain_round2, key):
    # 先进行半字节代替
    result1 = ''
    for i in range(0, len(plain_round2), 4):
        half_byte = plain_round2[i:i + 4]
        row = int(half_byte[:2], 2)
        col = int(half_byte[2:], 2)
        s_box_value = s_box[row][col]
        result1 += s_box_value

    # 再进行行移位操作,把第三段和第四段位置互换
    result2 = result1[:4] + result1[4:8] + result1[12:] + result1[8:12]

    # 轮密钥加
    # 最后进行轮密钥加
    key_genrerate(key)
    key_round3 = m4 + m5
    result3 = ''
    for i in range(len(result2)):
        result3 += '1' if result2[i] != key_round3[i] else '0'
    return result3


def cipher_round_1(ciphertext, key):
    key_genrerate(key)
    key_round1 = m4 + m5
    result1 = ''
    for i in range(len(ciphertext)):
        result1 += '1' if ciphertext[i] != key_round1[i] else '0'
    return result1


def cipher_round_2(cipher_round1, key):
    # 逆行移位
    result2 = cipher_round1[:4] + cipher_round1[4:8] + cipher_round1[12:] + cipher_round1[8:12]

    # 逆半字节代替
    result3 = ''
    print(result2)

    for i in range(0, len(result2), 4):
        half_byte = result2[i:i + 4]
        row = int(half_byte[:2], 2)
        col = int(half_byte[2:], 2)
        s_box_value = s_reverse_box[row][col]
        result3 += s_box_value
    # 轮密钥加
    key_genrerate(key)
    key_round2 = m2 + m3
    result4 = ''
    for i in range(len(result3)):
        result4 += '1' if result3[i] != key_round2[i] else '0'

    # 逆列混淆
    result5 = column_reverse_confusion(result4)
    return result5


def cipher_round_3(cipher_round2, key):
    # 逆行移位
    result2 = cipher_round2[:4] + cipher_round2[4:8] + cipher_round2[12:] + cipher_round2[8:12]

    # 逆半字节代替
    result3 = ''
    print(result2)

    for i in range(0, len(result2), 4):
        half_byte = result2[i:i + 4]
        row = int(half_byte[:2], 2)
        col = int(half_byte[2:], 2)
        s_box_value = s_reverse_box[row][col]
        result3 += s_box_value
    # 轮密钥加
    key_genrerate(key)
    key_round2 = m0 + m1
    result4 = ''
    for i in range(len(result3)):
        result4 += '1' if result3[i] != key_round2[i] else '0'

    return result4


# 加密函数
def saes_encrypt(plaintext, key):
    # 实现S-AES加密的代码
    # 得到所有的轮密钥
    # 实现3轮的加密
    plain_round1 = code_round_1(plaintext, key)
    plain_round2 = code_round_2(plain_round1, key)
    plain_round3 = code_round_3(plain_round2, key)
    return plain_round3


# 解密函数
def saes_decrypt(ciphertext, key):
    # 实现S-AES解密的代码
    cipher_round1 = cipher_round_1(ciphertext, key)
    cipher_round2 = cipher_round_2(cipher_round1, key)
    cipher_round3 = cipher_round_3(cipher_round2, key)

    return cipher_round3


def process_plaintext(plaintext: str) -> str:
    global IS_BINARY
    # 检查是否为16位的二进制字符串
    if len(plaintext) == 16 and all(ch in ['0', '1'] for ch in plaintext):
        IS_BINARY = True
        return plaintext

    # 如果不是二进制字符串，尝试视为2个字符的ASCII编码字符串并转换
    if len(plaintext) == 2:
        binary_str = ''.join(format(ord(char), '08b') for char in plaintext)
        IS_BINARY = False
        return binary_str


def preprocess_plaintext(plaintext):
    global IS_BINARY

    # 如果输入为空
    if not plaintext:
        return "Error: Empty input is not allowed."

    # 判断是否为二进制
    is_binary = all([ch in ['0', '1'] for ch in plaintext])

    if is_binary:
        # 如果是二进制，检查其长度是否是16的倍数
        if len(plaintext) % 16 != 0:
            return "Error: Binary plaintext length must be a multiple of 16."
        IS_BINARY = True
        return plaintext
    else:
        # 如果是字符，将其转换为二进制
        binary_text = ''.join(format(ord(ch), '08b') for ch in plaintext)
        if len(binary_text) % 16 != 0:
            return "Error: Binary representation of plaintext must be a multiple of 16 after conversion."
        IS_BINARY = False
        return binary_text


def output_result(result: str) -> str:
    global IS_BINARY
    if not IS_BINARY:
        output = ""
        for i in range(0, len(result), 8):  # 每8位处理一次
            output += chr(int(result[i:i + 8], 2))
        return output
    return result


def saes_double_encrypt(plaintext, key):
    key1 = key[:16]
    key2 = key[16:]

    # 第一次加密后的结果返回出来
    plain_middle = saes_encrypt(plaintext, key1)

    # 再进行一次加密

    plain_final = saes_encrypt(plain_middle, key2)
    print("plain_final", plain_final)
    return plain_final


def saes_double_decrypt(ciphertext, key):
    key1 = key[:16]
    key2 = key[16:]

    # 第一次解密的结果返回出来
    cipher_middle = saes_decrypt(ciphertext, key1)
    # 第二次解密
    cipher_final = saes_decrypt(cipher_middle, key2)

    return cipher_final


def saes_triple_encrypt(plaintext, key):
    key1 = key[:16]
    key2 = key[16:32]
    key3 = key[32:]

    # 第一次解密的结果返回出来
    plain_1 = saes_encrypt(plaintext, key1)
    plain_2 = saes_encrypt(plain_1, key2)
    plain_3 = saes_encrypt(plain_2, key3)

    return plain_3


def saes_triple_decrypt(ciphertext, key):
    key1 = key[:16]
    key2 = key[16:32]
    key3 = key[32:]

    # 第一次解密的结果返回出来
    plain_1 = saes_decrypt(ciphertext, key1)
    plain_2 = saes_decrypt(plain_1, key2)
    plain_3 = saes_decrypt(plain_2, key3)

    return plain_3


def meet_in_middle_attack(plaintext, ciphertext):
    start_time = time.time()
    keys_found = []

    # Step 1: Encrypt plaintext with all possible first half keys
    midtexts = {}
    for key0 in range(2 ** 16):
        binary_key0 = bin(key0)[2:].zfill(16)
        midtext_from_encry = saes_encrypt(plaintext, binary_key0)
        midtexts[midtext_from_encry] = binary_key0

    # Step 2: Decrypt ciphertext with all possible second half keys and check for match in midtexts
    for key1 in range(2 ** 16):
        binary_key1 = bin(key1)[2:].zfill(16)
        midtext_from_decry = saes_decrypt(ciphertext, binary_key1)
        if midtext_from_decry in midtexts:
            binary_key0 = midtexts[midtext_from_decry]
            keys_found.append(binary_key0 + binary_key1)

    end_time = time.time()

    keys_found_str = ' '.join(keys_found)
    return keys_found_str



def CBC_aes_encrypt(CBC_plaintexts, key, IV):
    # 获取明文分组数
    count = int(len(CBC_plaintexts) / 16)
    plaintexts = {}
    for i in range(int(count)):
        plaintexts[i] = CBC_plaintexts[0 + i * 16:16 + i * 16]

    get_ciphertexts = ''
    for i in range(int(count)):
        if i > 0:
            # i>0将明文与前一个生成的密文异或后输出S-AES加密
            get_plaintext = int(plaintexts[i], 2) ^ int(ciphertext, 2)
            get_plaintext = bin(get_plaintext)[2:].zfill(16)
            ciphertext = saes_encrypt(get_plaintext, key)
            get_ciphertexts += ciphertext

        if i == 0:
            # i=0将明文与初始向量异或后输入加密
            get_plaintext = int(plaintexts[0], 2) ^ int(IV)
            get_plaintext = bin(get_plaintext)[2:].zfill(16)

            ciphertext = saes_encrypt(get_plaintext, key)

            get_ciphertexts += ciphertext
    return get_ciphertexts


def CBC_aes_decrypt(CBC_ciphertexts, key, IV):
    # 获取密文分组数
    count = int(len(CBC_ciphertexts) / 16)
    ciphertexts = {}
    get_plaintexts = {}
    final_plaintexts = ''
    for i in reversed(range(int(count))):
        ciphertexts[i] = CBC_ciphertexts[0 + i * 16:16 + i * 16]
    for i in reversed(range(int(count))):
        if i > 0:
            plaintext = saes_decrypt(ciphertexts[i], key)
            get_plaintexts[i] = int(plaintext, 2) ^ int(ciphertexts[i - 1], 2)
        if i == 0:
            # i=0将明文与初始向量异或后输入加密
            get_ciphertext = int(ciphertexts[i], 2)
            get_ciphertext = bin(get_ciphertext)[2:].zfill(16)

            plaintext = saes_decrypt(get_ciphertext, key)

            get_plaintexts[i] = int(IV) ^ int(plaintext, 2)
    for i in range(int(count)):
        final_plaintexts += bin(get_plaintexts[i])[2:].zfill(16)
    return final_plaintexts


@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    IV = random.randint(0, 2 ** 16)
    # IV = 24358
    if request.method == 'POST':
        plaintext = request.form.get('plaintext', '')
        ciphertext = request.form.get('ciphertext', '')
        key = request.form.get('key', '')
        mode = request.form.get('mode', '')

        if mode == 'encrypt':
            plaintext = process_plaintext(plaintext)
            result = output_result(saes_encrypt(plaintext, key))
        elif mode == 'decrypt':
            plaintext = process_plaintext(ciphertext)
            result = output_result(saes_decrypt(plaintext, key))
        elif mode == 'CBC_encrypt':
            plaintext = preprocess_plaintext(plaintext)
            result = output_result(CBC_aes_encrypt(plaintext, key, IV))
        elif mode == 'CBC_decrypt':
            plaintext = preprocess_plaintext(ciphertext)
            result = output_result(CBC_aes_decrypt(plaintext, key, IV))
        elif mode == 'double_encrypt':
            plaintext = process_plaintext(plaintext)
            result = output_result(saes_double_encrypt(plaintext, key))
        elif mode == 'double_decrypt':
            plaintext = process_plaintext(ciphertext)
            result = output_result(saes_double_decrypt(plaintext, key))
        elif mode == 'meet_in_middle_attack':
            plaintext = process_plaintext(plaintext)
            ciphertext = process_plaintext(ciphertext)
            result = meet_in_middle_attack(plaintext, ciphertext)
        elif mode == 'triple_encrypt':
            plaintext = process_plaintext(plaintext)
            result = output_result(saes_triple_encrypt(plaintext, key))
        elif mode == 'triple_decrypt':
            plaintext = process_plaintext(ciphertext)
            result = output_result(saes_triple_decrypt(plaintext, key))
        return jsonify({"result": result})
    else:
        return render_template('index.html')


if __name__ == '__main__':
    app.run(debug=True)
