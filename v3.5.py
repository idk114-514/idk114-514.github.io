#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import hashlib
import argparse
import sys
import zlib
import random # 新增：用于生成随机节奏

# --- MoeCipher V4 核心常量 ---

# 1. 声音字符集 (Base10 - 用于承载数据)
SOUND_CHARS = ['哦', '啊', '嗯', '咿', '咕', '哼', '呼', '唔', '齁', '喔']

# 2. 标点/状态字符集 (用于制造节奏和停顿)
PUNCTUATION_CHARS = ['～', '❤', '…', '！']

# 3. 默认密钥
DEFAULT_KEY = "r18_onomatopoeia"

# 4. 校验码长度（字节）
CHECKSUM_LENGTH = 4

# --- 内部映射表生成 ---
# 确保字符集配置正确
if len(set(SOUND_CHARS)) != 10 or len(set(PUNCTUATION_CHARS)) < 1:
    raise ValueError("字符集配置错误：声音需10个，标点至少1个，且不能重复。")
SOUND_DECODE_MAP = {char: i for i, char in enumerate(SOUND_CHARS)}


def _keystream_generator(key: str):
    """
    基于密钥生成一个无限长的伪随机密钥流 (Keystream)。
    (此函数保持不变)
    """
    seed = hashlib.sha256(key.encode('utf-8')).digest()
    current_hash = seed
    while True:
        for byte in current_hash:
            yield byte
        current_hash = hashlib.sha256(current_hash).digest()

def moe_encrypt(plaintext: str, key: str = DEFAULT_KEY) -> str:
    """
    MoeCipher V4 核心加密函数。
    流程: 明文 -> 添加校验码 -> zlib压缩 -> XOR加密 -> 大数转Base10 -> 注入节奏。
    
    :param plaintext: 需要加密的明文字符串。
    :param key: 加密密钥。
    :return: 加密后的、富有随机节奏感的“呻吟”字符串。
    """
    # 1. 将明文编码为字节并计算校验码
    plaintext_bytes = plaintext.encode('utf-8')
    checksum = hashlib.sha256(plaintext_bytes).digest()[:CHECKSUM_LENGTH]
    
    # 2. 附加校验码后进行zlib压缩 (最高级别)
    data_with_checksum = checksum + plaintext_bytes
    compressed_data = zlib.compress(data_with_checksum, level=9)
    
    # 3. 与密钥流进行XOR加密
    keystream = _keystream_generator(key)
    encrypted_bytes = bytes([b ^ next(keystream) for b in compressed_data])
    
    # 4. 将加密后的字节流视为一个大整数，并转换为Base10（声音字符）表示
    if not encrypted_bytes:
        return "" # 处理空输入
        
    big_int = int.from_bytes(encrypted_bytes, 'big')
    
    if big_int == 0:
        base10_representation = SOUND_CHARS[0]
    else:
        digits = []
        temp_int = big_int
        while temp_int > 0:
            digits.append(temp_int % 10)
            temp_int //= 10
        base10_representation = "".join(SOUND_CHARS[d] for d in reversed(digits))
        
    # 5. 注入随机节奏感
    # 使用密钥作为种子，确保每次加密的节奏都一样
    rng = random.Random(key)
    
    moan_string = []
    source_chars = list(base10_representation)
    
    while source_chars:
        # 每段短语包含 1-5 个声音字符 (最终加上标点长度为 2-6)
        phrase_len = rng.randint(1, 5)
        
        phrase = "".join(source_chars.pop(0) for _ in range(phrase_len) if source_chars)
        
        if phrase:
            # 添加一个随机标点
            punctuation = rng.choice(PUNCTUATION_CHARS)
            moan_string.append(phrase + punctuation)
            
    return "".join(moan_string)


def moe_decrypt(ciphertext: str, key: str = DEFAULT_KEY) -> str:
    """
    MoeCipher V4 核心解密函数。
    流程: 提取纯声音数据 -> Base10转大数 -> XOR解密 -> zlib解压 -> 校验数据完整性。

    :param ciphertext: 需要解密的“呻吟”字符串。
    :param key: 解密密钥。
    :return: 解密后的明文字符串。
    """
    if not ciphertext:
        return ""

    # 1. 从密文中剥离所有标点，只留下纯粹的声音数据
    base10_representation = "".join([char for char in ciphertext if char in SOUND_DECODE_MAP])
    
    if not base10_representation:
        raise ValueError("密文无效：不包含任何有效的声音字符。")

    # 2. 将Base10（声音字符）表示转换回大整数
    big_int = 0
    for char in base10_representation:
        try:
            big_int = big_int * 10 + SOUND_DECODE_MAP[char]
        except KeyError:
            # 理论上不会发生，因为前面已经过滤，但作为保险
            raise ValueError(f"密文包含无效的声音字符: {char}")

    # 3. 将大整数转换回字节流
    byte_length = (big_int.bit_length() + 7) // 8
    encrypted_bytes = big_int.to_bytes(byte_length, 'big')
    
    # 4. 与密钥流进行XOR解密
    keystream = _keystream_generator(key)
    # 注意：需要确保密钥流与加密时完全同步
    # 由于 encrypted_bytes 的长度是确定的，所以 next(keystream) 的调用次数也是确定的
    # 这里我们重新生成一个keystream即可
    decrypted_stream = _keystream_generator(key)
    compressed_data = bytes([b ^ next(decrypted_stream) for b in encrypted_bytes])
    
    # 5. zlib解压缩
    try:
        decompressed_data = zlib.decompress(compressed_data)
    except zlib.error:
        # zlib解压错误极大概率是密钥错误导致的
        raise ValueError("解密失败：密钥错误或密文已损坏。")
        
    # 6. 校验数据完整性
    if len(decompressed_data) < CHECKSUM_LENGTH:
        raise ValueError("解密失败：密文数据不完整，缺少校验码。")
        
    received_checksum = decompressed_data[:CHECKSUM_LENGTH]
    plaintext_bytes = decompressed_data[CHECKSUM_LENGTH:]
    
    expected_checksum = hashlib.sha256(plaintext_bytes).digest()[:CHECKSUM_LENGTH]
    
    if received_checksum != expected_checksum:
        raise ValueError("校验失败：密钥错误或密文数据已被篡改。")
        
    # 7. 将字节解码为明文
    try:
        return plaintext_bytes.decode('utf-8')
    except UnicodeDecodeError:
        raise ValueError("解密失败：最终数据无法被正确解码为UTF-8文本。")


def main():
    """终端调用入口"""
    parser = argparse.ArgumentParser(
        description='MoeCipher V4: 一种高效、富有随机“神韵”的可逆呻吟加密算法。',
        epilog='示例: python moe_cipher_v4.py "要加密的秘密~"',
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument(
        'content', 
        metavar='文本内容',
        type=str,
        help='需要加密或解密的字符串。'
    )
    parser.add_argument(
        '-k', '--key', 
        dest='key',
        default=DEFAULT_KEY,
        help=f'用于加密/解密的密钥 (默认: "{DEFAULT_KEY}")'
    )
    parser.add_argument(
        '-d', '--decrypt',
        action='store_true',
        help='执行解密操作 (默认为加密)。'
    )
    
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)
        
    args = parser.parse_args()
    
    try:
        if args.decrypt:
            result = moe_decrypt(args.content, args.key)
            print("--- 解密成功 ---")
            print(result)
        else:
            original_len = len(args.content.encode('utf-8'))
            result = moe_encrypt(args.content, args.key)
            print("--- 加密成功 ---")
            print(result)
            print(f"\n原始字节长度: {original_len} | 密文长度: {len(result)}")
            # 对比测试
            # recovered = moe_decrypt(result, args.key)
            # print(f"校验解密是否成功: {recovered == args.content}")

    except Exception as e:
        print(f"错误: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()