#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import hashlib
import argparse
import sys
import lzma
import random
import os
import base64
import subprocess
from pathlib import Path

# 引入行业标准的加密库
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# --- MoeCipher-E2EE 核心常量 ---
SOUND_CHARS = ['哦', '啊', '嗯', '咿', '咕', '哼', '呼', '唔', '齁', '喔']
PUNCTUATION_CHARS = ['～', '❤', '…', '！']
SOUND_DECODE_MAP = {char: i for i, char in enumerate(SOUND_CHARS)}

class MoeCipherE2EE:
    """
    一个实现了端到端加密的MoeCipher。
    使用X25519进行密钥协商，HKDF进行密钥派生，ChaCha20Poly1305进行对称加密。
    """
    
    def __init__(self, private_key: x25519.X25519PrivateKey = None):
        """
        初始化一个用户实例，如果未提供私钥，则生成新的密钥对。
        """
        if private_key:
            self._private_key = private_key
        else:
            self._private_key = x25519.X25519PrivateKey.generate()
        
        self._public_key = self._private_key.public_key()

    @staticmethod
    def generate_key_pair_raw() -> (bytes, bytes):
        """
        生成一对新的密钥（私钥和公钥），并以原始字节形式返回。
        :return: (private_key_bytes, public_key_bytes)
        """
        private_key = x25519.X25519PrivateKey.generate()
        public_key = private_key.public_key()
        
        priv_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        pub_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        return priv_bytes, pub_bytes

    @staticmethod
    def from_private_bytes(priv_bytes: bytes):
        """从原始字节加载用户实例"""
        try:
            private_key = x25519.X25519PrivateKey.from_private_bytes(priv_bytes)
            return MoeCipherE2EE(private_key)
        except Exception:
            raise ValueError("提供的私钥无效或格式不正确。")

    def get_public_key_bytes(self) -> bytes:
        """获取当前实例的公钥（原始字节）"""
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

    def get_public_key_b64(self) -> str:
        """获取当前实例的公钥（Base64字符串）"""
        return base64.b64encode(self.get_public_key_bytes()).decode('ascii')

    def get_public_key_moe(self) -> str:
        """获取当前实例的公钥（Moe编码字符串）"""
        # 使用一个固定的种子来编码公钥，确保其Moe形式是确定性的
        return _binary_to_moan_with_seed(self.get_public_key_bytes(), seed="MoePublicKey")

    def encrypt(self, plaintext: str, recipient_public_key_bytes: bytes) -> str:
        """
        加密一段明文，使其只能由指定的公钥对应方解密。
        """
        compressed_data = lzma.compress(plaintext.encode('utf-8'))
        
        recipient_public_key = x25519.X25519PublicKey.from_public_bytes(recipient_public_key_bytes)
        
        ephemeral_priv_key = x25519.X25519PrivateKey.generate()
        ephemeral_pub_key = ephemeral_priv_key.public_key()
        ephemeral_pub_key_bytes = ephemeral_pub_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        shared_secret = ephemeral_priv_key.exchange(recipient_public_key)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'moecipher-e2ee-key'
        ).derive(shared_secret)
        
        aead = ChaCha20Poly1305(derived_key)
        nonce = os.urandom(12)
        ciphertext_bytes = aead.encrypt(nonce, compressed_data, None)
        
        payload = ephemeral_pub_key_bytes + nonce + ciphertext_bytes
        
        # 使用接收方公钥的原始字节作为节奏种子，确保加密结果的节奏是确定的
        return _binary_to_moan_with_seed(payload, seed=recipient_public_key_bytes)

    def decrypt(self, ciphertext: str) -> str:
        """
        使用自己的私钥解密收到的Moe密文。
        """
        payload = _moan_to_binary(ciphertext)
        
        if len(payload) < 44: # 32 bytes ephemeral pub key + 12 bytes nonce
            raise ValueError("密文已损坏或格式不正确。")
            
        ephemeral_pub_key_bytes = payload[:32]
        nonce = payload[32:44]
        encrypted_data = payload[44:]
        
        ephemeral_public_key = x25519.X25519PublicKey.from_public_bytes(ephemeral_pub_key_bytes)
        
        shared_secret = self._private_key.exchange(ephemeral_public_key)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'moecipher-e2ee-key'
        ).derive(shared_secret)
        
        aead = ChaCha20Poly1305(derived_key)
        try:
            compressed_data = aead.decrypt(nonce, encrypted_data, None)
        except Exception:
            raise ValueError("解密失败：密文可能已被篡改或密钥不匹配。")
            
        plaintext_bytes = lzma.decompress(compressed_data)
        return plaintext_bytes.decode('utf-8')

# --- Moe皮肤编码/解码 (辅助函数，不依赖MoeCipherE2EE实例) ---
def _binary_to_moan_with_seed(data_bytes: bytes, seed: bytes | str = None) -> str:
    """
    将二进制数据用 Moe 编码。
    :param data_bytes: 要编码的原始字节数据。
    :param seed: 用于生成随机节奏的种子。可以是字节或字符串。
                 如果为 None，则使用随机节奏。
    """
    if not data_bytes: return ""
    
    big_int = int.from_bytes(data_bytes, 'big')
    
    if big_int == 0:
        base10_representation = SOUND_CHARS[0]
    else:
        digits = []
        temp_int = big_int
        while temp_int > 0:
            digits.append(temp_int % 10)
            temp_int //= 10
        base10_representation = "".join(SOUND_CHARS[d] for d in reversed(digits))

    # 使用提供的种子初始化随机数生成器，确保节奏可重现
    if seed is not None:
        if isinstance(seed, bytes):
            rng = random.Random(seed)
        else: # Assume string
            rng = random.Random(seed)
    else:
        rng = random.Random() # 真正的随机节奏

    moan_string = []
    source_chars = list(base10_representation)
    while source_chars:
        phrase_len = rng.randint(1, 5)
        phrase = "".join(source_chars.pop(0) for _ in range(phrase_len) if source_chars)
        if phrase:
            punctuation = rng.choice(PUNCTUATION_CHARS)
            moan_string.append(phrase + punctuation)
    return "".join(moan_string)

def _moan_to_binary(ciphertext: str) -> bytes:
    """
    将 Moe 编码的密文解码回二进制数据。
    """
    if not ciphertext: return b""
    base10_representation = "".join([char for char in ciphertext if char in SOUND_DECODE_MAP])
    if not base10_representation:
        raise ValueError("密文无效：不包含任何有效的声音字符。")
    
    big_int = 0
    for char in base10_representation:
        big_int = big_int * 10 + SOUND_DECODE_MAP[char]
        
    # 计算所需的字节长度，确保能完整表示大整数
    # 如果 big_int 为 0，则 byte_length 至少为 1
    byte_length = (big_int.bit_length() + 7) // 8 if big_int > 0 else 1
    return big_int.to_bytes(byte_length, 'big')

# --- 辅助函数 ---
def set_clipboard(text):
    """跨平台设置剪贴板内容"""
    try:
        if sys.platform == 'darwin': # macOS
            p = subprocess.Popen(['pbcopy'], stdin=subprocess.PIPE)
            p.communicate(input=text.encode('utf-8'))
        elif sys.platform == 'win32': # Windows
            p = subprocess.Popen(['clip'], stdin=subprocess.PIPE)
            p.communicate(input=text.encode('utf-8'))
        elif sys.platform == 'linux': # Linux
            p = subprocess.Popen(['xclip', '-selection', 'clipboard'], stdin=subprocess.PIPE)
            p.communicate(input=text.encode('utf-8'))
        else:
            print("警告: 您的系统不支持自动复制到剪贴板，请手动复制以下内容。", file=sys.stderr)
            print(text)
            return False
        return True
    except FileNotFoundError:
        print("警告: 无法找到剪贴板工具 (pbcopy, clip, xclip)。请手动复制以下内容。", file=sys.stderr)
        print(text)
        return False
    except Exception as e:
        print(f"剪贴板操作失败: {e}", file=sys.stderr)
        return False

def get_clipboard():
    """跨平台获取剪贴板内容"""
    try:
        if sys.platform == 'darwin':
            p = subprocess.Popen(['pbpaste'], stdout=subprocess.PIPE)
            return p.communicate()[0].decode('utf-8')
        elif sys.platform == 'win32':
            p = subprocess.Popen(['powershell', 'Get-Clipboard'], stdout=subprocess.PIPE)
            return p.communicate()[0].decode('utf-8').strip()
        elif sys.platform == 'linux':
            p = subprocess.Popen(['xclip', '-selection', 'clipboard', '-o'], stdout=subprocess.PIPE)
            return p.communicate()[0].decode('utf-8')
        else:
            print("警告: 您的系统不支持自动粘贴。请手动输入内容。", file=sys.stderr)
            return None
    except FileNotFoundError:
        print("警告: 无法找到剪贴板工具。请手动输入内容。", file=sys.stderr)
        return None
    except Exception as e:
        print(f"剪贴板操作失败: {e}", file=sys.stderr)
        return None

def moe_key_encode(key_bytes: bytes) -> str:
    """将密钥原始字节用 Moe 编码"""
    # 使用一个固定的种子来编码密钥，确保其Moe形式是确定性的
    return _binary_to_moan_with_seed(key_bytes, seed="MoeKeyEncoder")

def moe_key_decode(moe_key_string: str) -> bytes:
    """将 Moe 编码的密钥解码回原始字节"""
    try:
        return _moan_to_binary(moe_key_string)
    except Exception:
        raise ValueError("Moe 编码的密钥格式不正确。")

def parse_public_key_input(key_input: str) -> bytes:
    """
    尝试解析输入的公钥字符串，可以是 Base64 或 Moe 编码，返回原始字节。
    """
    # 尝试 Base64 解码
    try:
        pub_bytes = base64.b64decode(key_input)
        # 验证是否是有效的 X25519 公钥长度 (32字节)
        if len(pub_bytes) == 32:
            x25519.X25519PublicKey.from_public_bytes(pub_bytes) # 尝试加载以验证
            return pub_bytes
    except Exception:
        pass # 不是有效的 Base64 或不是 X25519 长度

    # 尝试 Moe 解码
    try:
        pub_bytes = moe_key_decode(key_input)
        if len(pub_bytes) == 32:
            x25519.X25519PublicKey.from_public_bytes(pub_bytes) # 尝试加载以验证
            return pub_bytes
    except Exception:
        pass # 不是有效的 Moe 编码或不是 X25519 长度

    raise ValueError("提供的公钥无效或格式不正确（既不是 Base64 也不是 Moe 编码）。")
        
def load_key_from_file(filepath: Path, key_type: str) -> str:
    """从文件中加载指定类型的密钥"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                if line.startswith(f"{key_type}_KEY="):
                    key_data = line.split("=", 1)[1].strip()
                    return key_data
            raise ValueError(f"文件 {filepath} 中找不到 {key_type}_KEY。")
    except FileNotFoundError:
        raise FileNotFoundError(f"找不到密钥文件: {filepath}")
    except Exception as e:
        raise ValueError(f"加载密钥文件失败: {e}")

# --- 主程序逻辑 ---
def main():
    parser = argparse.ArgumentParser(
        description="MoeCipher-E2EE 命令行工具。安全、萌化的端到端加密。",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument(
        '-g', '--generate',
        action='store_true',
        help="生成并打印新的公钥和私钥。两者都使用 Moe 编码。"
    )
    
    parser.add_argument(
        '-e', '--encrypt',
        metavar='PUBKEY',
        help="""加密模式。需要指定接收方的公钥。
你可以提供 Base64 字符串、Moe 编码字符串或包含公钥的文件路径。
例如: `-e ABC...` 或 `-e 哦啊嗯...` 或 `-e friend_keys.txt`。"""
    )

    parser.add_argument(
        '-d', '--decrypt',
        action='store_true',
        help="解密模式。需要加载自己的私钥。"
    )

    parser.add_argument(
        '-m', '--message',
        type=str,
        help="加密时要发送的明文。如果未提供，则从标准输入（stdin）读取。"
    )

    parser.add_argument(
        '-c', '--ciphertext',
        type=str,
        help="解密时要解密的密文。如果未提供，则从标准输入（stdin）读取。"
    )
    
    parser.add_argument(
        '-s', '--save',
        type=str,
        metavar='FILE',
        help="将新生成的密钥对保存到指定文件。"
    )

    parser.add_argument(
        '-lp', '--load-private',
        type=str,
        metavar='FILE',
        help="从指定文件加载自己的 Moe 编码私钥。"
    )

    parser.add_argument(
        '-ls', '--load-public',
        type=str,
        metavar='FILE',
        help="从指定文件加载自己的 Moe 编码公钥 (仅用于显示或验证，加密时需要接收方公钥)。"
    )

    args = parser.parse_args()
    
    # 优先处理密钥生成和保存
    if args.generate:
        priv_bytes, pub_bytes = MoeCipherE2EE.generate_key_pair_raw()
        moe_priv = moe_key_encode(priv_bytes)
        moe_pub = moe_key_encode(pub_bytes) # 公钥也Moe化

        print("--- 新生成的密钥对 ---")
        print("你的公钥 (Moe编码，可分享):")
        print(moe_pub)
        print("\n你的私钥 (Moe编码，请妥善保管):")
        print(moe_priv)
        
        if set_clipboard(moe_pub):
            print("\n✅ 公钥已自动复制到剪贴板。")
            
        if args.save:
            try:
                with open(args.save, 'w', encoding='utf-8') as f:
                    f.write(f"PUBLIC_KEY={moe_pub}\n")
                    f.write(f"PRIVATE_KEY={moe_priv}\n")
                print(f"✅ 密钥对已保存到文件: {args.save}")
            except Exception as e:
                print(f"❌ 保存文件失败: {e}", file=sys.stderr)
        
        sys.exit(0)

    moecipher = None
    
    if args.decrypt:
        # 解密模式
        if not args.load_private:
            print("❌ 解密需要加载私钥，请使用 -lp 参数。", file=sys.stderr)
            sys.exit(1)
        
        try:
            moe_priv_key_str = load_key_from_file(Path(args.load_private), 'PRIVATE')
            priv_key_bytes = moe_key_decode(moe_priv_key_str)
            moecipher = MoeCipherE2EE.from_private_bytes(priv_key_bytes)
        except Exception as e:
            print(f"❌ 加载私钥失败: {e}", file=sys.stderr)
            sys.exit(1)
            
        ciphertext_to_decrypt = args.ciphertext
        if not ciphertext_to_decrypt:
            print("请输入要解密的 Moe 密文 (Ctrl+D 或 Ctrl+Z 结束输入):")
            ciphertext_to_decrypt = sys.stdin.read().strip()
            
        if not ciphertext_to_decrypt:
            print("❌ 未提供密文。", file=sys.stderr)
            sys.exit(1)
            
        try:
            plaintext = moecipher.decrypt(ciphertext_to_decrypt)
            print("\n--- 解密结果 ---")
            print(plaintext)
            if set_clipboard(plaintext):
                print("\n✅ 明文已自动复制到剪贴板。")
        except ValueError as e:
            print(f"❌ 解密失败: {e}", file=sys.stderr)
            sys.exit(1)

    elif args.encrypt:
        # 加密模式
        recipient_pub_key_input = args.encrypt
        if not recipient_pub_key_input:
            print("❌ 加密需要指定接收方的公钥。", file=sys.stderr)
            sys.exit(1)
            
        # 尝试加载接收方的公钥
        recipient_pub_key_bytes = None
        try:
            # 检查参数是否为文件路径
            if Path(recipient_pub_key_input).is_file():
                # 从文件加载公钥 (文件中的公钥可以是Moe或Base64，由parse_public_key_input处理)
                key_str_from_file = load_key_from_file(Path(recipient_pub_key_input), 'PUBLIC')
                recipient_pub_key_bytes = parse_public_key_input(key_str_from_file)
            else:
                # 直接解析输入的字符串 (可以是Moe或Base64)
                recipient_pub_key_bytes = parse_public_key_input(recipient_pub_key_input)
        except (FileNotFoundError, ValueError) as e:
            print(f"❌ 加载或解析接收方公钥失败: {e}", file=sys.stderr)
            sys.exit(1)

        # 加载自己的密钥
        moecipher = None
        if args.load_private:
            try:
                moe_priv_key_str = load_key_from_file(Path(args.load_private), 'PRIVATE')
                priv_key_bytes = moe_key_decode(moe_priv_key_str)
                moecipher = MoeCipherE2EE.from_private_bytes(priv_key_bytes)
            except Exception as e:
                print(f"❌ 加载私钥失败: {e}", file=sys.stderr)
                sys.exit(1)
        else:
            # 如果只加载公钥或未加载任何密钥，则生成一个新的临时密钥对用于本次加密
            print("⚠️ 警告: 未加载私钥。将为本次会话生成一个临时的密钥对用于加密。", file=sys.stderr)
            moecipher = MoeCipherE2EE()
        
        plaintext_to_encrypt = args.message
        if not plaintext_to_encrypt:
            print("请输入要加密的明文 (Ctrl+D 或 Ctrl+Z 结束输入):")
            plaintext_to_encrypt = sys.stdin.read().strip()
        
        if not plaintext_to_encrypt:
            print("❌ 未提供明文。", file=sys.stderr)
            sys.exit(1)

        try:
            encrypted_moan = moecipher.encrypt(plaintext_to_encrypt, recipient_pub_key_bytes)
            print("\n--- 加密结果 (Moe密文) ---")
            print(encrypted_moan)
            if set_clipboard(encrypted_moan):
                print("\n✅ 密文已自动复制到剪贴板。")
        except Exception as e:
            print(f"❌ 加密失败: {e}", file=sys.stderr)
            sys.exit(1)

    else:
        # 如果没有指定任何操作，则打印帮助信息
        parser.print_help()

if __name__ == '__main__':
    main()