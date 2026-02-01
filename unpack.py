import os
import struct
import argparse
import binascii
from typing import List, Dict
from Crypto.Cipher import ChaCha20

# ==============================================================================
# 1. 配置
# ==============================================================================

GLOBAL_KEY = bytes([
    0xE9, 0x5B, 0x31, 0x7A, 0xC4, 0xF8, 0x28, 0x56,
    0x9D, 0x23, 0xA8, 0x6B, 0xF2, 0x71, 0xDC, 0xB5,
    0x3E, 0x84, 0x6F, 0xA7, 0x5C, 0x92, 0x4D, 0x67,
    0x1D, 0xBA, 0x8E, 0x38, 0xF4, 0xCA, 0x52, 0xE1
])

# 如果后续遇到解密报错，尝试将此值改为固定值 3
FORCE_FIXED_VERSION = False 
FIXED_VERSION_VAL = 3

# ==============================================================================
# 2. 工具类
# ==============================================================================

class BinaryReader:
    def __init__(self, data: bytes):
        self.data = data
        self.offset = 0
        self.length = len(data)

    def read_bytes(self, count: int) -> bytes:
        if self.offset + count > self.length:
            raise ValueError(f"End of stream. Req: {count}, Left: {self.length - self.offset}")
        val = self.data[self.offset : self.offset + count]
        self.offset += count
        return val

    def read_byte(self) -> int:
        return self.read_bytes(1)[0]

    def read_bool(self) -> bool:
        return self.read_byte() != 0

    def read_int32(self) -> int:
        return struct.unpack('<i', self.read_bytes(4))[0]

    def read_int64(self) -> int:
        return struct.unpack('<q', self.read_bytes(8))[0]

    def read_uint128_hex(self) -> str:
        return binascii.hexlify(self.read_bytes(16)).decode('utf-8').upper()

    def read_string(self) -> str:
        length = struct.unpack('<H', self.read_bytes(2))[0]
        if length == 0: return ""
        return self.read_bytes(length).decode('utf-8', errors='replace')

# ==============================================================================
# 3. 解密逻辑
# ==============================================================================

def decipher_inplace(p_data: bytearray, seed: int, size: int, offset_to_file_start: int) -> None:
    """
    PCK文件专用解密函数 (自定义XOR流密码)

    :param p_data: 要解密的字节数组
    :param seed: 解密种子
    :param size: 数据大小
    :param offset_to_file_start: 数据相对文件起始的偏移
    """
    def generate_key(counter: int) -> bytes:
        CONST_M = 0x04E11C23
        CONST_X = 0x9C5A0B29

        val = ((counter & 0xFF) ^ CONST_X) * CONST_M & 0xFFFFFFFF
        val = (val ^ ((counter >> 8) & 0xFF)) * CONST_M & 0xFFFFFFFF
        val = (val ^ ((counter >> 16) & 0xFF)) * CONST_M & 0xFFFFFFFF
        val = (val ^ ((counter >> 24) & 0xFF)) * CONST_M & 0xFFFFFFFF
        return val.to_bytes(4, "little")

    if size == 0:
        return

    pos = 0
    base_counter = seed + (offset_to_file_start >> 2)
    aligned_offset = offset_to_file_start & 0b11
    aligned_size = (size - pos) & ~0b11
    num_blocks = aligned_size // 4

    # Head: 处理未对齐的开头
    if aligned_offset > 0:
        key_bytes = generate_key(base_counter)
        bytes_leading = min(4 - aligned_offset, size)
        for i in range(bytes_leading):
            p_data[pos] ^= key_bytes[aligned_offset + i]
            pos += 1
        base_counter += 1

    # Body: 处理4字节对齐的块
    for block_idx in range(num_blocks):
        key_bytes = generate_key(base_counter + block_idx)
        for i in range(4):
            p_data[pos + i] ^= key_bytes[i]
        pos += 4

    # Tail: 处理剩余字节
    if pos < size:
        key_bytes = generate_key(base_counter + num_blocks)
        bytes_remaining = size - pos
        for i in range(bytes_remaining):
            p_data[pos + i] ^= key_bytes[i]

def decrypt_chacha20(data: bytes, key: bytes, nonce: bytes) -> bytes:
    cipher = ChaCha20.new(key=key, nonce=nonce)
    cipher.seek(64) # Counter = 1
    return cipher.decrypt(data)

def decrypt_pck_file(file_path: str) -> bytes:
    """解密 PCK 文件头部，返回修复后的数据"""
    filename = os.path.basename(file_path)

    with open(file_path, 'rb') as f:
        data = f.read()

    # 检查魔数
    if len(data) < 8:
        return data

    magic = data[:4]
    if magic == b'AKPK':
        # 已经是明文 PCK，直接返回
        return data

    if magic != b':)xD':
        # 不是加密的 PCK 文件，直接返回
        return data

    print(f"      [PCK] 检测到加密 PCK，正在解密: {filename}")

    # 获取头部大小
    header_size = struct.unpack('<I', data[4:8])[0]

    # 读取头部内容
    header_content = data[8 : 8 + header_size]

    # 跳过头部内容的前4字节，然后解密
    p_data = bytearray(header_content[4:])
    decipher_inplace(p_data, header_size, header_size - 4, 0)

    # 拼装还原 (魔数改为 AKPK，header_size 调整为 len(p_data))
    new_data = b'AKPK' + len(p_data).to_bytes(4, 'little') + bytes(p_data) + data[8 + header_size:]

    return new_data

def decrypt_blc_file(file_path: str) -> bytes:
    with open(file_path, 'rb') as f:
        content = f.read()
    if len(content) < 12: raise ValueError("File too small")
    # Nonce 是文件头 12 字节
    return decrypt_chacha20(content[12:], GLOBAL_KEY, content[:12])

def decrypt_chk_data(data: bytes, version: int, iv_seed: int) -> bytes:
    # Nonce = Version(4B) + Seed(8B)
    ver = FIXED_VERSION_VAL if FORCE_FIXED_VERSION else version
    nonce = struct.pack('<I', ver) + struct.pack('<Q', iv_seed)
    return decrypt_chacha20(data, GLOBAL_KEY, nonce)

# ==============================================================================
# 4. 结构解析 (已修正)
# ==============================================================================

class VFSFile:
    def __init__(self):
        self.file_name = ""
        self.offset = 0
        self.length = 0
        self.b_use_encrypt = False
        self.iv_seed = 0
        self.chk_md5_name = ""

class VFSPackage:
    def __init__(self):
        self.version = 0
        self.group_name = ""
        self.base_dir = ""
        self.files = []

def parse_blc_content(data: bytes, blc_dir: str) -> VFSPackage:
    reader = BinaryReader(data)
    pkg = VFSPackage()
    pkg.base_dir = blc_dir

    # [Fixed] 1. Header/Version
    pkg.version = reader.read_int32()
    
    # [Fixed] 2. GroupName (直接读取，无Padding)
    pkg.group_name = reader.read_string()
    
    # [Fixed] 3. Hash (读取4字节)
    _hash_val = reader.read_bytes(4)
    
    # [Fixed] 4. Padding (跳过4字节 ffffffff)
    reader.read_bytes(4)

    # 5. Metadata
    reader.read_int32() # info num
    reader.read_int64() # chunks len
    reader.read_byte()  # block type
    
    # 6. Chunks
    chunk_count = reader.read_int32()
    
    for _ in range(chunk_count):
        chk_md5 = reader.read_uint128_hex()
        reader.read_bytes(16) # content md5
        reader.read_int64()   # len
        reader.read_byte()    # type
        
        file_count = reader.read_int32()
        
        for _ in range(file_count):
            f = VFSFile()
            f.chk_md5_name = chk_md5
            f.file_name = reader.read_string()
            
            reader.read_bytes(8)  # name hash
            reader.read_bytes(32) # file hashes (16+16)
            
            f.offset = reader.read_int64()
            f.length = reader.read_int64()
            reader.read_byte()    # type
            
            f.b_use_encrypt = reader.read_bool()
            f.iv_seed = reader.read_int64() if f.b_use_encrypt else 0
            
            pkg.files.append(f)
            
    return pkg

# ==============================================================================
# 5. 执行逻辑
# ==============================================================================

def extract_pkg(pkg: VFSPackage, output_root: str, keep_structure: bool = False):
    print(f"[+] 解析成功: {pkg.group_name} (包含 {len(pkg.files)} 个文件)")

    # 按 CHK 文件分组处理，减少 IO
    files_by_chk = {}
    for f in pkg.files:
        if f.chk_md5_name not in files_by_chk: files_by_chk[f.chk_md5_name] = []
        files_by_chk[f.chk_md5_name].append(f)

    for chk_name, files in files_by_chk.items():
        chk_path = os.path.join(pkg.base_dir, f"{chk_name}.chk")
        if not os.path.exists(chk_path):
            chk_path = chk_path.lower() # 尝试小写

        if not os.path.exists(chk_path):
            print(f"  [!] 缺失 CHK 文件: {chk_name}")
            continue

        try:
            with open(chk_path, 'rb') as f_chk:
                chk_data = f_chk.read() # 读取整个 CHK 到内存

            print(f"  [-] 处理 CHK: {chk_name}")
            for file_info in files:
                # 越界检查
                if file_info.offset + file_info.length > len(chk_data):
                    print(f"    [X] 偏移越界: {file_info.file_name}")
                    continue

                raw = chk_data[file_info.offset : file_info.offset + file_info.length]

                # 解密
                if file_info.b_use_encrypt:
                    # 注意：如果后续解密失败，可能需要将 pkg.version 替换为固定值 3
                    final_data = decrypt_chk_data(raw, pkg.version, file_info.iv_seed)
                else:
                    final_data = raw

                # 写入 - 根据 keep_structure 决定路径
                if keep_structure:
                    out_path = os.path.join(output_root, file_info.file_name)
                else:
                    # 扁平化输出：只保留文件名
                    out_path = os.path.join(output_root, os.path.basename(file_info.file_name))

                os.makedirs(os.path.dirname(out_path), exist_ok=True)
                with open(out_path, 'wb') as f_out:
                    f_out.write(final_data)
                print(f"    [√] {file_info.file_name}")

                # 如果是 PCK 文件，尝试解密
                if out_path.lower().endswith('.pck'):
                    try:
                        decrypted_pck = decrypt_pck_file(out_path)
                        with open(out_path, 'wb') as f_out:
                            f_out.write(decrypted_pck)
                    except Exception as e:
                        print(f"      [!] PCK 解密失败: {e}")

        except Exception as e:
            print(f"  [!] 读取错误 {chk_name}: {e}")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("path", help=".blc 文件路径")
    parser.add_argument("-o", "--output", default="output", help="输出目录 (默认: ./output)")
    parser.add_argument("-redir", "--keep-structure", action="store_true",
                        help="保留原始子文件夹结构 (默认: 扁平化输出)")
    args = parser.parse_args()

    if os.path.isfile(args.path) and args.path.endswith(".blc"):
        try:
            data = decrypt_blc_file(args.path)
            pkg = parse_blc_content(data, os.path.dirname(args.path))
            extract_pkg(pkg, args.output, keep_structure=args.keep_structure)
        except Exception as e:
            print(f"[ERROR] {e}")
    else:
        print("请提供正确的 .blc 文件路径")

if __name__ == "__main__":
    main()
