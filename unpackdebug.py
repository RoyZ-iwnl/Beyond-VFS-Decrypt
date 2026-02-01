import os
import struct
import argparse
import binascii
from typing import List, Dict
from Crypto.Cipher import ChaCha20

# ==============================================================================
# 1. 常量与配置
# ==============================================================================

# 游戏通用的 32 字节 ChaCha20 密钥 (来自逆向分析)
GLOBAL_KEY = bytes([
    0xE9, 0x5B, 0x31, 0x7A, 0xC4, 0xF8, 0x28, 0x56,
    0x9D, 0x23, 0xA8, 0x6B, 0xF2, 0x71, 0xDC, 0xB5,
    0x3E, 0x84, 0x6F, 0xA7, 0x5C, 0x92, 0x4D, 0x67,
    0x1D, 0xBA, 0x8E, 0x38, 0xF4, 0xCA, 0x52, 0xE1
])

# ==============================================================================
# 2. 辅助类：二进制流读取器
# ==============================================================================

class BinaryReader:
    def __init__(self, data: bytes):
        self.data = data
        self.offset = 0
        self.length = len(data)

    def read_bytes(self, count: int) -> bytes:
        if self.offset + count > self.length:
            # 打印当前状态以便调试
            print(f"[Debug] 尝试读取 {count} 字节，但剩余仅 {self.length - self.offset}")
            print(f"[Debug] 当前 Offset: {self.offset} / {self.length}")
            raise ValueError("End of stream")
        val = self.data[self.offset : self.offset + count]
        self.offset += count
        return val

    def read_byte(self) -> int:
        return self.read_bytes(1)[0]

    def read_bool(self) -> bool:
        return self.read_byte() != 0

    def read_int32(self) -> int:
        return struct.unpack('<i', self.read_bytes(4))[0]

    def read_uint32(self) -> int:
        return struct.unpack('<I', self.read_bytes(4))[0]

    def read_int64(self) -> int:
        return struct.unpack('<q', self.read_bytes(8))[0]

    def read_uint128_hex(self) -> str:
        val_bytes = self.read_bytes(16)
        return binascii.hexlify(val_bytes).decode('utf-8').upper()

    def read_string(self) -> str:
        # 调试：先读取长度看看是否合理
        len_bytes = self.read_bytes(2)
        length = struct.unpack('<H', len_bytes)[0]
        
        # 简单检查：如果长度大得离谱，说明解密可能失败了或者偏移错了
        if length > 1024:
            print(f"[Warning] 字符串长度异常: {length}，可能解密失败或解析位置错误")
        
        if length == 0:
            return ""
        
        bytes_str = self.read_bytes(length)
        return bytes_str.decode('utf-8', errors='replace')

# ==============================================================================
# 3. 核心解密逻辑
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

def decrypt_chacha20(encrypted_data: bytes, key: bytes, nonce: bytes, counter: int = 1) -> bytes:
    cipher = ChaCha20.new(key=key, nonce=nonce)
    cipher.seek(counter * 64)
    return cipher.decrypt(encrypted_data)

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
        file_content = f.read()

    if len(file_content) < 12:
        raise ValueError("File too small to be a BLC")

    nonce = file_content[:12]
    encrypted_body = file_content[12:]

    print(f"[Debug] BLC Nonce (Hex): {binascii.hexlify(nonce).decode('utf-8')}")
    
    decrypted_body = decrypt_chacha20(encrypted_body, GLOBAL_KEY, nonce, counter=1)
    return decrypted_body

def decrypt_chk_data(data: bytes, version: int, iv_seed: int) -> bytes:
    nonce = struct.pack('<I', version) + struct.pack('<Q', iv_seed)
    return decrypt_chacha20(data, GLOBAL_KEY, nonce, counter=1)

# ==============================================================================
# 4. 数据结构解析
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
        self.files: List[VFSFile] = []

def parse_blc_content(data: bytes, blc_dir: str) -> VFSPackage:
    # --- 调试：打印解密后前 64 字节 ---
    print("\n[Debug] 解密后数据预览 (前64字节):")
    print(binascii.hexlify(data[:64]).decode('utf-8'))
    print("--------------------------------------------------")
    # ----------------------------------

    reader = BinaryReader(data)
    pkg = VFSPackage()
    pkg.base_dir = blc_dir

    # 1. Version / Header (4 Bytes)
    # 根据你的 dump，前4字节是 22b14e00，我们暂时把它当作版本或魔数读掉
    # 注意：之前的代码试图在这里读 int32 然后跳过 12 字节，这显然错了。
    pkg.version = reader.read_int32() 
    print(f"[Debug] Header/Version (int32): {pkg.version} (Hex: {hex(pkg.version)})")

    # 2. GroupName (String)
    # 紧接着就是 "InitAudio"
    try:
        pkg.group_name = reader.read_string()
        print(f"[Debug] Parsed GroupName: {pkg.group_name}")
    except Exception as e:
        print(f"[Error] 解析 GroupName 失败。")
        raise e

    # 3. groupCfgHashName (4 bytes in your dump: 07 a1 bb 91)
    # 你的 dump 显示接下来的 4 字节就是 hash (07a1bb91)
    # 之前的代码读了 8 字节，这里改为读 4 字节
    _hash_val = reader.read_bytes(4)
    print(f"[Debug] Hash (4 bytes): {binascii.hexlify(_hash_val).decode('utf-8')}")

    # 4. Unknown Padding (4 bytes: ff ff ff ff)
    # 你的 dump 显示这里有 4 字节 ff
    _padding = reader.read_bytes(4)
    print(f"[Debug] Padding (4 bytes): {binascii.hexlify(_padding).decode('utf-8')}")

    # 5. Metadata
    _group_file_info_num = reader.read_int32()
    _group_chunks_length = reader.read_int64()
    _block_type = reader.read_byte()
    
    print(f"[Debug] InfoNum: {_group_file_info_num}, ChunksLen: {_group_chunks_length}, Type: {_block_type}")

    # 6. Chunks Array Size
    all_chunks_count = reader.read_int32()
    print(f"[Debug] Chunk Count: {all_chunks_count}")

    # 7. Chunks Loop
    for i in range(all_chunks_count):
        print(f"[Debug] Parsing Chunk #{i}")
        
        # FVFBlockChunkInfo
        chk_md5_name = reader.read_uint128_hex() 
        _content_md5 = reader.read_uint128_hex()
        _chunk_len = reader.read_int64()
        _chunk_block_type = reader.read_byte()
        
        # Files Array Size inside Chunk
        files_count = reader.read_int32()
        print(f"  > Chunk {chk_md5_name}, Files: {files_count}")

        for j in range(files_count):
            f = VFSFile()
            f.chk_md5_name = chk_md5_name
            
            # FVFBlockFileInfo
            f.file_name = reader.read_string()
            
            # fileNameHash (8 bytes)
            reader.read_bytes(8) 
            
            # fileChunkMD5Name (16)
            reader.read_bytes(16)
            # fileDataMD5 (16)
            reader.read_bytes(16)
            
            f.offset = reader.read_int64()
            f.length = reader.read_int64()
            _f_block_type = reader.read_byte()
            
            f.b_use_encrypt = reader.read_bool()
            
            if f.b_use_encrypt:
                f.iv_seed = reader.read_int64()
            else:
                f.iv_seed = 0
            
            pkg.files.append(f)
            # print(f"    - File: {f.file_name}")

    return pkg

# ==============================================================================
# 5. 主流程
# ==============================================================================

def process_blc_file(blc_path: str, output_root: str, keep_structure: bool = False):
    print(f"[*] 正在解析 BLC 文件: {blc_path}")

    try:
        # 1. 解密 BLC
        decrypted_blc = decrypt_blc_file(blc_path)

        # 2. 解析结构
        blc_dir = os.path.dirname(blc_path)
        vfs_pkg = parse_blc_content(decrypted_blc, blc_dir)

        print(f"    - 版本: {vfs_pkg.version}")
        print(f"    - 组名: {vfs_pkg.group_name}")
        print(f"    - 包含文件数: {len(vfs_pkg.files)}")

        # 3. 提取文件
        extract_files(vfs_pkg, output_root, keep_structure=keep_structure)

    except Exception as e:
        print(f"[!] 处理 BLC 失败: {e}")
        # import traceback
        # traceback.print_exc()

def extract_files(pkg: VFSPackage, output_root: str, keep_structure: bool = False):
    chk_handles: Dict[str, bytes] = {}

    for file_info in pkg.files:
        chk_filename = f"{file_info.chk_md5_name}.chk"
        chk_path = os.path.join(pkg.base_dir, chk_filename)

        if not os.path.exists(chk_path):
            # 尝试小写
            chk_path_lower = os.path.join(pkg.base_dir, chk_filename.lower())
            if os.path.exists(chk_path_lower):
                chk_path = chk_path_lower
            else:
                print(f"    [跳过] 找不到 CHK 文件: {chk_filename}")
                continue

        try:
            if chk_path not in chk_handles:
                print(f"    [Loading] 读取 CHK: {chk_filename}")
                with open(chk_path, 'rb') as f:
                    chk_handles[chk_path] = f.read()

            chk_data = chk_handles[chk_path]

            if file_info.offset + file_info.length > len(chk_data):
                print(f"    [错误] 偏移越界: {file_info.file_name}")
                continue

            raw_data = chk_data[file_info.offset : file_info.offset + file_info.length]

            if file_info.b_use_encrypt:
                final_data = decrypt_chk_data(raw_data, pkg.version, file_info.iv_seed)
            else:
                final_data = raw_data

            # 写入 - 根据 keep_structure 决定路径
            if keep_structure:
                save_path = os.path.join(output_root, file_info.file_name)
            else:
                # 扁平化输出：只保留文件名
                save_path = os.path.join(output_root, os.path.basename(file_info.file_name))

            os.makedirs(os.path.dirname(save_path), exist_ok=True)

            with open(save_path, 'wb') as out_f:
                out_f.write(final_data)

            print(f"    [提取] {file_info.file_name}")

            # 如果是 PCK 文件，尝试解密
            if save_path.lower().endswith('.pck'):
                try:
                    decrypted_pck = decrypt_pck_file(save_path)
                    with open(save_path, 'wb') as out_f:
                        out_f.write(decrypted_pck)
                except Exception as e:
                    print(f"      [!] PCK 解密失败: {e}")

        except Exception as e:
            print(f"    [失败] {file_info.file_name}: {e}")

def main():
    parser = argparse.ArgumentParser(description="终末地(CBT3) VFS 资源解包工具")
    parser.add_argument("path", help="输入路径：可以是 .blc 文件路径")
    parser.add_argument("-o", "--output", default="output", help="输出目录 (默认: ./output)")
    parser.add_argument("-redir", "--keep-structure", action="store_true",
                        help="保留原始子文件夹结构 (默认: 扁平化输出)")

    args = parser.parse_args()

    if os.path.isfile(args.path):
        process_blc_file(args.path, args.output, keep_structure=args.keep_structure)
    else:
        print("请提供有效的 .blc 文件路径")

if __name__ == "__main__":
    main()
