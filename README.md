# Beyond VFS 资源解包工具

用于解包 VFS (虚拟文件系统) 加密资源文件的 Python 工具集。支持解密魔术字节为 `:)xD` 的加密文件格式。

## 文件说明

### 核心解包工具
- **unpack.py** - 生产版本，用于正常解包操作
- **unpackdebug.py** - 调试版本，包含详细的调试输出信息

### 音频处理工具
- **wem2wav/wem2wav.py** - WEM 音频文件批量转换为 WAV 格式
- **wem2wav/wav_classifier.py** - WAV 文件按时长分类和重命名工具

## 功能特性

### VFS 解包功能
- 解密 `.blc` 文件（使用 ChaCha20 加密）
- 解析 VFS 包结构并提取文件
- 自动解密 `.chk` 数据块中的加密文件
- 自动解密 `.pck` 文件头部（使用自定义 XOR 流密码）
- 支持保留原始目录结构或扁平化输出

### 音频处理功能
- 批量转换 WEM 音频文件为 WAV 格式（基于 vgmstream）
- 多线程并行处理，提高转换效率
- 根据音频时长自动分类 WAV 文件
- 智能重命名，添加时长信息和随机前缀

## 依赖安装

### Python 依赖
```bash
pip install pycryptodome
```

### 音频转换工具依赖
WEM 转 WAV 功能需要 vgmstream 工具：
1. 下载 vgmstream: https://github.com/vgmstream/vgmstream/releases
2. 解压到以下位置之一：
   - `E:\Endfield\UNpack\vgmstream-win64\vgmstream-cli.exe`
   - 当前目录或上级目录的 `vgmstream-win64` 文件夹
   - 系统 PATH 环境变量中

## 使用方法

### VFS 解包工具

#### 基本用法

```bash
# 使用生产版本
python unpack.py <blc文件路径>

# 使用调试版本（查看详细解析过程）
python unpackdebug.py <blc文件路径>
```

#### 命令行参数

```bash
python unpack.py <blc文件路径> [选项]

选项:
  -o, --output <目录>      指定输出目录（默认: ./output）
  -redir, --keep-structure 保留原始子文件夹结构（默认: 扁平化输出）
```

#### 使用示例

```bash
# 解包到默认 output 目录（扁平化）
python unpack.py 07A1BB91.blc

# 解包到指定目录
python unpack.py 07A1BB91.blc -o extracted_files

# 保留原始目录结构
python unpack.py 07A1BB91.blc -redir

# 使用调试版本查看详细信息
python unpackdebug.py 07A1BB91.blc -o debug_output
```

### WEM 音频转换工具

#### 基本用法

```bash
# 交互式使用
python wem2wav/wem2wav.py

# 指定输入文件夹
python wem2wav/wem2wav.py -i ./wem_files

# 指定输入和输出文件夹
python wem2wav/wem2wav.py -i ./wem_files -o ./output

# 指定线程数
python wem2wav/wem2wav.py -i ./wem_files -w 8
```

#### 命令行参数

```bash
选项:
  -i, --input <目录>    WEM 文件所在的文件夹路径
  -o, --output <目录>   输出 WAV 文件的文件夹路径（默认: wem2wavoutput）
  -w, --workers <数量>  最大线程数（默认: CPU核心数）
```

### WAV 文件分类工具

#### 基本用法

```bash
# 分类当前目录的 WAV 文件
python wem2wav/wav_classifier.py ./audio_files

# 指定输出目录
python wem2wav/wav_classifier.py ./audio_files -o ./classified

# 自定义时长容差
python wem2wav/wav_classifier.py ./audio_files -t 0.05

# 指定线程数
python wem2wav/wav_classifier.py ./audio_files -w 8
```

#### 命令行参数

```bash
选项:
  -o, --output <目录>     输出目录（默认: 源目录下的classified文件夹）
  -t, --tolerance <秒数>  时长容差，用于判断是否为相同时长（默认: 0.1秒）
  -w, --workers <数量>    最大线程数（默认: CPU核心数）
```

#### 功能说明

- 自动扫描目录中的所有 WAV 文件
- 根据音频时长进行分组（可设置容差）
- 为每组生成随机字母前缀（3个大写字母）
- 重命名格式：`前缀_分钟_秒数s_原文件名.wav`
- 多线程并行处理，提高效率

## 工作原理

1. **解密 BLC 文件**: 使用文件头 12 字节作为 Nonce，通过 ChaCha20 解密文件内容
2. **解析包结构**: 读取版本、组名、文件列表等元数据
3. **提取文件**: 从对应的 `.chk` 文件中按偏移量提取数据
4. **解密文件数据**: 对标记为加密的文件使用 ChaCha20 解密
5. **处理 PCK 文件**: 自动检测并解密加密 PCK 文件

## 文件格式

- **BLC 文件**: 包含文件索引和元数据的加密清单
- **CHK 文件**: 实际存储文件数据的数据块
- **PCK 文件**: 资源包，可能包含加密头部

## 注意事项

- 确保 `.blc` 文件和对应的 `.chk` 文件在同一目录下
- 如果遇到解密错误，可以尝试修改 `unpack.py` 中的 `FORCE_FIXED_VERSION` 配置
- 调试版本会输出大量信息，仅用于排查问题

## 故障排除

### 解密失败
如果遇到解密错误，编辑 `unpack.py`:
```python
FORCE_FIXED_VERSION = True  # 改为 True
FIXED_VERSION_VAL = 3       # 尝试不同的版本值
```

### 缺失 CHK 文件
确保所有引用的 `.chk` 文件都存在于 `.blc` 文件所在目录。

### 调试问题
使用 `unpackdebug.py` 查看详细的解析过程和数据结构信息。

## 技术细节

### 加密算法

- **BLC/CHK 文件**: ChaCha20 (Counter = 1)
- **PCK 文件**: 自定义 XOR 流密码
  - 使用数学哈希函数生成密钥流
  - 常量: `CONST_M = 0x04E11C23`, `CONST_X = 0x9C5A0B29`
  - 支持字节对齐处理（Head/Body/Tail 三阶段）

### 密钥与 Nonce

- **密钥长度**: 256 位 (32 字节)
- **Nonce 构造**:
  - BLC: 文件头 12 字节
  - CHK: Version(4B) + IV Seed(8B)
  - PCK: 使用 `header_size` 作为解密种子

### PCK 解密流程

1. 检测魔术字节 `:)xD` (加密) 或 `AKPK` (明文)
2. 读取 header_size (偏移 4-8 字节)
3. 跳过头部内容的前 4 字节
4. 使用 `decipher_inplace()` 解密剩余头部
5. 重新组装为 `AKPK` 格式

## Credit

感谢Harryh老师的指导
仅供学习和研究使用。
