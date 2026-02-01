import os
import sys
import shutil
import argparse
import subprocess
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

def find_vgmstream():
    """查找 vgmstream-cli 工具路径"""
    # 常见路径
    possible_paths = [
        r"E:\Endfield\UNpack\vgmstream-win64\vgmstream-cli.exe",
        r".\vgmstream-cli.exe",
        r".\vgmstream-win64\vgmstream-cli.exe",
        r"..\vgmstream-win64\vgmstream-cli.exe",
    ]

    # 检查路径
    for path in possible_paths:
        if os.path.exists(path):
            return path

    # 检查系统 PATH
    try:
        result = subprocess.run(['where', 'vgmstream-cli'],
                              capture_output=True, text=True, shell=True)
        if result.returncode == 0:
            return result.stdout.strip().split('\n')[0]
    except:
        pass

    return None

def convert_single_wem(wem_path, output_folder, vgmstream_path):
    """
    转换单个WEM文件为WAV

    参数:
        wem_path: WEM文件路径
        output_folder: 输出文件夹
        vgmstream_path: vgmstream工具路径

    返回:
        (filename, success, error_msg): 文件名、是否成功、错误信息
    """
    filename = os.path.basename(wem_path)
    try:
        # 生成输出文件名
        wav_filename = filename.rsplit('.', 1)[0] + '.wav'
        wav_path = os.path.join(output_folder, wav_filename)

        # 使用 vgmstream 转换
        result = subprocess.run(
            [vgmstream_path, '-o', wav_path, wem_path],
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode == 0:
            return (filename, True, None)
        else:
            return (filename, False, "vgmstream 返回错误")

    except subprocess.TimeoutExpired:
        return (filename, False, "转换超时")
    except Exception as e:
        return (filename, False, str(e))

def batch_convert_wem_to_wav(source_folder, output_folder=None, vgmstream_path=None, max_workers=None):
    """
    批量将wem文件转换为wav文件（使用 vgmstream）

    参数:
        source_folder: wem文件所在的文件夹路径
        output_folder: 输出wav文件的文件夹路径（可选，默认为wem2wavoutput）
        vgmstream_path: vgmstream-cli 工具路径（可选，自动查找）
        max_workers: 最大线程数（可选，默认为CPU核心数）
    """
    # 查找 vgmstream 工具
    if vgmstream_path is None:
        vgmstream_path = find_vgmstream()

    if vgmstream_path is None or not os.path.exists(vgmstream_path):
        print("错误: 未找到 vgmstream-cli 工具")
        print("请下载 vgmstream 并放置在以下位置之一：")
        print("  - E:\\Endfield\\UNpack\\vgmstream-win64\\vgmstream-cli.exe")
        print("  - 当前目录或上级目录的 vgmstream-win64 文件夹")
        print("  - 系统 PATH 环境变量中")
        return False

    print(f"使用工具: {vgmstream_path}\n")

    # 检查源文件夹是否存在
    if not os.path.exists(source_folder):
        print(f"错误: 源文件夹不存在: {source_folder}")
        return False

    if not os.path.isdir(source_folder):
        print(f"错误: 路径不是文件夹: {source_folder}")
        return False

    # 如果未指定输出文件夹，使用默认的wem2wavoutput
    if output_folder is None:
        output_folder = 'wem2wavoutput'
    
    # 确保输出文件夹存在
    os.makedirs(output_folder, exist_ok=True)
    
    # 计数器
    success_count = 0
    failed_files = []
    total_wem_files = 0

    # 统计wem文件数量
    wem_files = [f for f in os.listdir(source_folder) if f.lower().endswith('.wem')]
    total_wem_files = len(wem_files)

    if total_wem_files == 0:
        print(f"警告: 在 {source_folder} 中未找到 .wem 文件")
        return False

    # 设置线程数
    if max_workers is None:
        max_workers = os.cpu_count() or 4

    print(f"找到 {total_wem_files} 个 .wem 文件")
    print(f"源文件夹: {os.path.abspath(source_folder)}")
    print(f"输出文件夹: {os.path.abspath(output_folder)}")
    print(f"使用线程数: {max_workers}")
    print("-" * 60)

    # 准备所有文件路径
    wem_paths = [os.path.join(source_folder, filename) for filename in wem_files]

    # 使用线程池并行处理
    print_lock = Lock()
    completed = 0

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # 提交所有任务
        future_to_file = {
            executor.submit(convert_single_wem, wem_path, output_folder, vgmstream_path): wem_path
            for wem_path in wem_paths
        }

        # 处理完成的任务
        for future in as_completed(future_to_file):
            filename, success, error_msg = future.result()
            completed += 1

            with print_lock:
                if success:
                    print(f"[{completed}/{total_wem_files}] ✓ {filename}")
                    success_count += 1
                else:
                    print(f"[{completed}/{total_wem_files}] ✗ {filename} - {error_msg}")
                    failed_files.append(filename)
    
    # 输出转换结果摘要
    print("-" * 60)
    print(f"\n转换完成!")
    print(f"总计: {total_wem_files} 个文件")
    print(f"成功: {success_count} 个")
    print(f"失败: {len(failed_files)} 个")
    print(f"输出目录: {os.path.abspath(output_folder)}")

    if failed_files:
        print(f"\n失败文件列表:")
        for f in failed_files:
            print(f"  - {f}")

    return True

def main():
    """主函数，处理命令行参数和交互式输入"""
    parser = argparse.ArgumentParser(
        description='批量将 WEM 文件转换为 WAV 文件',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
使用示例:
  python wem2wav.py                              # 交互式输入
  python wem2wav.py -i ./wem_files               # 指定输入文件夹
  python wem2wav.py -i ./wem_files -o ./output   # 指定输入和输出文件夹
  python wem2wav.py --input ./wem_files          # 使用完整参数名
        '''
    )

    parser.add_argument(
        '-i', '--input',
        dest='input_folder',
        help='WEM 文件所在的文件夹路径'
    )

    parser.add_argument(
        '-o', '--output',
        dest='output_folder',
        default=None,
        help='输出 WAV 文件的文件夹路径（默认: wem2wavoutput）'
    )

    parser.add_argument(
        '-w', '--workers',
        dest='max_workers',
        type=int,
        default=None,
        help='最大线程数（默认: CPU核心数）'
    )

    args = parser.parse_args()

    # 获取输入文件夹
    if args.input_folder:
        source_folder = args.input_folder
    else:
        # 交互式输入
        print("=" * 60)
        print("WEM 转 WAV 批量转换工具")
        print("=" * 60)
        source_folder = input("\n请输入 WEM 文件所在的文件夹路径: ").strip()

        if not source_folder:
            print("错误: 未指定输入文件夹")
            sys.exit(1)

    # 移除路径两端的引号（如果有）
    source_folder = source_folder.strip('"').strip("'")

    # 获取输出文件夹
    output_folder = args.output_folder
    if output_folder:
        output_folder = output_folder.strip('"').strip("'")

    # 执行转换
    print()
    success = batch_convert_wem_to_wav(source_folder, output_folder, max_workers=args.max_workers)

    if success:
        print("\n转换任务完成!")
        sys.exit(0)
    else:
        print("\n转换任务失败!")
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n用户中断操作")
        sys.exit(1)
    except Exception as e:
        print(f"\n发生错误: {str(e)}")
        sys.exit(1)
