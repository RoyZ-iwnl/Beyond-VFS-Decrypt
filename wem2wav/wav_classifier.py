#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WAV文件分类重命名脚本
根据音频时长对WAV文件进行分类，并使用随机字母前缀重命名
"""

import os
import wave
import string
import random
from pathlib import Path
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock


def get_wav_duration(wav_path):
    """
    获取WAV文件的时长（秒）

    Args:
        wav_path: WAV文件路径

    Returns:
        float: 音频时长（秒），如果读取失败返回None
    """
    try:
        with wave.open(str(wav_path), 'rb') as wav_file:
            frames = wav_file.getnframes()
            rate = wav_file.getframerate()
            duration = frames / float(rate)
            return duration
    except Exception as e:
        print(f"读取文件失败 {wav_path}: {e}")
        return None


def format_duration(seconds):
    """
    将秒数格式化为 分:秒.毫秒 格式

    Args:
        seconds: 秒数

    Returns:
        str: 格式化的时长字符串
    """
    minutes = int(seconds // 60)
    secs = seconds % 60
    return f"{minutes:01d}_{secs:06.3f}s"


def generate_random_prefix(length=3):
    """
    生成随机字母前缀

    Args:
        length: 前缀长度

    Returns:
        str: 随机字母字符串
    """
    return ''.join(random.choices(string.ascii_uppercase, k=length))


def copy_and_rename_file(wav_file, actual_duration, group_prefix, output_path):
    """
    复制并重命名单个文件

    Args:
        wav_file: 源文件路径
        actual_duration: 实际时长
        group_prefix: 组前缀
        output_path: 输出目录

    Returns:
        (original_name, new_name, success, error_msg)
    """
    import shutil

    original_name = wav_file.name
    try:
        duration_str = format_duration(actual_duration)
        new_name = f"{group_prefix}_{duration_str}_{original_name}"
        dest_path = output_path / new_name
        shutil.copy2(wav_file, dest_path)
        return (original_name, new_name, True, None)
    except Exception as e:
        return (original_name, None, False, str(e))


def classify_wav_files(source_dir, output_dir=None, tolerance=0.1, max_workers=None):
    """
    分类并重命名WAV文件

    Args:
        source_dir: 源目录路径
        output_dir: 输出目录路径，如果为None则在源目录下创建classified文件夹
        tolerance: 时长容差（秒），用于判断是否为相同时长
        max_workers: 最大线程数（可选，默认为CPU核心数）
    """
    source_path = Path(source_dir)

    if not source_path.exists():
        print(f"错误: 源目录不存在: {source_dir}")
        return

    # 设置输出目录
    if output_dir is None:
        output_path = source_path / "classified"
    else:
        output_path = Path(output_dir)

    output_path.mkdir(parents=True, exist_ok=True)

    # 设置线程数
    if max_workers is None:
        max_workers = os.cpu_count() or 4

    # 收集所有WAV文件路径
    print("正在扫描WAV文件...")
    all_wav_paths = [f for f in source_path.rglob("*.wav") if f.is_file()]

    if not all_wav_paths:
        print("未找到WAV文件")
        return

    print(f"找到 {len(all_wav_paths)} 个WAV文件")
    print(f"使用线程数: {max_workers}")
    print("正在读取音频时长...")

    # 使用多线程读取所有文件的时长
    wav_files = []
    print_lock = Lock()
    completed = 0

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_path = {executor.submit(get_wav_duration, path): path for path in all_wav_paths}

        for future in as_completed(future_to_path):
            path = future_to_path[future]
            duration = future.result()
            completed += 1

            if duration is not None:
                wav_files.append((path, duration))
                with print_lock:
                    print(f"  [{completed}/{len(all_wav_paths)}] {path.name} - {duration:.3f}秒")

    if not wav_files:
        print("未找到有效的WAV文件")
        return

    print(f"\n成功读取 {len(wav_files)} 个WAV文件")

    # 按时长分组（使用容差）
    duration_groups = defaultdict(list)

    for wav_file, duration in wav_files:
        # 四舍五入到容差精度
        rounded_duration = round(duration / tolerance) * tolerance
        duration_groups[rounded_duration].append((wav_file, duration))

    print(f"\n根据时长分为 {len(duration_groups)} 组")
    print("正在复制和重命名文件...")

    # 为每组生成随机前缀并使用多线程复制文件
    total_files = len(wav_files)
    processed = 0
    success_count = 0
    failed_count = 0

    for group_duration, files in sorted(duration_groups.items()):
        # 为这一组生成唯一的随机前缀
        group_prefix = generate_random_prefix()

        print(f"\n处理时长组 ~{group_duration:.2f}秒 (前缀: {group_prefix}): {len(files)} 个文件")

        # 使用多线程复制这一组的文件
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_file = {
                executor.submit(copy_and_rename_file, wav_file, actual_duration, group_prefix, output_path): wav_file
                for wav_file, actual_duration in files
            }

            for future in as_completed(future_to_file):
                original_name, new_name, success, error_msg = future.result()
                processed += 1

                with print_lock:
                    if success:
                        print(f"  [{processed}/{total_files}] ✓ {original_name} -> {new_name}")
                        success_count += 1
                    else:
                        print(f"  [{processed}/{total_files}] ✗ {original_name} - {error_msg}")
                        failed_count += 1

    print(f"\n完成! 文件已保存到: {output_path}")

    # 输出统计信息
    print("\n=== 处理统计 ===")
    print(f"总文件数: {total_files}")
    print(f"成功: {success_count}")
    print(f"失败: {failed_count}")

    print("\n=== 分类统计 ===")
    for group_duration, files in sorted(duration_groups.items()):
        print(f"时长 ~{group_duration:.2f}秒: {len(files)} 个文件")


def main():
    """主函数"""
    import argparse

    parser = argparse.ArgumentParser(
        description="根据音频时长对WAV文件进行分类和重命名",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python wav_classifier.py ./audio_files
  python wav_classifier.py ./audio_files -o ./output -t 0.05
        """
    )

    parser.add_argument(
        "source_dir",
        help="包含WAV文件的源目录"
    )

    parser.add_argument(
        "-o", "--output",
        help="输出目录（默认为源目录下的classified文件夹）",
        default=None
    )

    parser.add_argument(
        "-t", "--tolerance",
        type=float,
        help="时长容差（秒），用于判断是否为相同时长（默认0.1秒）",
        default=0.1
    )

    parser.add_argument(
        "-w", "--workers",
        type=int,
        help="最大线程数（默认: CPU核心数）",
        default=None
    )

    args = parser.parse_args()

    classify_wav_files(args.source_dir, args.output, args.tolerance, args.workers)


if __name__ == "__main__":
    main()
